import { deflateRawSync, inflateRawSync } from "node:zlib";
import {
  buildJobDescription,
  sanitizeForClaim,
} from "@bnbagent/sdk/erc8183";
import { getNetwork } from "@bnbagent/studio-runtime/networks";
import {
  createPublicClient,
  decodeAbiParameters,
  encodeAbiParameters,
  getAddress,
  http,
  parseAbiParameters,
  toFunctionSelector,
  type Hex,
  type Transport,
} from "viem";
import { z } from "zod";

const MIN_TICK = -887272;
const MAX_TICK = 887272;
const TASK_PREFIX = "mandatex-rebalance:v1:";
const MAX_ENCODED_TASK_BYTES = 2600;
const MAX_DECODED_TASK_BYTES = 16_000;
const FUTURE_BLOCK_TOLERANCE_SECONDS = 15;
export const BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS = 2;

const NETWORK_CHAIN_IDS: Record<string, number> = {
  "bsc-mainnet": 56,
  "bsc-testnet": 97,
};

export const PANCAKE_V3_DEPLOYMENTS = {
  "bsc-mainnet": {
    factory: "0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865",
    deployer: "0x41ff9aa7e16b8b1a8a8dc4f0efacd93d02d071c9",
    position_manager: "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364",
  },
  "bsc-testnet": {
    factory: "0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865",
    deployer: "0x41ff9aa7e16b8b1a8a8dc4f0efacd93d02d071c9",
    position_manager: "0x427bf5b37357632377ecbec9de3626c71a5396c1",
  },
} as const;

export const REQUIRED_REBALANCE_CALLS = [
  "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
  "collect((uint256,address,uint128,uint128))",
  "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
] as const;

export const FIXED_REBALANCE_TERMS = Object.freeze({
  deliverables:
    "A MandateX JSON receipt that is explicitly simulation_ready or refused.",
  quality_standards:
    "Re-read BSC state at delivery and refuse on stale evidence, expiry, unsafe permissions, target-range exit, or excessive tick drift. Do not claim a liquidity transaction occurred.",
  success_criteria: [
    "Receipt names the quote block and delivery block.",
    "Receipt preserves the approved target range and permission manifest.",
    "Simulation is clearly labelled and contains no fabricated transaction hash.",
  ],
});

const REFUSAL_CODES = [
  "INVALID_MANDATE",
  "UNSUPPORTED_CATEGORY",
  "UNSUPPORTED_CHAIN",
  "UNSUPPORTED_PROTOCOL",
  "EVIDENCE_UNAVAILABLE",
  "STALE_EVIDENCE",
  "POOL_POSITION_MISMATCH",
  "POSITION_INACTIVE",
  "REBALANCE_NOT_TRIGGERED",
  "RANGE_OUTSIDE_MANDATE",
  "GAS_LIMIT_EXCEEDED",
  "SLIPPAGE_LIMIT_EXCEEDED",
  "EXPOSURE_LIMIT_EXCEEDED",
  "CONTRACT_NOT_ALLOWED",
  "CALL_NOT_ALLOWED",
  "PERMISSION_EXPIRED",
  "MANDATE_EXPIRED",
  "STATE_DRIFT",
  "TARGET_RANGE_EXITED",
  "SIGNED_TASK_INVALID",
] as const;

const addressSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/, "must be a 20-byte EVM address")
  .transform((value) => value.toLowerCase());

const tickSchema = z.number().int().min(MIN_TICK).max(MAX_TICK);
const usdSchema = z.number().finite().nonnegative();
const unixSecondsSchema = z.number().int().positive();
const blockHashSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{64}$/, "must be a 32-byte block hash")
  .transform((value) => value.toLowerCase());

export const RebalancePermissionSchema = z
  .object({
    allowed_contracts: z.array(addressSchema).min(1).max(12),
    allowed_calls: z.array(z.string().trim().min(1).max(180)).min(1).max(20),
    spend_cap_usd: usdSchema,
    expires_at: unixSecondsSchema,
  })
  .strict();

export const RebalanceMandateSchema = z
  .object({
    version: z.literal("1"),
    mandate_id: z
      .string()
      .trim()
      .min(1)
      .max(80)
      .regex(/^[A-Za-z0-9._:-]+$/, "contains unsupported characters"),
    category: z.literal("rebalancing"),
    chain_id: z.number().int().positive(),
    protocol: z.literal("pancakeswap-v3"),
    expires_at: unixSecondsSchema,
    max_evidence_age_seconds: z.number().int().min(5).max(300).default(120),
    position: z
      .object({
        pool_address: addressSchema,
        position_manager_address: addressSchema,
        token_id: z
          .string()
          .trim()
          .regex(/^\d+$/, "must be an unsigned decimal integer")
          .transform((value) => BigInt(value).toString()),
      })
      .strict(),
    range_policy: z
      .object({
        approved_lower_tick: tickSchema,
        approved_upper_tick: tickSchema,
        target_width_ticks: z.number().int().positive().max(MAX_TICK - MIN_TICK),
        trigger_mode: z
          .enum(["out_of_range", "boundary_proximity"])
          .default("boundary_proximity"),
        trigger_distance_ticks: z.number().int().nonnegative().max(MAX_TICK - MIN_TICK),
        max_delivery_tick_drift: z.number().int().nonnegative().max(MAX_TICK - MIN_TICK),
      })
      .strict(),
    limits: z
      .object({
        max_gas_usd: usdSchema,
        max_slippage_bps: z.number().int().min(0).max(10_000),
        max_exposure_usd: usdSchema,
      })
      .strict(),
    execution_estimate: z
      .object({
        gas_usd: usdSchema,
        slippage_bps: z.number().int().min(0).max(10_000),
        exposure_usd: usdSchema,
        observed_at: unixSecondsSchema,
        source_url: z.string().url().max(500),
      })
      .strict(),
    permissions: RebalancePermissionSchema,
  })
  .strict()
  .superRefine((mandate, ctx) => {
    if (
      mandate.range_policy.approved_lower_tick >=
      mandate.range_policy.approved_upper_tick
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["range_policy", "approved_upper_tick"],
        message: "must be greater than approved_lower_tick",
      });
    }
    if (
      mandate.range_policy.target_width_ticks >
      mandate.range_policy.approved_upper_tick -
        mandate.range_policy.approved_lower_tick
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["range_policy", "target_width_ticks"],
        message: "must fit inside the approved tick envelope",
      });
    }
    if (mandate.permissions.expires_at > mandate.expires_at) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["permissions", "expires_at"],
        message: "must not outlive the mandate",
      });
    }
  });

export const RebalanceEvidenceSchema = z
  .object({
    network: z.string(),
    chain_id: z.number().int().positive(),
    snapshot_head_block: z.number().int().nonnegative(),
    confirmation_depth_blocks: z.literal(
      BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS,
    ),
    observed_block: z.number().int().nonnegative(),
    observed_block_hash: blockHashSchema,
    observed_at: unixSecondsSchema,
    pool_address: addressSchema,
    position_manager_address: addressSchema,
    position_token_id: z.string().regex(/^\d+$/),
    position_owner: addressSchema,
    token0: addressSchema,
    token1: addressSchema,
    token0_decimals: z.number().int().min(0).max(255),
    token1_decimals: z.number().int().min(0).max(255),
    fee: z.number().int().min(0).max(1_000_000),
    tick_spacing: z.number().int().positive().max(MAX_TICK - MIN_TICK),
    current_tick: tickSchema,
    sqrt_price_x96: z.string().regex(/^\d+$/),
    approximate_token1_per_token0: z.string().nullable(),
    position_tick_lower: tickSchema,
    position_tick_upper: tickSchema,
    pool_liquidity: z.string().regex(/^\d+$/),
    position_liquidity: z.string().regex(/^\d+$/),
    sources: z.array(
      z
        .object({
          type: z.literal("onchain"),
          url: z.string().url(),
          observed_block: z.number().int().nonnegative(),
        })
        .strict(),
    ),
  })
  .strict()
  .superRefine((evidence, ctx) => {
    if (
      evidence.snapshot_head_block - evidence.observed_block !==
      evidence.confirmation_depth_blocks
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["confirmation_depth_blocks"],
        message:
          "must equal snapshot_head_block minus observed_block",
      });
    }
    if (evidence.position_tick_lower >= evidence.position_tick_upper) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["position_tick_upper"],
        message: "must be greater than position_tick_lower",
      });
    }
    if (
      evidence.position_tick_lower % evidence.tick_spacing !== 0 ||
      evidence.position_tick_upper % evidence.tick_spacing !== 0
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["tick_spacing"],
        message: "position range endpoints must align to tick_spacing",
      });
    }
  });

export const RebalanceProposalSchema = z
  .object({
    execution_mode: z.literal("simulation"),
    proposed_lower_tick: tickSchema,
    proposed_upper_tick: tickSchema,
    trigger: z
      .object({
        fired: z.literal(true),
        reason: z.enum(["outside_current_range", "near_range_boundary"]),
        distance_to_boundary_ticks: z.number().int().nonnegative(),
      })
      .strict(),
    estimated_gas_usd: usdSchema,
    estimated_slippage_bps: z.number().int().min(0).max(10_000),
    estimated_exposure_usd: usdSchema,
    estimate_source_url: z.string().url(),
    permissions: z
      .object({
        contracts: z.array(addressSchema),
        calls: z.array(z.string()),
        spend_cap_usd: usdSchema,
        expires_at: unixSecondsSchema,
      })
      .strict(),
    break_even: z
      .object({
        status: z.literal("not_calculated"),
        reason: z.string(),
      })
      .strict(),
  })
  .strict()
  .superRefine((proposal, ctx) => {
    if (proposal.proposed_lower_tick >= proposal.proposed_upper_tick) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["proposed_upper_tick"],
        message: "must be greater than proposed_lower_tick",
      });
    }
  });

export const RebalanceRefusalSchema = z
  .object({
    code: z.enum(REFUSAL_CODES),
    message: z.string().min(1),
    details: z.record(z.unknown()).optional(),
  })
  .strict();

function validateSignedRange(
  task: {
    readonly mandate: RebalanceMandate;
    readonly evidence: RebalanceEvidence;
    readonly proposal: RebalanceProposal;
  },
  ctx: z.RefinementCtx,
): void {
    const width = task.mandate.range_policy.target_width_ticks;
    const spacing = task.evidence.tick_spacing;
    const lower = task.proposal.proposed_lower_tick;
    const upper = task.proposal.proposed_upper_tick;
    if (width % spacing !== 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["mandate", "range_policy", "target_width_ticks"],
        message: "must be divisible by evidence.tick_spacing",
      });
      return;
    }
    if (
      lower % spacing !== 0 ||
      upper % spacing !== 0 ||
      upper - lower !== width
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["proposal"],
        message: "proposal endpoints must be aligned and have exact target width",
      });
      return;
    }
    if (
      lower < task.mandate.range_policy.approved_lower_tick ||
      upper > task.mandate.range_policy.approved_upper_tick ||
      task.evidence.current_tick < lower ||
      task.evidence.current_tick >= upper
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["proposal"],
        message:
          "proposal must fit inside the approved envelope and contain the current tick",
      });
      return;
    }
    const expected = deriveExactTargetRange(
      task.evidence.current_tick,
      width,
      spacing,
    );
    if (lower !== expected.lower || upper !== expected.upper) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["proposal"],
        message: "proposal must use the deterministic exact target range",
      });
    }
}

export const SignedRebalanceTaskSchema = z
  .object({
    schema: z.literal("mandatex.rebalance.quote.v1"),
    mandate: RebalanceMandateSchema,
    evidence: RebalanceEvidenceSchema,
    proposal: RebalanceProposalSchema,
    eligibility: z
      .object({
        eligible: z.literal(true),
        checked_at: unixSecondsSchema,
        checks: z.array(z.string().min(1)),
      })
      .strict(),
  })
  .strict()
  .superRefine(validateSignedRange);

export const RebalanceReceiptSchema = z
  .object({
    schema: z.literal("mandatex.rebalance.receipt.v1"),
    job_id: z.number().int().nonnegative(),
    mandate_id: z.string(),
    status: z.enum(["simulation_ready", "refused"]),
    execution_mode: z.literal("simulation"),
    simulation_only: z.literal(true),
    policy_result: z.enum(["within_mandate", "refused_by_rule"]),
    quoted_evidence: RebalanceEvidenceSchema.nullable(),
    delivery_evidence: RebalanceEvidenceSchema.nullable(),
    proposal: RebalanceProposalSchema.nullable(),
    refusal: RebalanceRefusalSchema.nullable(),
    generated_at: unixSecondsSchema,
    note: z.string(),
  })
  .strict();

export type RebalanceMandate = z.infer<typeof RebalanceMandateSchema>;
export type RebalanceEvidence = z.infer<typeof RebalanceEvidenceSchema>;
export type RebalanceProposal = z.infer<typeof RebalanceProposalSchema>;
export type RebalanceRefusal = z.infer<typeof RebalanceRefusalSchema>;
export type SignedRebalanceTask = z.infer<typeof SignedRebalanceTaskSchema>;
export type RebalanceReceipt = z.infer<typeof RebalanceReceiptSchema>;

export interface RebalanceStateReader {
  read(mandate: RebalanceMandate, network: string): Promise<RebalanceEvidence>;
}

export interface PinnedBlockSnapshot {
  chainId: number;
  snapshotHeadBlock: number;
  confirmationDepthBlocks: number;
  number: number;
  hash: string;
  timestamp: number;
}

export interface PinnedRpcReader {
  getHead(network: string): Promise<PinnedBlockSnapshot>;
  getCode(address: string, blockHash: string, network: string): Promise<string>;
  call(
    address: string,
    functionSignature: string,
    args: unknown[] | null,
    outputTypes: string[] | null,
    blockHash: string,
    network: string,
  ): Promise<Record<string, unknown>>;
  assertCanonical(
    blockNumber: number,
    blockHash: string,
    network: string,
  ): Promise<void>;
}

export interface ViemPinnedRpcReaderOptions {
  confirmationDepthBlocks?: typeof BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS;
  transportFactory?: (network: string) => Transport;
}

export class ViemPinnedRpcReader implements PinnedRpcReader {
  private readonly clients = new Map<
    string,
    ReturnType<typeof createPublicClient>
  >();
  private readonly transportFactory?: (network: string) => Transport;

  constructor(opts: ViemPinnedRpcReaderOptions = {}) {
    if (
      opts.confirmationDepthBlocks !== undefined &&
      opts.confirmationDepthBlocks !== BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS
    ) {
      throw new Error(
        `confirmationDepthBlocks must equal ${BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS}`,
      );
    }
    this.transportFactory = opts.transportFactory;
  }

  async getHead(network: string): Promise<PinnedBlockSnapshot> {
    const client = this.client(network);
    const chainId = await client.getChainId();
    const head = await client.getBlock({ blockTag: "latest" });
    if (head.number === null) {
      throw new SnapshotChangedError("latest block number is unavailable");
    }
    const depth = BigInt(BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS);
    if (head.number < depth) {
      throw new SnapshotChangedError(
        "latest block is below the required confirmation depth",
      );
    }
    const targetNumber = head.number - depth;
    const block = await client.getBlock({ blockNumber: targetNumber });
    if (
      block.number === null ||
      block.hash === null ||
      block.number !== targetNumber
    ) {
      throw new SnapshotChangedError("confirmed block header is incomplete");
    }
    return {
      chainId,
      snapshotHeadBlock: asInteger(head.number, "snapshot head block number"),
      confirmationDepthBlocks: BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS,
      number: asInteger(block.number, "block number"),
      hash: blockHashSchema.parse(block.hash),
      timestamp: asInteger(block.timestamp, "block timestamp"),
    };
  }

  async getCode(
    address: string,
    blockHash: string,
    network: string,
  ): Promise<string> {
    const code = await this.client(network).getCode({
      address: getAddress(address),
      blockHash: blockHashSchema.parse(blockHash) as Hex,
      requireCanonical: true,
    });
    return code ?? "0x";
  }

  async call(
    address: string,
    functionSignature: string,
    args: unknown[] | null,
    outputTypes: string[] | null,
    blockHash: string,
    network: string,
  ): Promise<Record<string, unknown>> {
    const inputTypes = parseFunctionInputTypes(functionSignature);
    const callArgs = [...(args ?? [])];
    if (callArgs.length !== inputTypes.length) {
      throw new Error(
        `arg count mismatch: signature expects ${inputTypes.length}, got ${callArgs.length}`,
      );
    }
    const selector = toFunctionSelector(`function ${functionSignature}`);
    const encodedArgs =
      inputTypes.length === 0
        ? "0x"
        : encodeAbiParameters(
            parseAbiParameters(inputTypes.join(", ")),
            callArgs,
          );
    const calldata = `${selector}${encodedArgs.slice(2)}` as Hex;
    const { data } = await this.client(network).call({
      to: getAddress(address),
      data: calldata,
      blockHash: blockHashSchema.parse(blockHash) as Hex,
      requireCanonical: true,
    });
    const rawHex = data ?? "0x";
    const decodedValues =
      outputTypes !== null && outputTypes.length > 0
        ? decodeAbiParameters(
            parseAbiParameters(outputTypes.join(", ")),
            rawHex,
          )
        : null;
    return {
      address: getAddress(address),
      function_signature: functionSignature,
      raw_hex: rawHex,
      decoded:
        decodedValues === null ? null : [...decodedValues].map(jsonSafe),
    };
  }

  async assertCanonical(
    blockNumber: number,
    blockHash: string,
    network: string,
  ): Promise<void> {
    const block = await this.client(network).getBlock({
      blockNumber: BigInt(blockNumber),
    });
    if (
      block.hash === null ||
      blockHashSchema.parse(block.hash) !== blockHashSchema.parse(blockHash)
    ) {
      throw new SnapshotChangedError("the pinned block is no longer canonical");
    }
  }

  private client(network: string): ReturnType<typeof createPublicClient> {
    const existing = this.clients.get(network);
    if (existing !== undefined) return existing;
    const configured = getNetwork(network);
    const transport =
      this.transportFactory?.(network) ?? http(configured.rpcUrl);
    const client = createPublicClient({ transport });
    this.clients.set(network, client);
    return client;
  }
}

export class PancakeV3StateReader implements RebalanceStateReader {
  constructor(
    private readonly rpc: PinnedRpcReader = new ViemPinnedRpcReader(),
  ) {}

  async read(
    mandate: RebalanceMandate,
    network: string,
  ): Promise<RebalanceEvidence> {
    let lastSnapshotError: Error | null = null;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        return await this.readSnapshot(mandate, network);
      } catch (error) {
        if (
          !(error instanceof SnapshotChangedError) &&
          !isRetryableSnapshotError(error)
        ) {
          throw error;
        }
        lastSnapshotError = new SnapshotChangedError(
          "the pinned BSC snapshot could not be confirmed canonical",
        );
      }
    }
    throw lastSnapshotError ?? new Error("could not capture a coherent snapshot");
  }

  private async readSnapshot(
    mandate: RebalanceMandate,
    network: string,
  ): Promise<RebalanceEvidence> {
    const pool = mandate.position.pool_address;
    const manager = mandate.position.position_manager_address;
    const deployment =
      PANCAKE_V3_DEPLOYMENTS[network as keyof typeof PANCAKE_V3_DEPLOYMENTS];
    if (deployment === undefined || manager !== deployment.position_manager) {
      throw new StateReadError(
        "UNSUPPORTED_PROTOCOL",
        "the supplied position manager is not the verified PancakeSwap V3 deployment",
      );
    }
    const tokenId = BigInt(mandate.position.token_id);
    const expectedChainId = NETWORK_CHAIN_IDS[network];
    if (expectedChainId === undefined) {
      throw new StateReadError(
        "UNSUPPORTED_CHAIN",
        "the selected Studio network is not supported",
      );
    }
    const snapshot = await this.rpc.getHead(network);
    if (
      snapshot.confirmationDepthBlocks !==
        BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS ||
      snapshot.snapshotHeadBlock - snapshot.number !==
        BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS
    ) {
      throw new SnapshotChangedError(
        "the pinned block snapshot does not match the fixed confirmation depth",
      );
    }
    if (
      snapshot.chainId !== expectedChainId ||
      snapshot.chainId !== mandate.chain_id
    ) {
      throw new StateReadError(
        "UNSUPPORTED_CHAIN",
        "the configured RPC chain does not match the selected network and mandate",
      );
    }
    const blockHash = blockHashSchema.parse(snapshot.hash);

    const [managerCode, factoryCode, deployerCode, poolCode] = await Promise.all([
      this.rpc.getCode(manager, blockHash, network),
      this.rpc.getCode(deployment.factory, blockHash, network),
      this.rpc.getCode(deployment.deployer, blockHash, network),
      this.rpc.getCode(pool, blockHash, network),
    ]);
    if ([managerCode, factoryCode, deployerCode].some(isEmptyCode)) {
      throw new StateReadError(
        "UNSUPPORTED_PROTOCOL",
        "a verified PancakeSwap V3 deployment contract has no code at the pinned block",
      );
    }
    if (isEmptyCode(poolCode)) {
      throw new StateReadError(
        "POOL_POSITION_MISMATCH",
        "the supplied pool has no contract code at the pinned block",
      );
    }

    const [
      slot0Call,
      poolLiquidityCall,
      poolToken0Call,
      poolToken1Call,
      poolFeeCall,
      tickSpacingCall,
      poolFactoryCall,
      positionCall,
      ownerCall,
      managerFactoryCall,
      managerDeployerCall,
    ] = await Promise.all([
      this.rpc.call(
        pool,
        "slot0()",
        [],
        ["uint160", "int24", "uint16", "uint16", "uint16", "uint32", "bool"],
        blockHash,
        network,
      ),
      this.rpc.call(pool, "liquidity()", [], ["uint128"], blockHash, network),
      this.rpc.call(pool, "token0()", [], ["address"], blockHash, network),
      this.rpc.call(pool, "token1()", [], ["address"], blockHash, network),
      this.rpc.call(pool, "fee()", [], ["uint24"], blockHash, network),
      this.rpc.call(pool, "tickSpacing()", [], ["int24"], blockHash, network),
      this.rpc.call(pool, "factory()", [], ["address"], blockHash, network),
      this.rpc.call(
        manager,
        "positions(uint256)",
        [tokenId],
        [
          "uint96",
          "address",
          "address",
          "address",
          "uint24",
          "int24",
          "int24",
          "uint128",
          "uint256",
          "uint256",
          "uint128",
          "uint128",
        ],
        blockHash,
        network,
      ),
      this.rpc.call(
        manager,
        "ownerOf(uint256)",
        [tokenId],
        ["address"],
        blockHash,
        network,
      ),
      this.rpc.call(manager, "factory()", [], ["address"], blockHash, network),
      this.rpc.call(manager, "deployer()", [], ["address"], blockHash, network),
    ]);

    const slot0 = decoded(slot0Call, "pool slot0", 2);
    const poolLiquidity = asUnsignedString(
      decoded(poolLiquidityCall, "pool liquidity", 1)[0],
      "pool liquidity",
    );
    const poolToken0 = asAddress(decoded(poolToken0Call, "pool token0", 1)[0]);
    const poolToken1 = asAddress(decoded(poolToken1Call, "pool token1", 1)[0]);
    const poolFee = asInteger(decoded(poolFeeCall, "pool fee", 1)[0], "pool fee");
    const tickSpacing = asInteger(
      decoded(tickSpacingCall, "pool tick spacing", 1)[0],
      "pool tick spacing",
    );
    const poolFactory = asAddress(decoded(poolFactoryCall, "pool factory", 1)[0]);
    const position = decoded(positionCall, "position", 12);
    const owner = asAddress(decoded(ownerCall, "position owner", 1)[0]);
    const managerFactory = asAddress(
      decoded(managerFactoryCall, "position manager factory", 1)[0],
    );
    const managerDeployer = asAddress(
      decoded(managerDeployerCall, "position manager deployer", 1)[0],
    );
    if (
      poolFactory !== deployment.factory ||
      managerFactory !== deployment.factory ||
      managerDeployer !== deployment.deployer
    ) {
      throw new StateReadError(
        "UNSUPPORTED_PROTOCOL",
        "the supplied contracts do not resolve to the verified PancakeSwap V3 factory and deployer",
      );
    }

    const positionToken0 = asAddress(position[2]);
    const positionToken1 = asAddress(position[3]);
    const positionFee = asInteger(position[4], "position fee");
    if (
      positionToken0 !== poolToken0 ||
      positionToken1 !== poolToken1 ||
      positionFee !== poolFee
    ) {
      throw new StateReadError(
        "POOL_POSITION_MISMATCH",
        "the supplied pool does not match the NFT position token pair and fee tier",
      );
    }

    const [
      token0DecimalsCall,
      token1DecimalsCall,
      canonicalPoolCall,
      canonicalSpacingCall,
    ] = await Promise.all([
      this.rpc.call(
        poolToken0,
        "decimals()",
        [],
        ["uint8"],
        blockHash,
        network,
      ),
      this.rpc.call(
        poolToken1,
        "decimals()",
        [],
        ["uint8"],
        blockHash,
        network,
      ),
      this.rpc.call(
        deployment.factory,
        "getPool(address,address,uint24)",
        [positionToken0, positionToken1, positionFee],
        ["address"],
        blockHash,
        network,
      ),
      this.rpc.call(
        deployment.factory,
        "feeAmountTickSpacing(uint24)",
        [positionFee],
        ["int24"],
        blockHash,
        network,
      ),
    ]);
    const token0Decimals = asInteger(
      decoded(token0DecimalsCall, "token0 decimals", 1)[0],
      "token0 decimals",
    );
    const token1Decimals = asInteger(
      decoded(token1DecimalsCall, "token1 decimals", 1)[0],
      "token1 decimals",
    );
    const canonicalPool = asAddress(
      decoded(canonicalPoolCall, "factory pool", 1)[0],
    );
    const canonicalSpacing = asInteger(
      decoded(canonicalSpacingCall, "factory tick spacing", 1)[0],
      "factory tick spacing",
    );
    if (canonicalPool !== pool || canonicalSpacing !== tickSpacing) {
      throw new StateReadError(
        "POOL_POSITION_MISMATCH",
        "the supplied pool is not the factory-resolved pool for the position token pair and fee tier",
      );
    }

    await this.rpc.assertCanonical(snapshot.number, blockHash, network);
    const blockNumber = snapshot.number;
    const observedAt = snapshot.timestamp;
    const currentTick = asInteger(slot0[1], "current tick");
    const positionTickLower = asInteger(position[5], "position lower tick");
    const positionTickUpper = asInteger(position[6], "position upper tick");
    const positionLiquidity = asUnsignedString(position[7], "position liquidity");
    if (BigInt(positionLiquidity) === 0n) {
      throw new StateReadError(
        "POSITION_INACTIVE",
        "the supplied position has zero active liquidity",
      );
    }
    if (tickSpacing <= 0) {
      throw new Error("pool tick spacing must be positive");
    }

    const explorer =
      network === "bsc-mainnet" ? "https://bscscan.com" : "https://testnet.bscscan.com";
    return RebalanceEvidenceSchema.parse({
      network,
      chain_id: snapshot.chainId,
      snapshot_head_block: snapshot.snapshotHeadBlock,
      confirmation_depth_blocks: snapshot.confirmationDepthBlocks,
      observed_block: blockNumber,
      observed_block_hash: blockHash,
      observed_at: observedAt,
      pool_address: pool,
      position_manager_address: manager,
      position_token_id: mandate.position.token_id,
      position_owner: owner,
      token0: poolToken0,
      token1: poolToken1,
      token0_decimals: token0Decimals,
      token1_decimals: token1Decimals,
      fee: poolFee,
      tick_spacing: tickSpacing,
      current_tick: currentTick,
      sqrt_price_x96: asUnsignedString(slot0[0], "sqrt price"),
      approximate_token1_per_token0: approximatePrice(
        currentTick,
        token0Decimals,
        token1Decimals,
      ),
      position_tick_lower: positionTickLower,
      position_tick_upper: positionTickUpper,
      pool_liquidity: poolLiquidity,
      position_liquidity: positionLiquidity,
      sources: [
        {
          type: "onchain",
          url: `${explorer}/block/${blockNumber}`,
          observed_block: blockNumber,
        },
        {
          type: "onchain",
          url: `${explorer}/address/${pool}`,
          observed_block: blockNumber,
        },
        {
          type: "onchain",
          url: `${explorer}/address/${deployment.factory}`,
          observed_block: blockNumber,
        },
      ],
    });
  }
}

export interface RebalanceServiceOptions {
  network?: string;
  reader?: RebalanceStateReader;
  now?: () => number;
}

export type PreparedRebalanceQuote =
  | {
      ok: true;
      request: Record<string, unknown>;
      signedTask: SignedRebalanceTask;
    }
  | { ok: false; refusal: RebalanceRefusal };

export interface RebalanceDeliveryApi {
  prepareQuote(rawRequest: Record<string, unknown>): Promise<PreparedRebalanceQuote>;
  deliver(
    jobId: number,
    spec: { task: string; terms: Record<string, unknown> },
  ): Promise<RebalanceReceipt | null>;
}

export class RebalanceService implements RebalanceDeliveryApi {
  private readonly network: string;
  private readonly reader: RebalanceStateReader;
  private readonly now: () => number;

  constructor(opts: RebalanceServiceOptions = {}) {
    this.network = opts.network ?? "bsc-testnet";
    this.reader = opts.reader ?? new PancakeV3StateReader();
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async prepareQuote(
    rawRequest: Record<string, unknown>,
  ): Promise<PreparedRebalanceQuote> {
    const rawMandate = rawRequest.mandate;
    const preliminary = preliminaryRefusal(rawMandate, this.network);
    if (preliminary !== null) return { ok: false, refusal: preliminary };

    const parsed = RebalanceMandateSchema.safeParse(rawMandate);
    if (!parsed.success) {
      return {
        ok: false,
        refusal: refusal("INVALID_MANDATE", "the mandate schema is invalid", {
          issues: parsed.error.issues.map((issue) => ({
            path: issue.path.join("."),
            message: issue.message,
          })),
        }),
      };
    }
    const mandate = normalizeMandate(parsed.data);
    const now = this.now();

    const staticRefusal = validateStaticPolicy(mandate, now, this.network);
    if (staticRefusal !== null) return { ok: false, refusal: staticRefusal };

    let evidence: RebalanceEvidence;
    try {
      evidence = RebalanceEvidenceSchema.parse(
        await this.reader.read(mandate, this.network),
      );
    } catch (error) {
      if (error instanceof StateReadError) {
        return { ok: false, refusal: refusal(error.code, error.message) };
      }
      return {
        ok: false,
        refusal: refusal(
          "EVIDENCE_UNAVAILABLE",
          safeEvidenceReadMessage("quote", error),
        ),
      };
    }

    const completedAt = this.now();
    const postReadStaticRefusal = validateStaticPolicy(
      mandate,
      completedAt,
      this.network,
    );
    if (postReadStaticRefusal !== null) {
      return { ok: false, refusal: postReadStaticRefusal };
    }

    const evidenceIdentityRefusal = validateEvidenceIdentity(
      mandate,
      evidence,
      this.network,
    );
    if (evidenceIdentityRefusal !== null) {
      return { ok: false, refusal: evidenceIdentityRefusal };
    }

    const evidenceRefusal = validateEvidenceFreshness(
      mandate,
      evidence,
      completedAt,
    );
    if (evidenceRefusal !== null) return { ok: false, refusal: evidenceRefusal };

    const proposalResult = buildProposal(mandate, evidence);
    if (!proposalResult.ok) return proposalResult;

    const signedTask = SignedRebalanceTaskSchema.parse({
      schema: "mandatex.rebalance.quote.v1",
      mandate,
      evidence,
      proposal: proposalResult.proposal,
      eligibility: {
        eligible: true,
        checked_at: completedAt,
        checks: [
          "supported BSC network and PancakeSwap V3 mandate",
          "fresh on-chain pool and position evidence",
          "position matches the supplied pool",
          "rebalance trigger fired",
          "target range is inside approved bounds",
          "gas, slippage, and exposure fit the mandate",
          "required contracts and calls are subsets of the user allowlists",
          "permission and mandate expiries are valid",
        ],
      },
    });
    const taskDescription = encodeSignedRebalanceTask(signedTask);
    if (Buffer.byteLength(taskDescription, "utf8") > MAX_ENCODED_TASK_BYTES) {
      return {
        ok: false,
        refusal: refusal(
          "INVALID_MANDATE",
          "the normalized mandate is too large for the signed ERC-8183 job description",
        ),
      };
    }

    const request: Record<string, unknown> = {
      task_description: taskDescription,
      terms: FIXED_REBALANCE_TERMS,
    };
    try {
      assertSdkDescriptionFits(request, completedAt, mandate.chain_id);
    } catch (error) {
      return {
        ok: false,
        refusal: refusal(
          "INVALID_MANDATE",
          `the normalized request does not fit the ERC-8183 description limit: ${errorMessage(error)}`,
        ),
      };
    }

    return {
      ok: true,
      signedTask,
      request,
    };
  }

  async deliver(
    jobId: number,
    spec: { task: string; terms: Record<string, unknown> },
  ): Promise<RebalanceReceipt | null> {
    if (!spec.task.startsWith("mandatex-rebalance:")) {
      return null;
    }

    if (canonicalJson(spec.terms) !== canonicalJson(FIXED_REBALANCE_TERMS)) {
      return this.refusalReceipt(jobId, {
        mandateId: "unknown",
        quotedEvidence: null,
        proposal: null,
        refusal: refusal(
          "SIGNED_TASK_INVALID",
          "the anchored ERC-8183 terms do not match the seller-owned MandateX terms",
        ),
      });
    }

    let decodedTask: Record<string, unknown> | null;
    try {
      decodedTask = decodeSignedRebalanceTask(spec.task);
    } catch {
      decodedTask = null;
    }

    const parsed = SignedRebalanceTaskSchema.safeParse(decodedTask);
    if (!parsed.success) {
      const decodedMandate = asRecord(decodedTask?.mandate);
      return this.refusalReceipt(jobId, {
        mandateId:
          typeof decodedMandate?.mandate_id === "string"
            ? decodedMandate.mandate_id
            : "unknown",
        quotedEvidence: null,
        proposal: null,
        refusal: refusal(
          "SIGNED_TASK_INVALID",
          "the signed MandateX task could not be parsed safely",
        ),
      });
    }

    const task = parsed.data;
    const now = this.now();
    const expiryRefusal = validateExpiry(task.mandate, now);
    if (expiryRefusal !== null) {
      return this.refusalReceipt(jobId, {
        mandateId: task.mandate.mandate_id,
        quotedEvidence: task.evidence,
        proposal: task.proposal,
        refusal: expiryRefusal,
      });
    }

    let deliveryEvidence: RebalanceEvidence;
    try {
      deliveryEvidence = RebalanceEvidenceSchema.parse(
        await this.reader.read(task.mandate, this.network),
      );
    } catch (error) {
      const readRefusal =
        error instanceof StateReadError
          ? refusal(error.code, error.message)
          : refusal(
              "EVIDENCE_UNAVAILABLE",
              safeEvidenceReadMessage("delivery", error),
            );
      return this.refusalReceipt(jobId, {
        mandateId: task.mandate.mandate_id,
        quotedEvidence: task.evidence,
        proposal: task.proposal,
        refusal: readRefusal,
      });
    }

    const completedAt = this.now();
    const postReadStaticRefusal = validateStaticPolicy(
      task.mandate,
      completedAt,
      this.network,
    );
    if (postReadStaticRefusal !== null) {
      return this.refusalReceipt(jobId, {
        mandateId: task.mandate.mandate_id,
        quotedEvidence: task.evidence,
        deliveryEvidence,
        proposal: task.proposal,
        refusal: postReadStaticRefusal,
      });
    }

    const evidenceIdentityRefusal = validateEvidenceIdentity(
      task.mandate,
      deliveryEvidence,
      this.network,
    );
    if (evidenceIdentityRefusal !== null) {
      return this.refusalReceipt(jobId, {
        mandateId: task.mandate.mandate_id,
        quotedEvidence: task.evidence,
        deliveryEvidence,
        proposal: task.proposal,
        refusal: evidenceIdentityRefusal,
      });
    }

    const freshnessRefusal = validateEvidenceFreshness(
      task.mandate,
      deliveryEvidence,
      completedAt,
    );
    if (freshnessRefusal !== null) {
      return this.refusalReceipt(jobId, {
        mandateId: task.mandate.mandate_id,
        quotedEvidence: task.evidence,
        deliveryEvidence,
        proposal: task.proposal,
        refusal: freshnessRefusal,
      });
    }

    const driftRefusal = validateDeliveryState(task, deliveryEvidence);
    if (driftRefusal !== null) {
      return this.refusalReceipt(jobId, {
        mandateId: task.mandate.mandate_id,
        quotedEvidence: task.evidence,
        deliveryEvidence,
        proposal: task.proposal,
        refusal: driftRefusal,
      });
    }

    return RebalanceReceiptSchema.parse({
      schema: "mandatex.rebalance.receipt.v1",
      job_id: jobId,
      mandate_id: task.mandate.mandate_id,
      status: "simulation_ready",
      execution_mode: "simulation",
      simulation_only: true,
      policy_result: "within_mandate",
      quoted_evidence: task.evidence,
      delivery_evidence: deliveryEvidence,
      proposal: task.proposal,
      refusal: null,
      generated_at: completedAt,
      note:
        "Milestone 1 validated a bounded rebalance plan against fresh on-chain state. No PancakeSwap liquidity transaction was executed; the ERC-8183 submission only anchors this simulation receipt.",
    });
  }

  private refusalReceipt(
    jobId: number,
    input: {
      mandateId: string;
      quotedEvidence: RebalanceEvidence | null;
      deliveryEvidence?: RebalanceEvidence | null;
      proposal: RebalanceProposal | null;
      refusal: RebalanceRefusal;
    },
  ): RebalanceReceipt {
    return RebalanceReceiptSchema.parse({
      schema: "mandatex.rebalance.receipt.v1",
      job_id: jobId,
      mandate_id: input.mandateId,
      status: "refused",
      execution_mode: "simulation",
      simulation_only: true,
      policy_result: "refused_by_rule",
      quoted_evidence: input.quotedEvidence,
      delivery_evidence: input.deliveryEvidence ?? null,
      proposal: input.proposal,
      refusal: input.refusal,
      generated_at: this.now(),
      note:
        "The deterministic policy refused the plan. No PancakeSwap liquidity transaction was attempted.",
    });
  }
}

export function quoteRejectionEnvelope(
  refusalValue: RebalanceRefusal,
): Record<string, unknown> {
  return {
    request: {},
    request_hash: "",
    response: {
      accepted: false,
      reason_code: erc8183ReasonCode(refusalValue.code),
      reason: `${refusalValue.code}: ${refusalValue.message}`,
    },
    response_hash: "",
    negotiation_hash: "",
    provider_sig: "",
    mandatex: {
      eligible: false,
      refusal: refusalValue,
    },
  };
}

export function encodeSignedRebalanceTask(task: SignedRebalanceTask): string {
  const canonical = canonicalJson(SignedRebalanceTaskSchema.parse(task));
  const compressed = deflateRawSync(Buffer.from(canonical, "utf8"), { level: 9 });
  const encoded = `${TASK_PREFIX}${compressed.toString("base64url")}`;
  if (sanitizeForClaim(encoded) !== encoded) {
    throw new Error("MandateX task codec produced ERC-8183-unsafe characters");
  }
  return encoded;
}

export function decodeSignedRebalanceTask(
  encoded: string,
): Record<string, unknown> {
  if (!encoded.startsWith(TASK_PREFIX)) {
    throw new Error("unsupported MandateX task codec version");
  }
  if (Buffer.byteLength(encoded, "utf8") > MAX_ENCODED_TASK_BYTES) {
    throw new Error("encoded MandateX task exceeds the safety bound");
  }
  const compressed = Buffer.from(encoded.slice(TASK_PREFIX.length), "base64url");
  const decoded = inflateRawSync(compressed, {
    maxOutputLength: MAX_DECODED_TASK_BYTES,
  }).toString("utf8");
  return JSON.parse(decoded) as Record<string, unknown>;
}

export function assertSdkDescriptionFits(
  request: Record<string, unknown>,
  now: number,
  chainId: number,
): void {
  buildJobDescription({
    request,
    response: {
      accepted: true,
      terms: {
        ...FIXED_REBALANCE_TERMS,
        price: "0",
        currency: "0x0000000000000000000000000000000000000001",
      },
      quote_expires_at: now + 900,
    },
    negotiated_at: now,
    quote_expires_at: now + 900,
    negotiation_hash: `0x${"00".repeat(32)}`,
    provider_sig: `0x${"00".repeat(65)}`,
    chain_id: chainId,
    verifying_contract: "0x0000000000000000000000000000000000000002",
  });
}

function buildProposal(
  mandate: RebalanceMandate,
  evidence: RebalanceEvidence,
): { ok: true; proposal: RebalanceProposal } | { ok: false; refusal: RebalanceRefusal } {
  const staticRefusal = validateLimitsAndPermissions(mandate);
  if (staticRefusal !== null) return { ok: false, refusal: staticRefusal };

  const isOutside =
    evidence.current_tick < evidence.position_tick_lower ||
    evidence.current_tick >= evidence.position_tick_upper;
  const boundaryDistance = isOutside
    ? 0
    : Math.min(
        evidence.current_tick - evidence.position_tick_lower,
        evidence.position_tick_upper - evidence.current_tick,
      );
  const triggered =
    isOutside ||
    (mandate.range_policy.trigger_mode === "boundary_proximity" &&
      boundaryDistance <= mandate.range_policy.trigger_distance_ticks);
  if (!triggered) {
    return {
      ok: false,
      refusal: refusal(
        "REBALANCE_NOT_TRIGGERED",
        "the position is inside its current range and outside the approved boundary trigger",
        { distance_to_boundary_ticks: boundaryDistance },
      ),
    };
  }

  const targetWidth = mandate.range_policy.target_width_ticks;
  if (targetWidth % evidence.tick_spacing !== 0) {
    return {
      ok: false,
      refusal: refusal(
        "RANGE_OUTSIDE_MANDATE",
        "target_width_ticks must be divisible by the observed tick spacing",
        {
          target_width_ticks: targetWidth,
          tick_spacing: evidence.tick_spacing,
        },
      ),
    };
  }
  const exactRange = deriveExactTargetRange(
    evidence.current_tick,
    targetWidth,
    evidence.tick_spacing,
  );
  const proposedLower = exactRange.lower;
  const proposedUpper = exactRange.upper;
  if (
    proposedLower < MIN_TICK ||
    proposedUpper > MAX_TICK ||
    proposedLower < mandate.range_policy.approved_lower_tick ||
    proposedUpper > mandate.range_policy.approved_upper_tick ||
    evidence.current_tick < proposedLower ||
    evidence.current_tick >= proposedUpper
  ) {
    return {
      ok: false,
      refusal: refusal(
        "RANGE_OUTSIDE_MANDATE",
        "the deterministic target range does not fit inside the user-approved tick bounds",
        { proposed_lower_tick: proposedLower, proposed_upper_tick: proposedUpper },
      ),
    };
  }

  return {
    ok: true,
    proposal: RebalanceProposalSchema.parse({
      execution_mode: "simulation",
      proposed_lower_tick: proposedLower,
      proposed_upper_tick: proposedUpper,
      trigger: {
        fired: true,
        reason: isOutside ? "outside_current_range" : "near_range_boundary",
        distance_to_boundary_ticks: boundaryDistance,
      },
      estimated_gas_usd: mandate.execution_estimate.gas_usd,
      estimated_slippage_bps: mandate.execution_estimate.slippage_bps,
      estimated_exposure_usd: mandate.execution_estimate.exposure_usd,
      estimate_source_url: mandate.execution_estimate.source_url,
      permissions: {
        contracts: [mandate.position.position_manager_address],
        calls: [...REQUIRED_REBALANCE_CALLS],
        spend_cap_usd: mandate.permissions.spend_cap_usd,
        expires_at: mandate.permissions.expires_at,
      },
      break_even: {
        status: "not_calculated",
        reason:
          "Milestone 1 has no verified fee-income history or USD oracle for a reproducible break-even calculation; the estimate is displayed but execution remains simulation-only.",
      },
    }),
  };
}

function validateStaticPolicy(
  mandate: RebalanceMandate,
  now: number,
  network: string,
): RebalanceRefusal | null {
  const deployment =
    PANCAKE_V3_DEPLOYMENTS[network as keyof typeof PANCAKE_V3_DEPLOYMENTS];
  if (
    deployment === undefined ||
    mandate.position.position_manager_address !== deployment.position_manager
  ) {
    return refusal(
      "UNSUPPORTED_PROTOCOL",
      "the position manager is not the verified PancakeSwap V3 deployment for this network",
    );
  }
  const expiry = validateExpiry(mandate, now);
  if (expiry !== null) return expiry;

  const estimateAge = now - mandate.execution_estimate.observed_at;
  if (estimateAge > mandate.max_evidence_age_seconds) {
    return refusal(
      "STALE_EVIDENCE",
      "the execution cost estimate is older than the mandate freshness window",
      { age_seconds: estimateAge },
    );
  }
  if (estimateAge < -FUTURE_BLOCK_TOLERANCE_SECONDS) {
    return refusal(
      "INVALID_MANDATE",
      "the execution estimate timestamp is unreasonably far in the future",
    );
  }
  return validateLimitsAndPermissions(mandate);
}

function validateExpiry(
  mandate: RebalanceMandate,
  now: number,
): RebalanceRefusal | null {
  if (mandate.expires_at <= now) {
    return refusal("MANDATE_EXPIRED", "the mandate has expired");
  }
  if (mandate.permissions.expires_at <= now) {
    return refusal("PERMISSION_EXPIRED", "the permission manifest has expired");
  }
  return null;
}

function validateLimitsAndPermissions(
  mandate: RebalanceMandate,
): RebalanceRefusal | null {
  if (mandate.execution_estimate.gas_usd > mandate.limits.max_gas_usd) {
    return refusal("GAS_LIMIT_EXCEEDED", "estimated gas exceeds the mandate cap");
  }
  if (
    mandate.execution_estimate.slippage_bps > mandate.limits.max_slippage_bps
  ) {
    return refusal(
      "SLIPPAGE_LIMIT_EXCEEDED",
      "estimated slippage exceeds the mandate cap",
    );
  }
  if (
    mandate.execution_estimate.exposure_usd > mandate.limits.max_exposure_usd ||
    mandate.execution_estimate.exposure_usd > mandate.permissions.spend_cap_usd
  ) {
    return refusal(
      "EXPOSURE_LIMIT_EXCEEDED",
      "estimated exposure exceeds the mandate or permission spend cap",
    );
  }

  const allowedContracts = new Set(mandate.permissions.allowed_contracts);
  if (!allowedContracts.has(mandate.position.position_manager_address)) {
    return refusal(
      "CONTRACT_NOT_ALLOWED",
      "the PancakeSwap position manager is absent from the user contract allowlist",
    );
  }
  const allowedCalls = new Set(mandate.permissions.allowed_calls);
  const missingCall = REQUIRED_REBALANCE_CALLS.find((call) => !allowedCalls.has(call));
  if (missingCall !== undefined) {
    return refusal(
      "CALL_NOT_ALLOWED",
      "a required rebalance call is absent from the user call allowlist",
      { missing_call: missingCall },
    );
  }
  return null;
}

function validateEvidenceFreshness(
  mandate: RebalanceMandate,
  evidence: RebalanceEvidence,
  now: number,
): RebalanceRefusal | null {
  if (evidence.chain_id !== mandate.chain_id) {
    return refusal(
      "UNSUPPORTED_CHAIN",
      "the observed chain does not match the mandate chain",
    );
  }
  const age = now - evidence.observed_at;
  if (age > mandate.max_evidence_age_seconds) {
    return refusal("STALE_EVIDENCE", "the on-chain evidence is stale", {
      age_seconds: age,
      observed_block: evidence.observed_block,
    });
  }
  if (age < -FUTURE_BLOCK_TOLERANCE_SECONDS) {
    return refusal(
      "EVIDENCE_UNAVAILABLE",
      "the observed block timestamp is unreasonably far in the future",
    );
  }
  return null;
}

function validateEvidenceIdentity(
  mandate: RebalanceMandate,
  evidence: RebalanceEvidence,
  network: string,
): RebalanceRefusal | null {
  if (evidence.network !== network || evidence.chain_id !== mandate.chain_id) {
    return refusal(
      "UNSUPPORTED_CHAIN",
      "the observed network does not match the mandate and configured network",
    );
  }
  if (
    evidence.pool_address !== mandate.position.pool_address ||
    evidence.position_manager_address !==
      mandate.position.position_manager_address ||
    evidence.position_token_id !== mandate.position.token_id
  ) {
    return refusal(
      "POOL_POSITION_MISMATCH",
      "the observed pool or position identity does not match the mandate",
    );
  }
  return null;
}

function validateDeliveryState(
  task: SignedRebalanceTask,
  delivery: RebalanceEvidence,
): RebalanceRefusal | null {
  if (
    delivery.pool_address !== task.evidence.pool_address ||
    delivery.position_manager_address !== task.evidence.position_manager_address ||
    delivery.position_token_id !== task.evidence.position_token_id ||
    delivery.token0 !== task.evidence.token0 ||
    delivery.token1 !== task.evidence.token1 ||
    delivery.fee !== task.evidence.fee
  ) {
    return refusal(
      "POOL_POSITION_MISMATCH",
      "the pool or position identity changed after the quote",
    );
  }
  if (delivery.position_owner !== task.evidence.position_owner) {
    return refusal(
      "STATE_DRIFT",
      "the position owner changed after the quote",
      {
        quoted_position_owner: task.evidence.position_owner,
        delivery_position_owner: delivery.position_owner,
      },
    );
  }
  const drift = Math.abs(delivery.current_tick - task.evidence.current_tick);
  if (drift > task.mandate.range_policy.max_delivery_tick_drift) {
    return refusal(
      "STATE_DRIFT",
      "the pool tick moved beyond the mandate's delivery tolerance",
      {
        quoted_tick: task.evidence.current_tick,
        delivery_tick: delivery.current_tick,
        drift_ticks: drift,
      },
    );
  }
  if (
    delivery.current_tick < task.proposal.proposed_lower_tick ||
    delivery.current_tick >= task.proposal.proposed_upper_tick
  ) {
    return refusal(
      "TARGET_RANGE_EXITED",
      "the current tick no longer fits inside the quoted target range",
    );
  }
  return null;
}

function preliminaryRefusal(
  rawMandate: unknown,
  network: string,
): RebalanceRefusal | null {
  const raw = asRecord(rawMandate);
  if (raw === null) {
    return refusal("INVALID_MANDATE", "request.mandate must be an object");
  }
  if (raw.category !== "rebalancing") {
    return refusal(
      "UNSUPPORTED_CATEGORY",
      "this reference agent only accepts rebalancing mandates",
    );
  }
  if (raw.protocol !== "pancakeswap-v3") {
    return refusal(
      "UNSUPPORTED_PROTOCOL",
      "this milestone only supports PancakeSwap V3",
    );
  }
  const expectedChain = NETWORK_CHAIN_IDS[network];
  if (expectedChain === undefined || raw.chain_id !== expectedChain) {
    return refusal(
      "UNSUPPORTED_CHAIN",
      `the agent is configured for ${network} chain id ${expectedChain ?? "unknown"}`,
    );
  }
  return null;
}

function normalizeMandate(mandate: RebalanceMandate): RebalanceMandate {
  return {
    ...mandate,
    permissions: {
      ...mandate.permissions,
      allowed_contracts: [...new Set(mandate.permissions.allowed_contracts)].sort(),
      allowed_calls: [...new Set(mandate.permissions.allowed_calls)].sort(),
    },
  };
}

function refusal(
  code: (typeof REFUSAL_CODES)[number],
  message: string,
  details?: Record<string, unknown>,
): RebalanceRefusal {
  return RebalanceRefusalSchema.parse({ code, message, ...(details ? { details } : {}) });
}

function erc8183ReasonCode(code: RebalanceRefusal["code"]): string {
  if (code === "INVALID_MANDATE" || code === "SIGNED_TASK_INVALID") return "0x04";
  if (code.startsWith("UNSUPPORTED_")) return "0x06";
  if (code === "MANDATE_EXPIRED" || code === "PERMISSION_EXPIRED") return "0x02";
  return "0x03";
}

function deriveExactTargetRange(
  currentTick: number,
  targetWidthTicks: number,
  tickSpacing: number,
): { readonly lower: number; readonly upper: number } {
  const lower =
    Math.floor(
      (2 * currentTick - targetWidthTicks + tickSpacing) /
        (2 * tickSpacing),
    ) * tickSpacing;
  return { lower, upper: lower + targetWidthTicks };
}

function approximatePrice(
  tick: number,
  token0Decimals: number,
  token1Decimals: number,
): string | null {
  const exponent = tick * Math.log(1.0001) +
    (token0Decimals - token1Decimals) * Math.LN10;
  if (exponent > 700 || exponent < -700) return null;
  const price = Math.exp(exponent);
  return Number.isFinite(price) && price > 0 ? price.toPrecision(12) : null;
}

function parseFunctionInputTypes(functionSignature: string): string[] {
  if (!functionSignature.includes("(") || !functionSignature.endsWith(")")) {
    throw new Error(`invalid function signature: ${JSON.stringify(functionSignature)}`);
  }
  const inside = functionSignature
    .slice(functionSignature.indexOf("(") + 1, -1)
    .trim();
  return inside === "" ? [] : inside.split(",").map((type) => type.trim());
}

function jsonSafe(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(jsonSafe);
  return value;
}

function isEmptyCode(code: string): boolean {
  return /^0x0*$/i.test(code);
}

function isRetryableSnapshotError(error: unknown): boolean {
  const record = asRecord(error);
  const text = [
    error instanceof Error ? error.message : String(error),
    typeof record?.shortMessage === "string" ? record.shortMessage : "",
    typeof record?.details === "string" ? record.details : "",
  ].join(" ");
  return /header not found|block not found|could not be found|unknown block|non-?canonical|not canonical|missing trie node/i.test(
    text,
  );
}

function safeEvidenceReadMessage(context: "quote" | "delivery", error: unknown): string {
  const subject = context === "quote" ? "Quote evidence" : "Delivery evidence";
  if (error instanceof SnapshotChangedError || isRetryableSnapshotError(error)) {
    return `${subject} could not confirm a canonical block-pinned BSC snapshot`;
  }
  return `${subject} could not be verified through the configured BSC RPC`;
}

function decoded(
  result: Record<string, unknown>,
  label: string,
  minimumLength: number,
): unknown[] {
  if (typeof result.error === "string") {
    throw new Error(`${label}: ${result.error}`);
  }
  if (!Array.isArray(result.decoded) || result.decoded.length < minimumLength) {
    throw new Error(`${label}: decoded response is unavailable`);
  }
  return result.decoded;
}

function asInteger(value: unknown, label: string): number {
  let parsed: bigint;
  try {
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) throw new Error("unsafe integer");
      return value;
    }
    parsed = BigInt(String(value));
  } catch {
    throw new Error(`${label} is not an integer`);
  }
  const numberValue = Number(parsed);
  if (!Number.isSafeInteger(numberValue)) {
    throw new Error(`${label} exceeds the safe integer range`);
  }
  return numberValue;
}

function asUnsignedString(value: unknown, label: string): string {
  let parsed: bigint;
  try {
    parsed = BigInt(String(value));
  } catch {
    throw new Error(`${label} is not an unsigned integer`);
  }
  if (parsed < 0n) throw new Error(`${label} is not an unsigned integer`);
  return parsed.toString();
}

function asAddress(value: unknown): string {
  return addressSchema.parse(String(value));
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("value is not JSON serializable");
  return encoded;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

class StateReadError extends Error {
  constructor(
    readonly code:
      | "UNSUPPORTED_CHAIN"
      | "UNSUPPORTED_PROTOCOL"
      | "POOL_POSITION_MISMATCH"
      | "POSITION_INACTIVE",
    message: string,
  ) {
    super(message);
    this.name = "StateReadError";
  }
}

class SnapshotChangedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SnapshotChangedError";
  }
}
