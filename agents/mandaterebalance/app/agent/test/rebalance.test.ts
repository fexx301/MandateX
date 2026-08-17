import assert from "node:assert/strict";
import test from "node:test";
import {
  buildJobDescription,
  JobDescription,
} from "@bnbagent/sdk/erc8183";
import { custom } from "viem";
import {
  BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS,
  decodeSignedRebalanceTask,
  FIXED_REBALANCE_TERMS,
  PANCAKE_V3_DEPLOYMENTS,
  PancakeV3StateReader,
  type PinnedBlockSnapshot,
  type PinnedRpcReader,
  type RebalanceEvidence,
  type RebalanceMandate,
  type RebalanceStateReader,
  RebalanceEvidenceSchema,
  RebalanceMandateSchema,
  RebalanceService,
  REQUIRED_REBALANCE_CALLS,
  SignedRebalanceTaskSchema,
  type ViemPinnedRpcReaderOptions,
  ViemPinnedRpcReader,
} from "../src/rebalance.js";

const NOW = 1_800_000_000;
const POOL = "0x1111111111111111111111111111111111111111";
const MANAGER = "0x427bf5b37357632377ecbec9de3626c71a5396c1";
const TOKEN0 = "0x3333333333333333333333333333333333333333";
const TOKEN1 = "0x4444444444444444444444444444444444444444";
const OWNER = "0x5555555555555555555555555555555555555555";
const OTHER_OWNER = "0x7777777777777777777777777777777777777777";
const CURRENCY = "0x6666666666666666666666666666666666666666";
const BLOCK_HASH = `0x${"aa".repeat(32)}`;
const NEXT_BLOCK_HASH = `0x${"bb".repeat(32)}`;
const HEAD_BLOCK_HASH = `0x${"cc".repeat(32)}`;
const POOL_LIQUIDITY = "2000000";

function validMandate(): RebalanceMandate {
  return {
    version: "1",
    mandate_id: "rebalance-demo-1",
    category: "rebalancing",
    chain_id: 97,
    protocol: "pancakeswap-v3",
    expires_at: NOW + 900,
    max_evidence_age_seconds: 120,
    position: {
      pool_address: POOL,
      position_manager_address: MANAGER,
      token_id: "42",
    },
    range_policy: {
      approved_lower_tick: -600,
      approved_upper_tick: 600,
      target_width_ticks: 120,
      trigger_mode: "boundary_proximity",
      trigger_distance_ticks: 30,
      max_delivery_tick_drift: 30,
    },
    limits: {
      max_gas_usd: 3,
      max_slippage_bps: 50,
      max_exposure_usd: 1000,
    },
    execution_estimate: {
      gas_usd: 1.25,
      slippage_bps: 30,
      exposure_usd: 500,
      observed_at: NOW - 5,
      source_url: "https://example.com/estimates/rebalance-demo-1",
    },
    permissions: {
      allowed_contracts: [MANAGER],
      allowed_calls: [...REQUIRED_REBALANCE_CALLS],
      spend_cap_usd: 750,
      expires_at: NOW + 600,
    },
  };
}

function evidence(overrides: Partial<RebalanceEvidence> = {}): RebalanceEvidence {
  const observedBlock = overrides.observed_block ?? 50_000_000;
  const confirmationDepth =
    overrides.confirmation_depth_blocks ??
    BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS;
  return {
    network: "bsc-testnet",
    chain_id: 97,
    snapshot_head_block: observedBlock + confirmationDepth,
    confirmation_depth_blocks: confirmationDepth,
    observed_block: observedBlock,
    observed_block_hash: BLOCK_HASH,
    observed_at: NOW - 2,
    pool_address: POOL,
    position_manager_address: MANAGER,
    position_token_id: "42",
    position_owner: OWNER,
    token0: TOKEN0,
    token1: TOKEN1,
    token0_decimals: 18,
    token1_decimals: 18,
    fee: 2500,
    tick_spacing: 60,
    current_tick: 119,
    sqrt_price_x96: "79704936542881920863903188246",
    approximate_token1_per_token0: "1.01197061622",
    position_tick_lower: -120,
    position_tick_upper: 120,
    pool_liquidity: POOL_LIQUIDITY,
    position_liquidity: "1000000",
    sources: [
      {
        type: "onchain",
        url: "https://testnet.bscscan.com/block/50000000",
        observed_block: 50_000_000,
      },
    ],
    ...overrides,
  };
}

function pinnedSnapshot(
  number: number,
  hash: string,
  timestamp: number,
  chainId = 97,
): PinnedBlockSnapshot {
  return {
    chainId,
    snapshotHeadBlock:
      number + BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS,
    confirmationDepthBlocks: BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS,
    number,
    hash,
    timestamp,
  };
}

function rpcBlock(number: number, hash: string, timestamp: number) {
  const root = `0x${"00".repeat(32)}`;
  return {
    baseFeePerGas: "0x0",
    difficulty: "0x0",
    extraData: "0x",
    gasLimit: "0x0",
    gasUsed: "0x0",
    hash,
    logsBloom: `0x${"00".repeat(256)}`,
    miner: OWNER,
    mixHash: root,
    nonce: "0x0000000000000000",
    number: `0x${number.toString(16)}`,
    parentHash: root,
    receiptsRoot: root,
    sha3Uncles: root,
    size: "0x0",
    stateRoot: root,
    timestamp: `0x${timestamp.toString(16)}`,
    totalDifficulty: "0x0",
    transactions: [],
    transactionsRoot: root,
    uncles: [],
  };
}

function deterministicText(
  length: number,
  seed: number,
  alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-",
): string {
  let state = seed >>> 0;
  let output = "";
  for (let index = 0; index < length; index += 1) {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    output += alphabet[state % alphabet.length];
  }
  return output;
}

function splitCallPayload(payload: string): string[] {
  const calls: string[] = [];
  for (let offset = 0; offset < payload.length; offset += 180) {
    calls.push(payload.slice(offset, offset + 180));
  }
  return calls;
}

class SequenceReader implements RebalanceStateReader {
  calls = 0;

  constructor(private readonly sequence: Array<RebalanceEvidence | Error>) {}

  async read(): Promise<RebalanceEvidence> {
    const next = this.sequence[Math.min(this.calls, this.sequence.length - 1)];
    this.calls += 1;
    if (next instanceof Error) throw next;
    return structuredClone(next);
  }
}

function contractRead(
  canonicalPool = POOL,
): (
  address: string,
  signature: string,
) => Promise<Record<string, unknown>> {
  return async (address, signature) => {
    const normalized = address.toLowerCase();
    const deployment = PANCAKE_V3_DEPLOYMENTS["bsc-testnet"];
    if (signature === "slot0()") {
      return { decoded: ["79704936542881920863903188246", "119", 0, 0, 0, 0, true] };
    }
    if (signature === "liquidity()") return { decoded: [POOL_LIQUIDITY] };
    if (signature === "token0()") return { decoded: [TOKEN0] };
    if (signature === "token1()") return { decoded: [TOKEN1] };
    if (signature === "fee()") return { decoded: ["2500"] };
    if (signature === "tickSpacing()") return { decoded: ["60"] };
    if (signature === "positions(uint256)") {
      return {
        decoded: [
          "0",
          "0x0000000000000000000000000000000000000000",
          TOKEN0,
          TOKEN1,
          "2500",
          "-120",
          "120",
          "1000000",
          "0",
          "0",
          "0",
          "0",
        ],
      };
    }
    if (signature === "ownerOf(uint256)") return { decoded: [OWNER] };
    if (signature === "factory()") return { decoded: [deployment.factory] };
    if (signature === "deployer()") return { decoded: [deployment.deployer] };
    if (signature === "decimals()") return { decoded: ["18"] };
    if (signature === "getPool(address,address,uint24)") {
      assert.equal(normalized, deployment.factory);
      return { decoded: [canonicalPool] };
    }
    if (signature === "feeAmountTickSpacing(uint24)") return { decoded: ["60"] };
    return { error: `unexpected call ${signature}` };
  };
}

interface MockPinnedRpcOptions {
  heads?: PinnedBlockSnapshot[];
  canonicalPool?: string;
  missingCode?: string[];
  canonicalFailures?: number;
}

class MockPinnedRpcReader implements PinnedRpcReader {
  readonly codeReads: Array<{
    address: string;
    blockHash: string;
    network: string;
  }> = [];
  readonly contractReads: Array<{
    address: string;
    signature: string;
    args: unknown[] | null;
    outputTypes: string[] | null;
    blockHash: string;
    network: string;
  }> = [];
  readonly canonicalChecks: Array<{
    blockNumber: number;
    blockHash: string;
    network: string;
  }> = [];
  headReads = 0;

  private readonly heads: PinnedBlockSnapshot[];
  private readonly missingCode: Set<string>;
  private readonly readContract: ReturnType<typeof contractRead>;
  private remainingCanonicalFailures: number;

  constructor(options: MockPinnedRpcOptions = {}) {
    this.heads = options.heads ?? [
      pinnedSnapshot(50_000_000, BLOCK_HASH, NOW - 2),
    ];
    this.missingCode = new Set(
      (options.missingCode ?? []).map((address) => address.toLowerCase()),
    );
    this.readContract = contractRead(options.canonicalPool);
    this.remainingCanonicalFailures = options.canonicalFailures ?? 0;
  }

  async getHead(): Promise<PinnedBlockSnapshot> {
    const head = this.heads[Math.min(this.headReads, this.heads.length - 1)];
    this.headReads += 1;
    return structuredClone(head);
  }

  async getCode(
    address: string,
    blockHash: string,
    network: string,
  ): Promise<string> {
    this.codeReads.push({ address, blockHash, network });
    return this.missingCode.has(address.toLowerCase()) ? "0x" : "0x6000";
  }

  async call(
    address: string,
    signature: string,
    args: unknown[] | null,
    outputTypes: string[] | null,
    blockHash: string,
    network: string,
  ): Promise<Record<string, unknown>> {
    this.contractReads.push({
      address,
      signature,
      args,
      outputTypes,
      blockHash,
      network,
    });
    return this.readContract(address, signature);
  }

  async assertCanonical(
    blockNumber: number,
    blockHash: string,
    network: string,
  ): Promise<void> {
    this.canonicalChecks.push({ blockNumber, blockHash, network });
    if (this.remainingCanonicalFailures > 0) {
      this.remainingCanonicalFailures -= 1;
      throw new Error(`block ${blockHash} is not canonical`);
    }
  }
}

test("fixed Pancake reader pins every code and contract read to one block hash", async () => {
  const rpc = new MockPinnedRpcReader();
  const reader = new PancakeV3StateReader(rpc);
  const result = await reader.read(validMandate(), "bsc-testnet");
  assert.equal(result.pool_address, POOL);
  assert.equal(result.position_manager_address, MANAGER);
  assert.equal(result.current_tick, 119);
  assert.equal(result.tick_spacing, 60);
  assert.equal(result.observed_block_hash, BLOCK_HASH);
  assert.equal(result.pool_liquidity, POOL_LIQUIDITY);
  assert.equal(rpc.codeReads.length, 4);
  assert.equal(rpc.contractReads.length, 15);
  for (const read of [...rpc.codeReads, ...rpc.contractReads]) {
    assert.equal(read.blockHash, BLOCK_HASH);
    assert.equal(read.network, "bsc-testnet");
  }
  assert.deepEqual(rpc.canonicalChecks, [
    {
      blockNumber: 50_000_000,
      blockHash: BLOCK_HASH,
      network: "bsc-testnet",
    },
  ]);
});

test("fixed Pancake reader rejects a factory-resolved pool mismatch", async () => {
  const rpc = new MockPinnedRpcReader({
    canonicalPool: "0x7777777777777777777777777777777777777777",
  });
  const wrongPoolReader = new PancakeV3StateReader(
    rpc,
  );
  await assert.rejects(
    () => wrongPoolReader.read(validMandate(), "bsc-testnet"),
    /factory-resolved pool/,
  );
  assert.equal(rpc.headReads, 1);
});

test("fixed Pancake reader rejects an RPC chain mismatch before contract reads", async () => {
  const rpc = new MockPinnedRpcReader({
    heads: [
      pinnedSnapshot(50_000_000, BLOCK_HASH, NOW - 2, 56),
    ],
  });
  await assert.rejects(
    () => new PancakeV3StateReader(rpc).read(validMandate(), "bsc-testnet"),
    /configured RPC chain/,
  );
  assert.equal(rpc.codeReads.length, 0);
  assert.equal(rpc.contractReads.length, 0);
  assert.equal(rpc.canonicalChecks.length, 0);
});

test("fixed Pancake reader distinguishes missing deployment code from missing pool code", async () => {
  const deployment = PANCAKE_V3_DEPLOYMENTS["bsc-testnet"];
  const missingDeployment = await new RebalanceService({
    reader: new PancakeV3StateReader(
      new MockPinnedRpcReader({ missingCode: [deployment.factory] }),
    ),
    now: () => NOW,
  }).prepareQuote({ mandate: validMandate() });
  assert.equal(missingDeployment.ok, false);
  if (!missingDeployment.ok) {
    assert.equal(missingDeployment.refusal.code, "UNSUPPORTED_PROTOCOL");
    assert.match(missingDeployment.refusal.message, /deployment contract has no code/);
  }

  const missingPool = await new RebalanceService({
    reader: new PancakeV3StateReader(
      new MockPinnedRpcReader({ missingCode: [POOL] }),
    ),
    now: () => NOW,
  }).prepareQuote({ mandate: validMandate() });
  assert.equal(missingPool.ok, false);
  if (!missingPool.ok) {
    assert.equal(missingPool.refusal.code, "POOL_POSITION_MISMATCH");
    assert.match(missingPool.refusal.message, /pool has no contract code/);
  }
});

test("fixed Pancake reader retries canonicality failure with a new pinned head", async () => {
  const rpc = new MockPinnedRpcReader({
    heads: [
      pinnedSnapshot(50_000_000, BLOCK_HASH, NOW - 3),
      pinnedSnapshot(50_000_001, NEXT_BLOCK_HASH, NOW - 2),
    ],
    canonicalFailures: 1,
  });
  const reader = new PancakeV3StateReader(rpc);
  const result = await reader.read(validMandate(), "bsc-testnet");
  assert.equal(result.observed_block, 50_000_001);
  assert.equal(result.observed_block_hash, NEXT_BLOCK_HASH);
  assert.equal(rpc.headReads, 2);
  assert.deepEqual(
    rpc.canonicalChecks.map(({ blockHash }) => blockHash),
    [BLOCK_HASH, NEXT_BLOCK_HASH],
  );
  assert.ok(rpc.codeReads.slice(0, 4).every(({ blockHash }) => blockHash === BLOCK_HASH));
  assert.ok(
    rpc.codeReads.slice(4).every(({ blockHash }) => blockHash === NEXT_BLOCK_HASH),
  );
  assert.ok(
    rpc.contractReads
      .slice(0, 15)
      .every(({ blockHash }) => blockHash === BLOCK_HASH),
  );
  assert.ok(
    rpc.contractReads
      .slice(15)
      .every(({ blockHash }) => blockHash === NEXT_BLOCK_HASH),
  );
});

test("fixed Pancake reader fails closed after canonical retries are exhausted", async () => {
  const rpc = new MockPinnedRpcReader({ canonicalFailures: 2 });
  await assert.rejects(
    () => new PancakeV3StateReader(rpc).read(validMandate(), "bsc-testnet"),
    /could not be confirmed canonical/,
  );
  assert.equal(rpc.headReads, 2);
  assert.equal(rpc.canonicalChecks.length, 2);
});

test("fixed Pancake reader rejects injected non-two-block snapshots before state reads", async () => {
  const rpc = new MockPinnedRpcReader({
    heads: [
      {
        chainId: 97,
        snapshotHeadBlock: 50_000_001,
        confirmationDepthBlocks: 1,
        number: 50_000_000,
        hash: BLOCK_HASH,
        timestamp: NOW - 2,
      },
    ],
  });
  await assert.rejects(
    () => new PancakeV3StateReader(rpc).read(validMandate(), "bsc-testnet"),
    /could not be confirmed canonical/,
  );
  assert.equal(rpc.headReads, 2);
  assert.equal(rpc.codeReads.length, 0);
  assert.equal(rpc.contractReads.length, 0);
  assert.equal(rpc.canonicalChecks.length, 0);
});

test("Viem reader rejects every configurable depth except the fixed value two", () => {
  const invalidOptions = {
    confirmationDepthBlocks: 1,
  } as unknown as ViemPinnedRpcReaderOptions;
  assert.throws(
    () => new ViemPinnedRpcReader(invalidOptions),
    /must equal 2/,
  );
  assert.doesNotThrow(
    () => new ViemPinnedRpcReader({ confirmationDepthBlocks: 2 }),
  );
});

test("Viem reader sends state reads with canonical EIP-1898 block selectors", async () => {
  const requests: Array<{ method: string; params: unknown }> = [];
  const transport = custom({
    async request({ method, params }) {
      requests.push({ method, params });
      if (method === "eth_getCode") return "0x6000";
      if (method === "eth_call") return "0x";
      throw new Error(`unexpected RPC method ${method}`);
    },
  });
  const rpc = new ViemPinnedRpcReader({
    transportFactory: () => transport,
  });

  assert.equal(
    await rpc.getCode(POOL, BLOCK_HASH, "bsc-testnet"),
    "0x6000",
  );
  await rpc.call(
    POOL,
    "liquidity()",
    [],
    null,
    BLOCK_HASH,
    "bsc-testnet",
  );

  const codeRequest = requests.find(({ method }) => method === "eth_getCode");
  const callRequest = requests.find(({ method }) => method === "eth_call");
  assert.ok(codeRequest);
  assert.ok(callRequest);
  assert.deepEqual((codeRequest.params as unknown[])[1], {
    blockHash: BLOCK_HASH,
    requireCanonical: true,
  });
  assert.deepEqual((callRequest.params as unknown[])[1], {
    blockHash: BLOCK_HASH,
    requireCanonical: true,
  });
  assert.doesNotMatch(JSON.stringify(requests), /latest/);
});

test("Viem reader snapshots the block exactly two heads behind latest", async () => {
  const requests: Array<{ method: string; params: unknown }> = [];
  const transport = custom({
    async request({ method, params }) {
      requests.push({ method, params });
      if (method === "eth_chainId") return "0x61";
      if (method === "eth_getBlockByNumber") {
        const blockTag = (params as unknown[])[0];
        if (blockTag === "latest") return rpcBlock(100, HEAD_BLOCK_HASH, NOW);
        if (blockTag === "0x62") return rpcBlock(98, BLOCK_HASH, NOW - 2);
      }
      throw new Error(`unexpected RPC request ${method} ${JSON.stringify(params)}`);
    },
  });
  const rpc = new ViemPinnedRpcReader({
    transportFactory: () => transport,
  });

  const snapshot = await rpc.getHead("bsc-testnet");
  assert.deepEqual(snapshot, {
    chainId: 97,
    snapshotHeadBlock: 100,
    confirmationDepthBlocks: 2,
    number: 98,
    hash: BLOCK_HASH,
    timestamp: NOW - 2,
  });
  assert.deepEqual(
    requests
      .filter(({ method }) => method === "eth_getBlockByNumber")
      .map(({ params }) => (params as unknown[])[0]),
    ["latest", "0x62"],
  );
});

test("Viem reader fails closed when the head is below confirmation depth", async () => {
  const blockRequests: unknown[] = [];
  const transport = custom({
    async request({ method, params }) {
      if (method === "eth_chainId") return "0x61";
      if (method === "eth_getBlockByNumber") {
        blockRequests.push(params);
        return rpcBlock(1, HEAD_BLOCK_HASH, NOW);
      }
      throw new Error(`unexpected RPC request ${method}`);
    },
  });
  const rpc = new ViemPinnedRpcReader({
    transportFactory: () => transport,
  });

  await assert.rejects(
    () => rpc.getHead("bsc-testnet"),
    /below the required confirmation depth/,
  );
  assert.equal(blockRequests.length, 1);
});

test("valid mandate is normalized into a sanitizer-safe signed ERC-8183 task", async () => {
  const reader = new SequenceReader([evidence()]);
  const service = new RebalanceService({ reader, now: () => NOW });

  const result = await service.prepareQuote({ mandate: validMandate() });
  assert.equal(result.ok, true);
  if (!result.ok) return;

  const taskText = String(result.request.task_description);
  assert.match(taskText, /^mandatex-rebalance:v1:[A-Za-z0-9_-]+$/);
  assert.ok(Buffer.byteLength(taskText, "utf8") <= 2600);
  const decoded = decodeSignedRebalanceTask(taskText);
  assert.deepEqual(
    (decoded.mandate as RebalanceMandate).permissions.allowed_calls,
    [...REQUIRED_REBALANCE_CALLS].sort(),
  );
  assert.equal(result.signedTask.proposal.proposed_lower_tick, 60);
  assert.equal(result.signedTask.proposal.proposed_upper_tick, 180);
  assert.equal(
    result.signedTask.proposal.proposed_upper_tick -
      result.signedTask.proposal.proposed_lower_tick,
    120,
  );
  assert.equal(
    result.signedTask.proposal.proposed_lower_tick %
      result.signedTask.evidence.tick_spacing,
    0,
  );
  assert.equal(
    result.signedTask.proposal.proposed_upper_tick %
      result.signedTask.evidence.tick_spacing,
    0,
  );
  assert.ok(
    result.signedTask.proposal.proposed_lower_tick <=
      result.signedTask.evidence.current_tick,
  );
  assert.ok(
    result.signedTask.evidence.current_tick <
      result.signedTask.proposal.proposed_upper_tick,
  );

  const negotiatedAt = NOW;
  const description = buildJobDescription({
    request: result.request,
    response: {
      accepted: true,
      terms: {
        ...FIXED_REBALANCE_TERMS,
        price: "0",
        currency: CURRENCY,
      },
      quote_expires_at: NOW + 300,
    },
    negotiated_at: negotiatedAt,
    quote_expires_at: NOW + 300,
    negotiation_hash: `0x${"11".repeat(32)}`,
    provider_sig: `0x${"22".repeat(65)}`,
    chain_id: 97,
    verifying_contract: MANAGER,
  });
  const roundTrip = JobDescription.fromStr(description);
  assert.ok(roundTrip);
  assert.equal(roundTrip.task, taskText);
  assert.deepEqual(roundTrip.terms, {
    ...FIXED_REBALANCE_TERMS,
  });
  assert.deepEqual(decodeSignedRebalanceTask(roundTrip.task), decoded);
});

test("V3 ranges require aligned, exact, divisible deterministic target widths", async () => {
  const nondivisible = validMandate();
  nondivisible.range_policy.target_width_ticks = 100;
  const nondivisibleResult = await new RebalanceService({
    reader: new SequenceReader([evidence()]),
    now: () => NOW,
  }).prepareQuote({ mandate: nondivisible });
  assert.equal(nondivisibleResult.ok, false);
  if (!nondivisibleResult.ok) {
    assert.equal(nondivisibleResult.refusal.code, "RANGE_OUTSIDE_MANDATE");
    assert.deepEqual(nondivisibleResult.refusal.details, {
      target_width_ticks: 100,
      tick_spacing: 60,
    });
  }

  const negativeTieMandate = validMandate();
  negativeTieMandate.range_policy.target_width_ticks = 200;
  negativeTieMandate.range_policy.approved_lower_tick = -300;
  const negativeTieResult = await new RebalanceService({
    reader: new SequenceReader([
      evidence({
        tick_spacing: 10,
        current_tick: -95,
        position_tick_lower: -100,
        position_tick_upper: -90,
      }),
    ]),
    now: () => NOW,
  }).prepareQuote({ mandate: negativeTieMandate });
  assert.equal(negativeTieResult.ok, true);
  if (negativeTieResult.ok) {
    assert.equal(negativeTieResult.signedTask.proposal.proposed_lower_tick, -190);
    assert.equal(negativeTieResult.signedTask.proposal.proposed_upper_tick, 10);
  }

  const baseline = await new RebalanceService({
    reader: new SequenceReader([evidence()]),
    now: () => NOW,
  }).prepareQuote({ mandate: validMandate() });
  assert.equal(baseline.ok, true);
  if (!baseline.ok) return;
  const legacyOutward = structuredClone(baseline.signedTask);
  legacyOutward.proposal.proposed_lower_tick = 0;
  assert.throws(() => SignedRebalanceTaskSchema.parse(legacyOutward));

  const unaligned = structuredClone(baseline.signedTask);
  unaligned.proposal.proposed_lower_tick = 61;
  unaligned.proposal.proposed_upper_tick = 181;
  assert.throws(() => SignedRebalanceTaskSchema.parse(unaligned));

  const outsideApproved = structuredClone(baseline.signedTask);
  outsideApproved.mandate.range_policy.approved_upper_tick = 170;
  assert.throws(() => SignedRebalanceTaskSchema.parse(outsideApproved));

  const unalignedApproved = structuredClone(baseline.signedTask);
  unalignedApproved.mandate.range_policy.approved_lower_tick = 59;
  unalignedApproved.mandate.range_policy.approved_upper_tick = 181;
  assert.doesNotThrow(() => SignedRebalanceTaskSchema.parse(unalignedApproved));

  assert.throws(() =>
    RebalanceEvidenceSchema.parse(
      evidence({ position_tick_lower: -119 }),
    ),
  );
  const tooWide = validMandate();
  tooWide.range_policy.target_width_ticks = 1_201;
  assert.throws(() => RebalanceMandateSchema.parse(tooWide));
});

test("near-limit mandates retain codec and ERC-8183 round-trip headroom", async () => {
  let bestTask = "";
  let bestBytes = 0;
  let sawOversizedRefusal = false;

  for (let payloadLength = 3_060; payloadLength >= 0; payloadLength -= 20) {
    const mandate = validMandate();
    mandate.mandate_id = `near-limit-${deterministicText(69, 11)}`;
    mandate.execution_estimate.source_url =
      `https://example.com/${deterministicText(480, 29, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")}`;
    mandate.permissions.allowed_contracts = [
      MANAGER,
      ...Array.from({ length: 11 }, (_, index) =>
        `0x${deterministicText(40, 100 + index, "abcdef0123456789")}`,
      ),
    ];
    mandate.permissions.allowed_calls = [
      ...REQUIRED_REBALANCE_CALLS,
      ...splitCallPayload(
        deterministicText(
          payloadLength,
          71,
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-/",
        ),
      ),
    ];

    const result = await new RebalanceService({
      reader: new SequenceReader([evidence()]),
      now: () => NOW,
    }).prepareQuote({ mandate });
    if (!result.ok) {
      if (result.refusal.code === "INVALID_MANDATE") {
        sawOversizedRefusal = true;
      }
      continue;
    }

    const task = String(result.request.task_description);
    const bytes = Buffer.byteLength(task, "utf8");
    if (bytes > bestBytes) {
      bestTask = task;
      bestBytes = bytes;
    }
  }

  assert.equal(sawOversizedRefusal, true);
  assert.ok(bestBytes >= 2_400, `largest accepted task was only ${bestBytes} bytes`);
  assert.ok(bestBytes <= 2_600);
  const decoded = decodeSignedRebalanceTask(bestTask);
  assert.equal(
    (decoded.mandate as RebalanceMandate).mandate_id,
    `near-limit-${deterministicText(69, 11)}`,
  );
  const description = buildJobDescription({
    request: {
      task_description: bestTask,
      terms: FIXED_REBALANCE_TERMS,
    },
    response: {
      accepted: true,
      terms: { ...FIXED_REBALANCE_TERMS, price: "0", currency: CURRENCY },
      quote_expires_at: NOW + 300,
    },
    negotiated_at: NOW,
    quote_expires_at: NOW + 300,
    negotiation_hash: `0x${"11".repeat(32)}`,
    provider_sig: `0x${"22".repeat(65)}`,
    chain_id: 97,
    verifying_contract: MANAGER,
  });
  assert.equal(JobDescription.fromStr(description).task, bestTask);
});

test("unsupported category, chain, and protocol reject before evidence reads", async () => {
  for (const [field, value, code] of [
    ["category", "grid", "UNSUPPORTED_CATEGORY"],
    ["chain_id", 56, "UNSUPPORTED_CHAIN"],
    ["protocol", "uniswap-v3", "UNSUPPORTED_PROTOCOL"],
  ] as const) {
    const reader = new SequenceReader([evidence()]);
    const service = new RebalanceService({ reader, now: () => NOW });
    const mandate = validMandate() as unknown as Record<string, unknown>;
    mandate[field] = value;
    const result = await service.prepareQuote({ mandate });
    assert.equal(result.ok, false);
    if (result.ok) continue;
    assert.equal(result.refusal.code, code);
    assert.equal(reader.calls, 0);
  }
});

test("stale or unavailable quote evidence fails closed", async () => {
  const stale = new RebalanceService({
    reader: new SequenceReader([evidence({ observed_at: NOW - 121 })]),
    now: () => NOW,
  });
  const staleResult = await stale.prepareQuote({ mandate: validMandate() });
  assert.equal(staleResult.ok, false);
  if (!staleResult.ok) assert.equal(staleResult.refusal.code, "STALE_EVIDENCE");

  const unavailable = new RebalanceService({
    reader: new SequenceReader([new Error("RPC timeout")]),
    now: () => NOW,
  });
  const unavailableResult = await unavailable.prepareQuote({
    mandate: validMandate(),
  });
  assert.equal(unavailableResult.ok, false);
  if (!unavailableResult.ok) {
    assert.equal(unavailableResult.refusal.code, "EVIDENCE_UNAVAILABLE");
  }
});

test("malformed or mandate-mismatched reader evidence fails closed", async () => {
  const malformed = {
    ...evidence(),
    observed_block_hash: "not-a-block-hash",
  } as unknown as RebalanceEvidence;
  const malformedResult = await new RebalanceService({
    reader: new SequenceReader([malformed]),
    now: () => NOW,
  }).prepareQuote({ mandate: validMandate() });
  assert.equal(malformedResult.ok, false);
  if (!malformedResult.ok) {
    assert.equal(malformedResult.refusal.code, "EVIDENCE_UNAVAILABLE");
    assert.equal(
      malformedResult.refusal.message,
      "Quote evidence could not be verified through the configured BSC RPC",
    );
  }

  for (const [overrides, code] of [
    [
      { pool_address: "0x7777777777777777777777777777777777777777" },
      "POOL_POSITION_MISMATCH",
    ],
    [{ network: "bsc-mainnet" }, "UNSUPPORTED_CHAIN"],
  ] as const) {
    const result = await new RebalanceService({
      reader: new SequenceReader([evidence(overrides)]),
      now: () => NOW,
    }).prepareQuote({ mandate: validMandate() });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.refusal.code, code);
  }
});

test("evidence rejects inconsistent head and confirmation-depth metadata", () => {
  assert.throws(
    () =>
      RebalanceEvidenceSchema.parse(
        evidence({ snapshot_head_block: 50_000_003 }),
      ),
    /must equal snapshot_head_block minus observed_block/,
  );
});

test("evidence rejects a self-consistent one-block snapshot", () => {
  assert.throws(
    () =>
      RebalanceEvidenceSchema.parse(
        {
          ...evidence(),
          snapshot_head_block: 50_000_001,
          confirmation_depth_blocks: 1,
        },
      ),
    /Invalid literal value, expected 2/,
  );
});

test("quote preparation rechecks mandate and permission expiry after an async read", async () => {
  for (const expiry of ["mandate", "permission"] as const) {
    let clock = NOW;
    let reads = 0;
    const mandate = validMandate();
    if (expiry === "mandate") {
      mandate.expires_at = NOW + 1;
      mandate.permissions.expires_at = NOW + 1;
    } else {
      mandate.permissions.expires_at = NOW + 1;
    }
    const reader: RebalanceStateReader = {
      async read() {
        reads += 1;
        await Promise.resolve();
        clock = NOW + 1;
        return evidence({ observed_at: NOW });
      },
    };
    const result = await new RebalanceService({
      reader,
      now: () => clock,
    }).prepareQuote({ mandate });
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(
        result.refusal.code,
        expiry === "mandate" ? "MANDATE_EXPIRED" : "PERMISSION_EXPIRED",
      );
    }
    assert.equal(reads, 1);
  }
});

test("RPC errors are redacted from quote and delivery refusal messages", async () => {
  const secret = "rpc-secret-token-123";
  const rpcUrl = `https://rpc.example.test/v1?api_key=${secret}`;
  const rpcError = new Error(`POST ${rpcUrl} failed: upstream payload ${secret}`);

  const quoteResult = await new RebalanceService({
    reader: new SequenceReader([rpcError]),
    now: () => NOW,
  }).prepareQuote({ mandate: validMandate() });
  assert.equal(quoteResult.ok, false);
  if (!quoteResult.ok) {
    assert.equal(quoteResult.refusal.code, "EVIDENCE_UNAVAILABLE");
    assert.equal(
      quoteResult.refusal.message,
      "Quote evidence could not be verified through the configured BSC RPC",
    );
    assert.doesNotMatch(quoteResult.refusal.message, /rpc\.example\.test|api_key|secret-token/);
  }

  const deliveryService = new RebalanceService({
    reader: new SequenceReader([evidence(), rpcError]),
    now: () => NOW,
  });
  const prepared = await deliveryService.prepareQuote({ mandate: validMandate() });
  assert.equal(prepared.ok, true);
  if (!prepared.ok) return;
  const receipt = await deliveryService.deliver(11, {
    task: String(prepared.request.task_description),
    terms: structuredClone(FIXED_REBALANCE_TERMS),
  });
  assert.equal(receipt?.refusal?.code, "EVIDENCE_UNAVAILABLE");
  assert.equal(
    receipt?.refusal?.message,
    "Delivery evidence could not be verified through the configured BSC RPC",
  );
  assert.doesNotMatch(
    receipt?.refusal?.message ?? "",
    /rpc\.example\.test|api_key|secret-token/,
  );
});

test("gas, slippage, exposure, and permission subsets are hard gates", async () => {
  const cases: Array<{
    mutate: (mandate: RebalanceMandate) => void;
    code: string;
  }> = [
    {
      mutate: (mandate) => {
        mandate.limits.max_gas_usd = 1;
      },
      code: "GAS_LIMIT_EXCEEDED",
    },
    {
      mutate: (mandate) => {
        mandate.limits.max_slippage_bps = 10;
      },
      code: "SLIPPAGE_LIMIT_EXCEEDED",
    },
    {
      mutate: (mandate) => {
        mandate.permissions.spend_cap_usd = 100;
      },
      code: "EXPOSURE_LIMIT_EXCEEDED",
    },
    {
      mutate: (mandate) => {
        mandate.permissions.allowed_contracts = [POOL];
      },
      code: "CONTRACT_NOT_ALLOWED",
    },
    {
      mutate: (mandate) => {
        mandate.permissions.allowed_calls = mandate.permissions.allowed_calls.slice(1);
      },
      code: "CALL_NOT_ALLOWED",
    },
  ];

  for (const item of cases) {
    const mandate = validMandate();
    item.mutate(mandate);
    const result = await new RebalanceService({
      reader: new SequenceReader([evidence()]),
      now: () => NOW,
    }).prepareQuote({ mandate });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.refusal.code, item.code);
  }
});

test("delivery returns simulation receipt when state remains inside tolerance", async () => {
  const reader = new SequenceReader([
    evidence(),
    evidence({ observed_block: 50_000_001, current_tick: 120 }),
  ]);
  const service = new RebalanceService({ reader, now: () => NOW });
  const prepared = await service.prepareQuote({ mandate: validMandate() });
  assert.equal(prepared.ok, true);
  if (!prepared.ok) return;

  const receipt = await service.deliver(7, {
    task: String(prepared.request.task_description),
    terms: structuredClone(FIXED_REBALANCE_TERMS),
  });
  assert.ok(receipt);
  assert.equal(receipt.status, "simulation_ready");
  assert.equal(receipt.simulation_only, true);
  assert.equal(receipt.refusal, null);
  assert.match(receipt.note, /No PancakeSwap liquidity transaction was executed/);
});

test("delivery refuses when position ownership changes after the quote", async () => {
  const service = new RebalanceService({
    reader: new SequenceReader([
      evidence(),
      evidence({
        observed_block: 50_000_001,
        position_owner: OTHER_OWNER,
        current_tick: 200,
      }),
    ]),
    now: () => NOW,
  });
  const prepared = await service.prepareQuote({ mandate: validMandate() });
  assert.equal(prepared.ok, true);
  if (!prepared.ok) return;

  const receipt = await service.deliver(12, {
    task: String(prepared.request.task_description),
    terms: structuredClone(FIXED_REBALANCE_TERMS),
  });
  assert.equal(receipt?.status, "refused");
  assert.equal(receipt?.refusal?.code, "STATE_DRIFT");
  assert.equal(receipt?.refusal?.message, "the position owner changed after the quote");
  assert.deepEqual(receipt?.refusal?.details, {
    quoted_position_owner: OWNER,
    delivery_position_owner: OTHER_OWNER,
  });
});

test("delivery rechecks expiry after its asynchronous evidence read", async () => {
  let clock = NOW;
  let reads = 0;
  const mandate = validMandate();
  mandate.expires_at = NOW + 1;
  mandate.permissions.expires_at = NOW + 1;
  const reader: RebalanceStateReader = {
    async read() {
      reads += 1;
      if (reads === 2) {
        await Promise.resolve();
        clock = NOW + 1;
      }
      return evidence({
        observed_block: 50_000_000 + reads - 1,
        observed_at: NOW,
      });
    },
  };
  const service = new RebalanceService({ reader, now: () => clock });
  const prepared = await service.prepareQuote({ mandate });
  assert.equal(prepared.ok, true);
  if (!prepared.ok) return;

  const receipt = await service.deliver(13, {
    task: String(prepared.request.task_description),
    terms: structuredClone(FIXED_REBALANCE_TERMS),
  });
  assert.equal(receipt?.status, "refused");
  assert.equal(receipt?.refusal?.code, "MANDATE_EXPIRED");
  assert.equal(receipt?.delivery_evidence?.observed_block, 50_000_001);
  assert.equal(reads, 2);
});

test("delivery creates explicit refusal receipts for drift, expiry, and unavailable evidence", async () => {
  const driftReader = new SequenceReader([
    evidence(),
    evidence({ observed_block: 50_000_001, current_tick: 200 }),
  ]);
  const driftService = new RebalanceService({
    reader: driftReader,
    now: () => NOW,
  });
  const driftPrepared = await driftService.prepareQuote({ mandate: validMandate() });
  assert.equal(driftPrepared.ok, true);
  if (!driftPrepared.ok) return;
  const driftReceipt = await driftService.deliver(8, {
    task: String(driftPrepared.request.task_description),
    terms: structuredClone(FIXED_REBALANCE_TERMS),
  });
  assert.equal(driftReceipt?.status, "refused");
  assert.equal(driftReceipt?.refusal?.code, "STATE_DRIFT");

  let clock = NOW;
  const expiryReader = new SequenceReader([evidence()]);
  const expiryService = new RebalanceService({
    reader: expiryReader,
    now: () => clock,
  });
  const expiryPrepared = await expiryService.prepareQuote({ mandate: validMandate() });
  assert.equal(expiryPrepared.ok, true);
  if (!expiryPrepared.ok) return;
  clock = NOW + 901;
  const expiryReceipt = await expiryService.deliver(9, {
    task: String(expiryPrepared.request.task_description),
    terms: structuredClone(FIXED_REBALANCE_TERMS),
  });
  assert.equal(expiryReceipt?.refusal?.code, "MANDATE_EXPIRED");
  assert.equal(expiryReader.calls, 1);

  const unavailableReader = new SequenceReader([evidence(), new Error("RPC down")]);
  const unavailableService = new RebalanceService({
    reader: unavailableReader,
    now: () => NOW,
  });
  const unavailablePrepared = await unavailableService.prepareQuote({
    mandate: validMandate(),
  });
  assert.equal(unavailablePrepared.ok, true);
  if (!unavailablePrepared.ok) return;
  const unavailableReceipt = await unavailableService.deliver(10, {
    task: String(unavailablePrepared.request.task_description),
    terms: structuredClone(FIXED_REBALANCE_TERMS),
  });
  assert.equal(unavailableReceipt?.refusal?.code, "EVIDENCE_UNAVAILABLE");
});

test("unknown tasks fall through while altered fixed terms are refused", async () => {
  const service = new RebalanceService({
    reader: new SequenceReader([evidence()]),
    now: () => NOW,
  });
  assert.equal(
    await service.deliver(1, { task: "legacy task", terms: {} }),
    null,
  );

  const prepared = await service.prepareQuote({ mandate: validMandate() });
  assert.equal(prepared.ok, true);
  if (!prepared.ok) return;
  const receipt = await service.deliver(2, {
    task: String(prepared.request.task_description),
    terms: { ...FIXED_REBALANCE_TERMS, quality_standards: "changed" },
  });
  assert.equal(receipt?.refusal?.code, "SIGNED_TASK_INVALID");
});
