import { createHash } from "node:crypto";

import {
  decodeFunctionResult,
  encodeFunctionData,
  getAddress,
  isAddress,
  type Abi,
  type Address,
  type Hex,
} from "viem";

export const BSC_PANCAKE_V3 = Object.freeze({
  chainId: 56 as const,
  confirmationDepth: 2 as const,
  factory: "0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865" as Address,
  deployer: "0x41ff9aa7e16b8b1a8a8dc4f0efacd93d02d071c9" as Address,
  positionManager:
    "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364" as Address,
  erc8004Registry:
    "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432" as Address,
});

const MIN_TICK = -887_272;
const MAX_TICK = 887_272;
const UINT256_LIMIT = 1n << 256n;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export type PancakeStateRpcMethod =
  | "eth_chainId"
  | "eth_blockNumber"
  | "eth_getBlockByNumber"
  | "eth_getCode"
  | "eth_call";

export type PancakeStateRpcRequest = Readonly<{
  method: PancakeStateRpcMethod;
  params: readonly unknown[];
}>;

export interface PancakeStateRpc {
  request<T = unknown>(request: PancakeStateRpcRequest): Promise<T>;
}

export class PancakeStateRpcError extends Error {
  constructor(
    readonly kind: "propagation" | "unavailable" | "invalid-response",
  ) {
    super(kind);
    this.name = "PancakeStateRpcError";
  }
}

export type PancakeSnapshotTarget =
  | Readonly<{ mode: "fresh" }>
  | Readonly<{
      mode: "exact";
      blockNumber: string;
      blockHash: string;
    }>;

export type PancakeStateInvalidCode =
  | "INPUT_INVALID"
  | "UNSUPPORTED_CHAIN"
  | "POSITION_MANAGER_NOT_CANONICAL"
  | "AGENT_OWNER_MISMATCH"
  | "PROVIDER_NOT_EOA"
  | "DEPLOYMENT_CODE_MISSING"
  | "POOL_CODE_MISSING"
  | "TOKEN_CODE_MISSING"
  | "DEPLOYMENT_POINTER_MISMATCH"
  | "POOL_POSITION_MISMATCH"
  | "FACTORY_POOL_MISMATCH"
  | "TICK_SPACING_MISMATCH"
  | "TICK_STATE_INVALID"
  | "POOL_INACTIVE"
  | "POSITION_INACTIVE";

export type PancakeStateInconclusiveCode =
  | "CHAIN_ID_MISMATCH"
  | "HEAD_TOO_LOW"
  | "RPC_UNAVAILABLE"
  | "RPC_INVALID_RESPONSE"
  | "SNAPSHOT_INCONSISTENT";

export type ContractCodeSummary = Readonly<{
  bytes: number;
  sha256: string;
}>;

export type PancakeTokenState = Readonly<{
  address: string;
  code: ContractCodeSummary;
  decimals: number;
  callerBalance: string;
  callerAllowanceToPositionManager: string;
}>;

export type PancakeStateSnapshot = Readonly<{
  chainId: 56;
  pin: Readonly<{
    mode: PancakeSnapshotTarget["mode"];
    headBlockNumber: string | null;
    observedBlockNumber: string;
    observedBlockHash: string;
    observedAt: string;
    confirmationDepth: 2 | null;
    requireCanonical: true;
    attempts: number;
  }>;
  identity: Readonly<{
    registryAddress: string;
    registryCode: ContractCodeSummary;
    agentTokenId: string;
    expectedProvider: string;
    currentOwner: string;
    providerCode: ContractCodeSummary;
  }>;
  deployments: Readonly<{
    factory: Readonly<{ address: string; code: ContractCodeSummary }>;
    deployer: Readonly<{ address: string; code: ContractCodeSummary }>;
    positionManager: Readonly<{
      address: string;
      code: ContractCodeSummary;
      factory: string;
      deployer: string;
    }>;
  }>;
  pool: Readonly<{
    address: string;
    code: ContractCodeSummary;
    factory: string;
    token0: string;
    token1: string;
    fee: number;
    tickSpacing: number;
    sqrtPriceX96: string;
    currentTick: number;
    observationIndex: number;
    observationCardinality: number;
    observationCardinalityNext: number;
    feeProtocol: number;
    unlocked: boolean;
    liquidity: string;
  }>;
  position: Readonly<{
    tokenId: string;
    owner: string;
    approved: string;
    caller: string;
    callerApprovedForAll: boolean;
    callerCanManage: boolean;
    nonce: string;
    operator: string;
    token0: string;
    token1: string;
    fee: number;
    tickLower: number;
    tickUpper: number;
    liquidity: string;
    feeGrowthInside0LastX128: string;
    feeGrowthInside1LastX128: string;
    tokensOwed0: string;
    tokensOwed1: string;
  }>;
  tokens: Readonly<{
    token0: PancakeTokenState;
    token1: PancakeTokenState;
  }>;
}>;

export type PancakeStateResult =
  | Readonly<{ status: "verified"; snapshot: PancakeStateSnapshot }>
  | Readonly<{
      status: "invalid";
      code: PancakeStateInvalidCode;
      message: string;
      attempts: number;
    }>
  | Readonly<{
      status: "inconclusive";
      code: PancakeStateInconclusiveCode;
      message: string;
      attempts: number;
    }>;

export type VerifyPancakeStateOptions = Readonly<{
  rpc: PancakeStateRpc;
  chainId: number;
  poolAddress: string;
  positionManagerAddress: string;
  positionTokenId: string;
  caller: string;
  agentTokenId: string;
  expectedProvider: string;
  target?: PancakeSnapshotTarget;
}>;

type NormalizedOptions = Readonly<{
  rpc: PancakeStateRpc;
  poolAddress: Address;
  positionManagerAddress: Address;
  positionTokenId: bigint;
  positionTokenIdText: string;
  caller: Address;
  agentTokenId: bigint;
  agentTokenIdText: string;
  expectedProvider: Address;
  target: PancakeSnapshotTarget;
}>;

type PinnedBlock = Readonly<{
  head: bigint | null;
  number: bigint;
  hash: Hex;
  timestamp: bigint;
}>;

type BlockHeader = Readonly<{
  number: bigint;
  hash: Hex;
  timestamp: bigint;
}>;

type ReadFaultKind =
  | "propagation"
  | "unavailable"
  | "invalid-response"
  | "chain-id-mismatch"
  | "head-too-low";

class ReadFault extends Error {
  constructor(readonly kind: ReadFaultKind) {
    super(kind);
    this.name = "ReadFault";
  }
}

class StateFault extends Error {
  constructor(
    readonly code: PancakeStateInvalidCode,
    message: string,
  ) {
    super(message);
    this.name = "StateFault";
  }
}

const erc721Abi = [
  {
    type: "function",
    name: "ownerOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "owner", type: "address" }],
  },
  {
    type: "function",
    name: "getApproved",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "operator", type: "address" }],
  },
  {
    type: "function",
    name: "isApprovedForAll",
    stateMutability: "view",
    inputs: [
      { name: "owner", type: "address" },
      { name: "operator", type: "address" },
    ],
    outputs: [{ name: "approved", type: "bool" }],
  },
] as const;

const positionManagerAbi = [
  {
    type: "function",
    name: "factory",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "deployer",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "positions",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [
      { name: "nonce", type: "uint96" },
      { name: "operator", type: "address" },
      { name: "token0", type: "address" },
      { name: "token1", type: "address" },
      { name: "fee", type: "uint24" },
      { name: "tickLower", type: "int24" },
      { name: "tickUpper", type: "int24" },
      { name: "liquidity", type: "uint128" },
      { name: "feeGrowthInside0LastX128", type: "uint256" },
      { name: "feeGrowthInside1LastX128", type: "uint256" },
      { name: "tokensOwed0", type: "uint128" },
      { name: "tokensOwed1", type: "uint128" },
    ],
  },
] as const;

const poolAbi = [
  {
    type: "function",
    name: "slot0",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "sqrtPriceX96", type: "uint160" },
      { name: "tick", type: "int24" },
      { name: "observationIndex", type: "uint16" },
      { name: "observationCardinality", type: "uint16" },
      { name: "observationCardinalityNext", type: "uint16" },
      { name: "feeProtocol", type: "uint32" },
      { name: "unlocked", type: "bool" },
    ],
  },
  {
    type: "function",
    name: "liquidity",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint128" }],
  },
  {
    type: "function",
    name: "token0",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "token1",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "fee",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint24" }],
  },
  {
    type: "function",
    name: "tickSpacing",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "int24" }],
  },
  {
    type: "function",
    name: "factory",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
] as const;

const factoryAbi = [
  {
    type: "function",
    name: "getPool",
    stateMutability: "view",
    inputs: [
      { name: "tokenA", type: "address" },
      { name: "tokenB", type: "address" },
      { name: "fee", type: "uint24" },
    ],
    outputs: [{ name: "pool", type: "address" }],
  },
  {
    type: "function",
    name: "feeAmountTickSpacing",
    stateMutability: "view",
    inputs: [{ name: "fee", type: "uint24" }],
    outputs: [{ name: "", type: "int24" }],
  },
] as const;

const erc20Abi = [
  {
    type: "function",
    name: "decimals",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "allowance",
    stateMutability: "view",
    inputs: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

export async function verifyPancakeV3State(
  options: VerifyPancakeStateOptions,
): Promise<PancakeStateResult> {
  let normalized: NormalizedOptions;
  try {
    normalized = normalizeOptions(options);
  } catch (error) {
    const fault =
      error instanceof StateFault
        ? error
        : new StateFault("INPUT_INVALID", "preview state input is invalid");
    return {
      status: "invalid",
      code: fault.code,
      message: fault.message,
      attempts: 0,
    };
  }

  const maxAttempts = normalized.target.mode === "fresh" ? 2 : 1;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const snapshot = await readSnapshot(normalized, attempt);
      return { status: "verified", snapshot };
    } catch (error) {
      if (error instanceof StateFault) {
        return {
          status: "invalid",
          code: error.code,
          message: error.message,
          attempts: attempt,
        };
      }
      const fault = normalizeReadFault(error);
      if (
        fault.kind === "propagation" &&
        normalized.target.mode === "fresh" &&
        attempt === 1
      ) {
        continue;
      }
      return inconclusive(fault, attempt);
    }
  }

  return inconclusive(new ReadFault("propagation"), maxAttempts);
}

async function readSnapshot(
  options: NormalizedOptions,
  attempt: number,
): Promise<PancakeStateSnapshot> {
  const chainId = parseQuantity(
    await rpcRequest<unknown>(options.rpc, "eth_chainId", []),
  );
  if (chainId !== BigInt(BSC_PANCAKE_V3.chainId)) {
    throw new ReadFault("chain-id-mismatch");
  }

  const pinned = await captureBlock(options);
  const blockSelector = {
    blockHash: pinned.hash,
    requireCanonical: true,
  } as const;

  const [
    registryCodeRaw,
    providerCodeRaw,
    managerCodeRaw,
    factoryCodeRaw,
    deployerCodeRaw,
    poolCodeRaw,
  ] = await Promise.all([
    getCode(options.rpc, BSC_PANCAKE_V3.erc8004Registry, blockSelector),
    getCode(options.rpc, options.expectedProvider, blockSelector),
    getCode(options.rpc, options.positionManagerAddress, blockSelector),
    getCode(options.rpc, BSC_PANCAKE_V3.factory, blockSelector),
    getCode(options.rpc, BSC_PANCAKE_V3.deployer, blockSelector),
    getCode(options.rpc, options.poolAddress, blockSelector),
  ]);

  const registryCode = summarizeCode(registryCodeRaw);
  const providerCode = summarizeCode(providerCodeRaw);
  const managerCode = summarizeCode(managerCodeRaw);
  const factoryCode = summarizeCode(factoryCodeRaw);
  const deployerCode = summarizeCode(deployerCodeRaw);
  const poolCode = summarizeCode(poolCodeRaw);

  if (
    registryCode.bytes === 0 ||
    managerCode.bytes === 0 ||
    factoryCode.bytes === 0 ||
    deployerCode.bytes === 0
  ) {
    throw new StateFault(
      "DEPLOYMENT_CODE_MISSING",
      "a canonical BSC deployment has no code at the pinned block",
    );
  }
  if (providerCode.bytes !== 0) {
    throw new StateFault(
      "PROVIDER_NOT_EOA",
      "the expected provider has contract code at the pinned block",
    );
  }
  if (poolCode.bytes === 0) {
    throw new StateFault(
      "POOL_CODE_MISSING",
      "the mandate pool has no code at the pinned block",
    );
  }

  const [
    agentOwnerRaw,
    managerFactoryRaw,
    managerDeployerRaw,
    positionRaw,
    positionOwnerRaw,
    approvedRaw,
    slot0Raw,
    poolLiquidityRaw,
    poolToken0Raw,
    poolToken1Raw,
    poolFeeRaw,
    poolTickSpacingRaw,
    poolFactoryRaw,
  ] = await Promise.all([
    readContract(
      options.rpc,
      BSC_PANCAKE_V3.erc8004Registry,
      erc721Abi,
      "ownerOf",
      [options.agentTokenId],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.positionManagerAddress,
      positionManagerAbi,
      "factory",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.positionManagerAddress,
      positionManagerAbi,
      "deployer",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.positionManagerAddress,
      positionManagerAbi,
      "positions",
      [options.positionTokenId],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.positionManagerAddress,
      erc721Abi,
      "ownerOf",
      [options.positionTokenId],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.positionManagerAddress,
      erc721Abi,
      "getApproved",
      [options.positionTokenId],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.poolAddress,
      poolAbi,
      "slot0",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.poolAddress,
      poolAbi,
      "liquidity",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.poolAddress,
      poolAbi,
      "token0",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.poolAddress,
      poolAbi,
      "token1",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.poolAddress,
      poolAbi,
      "fee",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.poolAddress,
      poolAbi,
      "tickSpacing",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.poolAddress,
      poolAbi,
      "factory",
      [],
      blockSelector,
    ),
  ]);

  const agentOwner = asAddress(agentOwnerRaw, "ERC-8004 owner");
  if (agentOwner !== options.expectedProvider) {
    throw new StateFault(
      "AGENT_OWNER_MISMATCH",
      "the ERC-8004 owner no longer matches the expected provider",
    );
  }

  const managerFactory = asAddress(managerFactoryRaw, "manager factory");
  const managerDeployer = asAddress(managerDeployerRaw, "manager deployer");
  const poolFactory = asAddress(poolFactoryRaw, "pool factory");
  if (
    managerFactory !== BSC_PANCAKE_V3.factory ||
    managerDeployer !== BSC_PANCAKE_V3.deployer ||
    poolFactory !== BSC_PANCAKE_V3.factory
  ) {
    throw new StateFault(
      "DEPLOYMENT_POINTER_MISMATCH",
      "manager or pool pointers do not match the canonical PancakeSwap V3 deployment",
    );
  }

  const position = asTuple(positionRaw, 12, "position tuple");
  const slot0 = asTuple(slot0Raw, 7, "pool slot0");
  const positionOwner = asAddress(positionOwnerRaw, "position owner");
  const approved = asAddress(approvedRaw, "position approval", true);
  const positionOperator = asAddress(position[1], "position operator", true);
  const positionToken0 = asAddress(position[2], "position token0");
  const positionToken1 = asAddress(position[3], "position token1");
  const positionFee = asSafeInteger(position[4], "position fee");
  const positionTickLower = asSafeInteger(position[5], "position lower tick");
  const positionTickUpper = asSafeInteger(position[6], "position upper tick");
  const positionLiquidity = asUnsignedDecimal(
    position[7],
    "position liquidity",
  );
  const poolToken0 = asAddress(poolToken0Raw, "pool token0");
  const poolToken1 = asAddress(poolToken1Raw, "pool token1");
  const poolFee = asSafeInteger(poolFeeRaw, "pool fee");
  const poolTickSpacing = asSafeInteger(
    poolTickSpacingRaw,
    "pool tick spacing",
  );
  const currentTick = asSafeInteger(slot0[1], "current tick");
  const poolLiquidity = asUnsignedDecimal(
    poolLiquidityRaw,
    "pool liquidity",
  );

  if (
    positionToken0 !== poolToken0 ||
    positionToken1 !== poolToken1 ||
    positionFee !== poolFee ||
    positionToken0 === positionToken1
  ) {
    throw new StateFault(
      "POOL_POSITION_MISMATCH",
      "the pool does not match the position token pair and fee tier",
    );
  }
  if (poolTickSpacing <= 0) {
    throw new StateFault(
      "TICK_SPACING_MISMATCH",
      "the pool tick spacing is not positive",
    );
  }
  if (
    currentTick < MIN_TICK ||
    currentTick > MAX_TICK ||
    positionTickLower < MIN_TICK ||
    positionTickUpper > MAX_TICK ||
    positionTickLower >= positionTickUpper ||
    positionTickLower % poolTickSpacing !== 0 ||
    positionTickUpper % poolTickSpacing !== 0
  ) {
    throw new StateFault(
      "TICK_STATE_INVALID",
      "the pool or position tick state is invalid",
    );
  }
  if (BigInt(poolLiquidity) === 0n) {
    throw new StateFault(
      "POOL_INACTIVE",
      "the pool has zero active liquidity at the pinned block",
    );
  }
  if (BigInt(positionLiquidity) === 0n) {
    throw new StateFault(
      "POSITION_INACTIVE",
      "the position has zero active liquidity at the pinned block",
    );
  }

  const [
    token0CodeRaw,
    token1CodeRaw,
    canonicalPoolRaw,
    canonicalSpacingRaw,
    token0DecimalsRaw,
    token1DecimalsRaw,
    token0BalanceRaw,
    token1BalanceRaw,
    token0AllowanceRaw,
    token1AllowanceRaw,
    approvedForAllRaw,
  ] = await Promise.all([
    getCode(options.rpc, poolToken0, blockSelector),
    getCode(options.rpc, poolToken1, blockSelector),
    readContract(
      options.rpc,
      BSC_PANCAKE_V3.factory,
      factoryAbi,
      "getPool",
      [poolToken0, poolToken1, poolFee],
      blockSelector,
    ),
    readContract(
      options.rpc,
      BSC_PANCAKE_V3.factory,
      factoryAbi,
      "feeAmountTickSpacing",
      [poolFee],
      blockSelector,
    ),
    readContract(
      options.rpc,
      poolToken0,
      erc20Abi,
      "decimals",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      poolToken1,
      erc20Abi,
      "decimals",
      [],
      blockSelector,
    ),
    readContract(
      options.rpc,
      poolToken0,
      erc20Abi,
      "balanceOf",
      [options.caller],
      blockSelector,
    ),
    readContract(
      options.rpc,
      poolToken1,
      erc20Abi,
      "balanceOf",
      [options.caller],
      blockSelector,
    ),
    readContract(
      options.rpc,
      poolToken0,
      erc20Abi,
      "allowance",
      [options.caller, options.positionManagerAddress],
      blockSelector,
    ),
    readContract(
      options.rpc,
      poolToken1,
      erc20Abi,
      "allowance",
      [options.caller, options.positionManagerAddress],
      blockSelector,
    ),
    readContract(
      options.rpc,
      options.positionManagerAddress,
      erc721Abi,
      "isApprovedForAll",
      [positionOwner, options.caller],
      blockSelector,
    ),
  ]);

  const token0Code = summarizeCode(token0CodeRaw);
  const token1Code = summarizeCode(token1CodeRaw);
  if (token0Code.bytes === 0 || token1Code.bytes === 0) {
    throw new StateFault(
      "TOKEN_CODE_MISSING",
      "a position token has no code at the pinned block",
    );
  }

  const canonicalPool = asAddress(canonicalPoolRaw, "factory pool", true);
  if (canonicalPool !== options.poolAddress) {
    throw new StateFault(
      "FACTORY_POOL_MISMATCH",
      "the factory-resolved pool does not match the mandate pool",
    );
  }
  const canonicalSpacing = asSafeInteger(
    canonicalSpacingRaw,
    "factory tick spacing",
  );
  if (canonicalSpacing !== poolTickSpacing) {
    throw new StateFault(
      "TICK_SPACING_MISMATCH",
      "factory and pool tick spacing do not match",
    );
  }

  const approvedForAll = asBoolean(
    approvedForAllRaw,
    "position operator approval",
  );
  const finalBlock = await getBlockByNumber(options.rpc, pinned.number);
  if (
    finalBlock.number !== pinned.number ||
    finalBlock.hash !== pinned.hash
  ) {
    throw new ReadFault("propagation");
  }

  return {
    chainId: 56,
    pin: {
      mode: options.target.mode,
      headBlockNumber: pinned.head?.toString(10) ?? null,
      observedBlockNumber: pinned.number.toString(10),
      observedBlockHash: pinned.hash,
      observedAt: pinned.timestamp.toString(10),
      confirmationDepth:
        options.target.mode === "fresh"
          ? BSC_PANCAKE_V3.confirmationDepth
          : null,
      requireCanonical: true,
      attempts: attempt,
    },
    identity: {
      registryAddress: BSC_PANCAKE_V3.erc8004Registry,
      registryCode,
      agentTokenId: options.agentTokenIdText,
      expectedProvider: options.expectedProvider,
      currentOwner: agentOwner,
      providerCode,
    },
    deployments: {
      factory: { address: BSC_PANCAKE_V3.factory, code: factoryCode },
      deployer: { address: BSC_PANCAKE_V3.deployer, code: deployerCode },
      positionManager: {
        address: options.positionManagerAddress,
        code: managerCode,
        factory: managerFactory,
        deployer: managerDeployer,
      },
    },
    pool: {
      address: options.poolAddress,
      code: poolCode,
      factory: poolFactory,
      token0: poolToken0,
      token1: poolToken1,
      fee: poolFee,
      tickSpacing: poolTickSpacing,
      sqrtPriceX96: asUnsignedDecimal(slot0[0], "sqrt price"),
      currentTick,
      observationIndex: asSafeInteger(slot0[2], "observation index"),
      observationCardinality: asSafeInteger(
        slot0[3],
        "observation cardinality",
      ),
      observationCardinalityNext: asSafeInteger(
        slot0[4],
        "next observation cardinality",
      ),
      feeProtocol: asSafeInteger(slot0[5], "fee protocol"),
      unlocked: asBoolean(slot0[6], "pool unlocked flag"),
      liquidity: poolLiquidity,
    },
    position: {
      tokenId: options.positionTokenIdText,
      owner: positionOwner,
      approved,
      caller: options.caller,
      callerApprovedForAll: approvedForAll,
      callerCanManage:
        positionOwner === options.caller ||
        approved === options.caller ||
        approvedForAll,
      nonce: asUnsignedDecimal(position[0], "position nonce"),
      operator: positionOperator,
      token0: positionToken0,
      token1: positionToken1,
      fee: positionFee,
      tickLower: positionTickLower,
      tickUpper: positionTickUpper,
      liquidity: positionLiquidity,
      feeGrowthInside0LastX128: asUnsignedDecimal(
        position[8],
        "token0 fee growth",
      ),
      feeGrowthInside1LastX128: asUnsignedDecimal(
        position[9],
        "token1 fee growth",
      ),
      tokensOwed0: asUnsignedDecimal(position[10], "tokens owed 0"),
      tokensOwed1: asUnsignedDecimal(position[11], "tokens owed 1"),
    },
    tokens: {
      token0: {
        address: poolToken0,
        code: token0Code,
        decimals: asSafeInteger(token0DecimalsRaw, "token0 decimals"),
        callerBalance: asUnsignedDecimal(token0BalanceRaw, "token0 balance"),
        callerAllowanceToPositionManager: asUnsignedDecimal(
          token0AllowanceRaw,
          "token0 allowance",
        ),
      },
      token1: {
        address: poolToken1,
        code: token1Code,
        decimals: asSafeInteger(token1DecimalsRaw, "token1 decimals"),
        callerBalance: asUnsignedDecimal(token1BalanceRaw, "token1 balance"),
        callerAllowanceToPositionManager: asUnsignedDecimal(
          token1AllowanceRaw,
          "token1 allowance",
        ),
      },
    },
  };
}

function normalizeOptions(options: VerifyPancakeStateOptions): NormalizedOptions {
  if (options.chainId !== BSC_PANCAKE_V3.chainId) {
    throw new StateFault(
      "UNSUPPORTED_CHAIN",
      "preview state verification supports BSC mainnet only",
    );
  }
  const positionManagerAddress = normalizeAddress(
    options.positionManagerAddress,
    "position manager",
  );
  if (positionManagerAddress !== BSC_PANCAKE_V3.positionManager) {
    throw new StateFault(
      "POSITION_MANAGER_NOT_CANONICAL",
      "the position manager is not the canonical BSC PancakeSwap V3 deployment",
    );
  }

  return {
    rpc: options.rpc,
    poolAddress: normalizeAddress(options.poolAddress, "pool"),
    positionManagerAddress,
    positionTokenId: parseUint256(options.positionTokenId, "position token ID"),
    positionTokenIdText: canonicalUintText(
      options.positionTokenId,
      "position token ID",
    ),
    caller: normalizeAddress(options.caller, "caller"),
    agentTokenId: parseUint256(options.agentTokenId, "agent token ID"),
    agentTokenIdText: canonicalUintText(options.agentTokenId, "agent token ID"),
    expectedProvider: normalizeAddress(
      options.expectedProvider,
      "expected provider",
    ),
    target: normalizeTarget(options.target ?? { mode: "fresh" }),
  };
}

function normalizeTarget(target: PancakeSnapshotTarget): PancakeSnapshotTarget {
  if (target.mode === "fresh") return { mode: "fresh" };
  const blockNumber = canonicalUintText(target.blockNumber, "block number");
  return {
    mode: "exact",
    blockNumber,
    blockHash: normalizeBlockHash(target.blockHash),
  };
}

async function captureBlock(options: NormalizedOptions): Promise<PinnedBlock> {
  if (options.target.mode === "exact") {
    const number = BigInt(options.target.blockNumber);
    const block = await getBlockByNumber(options.rpc, number);
    if (block.hash !== options.target.blockHash) {
      throw new ReadFault("propagation");
    }
    return { head: null, ...block };
  }

  const head = parseQuantity(
    await rpcRequest<unknown>(options.rpc, "eth_blockNumber", []),
  );
  const depth = BigInt(BSC_PANCAKE_V3.confirmationDepth);
  if (head < depth) throw new ReadFault("head-too-low");
  const block = await getBlockByNumber(options.rpc, head - depth);
  return { head, ...block };
}

async function getBlockByNumber(
  rpc: PancakeStateRpc,
  number: bigint,
): Promise<BlockHeader> {
  const raw = await rpcRequest<unknown>(rpc, "eth_getBlockByNumber", [
    toQuantity(number),
    false,
  ]);
  if (raw === null) throw new ReadFault("propagation");
  if (!isRecord(raw)) throw new ReadFault("invalid-response");
  const parsedNumber = parseQuantity(raw.number);
  if (parsedNumber !== number) throw new ReadFault("propagation");
  return {
    number: parsedNumber,
    hash: normalizeBlockHashRead(raw.hash),
    timestamp: parseQuantity(raw.timestamp),
  };
}

async function getCode(
  rpc: PancakeStateRpc,
  address: Address,
  blockSelector: Readonly<{ blockHash: Hex; requireCanonical: true }>,
): Promise<Hex> {
  const raw = await rpcRequest<unknown>(rpc, "eth_getCode", [
    address,
    blockSelector,
  ]);
  return asHexBytes(raw, "contract code");
}

async function readContract(
  rpc: PancakeStateRpc,
  address: Address,
  abi: Abi,
  functionName: string,
  args: readonly unknown[],
  blockSelector: Readonly<{ blockHash: Hex; requireCanonical: true }>,
): Promise<unknown> {
  let data: Hex;
  try {
    data = encodeFunctionData({
      abi,
      functionName,
      args,
    } as never);
  } catch {
    throw new ReadFault("invalid-response");
  }
  const raw = await rpcRequest<unknown>(rpc, "eth_call", [
    { to: address, data },
    blockSelector,
  ]);
  const result = asHexBytes(raw, "contract result");
  try {
    return decodeFunctionResult({
      abi,
      functionName,
      data: result,
    } as never);
  } catch {
    throw new ReadFault("invalid-response");
  }
}

async function rpcRequest<T>(
  rpc: PancakeStateRpc,
  method: PancakeStateRpcMethod,
  params: readonly unknown[],
): Promise<T> {
  try {
    return await rpc.request<T>({ method, params });
  } catch (error) {
    if (error instanceof PancakeStateRpcError) {
      throw new ReadFault(error.kind);
    }
    if (error instanceof ReadFault || error instanceof StateFault) throw error;
    throw new ReadFault("unavailable");
  }
}

function normalizeReadFault(error: unknown): ReadFault {
  if (error instanceof ReadFault) return error;
  return new ReadFault("unavailable");
}

function inconclusive(
  fault: ReadFault,
  attempts: number,
): PancakeStateResult {
  switch (fault.kind) {
    case "propagation":
      return {
        status: "inconclusive",
        code: "SNAPSHOT_INCONSISTENT",
        message: "a canonical pinned BSC snapshot could not be established",
        attempts,
      };
    case "chain-id-mismatch":
      return {
        status: "inconclusive",
        code: "CHAIN_ID_MISMATCH",
        message: "the RPC chain ID does not match BSC mainnet",
        attempts,
      };
    case "head-too-low":
      return {
        status: "inconclusive",
        code: "HEAD_TOO_LOW",
        message: "the BSC head cannot satisfy the fixed confirmation depth",
        attempts,
      };
    case "invalid-response":
      return {
        status: "inconclusive",
        code: "RPC_INVALID_RESPONSE",
        message: "the BSC RPC returned an invalid response",
        attempts,
      };
    default:
      return {
        status: "inconclusive",
        code: "RPC_UNAVAILABLE",
        message: "the BSC RPC was unavailable within the preview budget",
        attempts,
      };
  }
}

function summarizeCode(code: Hex): ContractCodeSummary {
  const bytes = Buffer.from(code.slice(2), "hex");
  return {
    bytes: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

function normalizeAddress(value: unknown, label: string): Address {
  if (typeof value !== "string" || !isAddress(value)) {
    throw new StateFault("INPUT_INVALID", `${label} is not an EVM address`);
  }
  const normalized = getAddress(value).toLowerCase() as Address;
  if (normalized === ZERO_ADDRESS) {
    throw new StateFault("INPUT_INVALID", `${label} must not be the zero address`);
  }
  return normalized;
}

function asAddress(
  value: unknown,
  label: string,
  allowZero = false,
): Address {
  if (typeof value !== "string" || !isAddress(value)) {
    throw new ReadFault("invalid-response");
  }
  const normalized = getAddress(value).toLowerCase() as Address;
  if (!allowZero && normalized === ZERO_ADDRESS) {
    throw new StateFault(
      "POOL_POSITION_MISMATCH",
      `${label} unexpectedly resolved to the zero address`,
    );
  }
  return normalized;
}

function canonicalUintText(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new StateFault(
      "INPUT_INVALID",
      `${label} must be a canonical unsigned decimal integer`,
    );
  }
  return value;
}

function parseUint256(value: unknown, label: string): bigint {
  const canonical = canonicalUintText(value, label);
  const parsed = BigInt(canonical);
  if (parsed >= UINT256_LIMIT) {
    throw new StateFault("INPUT_INVALID", `${label} is outside uint256`);
  }
  return parsed;
}

function asTuple(value: unknown, length: number, label: string): readonly unknown[] {
  if (!Array.isArray(value) || value.length !== length) {
    void label;
    throw new ReadFault("invalid-response");
  }
  return value;
}

function asUnsignedDecimal(value: unknown, label: string): string {
  if (typeof value !== "bigint" || value < 0n) {
    void label;
    throw new ReadFault("invalid-response");
  }
  return value.toString(10);
}

function asSafeInteger(value: unknown, label: string): number {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new ReadFault("invalid-response");
    return value;
  }
  if (typeof value !== "bigint") {
    void label;
    throw new ReadFault("invalid-response");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new ReadFault("invalid-response");
  return parsed;
}

function asBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    void label;
    throw new ReadFault("invalid-response");
  }
  return value;
}

function asHexBytes(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(value)) {
    void label;
    throw new ReadFault("invalid-response");
  }
  return value.toLowerCase() as Hex;
}

function parseQuantity(value: unknown): bigint {
  if (
    typeof value !== "string" ||
    !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value)
  ) {
    throw new ReadFault("invalid-response");
  }
  try {
    return BigInt(value);
  } catch {
    throw new ReadFault("invalid-response");
  }
}

function toQuantity(value: bigint): Hex {
  return `0x${value.toString(16)}`;
}

function normalizeBlockHash(value: unknown): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new StateFault(
      "INPUT_INVALID",
      "block hash must be a 32-byte hex value",
    );
  }
  return value.toLowerCase();
}

function normalizeBlockHashRead(value: unknown): Hex {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new ReadFault("propagation");
  }
  return value.toLowerCase() as Hex;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
