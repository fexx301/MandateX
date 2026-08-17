import { createHash } from "node:crypto";

import {
  decodeFunctionData,
  decodeFunctionResult,
  encodeFunctionData,
  encodeFunctionResult,
  type Hex,
} from "viem";

import {
  canonicalQuoteJson,
  computeQuoteSha256,
} from "../quotes/protocol.js";
import type { QuoteMandatexSignedRebalanceTask } from "../quotes/schema.js";
import {
  BSC_PREVIEW_POSITION_MANAGER,
  BSC_PREVIEW_SIMULATION_GAS,
} from "../transport/http.js";
import {
  rebalanceTransactionPlanSchema,
  type RebalancePreviewErrorCode,
  type RebalanceTransactionPlan,
} from "./schema.js";

export const BSC_PANCAKE_V3_POSITION_MANAGER =
  BSC_PREVIEW_POSITION_MANAGER;
export const PREVIEW_TRANSACTION_GAS = BSC_PREVIEW_SIMULATION_GAS;
export const PREVIEW_FINAL_BUFFER_SECONDS = 30 as const;

const MAX_UINT128 = (1n << 128n) - 1n;
const REQUIRED_CALLS = [
  "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
  "collect((uint256,address,uint128,uint128))",
  "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
] as const;

const multicallAbi = [
  {
    type: "function",
    name: "multicall",
    stateMutability: "payable",
    inputs: [{ name: "data", type: "bytes[]" }],
    outputs: [{ name: "results", type: "bytes[]" }],
  },
] as const;

const decreaseLiquidityAbi = [
  {
    type: "function",
    name: "decreaseLiquidity",
    stateMutability: "payable",
    inputs: [
      {
        name: "params",
        type: "tuple",
        components: [
          { name: "tokenId", type: "uint256" },
          { name: "liquidity", type: "uint128" },
          { name: "amount0Min", type: "uint256" },
          { name: "amount1Min", type: "uint256" },
          { name: "deadline", type: "uint256" },
        ],
      },
    ],
    outputs: [
      { name: "amount0", type: "uint256" },
      { name: "amount1", type: "uint256" },
    ],
  },
] as const;

const collectAbi = [
  {
    type: "function",
    name: "collect",
    stateMutability: "payable",
    inputs: [
      {
        name: "params",
        type: "tuple",
        components: [
          { name: "tokenId", type: "uint256" },
          { name: "recipient", type: "address" },
          { name: "amount0Max", type: "uint128" },
          { name: "amount1Max", type: "uint128" },
        ],
      },
    ],
    outputs: [
      { name: "amount0", type: "uint256" },
      { name: "amount1", type: "uint256" },
    ],
  },
] as const;

const mintAbi = [
  {
    type: "function",
    name: "mint",
    stateMutability: "payable",
    inputs: [
      {
        name: "params",
        type: "tuple",
        components: [
          { name: "token0", type: "address" },
          { name: "token1", type: "address" },
          { name: "fee", type: "uint24" },
          { name: "tickLower", type: "int24" },
          { name: "tickUpper", type: "int24" },
          { name: "amount0Desired", type: "uint256" },
          { name: "amount1Desired", type: "uint256" },
          { name: "amount0Min", type: "uint256" },
          { name: "amount1Min", type: "uint256" },
          { name: "recipient", type: "address" },
          { name: "deadline", type: "uint256" },
        ],
      },
    ],
    outputs: [
      { name: "tokenId", type: "uint256" },
      { name: "liquidity", type: "uint128" },
      { name: "amount0", type: "uint256" },
      { name: "amount1", type: "uint256" },
    ],
  },
] as const;

export type PreviewPlanErrorCode = Extract<
  RebalancePreviewErrorCode,
  | "TRANSACTION_PLAN_INVALID"
  | "POSITION_AUTHORITY_REJECTED"
  | "TRANSACTION_POLICY_REJECTED"
  | "EVM_SIMULATION_INVALID"
>;

export class PreviewPlanError extends Error {
  readonly code: PreviewPlanErrorCode;

  constructor(code: PreviewPlanErrorCode) {
    super("the transaction preview does not satisfy MandateX policy");
    this.name = "PreviewPlanError";
    this.code = code;
  }
}

export type DecodedDecreaseLiquidity = Readonly<{
  method: "decreaseLiquidity";
  tokenId: bigint;
  liquidity: bigint;
  amount0Min: bigint;
  amount1Min: bigint;
  deadline: bigint;
}>;

export type DecodedCollect = Readonly<{
  method: "collect";
  tokenId: bigint;
  recipient: string;
  amount0Max: bigint;
  amount1Max: bigint;
}>;

export type DecodedMint = Readonly<{
  method: "mint";
  token0: string;
  token1: string;
  fee: number;
  tickLower: number;
  tickUpper: number;
  amount0Desired: bigint;
  amount1Desired: bigint;
  amount0Min: bigint;
  amount1Min: bigint;
  recipient: string;
  deadline: bigint;
}>;

export type DecodedRebalancePlan = Readonly<{
  plan: RebalanceTransactionPlan;
  decrease: DecodedDecreaseLiquidity;
  collect: DecodedCollect;
  mint: DecodedMint;
  innerCalldata: readonly [Hex, Hex, Hex];
  transactionPlanSha256: string;
  calldataSha256: string;
  decodedPlanSha256: string;
}>;

export type RebalancePlanPolicyState = Readonly<{
  expectedProvider: string;
  positionOwner: string;
  approvedAddress: string;
  operatorApproved: boolean;
  positionLiquidity: string;
  positionTickLower: number;
  positionTickUpper: number;
  token0: string;
  token1: string;
  fee: number;
  currentTick: number;
}>;

export type RebalancePlanPolicyResult = Readonly<{
  authority: "owner" | "token_approval" | "operator_approval";
  deadline: number;
  calls: readonly [
    Readonly<{ method: "decreaseLiquidity"; tokenId: string; deadline: number }>,
    Readonly<{ method: "collect"; tokenId: string; recipient: string }>,
    Readonly<{
      method: "mint";
      lowerTick: number;
      upperTick: number;
      recipient: string;
      deadline: number;
    }>,
  ];
}>;

export type DecodedSimulationResult = Readonly<{
  simulationResultSha256: string;
  mintedTokenId: string;
  mintedLiquidity: string;
}>;

export function decodeRebalanceTransactionPlan(
  input: unknown,
): DecodedRebalancePlan {
  const parsed = rebalanceTransactionPlanSchema.safeParse(input);
  if (!parsed.success) throw new PreviewPlanError("TRANSACTION_PLAN_INVALID");
  const plan = parsed.data;
  if (
    plan.to !== BSC_PANCAKE_V3_POSITION_MANAGER ||
    plan.valueWei !== "0"
  ) {
    throw new PreviewPlanError("TRANSACTION_PLAN_INVALID");
  }

  let innerCalldata: readonly Hex[];
  try {
    const outer = decodeFunctionData({
      abi: multicallAbi,
      data: plan.data as Hex,
    });
    if (outer.functionName !== "multicall" || outer.args.length !== 1) {
      throw new Error("unexpected outer call");
    }
    innerCalldata = outer.args[0];
    const reencoded = encodeFunctionData({
      abi: multicallAbi,
      functionName: "multicall",
      args: [innerCalldata],
    });
    if (reencoded.toLowerCase() !== plan.data) {
      throw new Error("non-canonical calldata");
    }
  } catch {
    throw new PreviewPlanError("TRANSACTION_PLAN_INVALID");
  }
  if (innerCalldata.length !== 3) {
    throw new PreviewPlanError("TRANSACTION_PLAN_INVALID");
  }

  const decrease = decodeDecrease(innerCalldata[0]!);
  const collect = decodeCollect(innerCalldata[1]!);
  const mint = decodeMint(innerCalldata[2]!);
  const normalized = normalizedDecodedPlan(plan, decrease, collect, mint);

  return {
    plan,
    decrease,
    collect,
    mint,
    innerCalldata: [innerCalldata[0]!, innerCalldata[1]!, innerCalldata[2]!],
    transactionPlanSha256: computeQuoteSha256(canonicalQuoteJson(plan)),
    calldataSha256: createHash("sha256")
      .update(Buffer.from(plan.data.slice(2), "hex"))
      .digest("hex"),
    decodedPlanSha256: computeQuoteSha256(canonicalQuoteJson(normalized)),
  };
}

export function validateRebalancePlanPolicy(input: {
  decoded: DecodedRebalancePlan;
  task: QuoteMandatexSignedRebalanceTask;
  state: RebalancePlanPolicyState;
  quoteExpiresAt: number;
  now: Date;
}): RebalancePlanPolicyResult {
  const { decoded, task, state } = input;
  const provider = state.expectedProvider.toLowerCase();
  if (decoded.plan.from !== provider) {
    throw new PreviewPlanError("POSITION_AUTHORITY_REJECTED");
  }

  let authority: RebalancePlanPolicyResult["authority"];
  if (state.positionOwner.toLowerCase() === provider) {
    authority = "owner";
  } else if (state.approvedAddress.toLowerCase() === provider) {
    authority = "token_approval";
  } else if (state.operatorApproved) {
    authority = "operator_approval";
  } else {
    throw new PreviewPlanError("POSITION_AUTHORITY_REJECTED");
  }

  const mandate = task.mandate;
  const proposal = task.proposal;
  if (
    !mandate.permissions.allowed_contracts.includes(decoded.plan.to) ||
    REQUIRED_CALLS.some(
      (call) => !mandate.permissions.allowed_calls.includes(call),
    ) ||
    decoded.decrease.tokenId.toString() !== mandate.position.token_id ||
    decoded.collect.tokenId !== decoded.decrease.tokenId ||
    decoded.decrease.liquidity.toString() !== state.positionLiquidity ||
    decoded.collect.recipient !== provider ||
    decoded.collect.amount0Max !== MAX_UINT128 ||
    decoded.collect.amount1Max !== MAX_UINT128 ||
    decoded.mint.token0 !== state.token0.toLowerCase() ||
    decoded.mint.token1 !== state.token1.toLowerCase() ||
    decoded.mint.fee !== state.fee ||
    decoded.mint.tickLower !== proposal.proposed_lower_tick ||
    decoded.mint.tickUpper !== proposal.proposed_upper_tick ||
    decoded.mint.recipient !== provider ||
    decoded.decrease.deadline !== decoded.mint.deadline ||
    (decoded.mint.amount0Desired === 0n &&
      decoded.mint.amount1Desired === 0n)
  ) {
    throw new PreviewPlanError("TRANSACTION_POLICY_REJECTED");
  }

  assertSlippage(
    decoded.mint.amount0Desired,
    decoded.mint.amount0Min,
    mandate.limits.max_slippage_bps,
  );
  assertSlippage(
    decoded.mint.amount1Desired,
    decoded.mint.amount1Min,
    mandate.limits.max_slippage_bps,
  );

  const deadline = decoded.mint.deadline;
  const nowMilliseconds = BigInt(input.now.valueOf());
  const maximumDeadline = BigInt(
    Math.min(
      input.quoteExpiresAt,
      mandate.expires_at,
      mandate.permissions.expires_at,
      proposal.permissions.expires_at,
    ),
  );
  if (
    deadline * 1_000n <
      nowMilliseconds + BigInt(PREVIEW_FINAL_BUFFER_SECONDS * 1_000) ||
    deadline > maximumDeadline ||
    deadline > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new PreviewPlanError("TRANSACTION_POLICY_REJECTED");
  }

  const drift = Math.abs(state.currentTick - task.evidence.current_tick);
  const outsidePosition =
    state.currentTick < state.positionTickLower ||
    state.currentTick >= state.positionTickUpper;
  const boundaryDistance = outsidePosition
    ? 0
    : Math.min(
        state.currentTick - state.positionTickLower,
        state.positionTickUpper - state.currentTick,
      );
  const triggerStillFires =
    outsidePosition ||
    (mandate.range_policy.trigger_mode === "boundary_proximity" &&
      boundaryDistance <= mandate.range_policy.trigger_distance_ticks);
  if (
    drift > mandate.range_policy.max_delivery_tick_drift ||
    !triggerStillFires ||
    state.currentTick < decoded.mint.tickLower ||
    state.currentTick >= decoded.mint.tickUpper
  ) {
    throw new PreviewPlanError("TRANSACTION_POLICY_REJECTED");
  }

  return {
    authority,
    deadline: Number(deadline),
    calls: [
      {
        method: "decreaseLiquidity",
        tokenId: decoded.decrease.tokenId.toString(),
        deadline: Number(deadline),
      },
      {
        method: "collect",
        tokenId: decoded.collect.tokenId.toString(),
        recipient: decoded.collect.recipient,
      },
      {
        method: "mint",
        lowerTick: decoded.mint.tickLower,
        upperTick: decoded.mint.tickUpper,
        recipient: decoded.mint.recipient,
        deadline: Number(deadline),
      },
    ],
  };
}

export function decodeRebalanceSimulationResult(input: {
  rawResult: Hex;
  decoded: DecodedRebalancePlan;
  maxSlippageBps: number;
}): DecodedSimulationResult {
  let results: readonly Hex[];
  try {
    results = decodeFunctionResult({
      abi: multicallAbi,
      functionName: "multicall",
      data: input.rawResult,
    });
    const reencoded = encodeFunctionResult({
      abi: multicallAbi,
      functionName: "multicall",
      result: results,
    });
    if (reencoded !== input.rawResult) throw new Error("non-canonical result");
  } catch {
    throw new PreviewPlanError("EVM_SIMULATION_INVALID");
  }
  if (results.length !== 3) {
    throw new PreviewPlanError("EVM_SIMULATION_INVALID");
  }

  try {
    const decreased = decodeFunctionResult({
      abi: decreaseLiquidityAbi,
      functionName: "decreaseLiquidity",
      data: results[0]!,
    });
    const collected = decodeFunctionResult({
      abi: collectAbi,
      functionName: "collect",
      data: results[1]!,
    });
    const minted = decodeFunctionResult({
      abi: mintAbi,
      functionName: "mint",
      data: results[2]!,
    });
    const canonicalDecrease = encodeFunctionResult({
      abi: decreaseLiquidityAbi,
      functionName: "decreaseLiquidity",
      result: decreased,
    });
    const canonicalCollect = encodeFunctionResult({
      abi: collectAbi,
      functionName: "collect",
      result: collected,
    });
    const canonicalMint = encodeFunctionResult({
      abi: mintAbi,
      functionName: "mint",
      result: minted,
    });
    if (
      canonicalDecrease !== results[0] ||
      canonicalCollect !== results[1] ||
      canonicalMint !== results[2]
    ) {
      throw new Error("non-canonical inner result");
    }
    const [mintedTokenId, mintedLiquidity, amount0, amount1] = minted;
    assertResultSlippage(
      decreased[0],
      input.decoded.decrease.amount0Min,
      input.maxSlippageBps,
    );
    assertResultSlippage(
      decreased[1],
      input.decoded.decrease.amount1Min,
      input.maxSlippageBps,
    );
    if (
      mintedLiquidity === 0n ||
      mintedTokenId === input.decoded.decrease.tokenId ||
      amount0 > input.decoded.mint.amount0Desired ||
      amount1 > input.decoded.mint.amount1Desired ||
      amount0 < input.decoded.mint.amount0Min ||
      amount1 < input.decoded.mint.amount1Min ||
      amount0 > collected[0] ||
      amount1 > collected[1]
    ) {
      throw new Error("simulation result violates policy");
    }
    return {
      simulationResultSha256: createHash("sha256")
        .update(Buffer.from(input.rawResult.slice(2), "hex"))
        .digest("hex"),
      mintedTokenId: mintedTokenId.toString(),
      mintedLiquidity: mintedLiquidity.toString(),
    };
  } catch (error) {
    if (error instanceof PreviewPlanError) throw error;
    throw new PreviewPlanError("EVM_SIMULATION_INVALID");
  }
}

function assertResultSlippage(
  actual: bigint,
  minimum: bigint,
  maxSlippageBps: number,
): void {
  if (
    minimum > actual ||
    (actual === 0n && minimum !== 0n) ||
    (actual > 0n &&
      (actual - minimum) * 10_000n > actual * BigInt(maxSlippageBps))
  ) {
    throw new PreviewPlanError("EVM_SIMULATION_INVALID");
  }
}

function decodeDecrease(data: Hex): DecodedDecreaseLiquidity {
  try {
    const decoded = decodeFunctionData({ abi: decreaseLiquidityAbi, data });
    const params = decoded.args[0];
    const reencoded = encodeFunctionData({
      abi: decreaseLiquidityAbi,
      functionName: "decreaseLiquidity",
      args: [params],
    });
    if (reencoded.toLowerCase() !== data.toLowerCase()) throw new Error();
    return { method: "decreaseLiquidity", ...params };
  } catch {
    throw new PreviewPlanError("TRANSACTION_PLAN_INVALID");
  }
}

function decodeCollect(data: Hex): DecodedCollect {
  try {
    const decoded = decodeFunctionData({ abi: collectAbi, data });
    const params = decoded.args[0];
    const reencoded = encodeFunctionData({
      abi: collectAbi,
      functionName: "collect",
      args: [params],
    });
    if (reencoded.toLowerCase() !== data.toLowerCase()) throw new Error();
    return {
      method: "collect",
      tokenId: params.tokenId,
      recipient: params.recipient.toLowerCase(),
      amount0Max: params.amount0Max,
      amount1Max: params.amount1Max,
    };
  } catch {
    throw new PreviewPlanError("TRANSACTION_PLAN_INVALID");
  }
}

function decodeMint(data: Hex): DecodedMint {
  try {
    const decoded = decodeFunctionData({ abi: mintAbi, data });
    const params = decoded.args[0];
    const reencoded = encodeFunctionData({
      abi: mintAbi,
      functionName: "mint",
      args: [params],
    });
    if (reencoded.toLowerCase() !== data.toLowerCase()) throw new Error();
    return {
      method: "mint",
      ...params,
      token0: params.token0.toLowerCase(),
      token1: params.token1.toLowerCase(),
      recipient: params.recipient.toLowerCase(),
    };
  } catch {
    throw new PreviewPlanError("TRANSACTION_PLAN_INVALID");
  }
}

function assertSlippage(
  desired: bigint,
  minimum: bigint,
  maxSlippageBps: number,
): void {
  if (
    minimum > desired ||
    (desired === 0n && minimum !== 0n) ||
    (desired > 0n &&
      (desired - minimum) * 10_000n > desired * BigInt(maxSlippageBps))
  ) {
    throw new PreviewPlanError("TRANSACTION_POLICY_REJECTED");
  }
}

function normalizedDecodedPlan(
  plan: RebalanceTransactionPlan,
  decrease: DecodedDecreaseLiquidity,
  collect: DecodedCollect,
  mint: DecodedMint,
): unknown {
  return {
    chainId: plan.chainId,
    from: plan.from,
    to: plan.to,
    valueWei: plan.valueWei,
    calls: [
      {
        method: decrease.method,
        tokenId: decrease.tokenId.toString(),
        liquidity: decrease.liquidity.toString(),
        amount0Min: decrease.amount0Min.toString(),
        amount1Min: decrease.amount1Min.toString(),
        deadline: decrease.deadline.toString(),
      },
      {
        method: collect.method,
        tokenId: collect.tokenId.toString(),
        recipient: collect.recipient,
        amount0Max: collect.amount0Max.toString(),
        amount1Max: collect.amount1Max.toString(),
      },
      {
        method: mint.method,
        token0: mint.token0,
        token1: mint.token1,
        fee: mint.fee,
        tickLower: mint.tickLower,
        tickUpper: mint.tickUpper,
        amount0Desired: mint.amount0Desired.toString(),
        amount1Desired: mint.amount1Desired.toString(),
        amount0Min: mint.amount0Min.toString(),
        amount1Min: mint.amount1Min.toString(),
        recipient: mint.recipient,
        deadline: mint.deadline.toString(),
      },
    ],
  };
}

export const previewMulticallAbi = multicallAbi;
export const previewDecreaseLiquidityAbi = decreaseLiquidityAbi;
export const previewCollectAbi = collectAbi;
export const previewMintAbi = mintAbi;
