import assert from "node:assert/strict";
import test from "node:test";

import {
  encodeFunctionData,
  encodeFunctionResult,
  type Hex,
} from "viem";

import { quoteMandatexSignedRebalanceTaskSchema } from "../src/quotes/schema.js";
import {
  BSC_PANCAKE_V3_POSITION_MANAGER,
  decodeRebalanceSimulationResult,
  decodeRebalanceTransactionPlan,
  PreviewPlanError,
  previewCollectAbi,
  previewDecreaseLiquidityAbi,
  previewMintAbi,
  previewMulticallAbi,
  validateRebalancePlanPolicy,
} from "../src/preview/plan.js";

const PROVIDER = "0x1111111111111111111111111111111111111111";
const POOL = "0x2222222222222222222222222222222222222222";
const TOKEN0 = "0x3333333333333333333333333333333333333333";
const TOKEN1 = "0x4444444444444444444444444444444444444444";
const ZERO = "0x0000000000000000000000000000000000000000";
const NOW_SECONDS = 1_800_000_000;
const DEADLINE = BigInt(NOW_SECONDS + 300);
const MAX_UINT128 = (1n << 128n) - 1n;

test("decodes, binds, and verifies one exact zero-value rebalance simulation", () => {
  const decoded = decodeRebalanceTransactionPlan(plan());
  const policy = validateRebalancePlanPolicy({
    decoded,
    task: task(),
    state: state(),
    quoteExpiresAt: NOW_SECONDS + 600,
    now: new Date(NOW_SECONDS * 1_000),
  });
  const simulation = decodeRebalanceSimulationResult({
    decoded,
    rawResult: simulationResult({ collected0: 1_000n, collected1: 2_000n }),
    maxSlippageBps: 100,
  });

  assert.equal(policy.authority, "owner");
  assert.equal(policy.calls.length, 3);
  assert.equal(decoded.transactionPlanSha256.length, 64);
  assert.equal(decoded.calldataSha256.length, 64);
  assert.equal(decoded.decodedPlanSha256.length, 64);
  assert.equal(simulation.mintedLiquidity, "500");
  assert.equal(simulation.simulationResultSha256.length, 64);
});

test("rejects nonzero value, noncanonical target, and additional calls", () => {
  assertPlanError(
    () => decodeRebalanceTransactionPlan({ ...plan(), valueWei: "1" }),
    "TRANSACTION_PLAN_INVALID",
  );
  assertPlanError(
    () =>
      decodeRebalanceTransactionPlan({
        ...plan(),
        to: "0x5555555555555555555555555555555555555555",
      }),
    "TRANSACTION_PLAN_INVALID",
  );
  const calls = innerCalls();
  assertPlanError(
    () =>
      decodeRebalanceTransactionPlan(
        plan([calls[0], calls[1], calls[2], calls[2]]),
      ),
    "TRANSACTION_PLAN_INVALID",
  );
  assertPlanError(
    () =>
      decodeRebalanceTransactionPlan({
        ...plan(),
        from: PROVIDER.toUpperCase(),
      }),
    "TRANSACTION_PLAN_INVALID",
  );
  assertPlanError(
    () => decodeRebalanceTransactionPlan({ ...plan(), unexpected: true }),
    "TRANSACTION_PLAN_INVALID",
  );
});

test("rejects wrong call order and trailing calldata", () => {
  const calls = innerCalls();
  assertPlanError(
    () => decodeRebalanceTransactionPlan(plan([calls[1], calls[0], calls[2]])),
    "TRANSACTION_PLAN_INVALID",
  );
  const valid = plan();
  assertPlanError(
    () =>
      decodeRebalanceTransactionPlan({ ...valid, data: `${valid.data}00` }),
    "TRANSACTION_PLAN_INVALID",
  );
});

test("requires the verified provider to own or operate the position", () => {
  const decoded = decodeRebalanceTransactionPlan(plan());
  assertPlanError(
    () =>
      validateRebalancePlanPolicy({
        decoded,
        task: task(),
        state: {
          ...state(),
          positionOwner: "0x5555555555555555555555555555555555555555",
          approvedAddress: ZERO,
          operatorApproved: false,
        },
        quoteExpiresAt: NOW_SECONDS + 600,
        now: new Date(NOW_SECONDS * 1_000),
      }),
    "POSITION_AUTHORITY_REJECTED",
  );
});

test("requires full liquidity and the exact quoted token tuple and range", () => {
  const decoded = decodeRebalanceTransactionPlan(plan());
  assertPlanError(
    () =>
      validateRebalancePlanPolicy({
        decoded,
        task: task(),
        state: { ...state(), positionLiquidity: "1001" },
        quoteExpiresAt: NOW_SECONDS + 600,
        now: new Date(NOW_SECONDS * 1_000),
      }),
    "TRANSACTION_POLICY_REJECTED",
  );

  const changed = innerCalls({ mintTickUpper: 240 });
  assertPlanError(
    () =>
      validateRebalancePlanPolicy({
        decoded: decodeRebalanceTransactionPlan(plan(changed)),
        task: task(),
        state: state(),
        quoteExpiresAt: NOW_SECONDS + 600,
        now: new Date(NOW_SECONDS * 1_000),
      }),
    "TRANSACTION_POLICY_REJECTED",
  );
});

test("rejects deadlines outside the final buffer and min amounts beyond slippage", () => {
  const nearDeadline = innerCalls({ deadline: BigInt(NOW_SECONDS + 29) });
  assertPlanError(
    () =>
      validateRebalancePlanPolicy({
        decoded: decodeRebalanceTransactionPlan(plan(nearDeadline)),
        task: task(),
        state: state(),
        quoteExpiresAt: NOW_SECONDS + 600,
        now: new Date(NOW_SECONDS * 1_000),
      }),
    "TRANSACTION_POLICY_REJECTED",
  );

  const exactSecondDeadline = innerCalls({
    deadline: BigInt(NOW_SECONDS + 30),
  });
  assertPlanError(
    () =>
      validateRebalancePlanPolicy({
        decoded: decodeRebalanceTransactionPlan(plan(exactSecondDeadline)),
        task: task(),
        state: state(),
        quoteExpiresAt: NOW_SECONDS + 600,
        now: new Date(NOW_SECONDS * 1_000 + 1),
      }),
    "TRANSACTION_POLICY_REJECTED",
  );

  const looseMinimum = innerCalls({ mintAmount0Min: 800n });
  assertPlanError(
    () =>
      validateRebalancePlanPolicy({
        decoded: decodeRebalanceTransactionPlan(plan(looseMinimum)),
        task: task(),
        state: state(),
        quoteExpiresAt: NOW_SECONDS + 600,
        now: new Date(NOW_SECONDS * 1_000),
      }),
    "TRANSACTION_POLICY_REJECTED",
  );
});

test("rejects malformed results and incremental token spend", () => {
  const decoded = decodeRebalanceTransactionPlan(plan());
  assertPlanError(
    () =>
      decodeRebalanceSimulationResult({
        decoded,
        rawResult: "0x1234",
        maxSlippageBps: 100,
      }),
    "EVM_SIMULATION_INVALID",
  );
  assertPlanError(
    () =>
      decodeRebalanceSimulationResult({
        decoded,
        rawResult: simulationResult({ collected0: 900n, collected1: 2_000n }),
        maxSlippageBps: 100,
      }),
    "EVM_SIMULATION_INVALID",
  );
  const looseDecrease = decodeRebalanceTransactionPlan(
    plan(innerCalls({ decreaseAmount0Min: 800n })),
  );
  assertPlanError(
    () =>
      decodeRebalanceSimulationResult({
        decoded: looseDecrease,
        rawResult: simulationResult({ collected0: 1_000n, collected1: 2_000n }),
        maxSlippageBps: 100,
      }),
    "EVM_SIMULATION_INVALID",
  );
});

test("rejects noncanonical outer and inner simulation result bytes", () => {
  const decoded = decodeRebalanceTransactionPlan(plan());
  const canonical = simulationResult({ collected0: 1_000n, collected1: 2_000n });
  assertPlanError(
    () =>
      decodeRebalanceSimulationResult({
        decoded,
        rawResult: `${canonical}00` as Hex,
        maxSlippageBps: 100,
      }),
    "EVM_SIMULATION_INVALID",
  );
  assertPlanError(
    () =>
      decodeRebalanceSimulationResult({
        decoded,
        rawResult: simulationResult({
          collected0: 1_000n,
          collected1: 2_000n,
          decreaseSuffix: "00",
        }),
        maxSlippageBps: 100,
      }),
    "EVM_SIMULATION_INVALID",
  );
});

function plan(calls: readonly Hex[] = innerCalls()) {
  return {
    schema: "mandatex.rebalance.transaction-plan.v1" as const,
    chainId: 56 as const,
    from: PROVIDER,
    to: BSC_PANCAKE_V3_POSITION_MANAGER,
    valueWei: "0",
    data: encodeFunctionData({
      abi: previewMulticallAbi,
      functionName: "multicall",
      args: [calls],
    }),
  };
}

function innerCalls(
  options: {
    deadline?: bigint;
    decreaseAmount0Min?: bigint;
    mintTickUpper?: number;
    mintAmount0Min?: bigint;
  } = {},
): [Hex, Hex, Hex] {
  const deadline = options.deadline ?? DEADLINE;
  return [
    encodeFunctionData({
      abi: previewDecreaseLiquidityAbi,
      functionName: "decreaseLiquidity",
      args: [
        {
          tokenId: 7n,
          liquidity: 1_000n,
          amount0Min: options.decreaseAmount0Min ?? 891n,
          amount1Min: 1_782n,
          deadline,
        },
      ],
    }),
    encodeFunctionData({
      abi: previewCollectAbi,
      functionName: "collect",
      args: [
        {
          tokenId: 7n,
          recipient: PROVIDER,
          amount0Max: MAX_UINT128,
          amount1Max: MAX_UINT128,
        },
      ],
    }),
    encodeFunctionData({
      abi: previewMintAbi,
      functionName: "mint",
      args: [
        {
          token0: TOKEN0,
          token1: TOKEN1,
          fee: 500,
          tickLower: 60,
          tickUpper: options.mintTickUpper ?? 180,
          amount0Desired: 1_000n,
          amount1Desired: 2_000n,
          amount0Min: options.mintAmount0Min ?? 990n,
          amount1Min: 1_980n,
          recipient: PROVIDER,
          deadline,
        },
      ],
    }),
  ];
}

function task() {
  return quoteMandatexSignedRebalanceTaskSchema.parse({
    schema: "mandatex.rebalance.quote.v1",
    mandate: {
      version: "1",
      mandate_id: "preview-plan-test",
      category: "rebalancing",
      chain_id: 56,
      protocol: "pancakeswap-v3",
      expires_at: NOW_SECONDS + 900,
      max_evidence_age_seconds: 120,
      position: {
        pool_address: POOL,
        position_manager_address: BSC_PANCAKE_V3_POSITION_MANAGER,
        token_id: "7",
      },
      range_policy: {
        approved_lower_tick: -600,
        approved_upper_tick: 600,
        target_width_ticks: 120,
        trigger_mode: "boundary_proximity",
        trigger_distance_ticks: 30,
        max_delivery_tick_drift: 20,
      },
      limits: {
        max_gas_usd: 5,
        max_slippage_bps: 100,
        max_exposure_usd: 1_000,
      },
      execution_estimate: {
        gas_usd: 1,
        slippage_bps: 50,
        exposure_usd: 500,
        observed_at: NOW_SECONDS,
        source_url: "https://oracle.example/estimate",
      },
      permissions: {
        allowed_contracts: [BSC_PANCAKE_V3_POSITION_MANAGER],
        allowed_calls: [
          "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
          "collect((uint256,address,uint128,uint128))",
          "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
        ],
        spend_cap_usd: 1_000,
        expires_at: NOW_SECONDS + 800,
      },
    },
    evidence: {
      network: "bsc-mainnet",
      chain_id: 56,
      snapshot_head_block: 102,
      confirmation_depth_blocks: 2,
      observed_block: 100,
      observed_block_hash: `0x${"a".repeat(64)}`,
      observed_at: NOW_SECONDS,
      pool_address: POOL,
      position_manager_address: BSC_PANCAKE_V3_POSITION_MANAGER,
      position_token_id: "7",
      position_owner: PROVIDER,
      token0: TOKEN0,
      token1: TOKEN1,
      token0_decimals: 18,
      token1_decimals: 18,
      fee: 500,
      tick_spacing: 60,
      current_tick: 120,
      sqrt_price_x96: "1",
      approximate_token1_per_token0: null,
      position_tick_lower: 120,
      position_tick_upper: 240,
      pool_liquidity: "10000",
      position_liquidity: "1000",
      sources: [
        {
          type: "onchain",
          url: "https://bscscan.com/block/100",
          observed_block: 100,
        },
      ],
    },
    proposal: {
      execution_mode: "simulation",
      proposed_lower_tick: 60,
      proposed_upper_tick: 180,
      trigger: {
        fired: true,
        reason: "near_range_boundary",
        distance_to_boundary_ticks: 0,
      },
      estimated_gas_usd: 1,
      estimated_slippage_bps: 50,
      estimated_exposure_usd: 500,
      estimate_source_url: "https://oracle.example/estimate",
      permissions: {
        contracts: [BSC_PANCAKE_V3_POSITION_MANAGER],
        calls: [
          "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
          "collect((uint256,address,uint128,uint128))",
          "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
        ],
        spend_cap_usd: 1_000,
        expires_at: NOW_SECONDS + 800,
      },
      break_even: { status: "not_calculated", reason: "not priced" },
    },
    eligibility: {
      eligible: true,
      checked_at: NOW_SECONDS,
      checks: ["policy"],
    },
  });
}

function state() {
  return {
    expectedProvider: PROVIDER,
    positionOwner: PROVIDER,
    approvedAddress: ZERO,
    operatorApproved: false,
    positionLiquidity: "1000",
    positionTickLower: 120,
    positionTickUpper: 240,
    token0: TOKEN0,
    token1: TOKEN1,
    fee: 500,
    currentTick: 120,
  };
}

function simulationResult(options: {
  collected0: bigint;
  collected1: bigint;
  decreaseSuffix?: string;
}): Hex {
  const decrease = encodeFunctionResult({
    abi: previewDecreaseLiquidityAbi,
    functionName: "decreaseLiquidity",
    result: [900n, 1_800n],
  });
  const collect = encodeFunctionResult({
    abi: previewCollectAbi,
    functionName: "collect",
    result: [options.collected0, options.collected1],
  });
  const mint = encodeFunctionResult({
    abi: previewMintAbi,
    functionName: "mint",
    result: [8n, 500n, 1_000n, 2_000n],
  });
  return encodeFunctionResult({
    abi: previewMulticallAbi,
    functionName: "multicall",
    result: [
      `${decrease}${options.decreaseSuffix ?? ""}` as Hex,
      collect,
      mint,
    ],
  });
}

function assertPlanError(
  fn: () => unknown,
  code: PreviewPlanError["code"],
): void {
  assert.throws(
    fn,
    (error: unknown) => error instanceof PreviewPlanError && error.code === code,
  );
}
