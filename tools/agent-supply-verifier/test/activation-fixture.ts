import { deflateRawSync } from "node:zlib";

import { buildJobDescription } from "@bnbagent/sdk/erc8183";

import {
  activationBindingSchema,
  activationDeploymentObservationSchema,
  activationJobObservationSchema,
  activationPreviewSchema,
  activationReceiptSchema,
  type ActivationDeploymentObservation,
  type ActivationJobObservation,
  type ActivationReceipt,
  type ActivationState,
} from "../src/activation/schema.js";
import { BSC_ACTIVATION_DEPLOYMENT } from "../src/activation/deployment.js";
import { prepareCreateActivation } from "../src/activation/state.js";
import {
  canonicalQuoteJson,
  computeQuoteSha256,
} from "../src/quotes/protocol.js";
import { quoteMandatexSignedRebalanceTaskSchema } from "../src/quotes/schema.js";
import { rebalanceTransactionPlanSchema } from "../src/preview/schema.js";

export const ACTIVATION_NOW = 1_700_000_000;
export const ACTIVATION_CLIENT = "0x1111111111111111111111111111111111111111";
export const ACTIVATION_PROVIDER = "0x2222222222222222222222222222222222222222";
export const ACTIVATION_POOL = "0x3333333333333333333333333333333333333333";
export const ACTIVATION_MANAGER = "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364";
export const ACTIVATION_TOKEN0 = "0x4444444444444444444444444444444444444444";
export const ACTIVATION_TOKEN1 = "0x5555555555555555555555555555555555555555";
export const ACTIVATION_JOB_ID = "7";
export const ACTIVATION_JOB_EXPIRES_AT = ACTIVATION_NOW + 3_600;

const REQUIRED_CALLS = [
  "collect((uint256,address,uint128,uint128))",
  "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
  "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
] as const;

export function activationSignedTask() {
  return quoteMandatexSignedRebalanceTaskSchema.parse({
    schema: "mandatex.rebalance.quote.v1",
    mandate: {
      version: "1",
      mandate_id: "activation-fixture",
      category: "rebalancing",
      chain_id: 56,
      protocol: "pancakeswap-v3",
      expires_at: ACTIVATION_NOW + 800,
      max_evidence_age_seconds: 120,
      position: {
        pool_address: ACTIVATION_POOL,
        position_manager_address: ACTIVATION_MANAGER,
        token_id: "9",
      },
      range_policy: {
        approved_lower_tick: -400,
        approved_upper_tick: 400,
        target_width_ticks: 200,
        trigger_mode: "boundary_proximity",
        trigger_distance_ticks: 20,
        max_delivery_tick_drift: 10,
      },
      limits: {
        max_gas_usd: 10,
        max_slippage_bps: 50,
        max_exposure_usd: 1_000,
      },
      execution_estimate: {
        gas_usd: 5,
        slippage_bps: 20,
        exposure_usd: 500,
        observed_at: ACTIVATION_NOW - 20,
        source_url: "https://evidence.example/estimate",
      },
      permissions: {
        allowed_contracts: [ACTIVATION_MANAGER],
        allowed_calls: REQUIRED_CALLS,
        spend_cap_usd: 500,
        expires_at: ACTIVATION_NOW + 800,
      },
    },
    evidence: {
      network: "bsc-mainnet",
      chain_id: 56,
      snapshot_head_block: 100,
      confirmation_depth_blocks: 2,
      observed_block: 98,
      observed_block_hash: `0x${"9".repeat(64)}`,
      observed_at: ACTIVATION_NOW - 20,
      pool_address: ACTIVATION_POOL,
      position_manager_address: ACTIVATION_MANAGER,
      position_token_id: "9",
      position_owner: ACTIVATION_PROVIDER,
      token0: ACTIVATION_TOKEN0,
      token1: ACTIVATION_TOKEN1,
      token0_decimals: 18,
      token1_decimals: 18,
      fee: 500,
      tick_spacing: 10,
      current_tick: 95,
      sqrt_price_x96: "79228162514264337593543950336",
      approximate_token1_per_token0: "1",
      position_tick_lower: -100,
      position_tick_upper: 100,
      pool_liquidity: "1000000",
      position_liquidity: "1000",
      sources: [
        {
          type: "onchain",
          url: "https://bscscan.com/block/98",
          observed_block: 98,
        },
      ],
    },
    proposal: {
      execution_mode: "simulation",
      proposed_lower_tick: 0,
      proposed_upper_tick: 200,
      trigger: {
        fired: true,
        reason: "near_range_boundary",
        distance_to_boundary_ticks: 5,
      },
      estimated_gas_usd: 5,
      estimated_slippage_bps: 20,
      estimated_exposure_usd: 500,
      estimate_source_url: "https://evidence.example/estimate",
      permissions: {
        contracts: [ACTIVATION_MANAGER],
        calls: REQUIRED_CALLS,
        spend_cap_usd: 500,
        expires_at: ACTIVATION_NOW + 800,
      },
      break_even: {
        status: "not_calculated",
        reason: "not required for activation fixture",
      },
    },
    eligibility: {
      eligible: true,
      checked_at: ACTIVATION_NOW - 10,
      checks: ["range", "permissions"],
    },
  });
}

export function activationTransactionPlan() {
  return rebalanceTransactionPlanSchema.parse({
    schema: "mandatex.rebalance.transaction-plan.v1",
    chainId: 56,
    from: ACTIVATION_PROVIDER,
    to: ACTIVATION_MANAGER,
    valueWei: "0",
    data: "0x1234",
  });
}

export function activationPreview(input: Readonly<{
  blockNumber?: string;
  blockHash?: string;
  blockTimestamp?: number;
  validUntil?: number;
}> = {}) {
  const signedTask = activationSignedTask();
  const transactionPlan = activationTransactionPlan();
  const blockTimestamp = input.blockTimestamp ?? ACTIVATION_NOW;
  return activationPreviewSchema.parse({
    schema: "mandatex.erc8183.activation-preview.v1",
    observedAt: new Date(blockTimestamp * 1_000).toISOString(),
    blockNumber: input.blockNumber ?? "100",
    blockHash: input.blockHash ?? `0x${"a".repeat(64)}`,
    blockTimestamp,
    quoteExpiresAt: ACTIVATION_NOW + 800,
    transactionPlanSha256: computeQuoteSha256(
      canonicalQuoteJson(transactionPlan),
    ),
    signedTaskSha256: computeQuoteSha256(canonicalQuoteJson(signedTask)),
    allGatesPass: true,
    validUntil: input.validUntil ?? ACTIVATION_NOW + 600,
  });
}

export function activationDeployment(input: Readonly<{
  blockNumber?: string;
  blockTimestamp?: number;
  blockHash?: string;
}> = {}): ActivationDeploymentObservation {
  const blockNumber = input.blockNumber ?? "101";
  return activationDeploymentObservationSchema.parse({
    chainId: 56,
    headBlockNumber: (BigInt(blockNumber) + 2n).toString(),
    blockNumber,
    blockHash: input.blockHash ?? `0x${"b".repeat(64)}`,
    blockTimestamp: input.blockTimestamp ?? ACTIVATION_NOW + 5,
    confirmationDepth: 2,
    commerceImplementation: BSC_ACTIVATION_DEPLOYMENT.commerceImplementation,
    commerceProxyCodeHash: BSC_ACTIVATION_DEPLOYMENT.commerceProxyCodeHash,
    commerceImplementationCodeHash:
      BSC_ACTIVATION_DEPLOYMENT.commerceImplementationCodeHash,
    routerImplementation: BSC_ACTIVATION_DEPLOYMENT.routerImplementation,
    routerProxyCodeHash: BSC_ACTIVATION_DEPLOYMENT.routerProxyCodeHash,
    routerImplementationCodeHash:
      BSC_ACTIVATION_DEPLOYMENT.routerImplementationCodeHash,
    policyCodeHash: BSC_ACTIVATION_DEPLOYMENT.policyCodeHash,
    paymentToken: BSC_ACTIVATION_DEPLOYMENT.paymentToken,
    paymentTokenCodeHash: BSC_ACTIVATION_DEPLOYMENT.paymentTokenCodeHash,
    routerCommerce: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
    policyCommerce: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
    policyRouter: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
    policyWhitelisted: true,
    commercePaused: false,
    routerPaused: false,
    disputeWindowSeconds: "600",
  });
}

export async function preparedCreateState(input: Readonly<{
  preview?: ReturnType<typeof activationPreview>;
  deployment?: ActivationDeploymentObservation;
}> = {}): Promise<ActivationState> {
  const signedTask = activationSignedTask();
  const transactionPlan = activationTransactionPlan();
  const preview = input.preview ?? activationPreview();
  const taskDescription = `mandatex-rebalance:v1:${deflateRawSync(
    Buffer.from(canonicalQuoteJson(signedTask), "utf8"),
  ).toString("base64url")}`;
  const envelope = {
    request: {
      task_description: taskDescription,
      terms: {
        deliverables: "rebalance position",
        quality_standards: "match the signed mandate",
        evaluation_required: true,
        evaluator_type: "router",
      },
    },
    response: {
      accepted: true,
      terms: {
        deliverables: "rebalance position",
        quality_standards: "match the signed mandate",
        evaluation_required: true,
        evaluator_type: "router",
        price: "0",
        currency: BSC_ACTIVATION_DEPLOYMENT.paymentToken,
      },
      estimated_completion_seconds: 300,
      quote_expires_at: ACTIVATION_NOW + 800,
      negotiated_at: ACTIVATION_NOW,
    },
    negotiation_hash: `0x${"6".repeat(64)}`,
    provider_sig: "0x11",
    chain_id: 56,
    verifying_contract: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
  };
  const jobDescription = buildJobDescription(envelope);
  const binding = activationBindingSchema.parse({
    chainId: 56,
    tokenId: "265375",
    client: ACTIVATION_CLIENT,
    provider: ACTIVATION_PROVIDER,
    commerceProxy: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
    commerceImplementation: BSC_ACTIVATION_DEPLOYMENT.commerceImplementation,
    commerceImplementationCodeHash:
      BSC_ACTIVATION_DEPLOYMENT.commerceImplementationCodeHash,
    routerProxy: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
    routerImplementation: BSC_ACTIVATION_DEPLOYMENT.routerImplementation,
    routerImplementationCodeHash:
      BSC_ACTIVATION_DEPLOYMENT.routerImplementationCodeHash,
    policy: BSC_ACTIVATION_DEPLOYMENT.policy,
    paymentToken: BSC_ACTIVATION_DEPLOYMENT.paymentToken,
    paymentTokenCodeHash: BSC_ACTIVATION_DEPLOYMENT.paymentTokenCodeHash,
    localReplayOnly: true,
    replayKey: "1".repeat(64),
    negotiationHash: envelope.negotiation_hash,
    mandateSha256: computeQuoteSha256(canonicalQuoteJson(signedTask.mandate)),
    signedTaskSha256: computeQuoteSha256(canonicalQuoteJson(signedTask)),
    transactionPlanSha256: computeQuoteSha256(
      canonicalQuoteJson(transactionPlan),
    ),
    previewSidecarSha256: computeQuoteSha256(canonicalQuoteJson(preview)),
    initialPreviewSha256: computeQuoteSha256(canonicalQuoteJson(preview)),
    previewBlockNumber: preview.blockNumber,
    previewBlockHash: preview.blockHash,
    negotiatedAt: ACTIVATION_NOW,
    quoteExpiresAt: ACTIVATION_NOW + 800,
    jobExpiresAt: ACTIVATION_JOB_EXPIRES_AT,
    price: "0",
    currency: BSC_ACTIVATION_DEPLOYMENT.paymentToken,
    jobDescription,
  });
  return prepareCreateActivation({
    binding,
    signedTask,
    transactionPlan,
    initialPreview: preview,
    deployment: input.deployment ?? activationDeployment(),
    cleanupOwner: "mandatex_operator",
    now: new Date(ACTIVATION_NOW * 1_000),
  });
}

export function activationReceipt(
  state: ActivationState,
  deployment: ActivationDeploymentObservation,
  transactionDigit: string,
): ActivationReceipt {
  if (state.intent === undefined) throw new Error("fixture state has no intent");
  const jobId = state.jobId ?? ACTIVATION_JOB_ID;
  const events =
    state.phase === "PREPARED_CREATE"
      ? [
          {
            name: "JobCreated" as const,
            jobId,
            client: ACTIVATION_CLIENT,
            provider: ACTIVATION_PROVIDER,
            evaluator: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
            expiredAt: ACTIVATION_JOB_EXPIRES_AT.toString(),
            hook: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
          },
        ]
      : state.phase === "PREPARED_REGISTER"
        ? [
            {
              name: "JobRegistered" as const,
              jobId,
              policy: BSC_ACTIVATION_DEPLOYMENT.policy,
              client: ACTIVATION_CLIENT,
            },
          ]
        : state.phase === "PREPARED_FUND"
          ? [
              {
                name: "JobFunded" as const,
                jobId,
                client: ACTIVATION_CLIENT,
                provider: ACTIVATION_PROVIDER,
                amount: "0",
              },
            ]
          : [];
  return activationReceiptSchema.parse({
    operation: state.intent.operation,
    transactionHash: `0x${transactionDigit.repeat(64)}`,
    blockNumber: deployment.blockNumber,
    blockHash: deployment.blockHash,
    blockTimestamp: deployment.blockTimestamp,
    status: "success",
    from: state.intent.from,
    to: state.intent.to,
    valueWei: "0",
    calldataSha256: state.intent.calldataSha256,
    events,
  });
}

export function activationJob(
  state: ActivationState,
  phase: "CREATE_CONFIRMED" | "REGISTER_CONFIRMED" | "BUDGET_CONFIRMED" | "FUNDED_CONFIRMED",
): ActivationJobObservation {
  return activationJobObservationSchema.parse({
    jobId: state.jobId ?? ACTIVATION_JOB_ID,
    client: ACTIVATION_CLIENT,
    provider: ACTIVATION_PROVIDER,
    evaluator: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
    hook: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
    descriptionSha256: computeTextSha256(state.binding.jobDescription),
    budget: "0",
    expiredAt: ACTIVATION_JOB_EXPIRES_AT.toString(),
    status: phase === "FUNDED_CONFIRMED" ? "FUNDED" : "OPEN",
    hasBudget: phase === "BUDGET_CONFIRMED" || phase === "FUNDED_CONFIRMED",
    policy:
      phase === "CREATE_CONFIRMED"
        ? "0x0000000000000000000000000000000000000000"
        : BSC_ACTIVATION_DEPLOYMENT.policy,
  });
}

function computeTextSha256(value: string): string {
  return computeQuoteSha256(value);
}
