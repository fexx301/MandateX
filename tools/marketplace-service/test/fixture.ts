import {
  BSC_PANCAKE_V3,
  canonicalQuoteJson,
  decodeRebalanceTransactionPlan,
  marketplaceDecodedRebalancePlanSchema,
  type MarketplaceDecodedRebalancePlan,
  type PancakeStateSnapshot,
  type TrustedPreviewMarketplaceEvaluationSuccess,
} from "@mandatex/agent-supply-verifier";
import { canonicalSha256 } from "@mandatex/marketplace-core";

import { marketplaceVerifierPolicySha256 } from "../src/issuer.js";
import {
  marketplaceEvaluationRequestSchema,
  type MarketplaceEvaluationRequest,
} from "../src/schema.js";

export const ISSUED_AT = 1_786_900_000;
export const PROVIDER = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
export const POSITION_MANAGER =
  "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364";
export const POOL = "0x4444444444444444444444444444444444444444";
export const TOKEN0 = "0x7777777777777777777777777777777777777777";
export const TOKEN1 = "0x8888888888888888888888888888888888888888";
export const CURRENCY = "0x3333333333333333333333333333333333333333";
export const PASSIVE_POLICY_FINGERPRINT = "aa".repeat(32);
export const TRUST_POLICY_SHA256 = "bb".repeat(32);
export const VERIFIER_POLICY_SHA256 = marketplaceVerifierPolicySha256({
  passivePolicyFingerprint: PASSIVE_POLICY_FINGERPRINT,
  trustPolicySha256: TRUST_POLICY_SHA256,
});

const REQUIRED_CALLS = [
  "collect((uint256,address,uint128,uint128))",
  "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
  "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
] as const;

const TRANSACTION_DATA =
  "0xac9650d80000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a40c49ccbe000000000000000000000000000000000000000000000000000000000000000900000000000000000000000000000000000000000000000000000000000003e8000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000006ff000000000000000000000000000000000000000000000000000000006a81ef4c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000084fc6f7865000000000000000000000000000000000000000000000000000000000000000900000000000000000000000019e7e376e7c213b7e7e7e46cc70a5dd086daff2a00000000000000000000000000000000ffffffffffffffffffffffffffffffff00000000000000000000000000000000ffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000164883164560000000000000000000000007777777777777777777777777777777777777777000000000000000000000000888888888888888888888888888888888888888800000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c800000000000000000000000000000000000000000000000000000000000003e800000000000000000000000000000000000000000000000000000000000007d000000000000000000000000000000000000000000000000000000000000003e300000000000000000000000000000000000000000000000000000000000007c600000000000000000000000019e7e376e7c213b7e7e7e46cc70a5dd086daff2a000000000000000000000000000000000000000000000000000000006a81ef4c00000000000000000000000000000000000000000000000000000000";

export function fixtureRequest(): MarketplaceEvaluationRequest {
  return marketplaceEvaluationRequestSchema.parse({
    mandate: {
      version: "1",
      mandate_id: "mandate-service-test",
      category: "rebalancing",
      chain_id: 56,
      protocol: "pancakeswap-v3",
      expires_at: ISSUED_AT + 3_600,
      max_evidence_age_seconds: 120,
      position: {
        pool_address: POOL,
        position_manager_address: POSITION_MANAGER,
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
        observed_at: ISSUED_AT - 30,
        source_url: "https://evidence.example/estimate",
      },
      permissions: {
        allowed_contracts: [POSITION_MANAGER],
        allowed_calls: [...REQUIRED_CALLS],
        spend_cap_usd: 500,
        expires_at: ISSUED_AT + 1_800,
      },
    },
    policy: {
      createdAt: ISSUED_AT - 600,
      maxClockSkewSeconds: 30,
      maxPreviewAgeSeconds: 300,
      maxAgentFeeUsdMicros: "0",
    },
    candidate: {
      selector: { chainId: 56, tokenId: "1" },
      transactionPlan: {
        schema: "mandatex.rebalance.transaction-plan.v1",
        chainId: 56,
        from: PROVIDER,
        to: POSITION_MANAGER,
        valueWei: "0",
        data: TRANSACTION_DATA,
      },
    },
  });
}

export function fixtureSuccess(
  request = fixtureRequest(),
): TrustedPreviewMarketplaceEvaluationSuccess {
  const decoded = decodeRebalanceTransactionPlan(
    request.candidate.transactionPlan,
  );
  const decodedArtifact = marketplaceDecodedPlan(decoded);
  const signedSnapshot = snapshot("exact", "100", null, ISSUED_AT - 20, 95);
  const freshSnapshot = snapshot("fresh", "103", "105", ISSUED_AT, 96);
  const signedTask = {
    schema: "mandatex.rebalance.quote.v1" as const,
    mandate: request.mandate,
    evidence: {
      network: "bsc-mainnet",
      chain_id: 56,
      snapshot_head_block: 102,
      confirmation_depth_blocks: 2 as const,
      observed_block: 100,
      observed_block_hash: `0x${"d".repeat(64)}`,
      observed_at: ISSUED_AT - 20,
      pool_address: POOL,
      position_manager_address: POSITION_MANAGER,
      position_token_id: "9",
      position_owner: PROVIDER,
      token0: TOKEN0,
      token1: TOKEN1,
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
          type: "onchain" as const,
          url: "https://bscscan.com/block/100",
          observed_block: 100,
        },
      ],
    },
    proposal: {
      execution_mode: "simulation" as const,
      proposed_lower_tick: 0,
      proposed_upper_tick: 200,
      trigger: {
        fired: true as const,
        reason: "near_range_boundary" as const,
        distance_to_boundary_ticks: 5,
      },
      estimated_gas_usd: 5,
      estimated_slippage_bps: 20,
      estimated_exposure_usd: 500,
      estimate_source_url: "https://evidence.example/estimate",
      permissions: {
        contracts: [POSITION_MANAGER],
        calls: [...REQUIRED_CALLS],
        spend_cap_usd: 500,
        expires_at: ISSUED_AT + 1_800,
      },
      break_even: {
        status: "not_calculated" as const,
        reason: "not required for evaluation",
      },
    },
    eligibility: {
      eligible: true as const,
      checked_at: ISSUED_AT - 10,
      checks: ["range", "permissions"],
    },
  };
  const acceptedEnvelope = {
    request: {
      task_description: "mandatex service test",
      terms: {
        deliverables: "rebalance position",
        quality_standards: "match the signed mandate",
        evaluation_required: true,
        evaluator_type: "uma_oov3",
        success_criteria: ["position is rebalanced"],
      },
    },
    request_hash: `0x${"1".repeat(64)}` as `0x${string}`,
    response: {
      accepted: true as const,
      terms: {
        deliverables: "rebalance position",
        quality_standards: "match the signed mandate",
        evaluation_required: true,
        evaluator_type: "uma_oov3",
        success_criteria: ["position is rebalanced"],
        price: "0",
        currency: CURRENCY,
      },
      estimated_completion_seconds: 300,
      quote_expires_at: ISSUED_AT + 600,
      negotiated_at: ISSUED_AT,
    },
    response_hash: `0x${"2".repeat(64)}` as `0x${string}`,
    negotiation_hash: `0x${"3".repeat(64)}` as `0x${string}`,
    provider_sig: "0x00" as `0x${string}`,
    chain_id: 56,
    verifying_contract: CURRENCY,
  };
  const verification = {
    signatureMethod: "eip191" as const,
    signer: PROVIDER,
    validatedProvider: PROVIDER,
    requestHash: acceptedEnvelope.request_hash,
    responseHash: acceptedEnvelope.response_hash,
    negotiationHash: acceptedEnvelope.negotiation_hash,
    chainId: 56 as const,
    verifyingContract: CURRENCY,
    negotiatedAt: ISSUED_AT,
    quoteExpiresAt: ISSUED_AT + 600,
    price: "0",
    currency: CURRENCY,
    estimatedCompletionSeconds: 300,
  };
  const mandateSha256 = canonicalSha256(request.mandate);
  const quoteEvidence = {
    schema: "mandatex.agent-supply.quote-marketplace-evaluation-evidence.v1" as const,
    observedAt: new Date(ISSUED_AT * 1_000).toISOString(),
    candidate: { chainId: 56 as const, tokenId: "1" },
    passiveReportSha256: "cc".repeat(32),
    passiveCandidateSha256: "dd".repeat(32),
    passivePolicyFingerprint: PASSIVE_POLICY_FINGERPRINT,
    trustPolicySha256: TRUST_POLICY_SHA256,
    quoteEndpoint: "https://agent.example/",
    a2aRequestSha256: "ee".repeat(32),
    a2aResponseSha256: "ff".repeat(32),
    expectedProvider: PROVIDER,
    providerKind: "eoa" as const,
    acceptedEnvelope,
    verification,
    signedTask,
    mandateSha256,
    gates: {
      passivePreflight: "pass" as const,
      endpointBinding: "pass" as const,
      quoteSignature: "pass" as const,
      quotePolicy: "pass" as const,
      finalChecks: "pass" as const,
    },
  };
  const quoteEvidenceSha256 = canonicalSha256(quoteEvidence);
  const preview = {
    status: "pass" as const,
    gates: {
      signedEvidence: "pass" as const,
      freshState: "pass" as const,
      identityOwner: "pass" as const,
      positionAuthority: "pass" as const,
      transactionPolicy: "pass" as const,
      evmSimulation: "pass" as const,
    },
    snapshot: freshSnapshot,
    policy: {
      authority: "owner" as const,
      deadline: ISSUED_AT + 300,
      calls: [
        {
          method: "decreaseLiquidity" as const,
          tokenId: "9",
          deadline: ISSUED_AT + 300,
        },
        { method: "collect" as const, tokenId: "9", recipient: PROVIDER },
        {
          method: "mint" as const,
          lowerTick: 0,
          upperTick: 200,
          recipient: PROVIDER,
          deadline: ISSUED_AT + 300,
        },
      ] as const,
    },
    simulationRequestSha256: "12".repeat(32),
    simulationResponseSha256: "13".repeat(32),
    simulationResultSha256: "14".repeat(32),
  };
  const previewEvidence = {
    schema: "mandatex.agent-supply.marketplace-preview-evidence.v1" as const,
    quoteEvidenceSha256,
    mandateSha256,
    transactionPlanSha256: decoded.transactionPlanSha256,
    calldataSha256: decoded.calldataSha256,
    decodedPlanSha256: decoded.decodedPlanSha256,
    decodedPlan: decodedArtifact,
    signedSnapshot: {
      snapshotSha256: canonicalSha256(signedSnapshot),
      snapshot: signedSnapshot,
    },
    freshSnapshot: {
      snapshotSha256: canonicalSha256(freshSnapshot),
      snapshot: freshSnapshot,
    },
    simulationRequestSha256: preview.simulationRequestSha256,
    simulationResponseSha256: preview.simulationResponseSha256,
    simulationResultSha256: preview.simulationResultSha256,
    policy: {
      ...preview.policy,
      calls: [...preview.policy.calls],
    },
    gates: preview.gates,
  };
  const artifact = {
    schema: "mandatex.agent-supply.marketplace-preview-evaluation.v1" as const,
    scope: "evaluation_only" as const,
    actionability: "unreserved" as const,
    outcome: "verified_unreserved" as const,
    observedAt: new Date(ISSUED_AT * 1_000).toISOString(),
    replayStatus: "not_attempted" as const,
    candidate: { chainId: 56 as const, tokenId: "1" },
    prospectiveReplayKey: "15".repeat(32),
    commitments: {
      quoteEvidenceSha256,
      previewEvidenceSha256: canonicalSha256(previewEvidence),
    },
    evidence: { quote: quoteEvidence, preview: previewEvidence },
  };

  return {
    schema: "mandatex.agent-supply.marketplace-preview-evaluation-result.v1",
    scope: "evaluation_only",
    actionability: "unreserved",
    outcome: "verified_unreserved",
    artifact,
    context: {
      passiveReport: { policyFingerprint: PASSIVE_POLICY_FINGERPRINT },
      passiveReportSha256: quoteEvidence.passiveReportSha256,
      passiveCandidateSha256: quoteEvidence.passiveCandidateSha256,
      trustPolicySha256: TRUST_POLICY_SHA256,
      trust: {
        quoteEndpoint: quoteEvidence.quoteEndpoint,
        expectedProvider: PROVIDER,
        providerKind: "eoa",
      },
    } as never,
    acceptedEnvelope,
    verification,
    signedTask,
    decodedPlan: decoded,
    signedSnapshot,
    preview,
  };
}

function marketplaceDecodedPlan(
  decoded: ReturnType<typeof decodeRebalanceTransactionPlan>,
): MarketplaceDecodedRebalancePlan {
  return marketplaceDecodedRebalancePlanSchema.parse({
    plan: decoded.plan,
    decrease: {
      method: "decreaseLiquidity",
      tokenId: decoded.decrease.tokenId.toString(),
      liquidity: decoded.decrease.liquidity.toString(),
      amount0Min: decoded.decrease.amount0Min.toString(),
      amount1Min: decoded.decrease.amount1Min.toString(),
      deadline: decoded.decrease.deadline.toString(),
    },
    collect: {
      method: "collect",
      tokenId: decoded.collect.tokenId.toString(),
      recipient: decoded.collect.recipient,
      amount0Max: decoded.collect.amount0Max.toString(),
      amount1Max: decoded.collect.amount1Max.toString(),
    },
    mint: {
      method: "mint",
      token0: decoded.mint.token0,
      token1: decoded.mint.token1,
      fee: decoded.mint.fee,
      tickLower: decoded.mint.tickLower,
      tickUpper: decoded.mint.tickUpper,
      amount0Desired: decoded.mint.amount0Desired.toString(),
      amount1Desired: decoded.mint.amount1Desired.toString(),
      amount0Min: decoded.mint.amount0Min.toString(),
      amount1Min: decoded.mint.amount1Min.toString(),
      recipient: decoded.mint.recipient,
      deadline: decoded.mint.deadline.toString(),
    },
    innerCalldata: [...decoded.innerCalldata],
    transactionPlanSha256: decoded.transactionPlanSha256,
    calldataSha256: decoded.calldataSha256,
    decodedPlanSha256: decoded.decodedPlanSha256,
  });
}

function snapshot(
  mode: "exact" | "fresh",
  block: string,
  head: string | null,
  observedAt: number,
  currentTick: number,
): PancakeStateSnapshot {
  const code = { bytes: 4, sha256: "16".repeat(32) };
  const emptyCode = {
    bytes: 0,
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  };
  return {
    chainId: 56,
    pin: {
      mode,
      headBlockNumber: head,
      observedBlockNumber: block,
      observedBlockHash:
        mode === "exact" ? `0x${"d".repeat(64)}` : `0x${"f".repeat(64)}`,
      observedAt: observedAt.toString(),
      confirmationDepth: mode === "fresh" ? 2 : null,
      requireCanonical: true,
      attempts: 1,
    },
    identity: {
      registryAddress: BSC_PANCAKE_V3.erc8004Registry,
      registryCode: code,
      agentTokenId: "1",
      expectedProvider: PROVIDER,
      currentOwner: PROVIDER,
      providerCode: emptyCode,
    },
    deployments: {
      factory: { address: BSC_PANCAKE_V3.factory, code },
      deployer: { address: BSC_PANCAKE_V3.deployer, code },
      positionManager: {
        address: POSITION_MANAGER,
        code,
        factory: BSC_PANCAKE_V3.factory,
        deployer: BSC_PANCAKE_V3.deployer,
      },
    },
    pool: {
      address: POOL,
      code,
      factory: BSC_PANCAKE_V3.factory,
      token0: TOKEN0,
      token1: TOKEN1,
      fee: 500,
      tickSpacing: 10,
      sqrtPriceX96: "79228162514264337593543950336",
      currentTick,
      observationIndex: 1,
      observationCardinality: 2,
      observationCardinalityNext: 3,
      feeProtocol: 0,
      unlocked: true,
      liquidity: "1000000",
    },
    position: {
      tokenId: "9",
      owner: PROVIDER,
      approved: "0x0000000000000000000000000000000000000000",
      caller: PROVIDER,
      callerApprovedForAll: false,
      callerCanManage: true,
      nonce: "0",
      operator: "0x0000000000000000000000000000000000000000",
      token0: TOKEN0,
      token1: TOKEN1,
      fee: 500,
      tickLower: -100,
      tickUpper: 100,
      liquidity: "1000",
      feeGrowthInside0LastX128: "0",
      feeGrowthInside1LastX128: "0",
      tokensOwed0: "0",
      tokensOwed1: "0",
    },
    tokens: {
      token0: {
        address: TOKEN0,
        code,
        decimals: 18,
        callerBalance: "10000",
        callerAllowanceToPositionManager: "10000",
      },
      token1: {
        address: TOKEN1,
        code,
        decimals: 18,
        callerBalance: "20000",
        callerAllowanceToPositionManager: "20000",
      },
    },
  };
}

export function refreshArtifactCommitments(
  result: TrustedPreviewMarketplaceEvaluationSuccess,
): void {
  const mutable = result as unknown as {
    artifact: {
      commitments: {
        quoteEvidenceSha256: string;
        previewEvidenceSha256: string;
      };
      evidence: {
        quote: unknown;
        preview: {
          quoteEvidenceSha256: string;
          signedSnapshot: { snapshotSha256: string; snapshot: unknown };
          freshSnapshot: { snapshotSha256: string; snapshot: unknown };
        };
      };
    };
  };
  const quoteHash = canonicalSha256(mutable.artifact.evidence.quote as never);
  mutable.artifact.commitments.quoteEvidenceSha256 = quoteHash;
  mutable.artifact.evidence.preview.quoteEvidenceSha256 = quoteHash;
  mutable.artifact.evidence.preview.signedSnapshot.snapshotSha256 =
    canonicalSha256(
      mutable.artifact.evidence.preview.signedSnapshot.snapshot as never,
    );
  mutable.artifact.evidence.preview.freshSnapshot.snapshotSha256 =
    canonicalSha256(
      mutable.artifact.evidence.preview.freshSnapshot.snapshot as never,
    );
  mutable.artifact.commitments.previewEvidenceSha256 = canonicalSha256(
    mutable.artifact.evidence.preview as never,
  );
}

export function canonicalClone<T>(value: T): T {
  return JSON.parse(canonicalQuoteJson(value as never)) as T;
}
