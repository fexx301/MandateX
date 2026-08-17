import {
  STRATEGY_WEIGHTS,
  rankingScoreSchema,
  type MarketplaceMandate,
  type MarketplaceQuote,
  type RankingScore,
} from "./schemas.js";

function clampBps(value: number): number {
  return Math.max(0, Math.min(10_000, Math.floor(value)));
}

function ratioScore(numerator: bigint, denominator: bigint): number {
  if (denominator <= 0n) return numerator === 0n ? 10_000 : 0;
  if (numerator <= 0n) return 10_000;
  if (numerator >= denominator) return 0;
  return Number(((denominator - numerator) * 10_000n) / denominator);
}

function ageScore(ageSeconds: number, maxAgeSeconds: number): number {
  if (ageSeconds <= 0) return 10_000;
  if (ageSeconds >= maxAgeSeconds) return 0;
  return Math.floor(((maxAgeSeconds - ageSeconds) * 10_000) / maxAgeSeconds);
}

function factor<const W extends 30 | 20 | 15 | 10 | 5>(
  weight: W,
  scoreBps: number,
): { readonly weight: W; readonly scoreBps: number; readonly weightedPoints: number } {
  const canonicalScore = clampBps(scoreBps);
  return {
    weight,
    scoreBps: canonicalScore,
    weightedPoints: weight * canonicalScore,
  };
}

export function scoreEligibleQuote(
  mandate: MarketplaceMandate,
  quote: MarketplaceQuote,
  evaluatedAt: number,
): RankingScore {
  const evidenceFreshness = Math.min(
    ageScore(
      evaluatedAt - quote.observedAt,
      mandate.maxEvidenceAgeSeconds,
    ),
    ageScore(
      evaluatedAt - quote.estimates.observedAt,
      mandate.maxEvidenceAgeSeconds,
    ),
    ageScore(
      evaluatedAt - quote.categoryEvidence.observedAt,
      mandate.maxEvidenceAgeSeconds,
    ),
    ageScore(
      evaluatedAt - quote.reputation.observedAt,
      mandate.maxEvidenceAgeSeconds,
    ),
    quote.preview.status === "passed"
      ? ageScore(
          evaluatedAt - quote.preview.observedAt,
          mandate.maxPreviewAgeSeconds,
        )
      : 0,
  );

  const permissionLifetime = mandate.permissions.expiresAt - mandate.createdAt;
  const requestedLifetime = quote.permissions.expiresAt - mandate.createdAt;
  const permissionExpiryMargin = ratioScore(
    BigInt(requestedLifetime),
    BigInt(permissionLifetime),
  );
  const spendMargin = ratioScore(
    BigInt(quote.permissions.spendCapUsdMicros),
    BigInt(mandate.permissions.maxSpendUsdMicros),
  );
  const exposureMargin = ratioScore(
    BigInt(quote.estimates.exposureUsdMicros),
    BigInt(mandate.budgets.maxExposureUsdMicros),
  );
  const slippageMargin = ratioScore(
    BigInt(quote.estimates.slippageBps),
    BigInt(mandate.budgets.maxSlippageBps),
  );
  const riskCompatibility = Math.floor(
    (permissionExpiryMargin + spendMargin + exposureMargin + slippageMargin) / 4,
  );

  const feeUsdMicros =
    quote.pricing.status === "normalized_zero"
      ? BigInt(quote.pricing.agentFeeUsdMicros)
      : 0n;
  const feeMargin = ratioScore(
    feeUsdMicros,
    BigInt(mandate.budgets.maxAgentFeeUsdMicros),
  );
  const gasMargin = ratioScore(
    BigInt(quote.estimates.gasUsdMicros),
    BigInt(mandate.budgets.maxGasUsdMicros),
  );
  const totalCost = Math.floor((feeMargin + gasMargin + slippageMargin) / 3);

  const sampleConfidence = Math.min(
    10_000,
    quote.reputation.sampleSize * 1_000,
  );
  const reputationConfidence = Math.floor(
    (quote.reputation.scoreBps * 50 +
      quote.reputation.evidenceConfidenceBps * 30 +
      sampleConfidence * 20) /
      100,
  );

  const factors = {
    mandateFit: factor(STRATEGY_WEIGHTS.mandateFit, 10_000),
    executionReadiness: factor(
      STRATEGY_WEIGHTS.executionReadiness,
      quote.preview.status === "passed" ? 10_000 : 0,
    ),
    evidenceFreshness: factor(
      STRATEGY_WEIGHTS.evidenceFreshness,
      evidenceFreshness,
    ),
    riskCompatibility: factor(
      STRATEGY_WEIGHTS.riskCompatibility,
      riskCompatibility,
    ),
    totalCost: factor(STRATEGY_WEIGHTS.totalCost, totalCost),
    reputationConfidence: factor(
      STRATEGY_WEIGHTS.reputationConfidence,
      reputationConfidence,
    ),
  };
  const weightedTotal = Object.values(factors).reduce(
    (total, entry) => total + entry.weightedPoints,
    0,
  );
  return rankingScoreSchema.parse({
    factors,
    weightedTotal,
    scoreBps: Math.floor(weightedTotal / 100),
  });
}
