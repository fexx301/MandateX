import { canonicalSha256 } from "./canonical.js";
import type {
  CapturedDisplaySafeQuoteProjection,
  ProjectionCapability,
} from "./capture.js";
import { unsupportedCodeForCategory } from "./codes.js";
import {
  type DisplaySafeQuoteProjection,
  marketplaceQuoteSchema,
  type MarketplaceQuote,
} from "./schemas.js";

export function normalizeCapturedQuote(
  projection: CapturedDisplaySafeQuoteProjection,
  capability: ProjectionCapability,
): MarketplaceQuote {
  capability.assertCaptured(projection);
  return normalizeDisplaySafeQuoteProjection(projection);
}

export function normalizeDisplaySafeQuoteProjection(
  projection: DisplaySafeQuoteProjection,
): MarketplaceQuote {
  const pricing =
    projection.price.amountAtomic === "0"
      ? {
          status: "normalized_zero" as const,
          amountAtomic: "0" as const,
          currency: projection.price.currency,
          agentFeeUsdMicros: "0" as const,
        }
      : {
          status: "usd_unavailable" as const,
          amountAtomic: projection.price.amountAtomic,
          currency: projection.price.currency,
          code: "PRICING_USD_UNAVAILABLE" as const,
        };

  const normalization =
    projection.category === "rebalancing"
      ? projection.price.amountAtomic === "0"
        ? {
            status: "normalized" as const,
            adapter: "pancakeswap-v3-rebalancing-v1" as const,
          }
        : {
            status: "inconclusive" as const,
            code: "PRICING_USD_UNAVAILABLE" as const,
          }
      : {
          status: "unsupported" as const,
          code: unsupportedCodeForCategory(projection.category),
        };

  return marketplaceQuoteSchema.parse({
    schema: "mandatex.marketplace.quote.v1",
    sourceCommitments: projection.sourceCommitments,
    sourceProjectionSha256: canonicalSha256(projection),
    capturedAt: projection.capturedAt,
    quoteId: projection.quoteId,
    mandateId: projection.mandateId,
    category: projection.category,
    candidate: projection.candidate,
    observedAt: projection.observedAt,
    observedBlock: projection.observedBlock,
    observedBlockHash: projection.observedBlockHash,
    expiresAt: projection.expiresAt,
    proposedAction: projection.proposedAction,
    pricing,
    estimates: projection.estimates,
    permissions: projection.permissions,
    verification: projection.verification,
    preview: projection.preview,
    reputation: projection.reputation,
    categoryEvidence: projection.categoryEvidence,
    normalization,
  });
}
