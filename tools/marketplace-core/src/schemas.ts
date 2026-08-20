import { z } from "zod";

import {
  CATEGORY_POLICIES,
  MARKETPLACE_REBALANCING_ADAPTER,
} from "./category-policy.js";
import type { DeepReadonly } from "./immutable.js";
import {
  findingSchema,
  inconclusiveCodeSchema,
  unsupportedCodeSchema,
} from "./codes.js";
import {
  addressSchema,
  basisPointsSchema,
  blockNumberSchema,
  bytes32Schema,
  callIdSchema,
  canonicalIdentifierSchema,
  compareCanonicalStrings,
  gateObservationSchema,
  marketplaceCategorySchema,
  protocolIdSchema,
  sha256Schema,
  sortUnique,
  tickSchema,
  tokenIdSchema,
  uint256DecimalSchema,
  unixSecondsSchema,
  usdMicrosSchema,
} from "./primitives.js";

export const MARKETPLACE_MANDATE_SCHEMA =
  "mandatex.marketplace.mandate.v1" as const;
export const MARKETPLACE_QUOTE_SCHEMA =
  "mandatex.marketplace.quote.v1" as const;
export const MARKETPLACE_ELIGIBILITY_DECISION_SCHEMA =
  "mandatex.marketplace.eligibility-decision.v1" as const;
export const MARKETPLACE_RECEIPT_SCHEMA =
  "mandatex.marketplace.receipt.v1" as const;
export const DISPLAY_SAFE_QUOTE_PROJECTION_SCHEMA =
  "mandatex.marketplace.display-safe-quote-projection.v1" as const;

const uniqueSortedAddressesSchema = z
  .array(addressSchema)
  .min(1)
  .max(32)
  .superRefine((values, context) => {
    if (new Set(values).size !== values.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "addresses must be unique",
      });
    }
  })
  .transform(sortUnique);

const uniqueSortedCallsSchema = z
  .array(callIdSchema)
  .min(1)
  .max(64)
  .superRefine((values, context) => {
    if (new Set(values).size !== values.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "calls must be unique",
      });
    }
  })
  .transform(sortUnique);

const uniqueSortedProtocolsSchema = z
  .array(protocolIdSchema)
  .min(1)
  .max(16)
  .superRefine((values, context) => {
    if (new Set(values).size !== values.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "protocols must be unique",
      });
    }
  })
  .transform(sortUnique);

export const marketplaceCandidateSchema = z
  .object({
    chainId: z.literal(56),
    tokenId: tokenIdSchema,
    owner: addressSchema,
    publisher: addressSchema,
    taskInterface: z.enum(["erc8183", "a2a", "mcp"]),
  })
  .strict();
export type MarketplaceCandidate = DeepReadonly<
  z.infer<typeof marketplaceCandidateSchema>
>;

const rebalancingPositionSchema = z
  .object({
    protocol: z.literal("pancakeswap-v3"),
    poolAddress: addressSchema,
    positionManagerAddress: addressSchema,
    tokenId: tokenIdSchema,
  })
  .strict();

const rebalancingMandatePolicySchema = z
  .object({
    position: rebalancingPositionSchema,
    approvedLowerTick: tickSchema,
    approvedUpperTick: tickSchema,
    targetWidthTicks: z.number().int().positive().max(1_774_544),
    triggerMode: z.enum(["out_of_range", "boundary_proximity"]),
    triggerDistanceTicks: z.number().int().nonnegative().max(1_774_544),
  })
  .strict();

export const marketplaceMandateSchema = z
  .object({
    schema: z.literal(MARKETPLACE_MANDATE_SCHEMA),
    mandateId: canonicalIdentifierSchema,
    category: marketplaceCategorySchema,
    chainId: z.literal(56),
    createdAt: unixSecondsSchema,
    expiresAt: unixSecondsSchema,
    maxClockSkewSeconds: z.number().int().min(0).max(300),
    maxEvidenceAgeSeconds: z.number().int().min(5).max(3_600),
    maxPreviewAgeSeconds: z.number().int().min(5).max(3_600),
    budgets: z
      .object({
        maxAgentFeeUsdMicros: usdMicrosSchema,
        maxGasUsdMicros: usdMicrosSchema,
        maxSlippageBps: basisPointsSchema,
        maxExposureUsdMicros: usdMicrosSchema,
      })
      .strict(),
    permissions: z
      .object({
        allowedProtocols: uniqueSortedProtocolsSchema,
        allowedContracts: uniqueSortedAddressesSchema,
        allowedCalls: uniqueSortedCallsSchema,
        maxSpendUsdMicros: usdMicrosSchema,
        expiresAt: unixSecondsSchema,
      })
      .strict(),
    rebalancing: rebalancingMandatePolicySchema.optional(),
  })
  .strict()
  .superRefine((mandate, context) => {
    if (mandate.createdAt >= mandate.expiresAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expiresAt"],
        message: "expiresAt must be later than createdAt",
      });
    }
    if (
      mandate.permissions.expiresAt <= mandate.createdAt ||
      mandate.permissions.expiresAt > mandate.expiresAt
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["permissions", "expiresAt"],
        message: "permission expiry must be inside the mandate lifetime",
      });
    }
    if (mandate.category === "rebalancing" && mandate.rebalancing === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["rebalancing"],
        message: "a rebalancing mandate requires rebalancing policy data",
      });
      return;
    }
    if (
      mandate.category !== "rebalancing" &&
      Object.prototype.hasOwnProperty.call(mandate, "rebalancing")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["rebalancing"],
        message: "unsupported category mandates must not invent rebalancing data",
      });
      return;
    }
    const policy = mandate.rebalancing;
    if (policy === undefined) return;
    if (policy.approvedLowerTick >= policy.approvedUpperTick) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["rebalancing", "approvedUpperTick"],
        message: "approvedUpperTick must be greater than approvedLowerTick",
      });
    }
    if (
      policy.targetWidthTicks >
      policy.approvedUpperTick - policy.approvedLowerTick
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["rebalancing", "targetWidthTicks"],
        message: "target width must fit inside the approved range",
      });
    }
  });
export type MarketplaceMandate = DeepReadonly<
  z.infer<typeof marketplaceMandateSchema>
>;

const sourceCommitmentsSchema = z
  .object({
    quoteValidationSha256: sha256Schema,
    previewValidationSha256: sha256Schema,
  })
  .strict();

const estimatesSchema = z
  .object({
    gasUsdMicros: usdMicrosSchema,
    slippageBps: basisPointsSchema,
    exposureUsdMicros: usdMicrosSchema,
    observedAt: unixSecondsSchema,
  })
  .strict();

const quotePermissionsSchema = z
  .object({
    contracts: uniqueSortedAddressesSchema,
    calls: uniqueSortedCallsSchema,
    spendCapUsdMicros: usdMicrosSchema,
    expiresAt: unixSecondsSchema,
  })
  .strict();

const verificationSchema = z
  .object({
    identity: gateObservationSchema,
    publisher: gateObservationSchema,
    endpoint: gateObservationSchema,
    taskInterface: gateObservationSchema,
    category: gateObservationSchema,
    quoteCompleteness: gateObservationSchema,
  })
  .strict();

export const previewErrorCodeSchema = z.enum([
  "CALLER_AUTHORITY_REJECTED",
  "EVM_SIMULATION_REVERTED",
  "IDENTITY_OWNER_MISMATCH",
  "POSITION_AUTHORITY_REJECTED",
  "PREVIEW_STATE_INVALID",
  "TRANSACTION_PLAN_INVALID",
  "TRANSACTION_POLICY_REJECTED",
]);
export type PreviewErrorCode = z.infer<typeof previewErrorCodeSchema>;

const previewSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("passed"),
      observedAt: unixSecondsSchema,
      observedBlock: blockNumberSchema,
      observedBlockHash: bytes32Schema,
    })
    .strict(),
  z
    .object({
      status: z.literal("failed"),
      errorCode: previewErrorCodeSchema,
    })
    .strict(),
  z.object({ status: z.literal("unavailable") }).strict(),
]);

const reputationSchema = z
  .object({
    scoreBps: basisPointsSchema,
    sampleSize: z.number().int().nonnegative().max(1_000_000),
    evidenceConfidenceBps: basisPointsSchema,
    observedAt: unixSecondsSchema,
  })
  .strict();

const rebalancingCategoryEvidenceSchema = z
  .object({
    category: z.literal("rebalancing"),
    protocol: z.literal("pancakeswap-v3"),
    position: rebalancingPositionSchema.omit({ protocol: true }),
    observedAt: unixSecondsSchema,
    observedBlock: blockNumberSchema,
    observedBlockHash: bytes32Schema,
    currentTick: tickSchema,
    tickSpacing: z.number().int().positive().max(1_774_544),
    currentLowerTick: tickSchema,
    currentUpperTick: tickSchema,
    proposedLowerTick: tickSchema,
    proposedUpperTick: tickSchema,
    trigger: z
      .object({
        fired: z.boolean(),
        reason: z.enum(["outside_current_range", "near_range_boundary"]),
        distanceToBoundaryTicks: z.number().int().nonnegative().max(1_774_544),
      })
      .strict(),
  })
  .strict()
  .superRefine((evidence, context) => {
    if (evidence.currentLowerTick >= evidence.currentUpperTick) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["currentUpperTick"],
        message: "currentUpperTick must be greater than currentLowerTick",
      });
    }
    if (evidence.proposedLowerTick >= evidence.proposedUpperTick) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["proposedUpperTick"],
        message: "proposedUpperTick must be greater than proposedLowerTick",
      });
    }
  });

const unsupportedCategoryEvidenceSchema = z.discriminatedUnion("category", [
  z
    .object({ category: z.literal("grid"), observedAt: unixSecondsSchema })
    .strict(),
  z
    .object({ category: z.literal("yield"), observedAt: unixSecondsSchema })
    .strict(),
  z
    .object({ category: z.literal("health"), observedAt: unixSecondsSchema })
    .strict(),
]);

export const categoryEvidenceSchema = z.union([
  rebalancingCategoryEvidenceSchema,
  unsupportedCategoryEvidenceSchema,
]);

const displaySafeQuoteProjectionPayloadShape = {
    sourceCommitments: sourceCommitmentsSchema,
    quoteId: canonicalIdentifierSchema,
    mandateId: canonicalIdentifierSchema,
    category: marketplaceCategorySchema,
    candidate: marketplaceCandidateSchema,
    observedAt: unixSecondsSchema,
    observedBlock: blockNumberSchema,
    observedBlockHash: bytes32Schema,
    expiresAt: unixSecondsSchema,
    proposedAction: z.string().trim().min(1).max(1_000),
    price: z
      .object({
        amountAtomic: uint256DecimalSchema,
        currency: addressSchema,
      })
      .strict(),
    estimates: estimatesSchema,
    permissions: quotePermissionsSchema,
    verification: verificationSchema,
    preview: previewSchema,
    reputation: reputationSchema,
    categoryEvidence: categoryEvidenceSchema,
} as const;

export const displaySafeQuoteProjectionPayloadSchema = z
  .object(displaySafeQuoteProjectionPayloadShape)
  .strict();
export type DisplaySafeQuoteProjectionPayload = DeepReadonly<
  z.infer<typeof displaySafeQuoteProjectionPayloadSchema>
>;

export const displaySafeQuoteProjectionSchema = z
  .object({
    schema: z.literal(DISPLAY_SAFE_QUOTE_PROJECTION_SCHEMA),
    captureContext: z.literal("trusted-quote-validation-success"),
    capturedAt: unixSecondsSchema,
    ...displaySafeQuoteProjectionPayloadShape,
  })
  .strict()
  .superRefine((projection, context) => {
    if (projection.category !== projection.categoryEvidence.category) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categoryEvidence", "category"],
        message: "category evidence must match the quote category",
      });
    }
    if (projection.observedAt > projection.capturedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["observedAt"],
        message: "quote observation must not follow in-process capture",
      });
    }
    if (projection.estimates.observedAt > projection.capturedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["estimates", "observedAt"],
        message: "estimate observation must not follow in-process capture",
      });
    }
    if (projection.categoryEvidence.observedAt > projection.capturedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categoryEvidence", "observedAt"],
        message: "category evidence observation must not follow in-process capture",
      });
    }
    if (projection.reputation.observedAt > projection.capturedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reputation", "observedAt"],
        message: "reputation observation must not follow in-process capture",
      });
    }
    if (projection.expiresAt <= projection.observedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expiresAt"],
        message: "quote expiry must follow quote observation",
      });
    }
    if (projection.expiresAt <= projection.capturedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expiresAt"],
        message: "a successfully captured quote must still be live",
      });
    }
    if (
      projection.preview.status === "passed" &&
      projection.preview.observedAt > projection.capturedAt
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["preview", "observedAt"],
        message: "preview observation must not follow in-process capture",
      });
    }
  });
export type DisplaySafeQuoteProjection = DeepReadonly<
  z.infer<typeof displaySafeQuoteProjectionSchema>
>;

const normalizedPricingSchema = z
  .object({
    status: z.literal("normalized_zero"),
    amountAtomic: z.literal("0"),
    currency: addressSchema,
    agentFeeUsdMicros: z.literal("0"),
  })
  .strict();

const unavailablePricingSchema = z
  .object({
    status: z.literal("usd_unavailable"),
    amountAtomic: uint256DecimalSchema.refine((value) => value !== "0", {
      message: "unavailable pricing requires a nonzero atomic amount",
    }),
    currency: addressSchema,
    code: z.literal("PRICING_USD_UNAVAILABLE"),
  })
  .strict();

export const marketplacePricingSchema = z.discriminatedUnion("status", [
  normalizedPricingSchema,
  unavailablePricingSchema,
]);

export const quoteNormalizationSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("normalized"),
      adapter: z.literal(MARKETPLACE_REBALANCING_ADAPTER),
    })
    .strict(),
  z
    .object({
      status: z.literal("inconclusive"),
      code: inconclusiveCodeSchema,
    })
    .strict(),
  z
    .object({
      status: z.literal("unsupported"),
      code: unsupportedCodeSchema,
    })
    .strict(),
]);

export const marketplaceQuoteSchema = z
  .object({
    schema: z.literal(MARKETPLACE_QUOTE_SCHEMA),
    sourceCommitments: sourceCommitmentsSchema,
    sourceProjectionSha256: sha256Schema,
    capturedAt: unixSecondsSchema,
    quoteId: canonicalIdentifierSchema,
    mandateId: canonicalIdentifierSchema,
    category: marketplaceCategorySchema,
    candidate: marketplaceCandidateSchema,
    observedAt: unixSecondsSchema,
    observedBlock: blockNumberSchema,
    observedBlockHash: bytes32Schema,
    expiresAt: unixSecondsSchema,
    proposedAction: z.string().trim().min(1).max(1_000),
    pricing: marketplacePricingSchema,
    estimates: estimatesSchema,
    permissions: quotePermissionsSchema,
    verification: verificationSchema,
    preview: previewSchema,
    reputation: reputationSchema,
    categoryEvidence: categoryEvidenceSchema,
    normalization: quoteNormalizationSchema,
  })
  .strict()
  .superRefine((quote, context) => {
    if (quote.category !== quote.categoryEvidence.category) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categoryEvidence", "category"],
        message: "category evidence must match the quote category",
      });
    }
    const capturedAt = quote.capturedAt;
    const chronology = [
      ["observedAt", quote.observedAt],
      ["estimates.observedAt", quote.estimates.observedAt],
      ["reputation.observedAt", quote.reputation.observedAt],
      ...(quote.preview.status === "passed"
        ? [["preview.observedAt", quote.preview.observedAt] as const]
        : []),
      ["categoryEvidence.observedAt", quote.categoryEvidence.observedAt],
    ] as const;
    for (const [path, observedAt] of chronology) {
      if (observedAt > capturedAt) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: path.split("."),
          message: "observation must not follow in-process capture",
        });
      }
    }
    if (quote.expiresAt <= quote.observedAt || quote.expiresAt <= quote.capturedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expiresAt"],
        message: "quote expiry must follow observation and capture",
      });
    }
    if (quote.category === "rebalancing") {
      if (quote.normalization.status === "unsupported") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["normalization"],
          message: "rebalancing must use the implemented normalizer",
        });
      }
      if (
        quote.pricing.status === "usd_unavailable" &&
        (quote.normalization.status !== "inconclusive" ||
          quote.normalization.code !== "PRICING_USD_UNAVAILABLE")
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["normalization"],
          message: "nonzero pricing must be explicitly inconclusive",
        });
      }
      if (
        quote.pricing.status === "normalized_zero" &&
        quote.normalization.status !== "normalized"
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["normalization"],
          message: "zero-price rebalancing quotes must normalize",
        });
      }
    } else {
      const categoryPolicy = CATEGORY_POLICIES[quote.category];
      if (quote.normalization.status !== "unsupported") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["normalization"],
          message: "grid, yield, and health quotes are explicitly unsupported",
        });
      } else if (
        categoryPolicy.receiptAdapter.status !== "unsupported" ||
        quote.normalization.code !== categoryPolicy.receiptAdapter.code
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["normalization", "code"],
          message: "unsupported code must match the quote category",
        });
      }
    }
  });
export type MarketplaceQuote = DeepReadonly<z.infer<typeof marketplaceQuoteSchema>>;

export const STRATEGY_WEIGHTS = Object.freeze({
  mandateFit: 30,
  executionReadiness: 20,
  evidenceFreshness: 20,
  riskCompatibility: 15,
  totalCost: 10,
  reputationConfidence: 5,
} as const);

const factorSchema = (weight: 30 | 20 | 15 | 10 | 5) =>
  z
    .object({
      weight: z.literal(weight),
      scoreBps: basisPointsSchema,
      weightedPoints: z.number().int().min(0).max(weight * 10_000),
    })
    .strict()
    .superRefine((factor, context) => {
      if (factor.weightedPoints !== factor.weight * factor.scoreBps) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["weightedPoints"],
          message: "weightedPoints must use exact integer multiplication",
        });
      }
    });

export const rankingScoreSchema = z
  .object({
    factors: z
      .object({
        mandateFit: factorSchema(30),
        executionReadiness: factorSchema(20),
        evidenceFreshness: factorSchema(20),
        riskCompatibility: factorSchema(15),
        totalCost: factorSchema(10),
        reputationConfidence: factorSchema(5),
      })
      .strict(),
    weightedTotal: z.number().int().min(0).max(1_000_000),
    scoreBps: basisPointsSchema,
  })
  .strict()
  .superRefine((score, context) => {
    const weightedTotal = Object.values(score.factors).reduce(
      (total, factor) => total + factor.weightedPoints,
      0,
    );
    if (score.weightedTotal !== weightedTotal) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["weightedTotal"],
        message: "weightedTotal does not match the six factors",
      });
    }
    if (score.scoreBps !== Math.floor(weightedTotal / 100)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["scoreBps"],
        message: "scoreBps must be the integer weighted total",
      });
    }
  });
export type RankingScore = DeepReadonly<z.infer<typeof rankingScoreSchema>>;

export const eligibilityOutcomeSchema = z.enum([
  "eligible",
  "excluded",
  "inconclusive",
  "unsupported",
]);
export type EligibilityOutcome = z.infer<typeof eligibilityOutcomeSchema>;

export const marketplaceEligibilityDecisionSchema = z
  .object({
    schema: z.literal(MARKETPLACE_ELIGIBILITY_DECISION_SCHEMA),
    mandateId: canonicalIdentifierSchema,
    evaluatedAt: unixSecondsSchema,
    quoteId: canonicalIdentifierSchema,
    candidate: marketplaceCandidateSchema,
    quoteSha256: sha256Schema,
    outcome: eligibilityOutcomeSchema,
    findings: z.array(findingSchema).max(64),
    score: rankingScoreSchema.nullable(),
  })
  .strict()
  .superRefine((decision, context) => {
    const findingKeys = decision.findings.map(
      (finding) => `${finding.kind}:${finding.code}`,
    );
    if (new Set(findingKeys).size !== findingKeys.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["findings"],
        message: "findings must be unique",
      });
    }
    const sorted = [...findingKeys].sort(compareCanonicalStrings);
    if (findingKeys.some((key, index) => key !== sorted[index])) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["findings"],
        message: "findings must use canonical code order",
      });
    }
    const expectedOutcome = decision.findings.some(
      (finding) => finding.kind === "exclusion",
    )
      ? "excluded"
      : decision.findings.some((finding) => finding.kind === "inconclusive")
        ? "inconclusive"
        : decision.findings.some((finding) => finding.kind === "unsupported")
          ? "unsupported"
          : "eligible";
    if (decision.outcome !== expectedOutcome) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["outcome"],
        message:
          "outcome must apply exclusion > inconclusive > unsupported precedence",
      });
    }
    if (expectedOutcome === "eligible") {
      if (decision.findings.length !== 0 || decision.score === null) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "eligible decisions require a score and no findings",
        });
      }
      return;
    }
    if (decision.score !== null || decision.findings.length === 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "non-eligible decisions require findings and no score",
      });
    }
  });
export type MarketplaceEligibilityDecision = DeepReadonly<
  z.infer<typeof marketplaceEligibilityDecisionSchema>
>;

const rankedCandidateSchema = z
  .object({
    rank: z.number().int().positive().max(8),
    quoteId: canonicalIdentifierSchema,
    candidate: marketplaceCandidateSchema,
    score: rankingScoreSchema,
  })
  .strict();

const artifactReferenceSchema = z
  .object({
    quoteId: canonicalIdentifierSchema,
    candidate: marketplaceCandidateSchema,
    sha256: sha256Schema,
  })
  .strict();

export const marketplaceReceiptSchema = z
  .object({
    schema: z.literal(MARKETPLACE_RECEIPT_SCHEMA),
    receiptId: sha256Schema,
    effect: z.literal("evaluation_only"),
    evaluatedAt: unixSecondsSchema,
    mandateId: canonicalIdentifierSchema,
    category: marketplaceCategorySchema,
    adapter: z.discriminatedUnion("status", [
      z
        .object({
          status: z.literal("supported"),
          name: z.literal(MARKETPLACE_REBALANCING_ADAPTER),
        })
        .strict(),
      z
        .object({
          status: z.literal("unsupported"),
          code: unsupportedCodeSchema,
        })
        .strict(),
    ]),
    commitments: z
      .object({
        mandateSha256: sha256Schema,
        quotesSha256: sha256Schema,
        decisionsSha256: sha256Schema,
        rankingSha256: sha256Schema,
      })
      .strict(),
    quotes: z.array(artifactReferenceSchema).max(8),
    decisions: z.array(artifactReferenceSchema).max(8),
    ranking: z.array(rankedCandidateSchema).max(8),
    summary: z
      .object({
        candidates: z.number().int().min(0).max(8),
        eligible: z.number().int().min(0).max(8),
        excluded: z.number().int().min(0).max(8),
        inconclusive: z.number().int().min(0).max(8),
        unsupported: z.number().int().min(0).max(8),
      })
      .strict(),
  })
  .strict()
  .superRefine((receipt, context) => {
    const referenceKey = (reference: {
      readonly quoteId: string;
      readonly candidate: { readonly chainId: number; readonly tokenId: string };
    }) => `${reference.candidate.chainId}:${reference.candidate.tokenId}:${reference.quoteId}`;
    const assertUniqueReferences = (
      references: readonly {
        readonly quoteId: string;
        readonly candidate: { readonly chainId: number; readonly tokenId: string };
      }[],
      path: "quotes" | "decisions" | "ranking",
    ) => {
      const candidateKeys = references.map(
        (reference) =>
          `${reference.candidate.chainId}:${reference.candidate.tokenId}`,
      );
      const quoteIds = references.map((reference) => reference.quoteId);
      if (new Set(candidateKeys).size !== candidateKeys.length) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [path],
          message: `${path} must contain unique candidate identities`,
        });
      }
      if (new Set(quoteIds).size !== quoteIds.length) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [path],
          message: `${path} must contain unique quote IDs`,
        });
      }
    };
    assertUniqueReferences(receipt.quotes, "quotes");
    assertUniqueReferences(receipt.decisions, "decisions");
    assertUniqueReferences(receipt.ranking, "ranking");
    const quoteKeys = receipt.quotes.map(referenceKey);
    const decisionKeys = receipt.decisions.map(referenceKey);
    if (
      quoteKeys.length !== decisionKeys.length ||
      quoteKeys.some((key, index) => key !== decisionKeys[index])
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["decisions"],
        message: "decision references must match quote references in exact order",
      });
    }
    const quoteKeySet = new Set(quoteKeys);
    if (receipt.ranking.some((reference) => !quoteKeySet.has(referenceKey(reference)))) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["ranking"],
        message: "ranking entries must reference quoted candidates",
      });
    }
    if (
      receipt.summary.candidates !== receipt.quotes.length ||
      receipt.quotes.length !== receipt.decisions.length
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["summary", "candidates"],
        message: "candidate count must match quote and decision references",
      });
    }
    const classified =
      receipt.summary.eligible +
      receipt.summary.excluded +
      receipt.summary.inconclusive +
      receipt.summary.unsupported;
    if (classified !== receipt.summary.candidates) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["summary"],
        message: "classification counts must sum to the candidate count",
      });
    }
    if (receipt.ranking.length !== receipt.summary.eligible) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["ranking"],
        message: "ranking must contain eligible candidates only",
      });
    }
    if (receipt.ranking.some((entry, index) => entry.rank !== index + 1)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["ranking"],
        message: "ranking positions must be contiguous and one-based",
      });
    }
    const categoryPolicy = CATEGORY_POLICIES[receipt.category];
    if (categoryPolicy.receiptAdapter.status === "unsupported") {
      if (
        receipt.adapter.status !== "unsupported" ||
        receipt.adapter.code !== categoryPolicy.receiptAdapter.code
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["adapter", "code"],
          message: "unsupported adapter code must match the receipt category",
        });
      }
    } else if (
      receipt.adapter.status !== "supported" ||
      receipt.adapter.name !== categoryPolicy.receiptAdapter.name
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapter"],
        message: "supported adapter must match the category policy",
      });
    }
  });
export type MarketplaceReceipt = DeepReadonly<
  z.infer<typeof marketplaceReceiptSchema>
>;

export type MarketplaceEvaluationResult = DeepReadonly<{
  mandate: MarketplaceMandate;
  quotes: MarketplaceQuote[];
  decisions: MarketplaceEligibilityDecision[];
  receipt: MarketplaceReceipt;
}>;

export type MarketplaceEvaluationConsistency = DeepReadonly<{
  scope: "integrity_only";
  result: MarketplaceEvaluationResult;
}>;
