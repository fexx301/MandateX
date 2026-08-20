import { createHash } from "node:crypto";

import { canonicalJson, canonicalSha256 } from "./canonical.js";
import {
  CATEGORY_ADAPTER_REGISTRY,
  MARKETPLACE_AAVE_HEALTH_ADAPTER,
  MARKETPLACE_GRID_ADAPTER,
  MARKETPLACE_HEALTH_EVIDENCE_SCHEMA,
  MARKETPLACE_GRID_EVIDENCE_SCHEMA,
  MARKETPLACE_VENUS_HEALTH_ADAPTER,
  MARKETPLACE_VENUS_HEALTH_EVIDENCE_SCHEMA,
  MARKETPLACE_YIELD_ADAPTER,
  MARKETPLACE_YIELD_EVIDENCE_SCHEMA,
  type MarketplaceCategoryAdapterId,
} from "./category-policy.js";
import { deepFreeze, type DeepReadonly } from "./immutable.js";
import {
  addressSchema,
  bytes32Schema,
  callIdSchema,
  canonicalIdentifierSchema,
  compareCanonicalStrings,
  sha256Schema,
  tickSchema,
  tokenIdSchema,
  uint256DecimalSchema,
  unixSecondsSchema,
} from "./primitives.js";
import { z } from "zod";

/**
 * Successor category contract primitives.
 *
 * This module is deliberately disconnected from the experimental condition
 * attestation path. It validates the production shape, but does not sign,
 * issue, deploy, or enable a category.
 */

export const MARKETPLACE_MANDATE_V2_SCHEMA =
  "mandatex.marketplace.mandate.v2" as const;
export const MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA =
  "mandatex.marketplace.category-quote-request.v1" as const;
export const MARKETPLACE_CATEGORY_CANDIDATE_IDENTITY_SCHEMA =
  "mandatex.marketplace.category-candidate-identity.v1" as const;
export const MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA =
  "mandatex.marketplace.category-target-observation.v1" as const;
export const MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA =
  "mandatex.marketplace.category-read-profile.v1" as const;
export const MARKETPLACE_CATEGORY_STATIC_READ_PROFILE_SCHEMA =
  "mandatex.marketplace.category-static-read-profile.v1" as const;
export const MARKETPLACE_CATEGORY_ACTION_PROFILE_SCHEMA =
  "mandatex.marketplace.category-action-profile.v1" as const;
export const MARKETPLACE_CATEGORY_ACTION_PROFILE_APPROVAL =
  "draft_unapproved" as const;
export const MARKETPLACE_CATEGORY_RELEASE_UNIT_SCHEMA =
  "mandatex.marketplace.category-release-unit.v1" as const;
export const MARKETPLACE_ACTIVE_CANDIDATE_REPORT_SCHEMA =
  "mandatex.marketplace.active-candidate-report.v1" as const;

export const serviceModeSchema = z.enum(["observe_only", "transactional"]);
export type CategoryServiceMode = z.infer<typeof serviceModeSchema>;

const nonNegativeSafeIntegerSchema = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER);

const bytes4Schema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{8}$/, "expected a four-byte selector")
  .transform((value) => value.toLowerCase());

const adapterIdSchema = z.union([
  z.literal(MARKETPLACE_GRID_ADAPTER),
  z.literal(MARKETPLACE_YIELD_ADAPTER),
  z.literal(MARKETPLACE_AAVE_HEALTH_ADAPTER),
  z.literal(MARKETPLACE_VENUS_HEALTH_ADAPTER),
]);

const categorySchema = z.enum(["grid", "yield", "health"]);

const positiveUint256DecimalSchema = uint256DecimalSchema.refine(
  (value) => value !== "0",
  "threshold must be greater than zero",
);

/**
 * Threshold units are part of the signed mandate scope.  They are deliberately
 * versioned literals so a future rescaling cannot be interpreted as the old
 * metric merely because the field name stayed the same.
 */
export const CATEGORY_THRESHOLD_UNITS = Object.freeze({
  gridTick: "uniswap-v3-tick",
  yieldSharePrice: "1e18-share-price",
  aaveHealthFactor: "1e18-health-factor",
  venusUsd: "1e18-usd",
} as const);

const ONE_E18 = 10n ** 18n;
const MAX_SCALED_RATIO = 10n ** 36n;
const MAX_VENUS_LIQUIDITY_SCALED = 10n ** 30n;

const boundedDecimal = (
  minimum: bigint,
  maximum: bigint,
  minimumMessage: string,
  maximumMessage: string,
) =>
  uint256DecimalSchema
    .refine((value) => BigInt(value) >= minimum, minimumMessage)
    .refine((value) => BigInt(value) <= maximum, maximumMessage);

const yieldSharePriceSchema = boundedDecimal(
  ONE_E18,
  MAX_SCALED_RATIO,
  "share-price threshold must be at least 1e18 scaled units",
  "share-price threshold exceeds the adapter admissible range",
);

const aaveHealthFactorSchema = boundedDecimal(
  ONE_E18 + 1n,
  MAX_SCALED_RATIO,
  "health-factor threshold must be above the 1e18 liquidation floor",
  "health-factor threshold exceeds the adapter admissible range",
);

const venusLiquiditySchema = boundedDecimal(
  1n,
  MAX_VENUS_LIQUIDITY_SCALED,
  "liquidity threshold must be positive",
  "liquidity threshold exceeds the adapter admissible range",
);

const candidateSelectorSchema = z
  .object({
    chainId: z.literal(56),
    tokenId: tokenIdSchema,
  })
  .strict();
export type CategoryCandidateSelector = DeepReadonly<
  z.infer<typeof candidateSelectorSchema>
>;

const gridCategoryScopeSchema = z
  .object({
    adapterId: z.literal(MARKETPLACE_GRID_ADAPTER),
    category: z.literal("grid"),
    evidenceSchema: z.literal(MARKETPLACE_GRID_EVIDENCE_SCHEMA),
    protocol: z.literal("pancakeswap-v3"),
    subject: z.object({ poolAddress: addressSchema }).strict(),
    conditionPolicy: z
      .object({
        unit: z.literal(CATEGORY_THRESHOLD_UNITS.gridTick),
        lowerTick: tickSchema,
        upperTick: tickSchema,
      })
      .strict()
      .superRefine((policy, context) => {
        if (policy.lowerTick >= policy.upperTick) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["upperTick"],
            message: "lowerTick must be less than upperTick",
          });
        }
      }),
  })
  .strict();

const yieldCategoryScopeSchema = z
  .object({
    adapterId: z.literal(MARKETPLACE_YIELD_ADAPTER),
    category: z.literal("yield"),
    evidenceSchema: z.literal(MARKETPLACE_YIELD_EVIDENCE_SCHEMA),
    protocol: z.literal("erc4626"),
    subject: z.object({ vaultAddress: addressSchema }).strict(),
    conditionPolicy: z
      .object({
        unit: z.literal(CATEGORY_THRESHOLD_UNITS.yieldSharePrice),
        minSharePriceScaled: yieldSharePriceSchema,
      })
      .strict(),
  })
  .strict();

const aaveCategoryScopeSchema = z
  .object({
    adapterId: z.literal(MARKETPLACE_AAVE_HEALTH_ADAPTER),
    category: z.literal("health"),
    evidenceSchema: z.literal(MARKETPLACE_HEALTH_EVIDENCE_SCHEMA),
    protocol: z.literal("aave-v3"),
    subject: z
      .object({ poolAddress: addressSchema, accountAddress: addressSchema })
      .strict(),
    conditionPolicy: z
      .object({
        unit: z.literal(CATEGORY_THRESHOLD_UNITS.aaveHealthFactor),
        minHealthFactorScaled: aaveHealthFactorSchema,
      })
      .strict(),
  })
  .strict();

const venusCategoryScopeSchema = z
  .object({
    adapterId: z.literal(MARKETPLACE_VENUS_HEALTH_ADAPTER),
    category: z.literal("health"),
    evidenceSchema: z.literal(MARKETPLACE_VENUS_HEALTH_EVIDENCE_SCHEMA),
    protocol: z.literal("venus"),
    subject: z
      .object({
        comptrollerAddress: addressSchema,
        accountAddress: addressSchema,
        borrowMarketAddress: addressSchema,
      })
      .strict(),
    conditionPolicy: z
      .object({
        unit: z.literal(CATEGORY_THRESHOLD_UNITS.venusUsd),
        minLiquidityUsdScaled: venusLiquiditySchema,
      })
      .strict(),
  })
  .strict();

export const categoryScopeSchema = z.discriminatedUnion("adapterId", [
  gridCategoryScopeSchema,
  yieldCategoryScopeSchema,
  aaveCategoryScopeSchema,
  venusCategoryScopeSchema,
]);
export type CategoryScope = DeepReadonly<z.infer<typeof categoryScopeSchema>>;

const actionPermissionSchema = z
  .object({
    actionId: canonicalIdentifierSchema,
    targetRole: canonicalIdentifierSchema,
    target: addressSchema,
    callId: callIdSchema,
    selector: bytes4Schema,
    maxValueWei: uint256DecimalSchema,
  })
  .strict();
export type CategoryActionPermission = DeepReadonly<
  z.infer<typeof actionPermissionSchema>
>;

function addUniqueSortedIssue(
  values: readonly { readonly actionId: string }[],
  context: z.RefinementCtx,
): void {
  const ids = values.map((value) => value.actionId);
  if (new Set(ids).size !== ids.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["actionPermissions"],
      message: "action permissions must have unique action IDs",
    });
  }
  const sorted = [...ids].sort();
  if (ids.some((id, index) => id !== sorted[index])) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["actionPermissions"],
      message: "action permissions must be in canonical action ID order",
    });
  }
}

const mandateV2Shape = {
  schema: z.literal(MARKETPLACE_MANDATE_V2_SCHEMA),
  mandateId: canonicalIdentifierSchema,
  category: categorySchema,
  adapterId: adapterIdSchema,
  chainId: z.literal(56),
  createdAt: unixSecondsSchema,
  expiresAt: unixSecondsSchema,
  maxClockSkewSeconds: z.number().int().min(0).max(300),
  maxEvidenceAgeSeconds: z.number().int().min(5).max(3_600),
  serviceMode: serviceModeSchema,
  categoryScope: categoryScopeSchema,
  actionPermissions: z.array(actionPermissionSchema).max(64),
  maxSpendUsdMicros: uint256DecimalSchema,
  permissionsExpiresAt: unixSecondsSchema,
} as const;

export const marketplaceMandateV2Schema = z
  .object(mandateV2Shape)
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
      mandate.permissionsExpiresAt <= mandate.createdAt ||
      mandate.permissionsExpiresAt > mandate.expiresAt
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["permissionsExpiresAt"],
        message: "permission expiry must be inside the mandate lifetime",
      });
    }
    if (mandate.category !== mandate.categoryScope.category) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categoryScope", "category"],
        message: "category scope category must match the mandate",
      });
    }
    if (mandate.adapterId !== mandate.categoryScope.adapterId) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapterId"],
        message: "adapter ID must match the category scope",
      });
    }
    addUniqueSortedIssue(mandate.actionPermissions, context);
    if (mandate.serviceMode === "observe_only") {
      if (mandate.actionPermissions.length !== 0) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["actionPermissions"],
          message: "observe-only mandates cannot grant action permissions",
        });
      }
      if (mandate.maxSpendUsdMicros !== "0") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["maxSpendUsdMicros"],
          message: "observe-only mandates must have a zero spend cap",
        });
      }
    } else if (mandate.actionPermissions.length === 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionPermissions"],
        message: "transactional mandates require explicit action permissions",
      });
    }
  });
export type MarketplaceMandateV2 = DeepReadonly<
  z.infer<typeof marketplaceMandateV2Schema>
>;

const categoryQuoteRequestShape = {
  schema: z.literal(MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA),
  requestId: canonicalIdentifierSchema,
  mandateId: canonicalIdentifierSchema,
  mandateSha256: sha256Schema,
  category: categorySchema,
  adapterId: adapterIdSchema,
  protocol: canonicalIdentifierSchema,
  categoryScope: categoryScopeSchema,
  categoryScopeSha256: sha256Schema,
  candidate: candidateSelectorSchema,
  serviceMode: serviceModeSchema,
  actionPermissions: z.array(actionPermissionSchema).max(64),
  actionPermissionsSha256: sha256Schema,
  maxSpendUsdMicros: uint256DecimalSchema,
  permissionsExpiresAt: unixSecondsSchema,
  nonce: canonicalIdentifierSchema,
  issuedAt: unixSecondsSchema,
  expiresAt: unixSecondsSchema,
} as const;

export const marketplaceCategoryQuoteRequestSchema = z
  .object(categoryQuoteRequestShape)
  .strict()
  .superRefine((request, context) => {
    if (request.category !== request.categoryScope.category) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categoryScope", "category"],
        message: "category scope category must match the request",
      });
    }
    if (request.adapterId !== request.categoryScope.adapterId) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapterId"],
        message: "adapter ID must match the category scope",
      });
    }
    if (request.protocol !== request.categoryScope.protocol) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["protocol"],
        message: "protocol must match the category scope",
      });
    }
    if (request.issuedAt >= request.expiresAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expiresAt"],
        message: "quote request expiry must follow issuance",
      });
    }
    if (
      request.permissionsExpiresAt <= request.issuedAt ||
      request.permissionsExpiresAt > request.expiresAt
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["permissionsExpiresAt"],
        message: "permission expiry must follow issuance and not exceed quote expiry",
      });
    }
    addUniqueSortedIssue(request.actionPermissions, context);
    if (request.serviceMode === "observe_only") {
      if (request.actionPermissions.length !== 0 || request.maxSpendUsdMicros !== "0") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["serviceMode"],
          message: "observe-only requests have no actions and zero spend",
        });
      }
    } else if (request.actionPermissions.length === 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionPermissions"],
        message: "transactional requests require explicit actions",
      });
    }
  });
export type MarketplaceCategoryQuoteRequest = DeepReadonly<
  z.infer<typeof marketplaceCategoryQuoteRequestSchema>
>;

/** Validate a request's duplicated mandate/scope fields against the mandate. */
export function validateCategoryQuoteRequestBinding(input: {
  readonly request: unknown;
  readonly mandate: unknown;
}): MarketplaceCategoryQuoteRequest {
  const mandate = parse(marketplaceMandateV2Schema, input.mandate, "mandate v2");
  const request = parse(
    marketplaceCategoryQuoteRequestSchema,
    input.request,
    "category quote request",
  );
  if (request.mandateId !== mandate.mandateId) fail("request mandate ID does not match mandate");
  if (request.mandateSha256 !== canonicalSha256(mandate)) fail("request mandate hash does not match mandate");
  if (request.category !== mandate.category || request.adapterId !== mandate.adapterId) {
    fail("request category identity does not match mandate");
  }
  if (request.protocol !== mandate.categoryScope.protocol) {
    fail("request protocol does not match mandate category scope");
  }
  if (canonicalJson(request.categoryScope) !== canonicalJson(mandate.categoryScope)) {
    fail("request category scope does not match mandate");
  }
  if (request.categoryScopeSha256 !== canonicalSha256(mandate.categoryScope)) {
    fail("request category scope hash does not match mandate");
  }
  if (request.serviceMode !== mandate.serviceMode) fail("request service mode does not match mandate");
  if (request.actionPermissionsSha256 !== canonicalSha256(request.actionPermissions)) {
    fail("request action permission hash does not match the requested permissions");
  }
  for (const requestedAction of request.actionPermissions) {
    const permittedAction = mandate.actionPermissions.find(
      (candidate) => candidate.actionId === requestedAction.actionId,
    );
    if (
      permittedAction === undefined ||
      permittedAction.targetRole !== requestedAction.targetRole ||
      permittedAction.target !== requestedAction.target ||
      permittedAction.callId !== requestedAction.callId ||
      permittedAction.selector !== requestedAction.selector ||
      BigInt(requestedAction.maxValueWei) > BigInt(permittedAction.maxValueWei)
    ) {
      fail(`requested action ${requestedAction.actionId} exceeds the mandate permission`);
    }
  }
  if (BigInt(request.maxSpendUsdMicros) > BigInt(mandate.maxSpendUsdMicros)) {
    fail("request spend cap exceeds mandate");
  }
  if (request.permissionsExpiresAt > mandate.permissionsExpiresAt) {
    fail("request permission expiry exceeds mandate");
  }
  if (request.permissionsExpiresAt <= request.issuedAt) {
    fail("request permission expiry must follow request issuance");
  }
  if (request.issuedAt < mandate.createdAt || request.expiresAt > mandate.expiresAt) {
    fail("request lifetime must be contained by mandate lifetime");
  }
  return deepFreeze(request);
}

const candidateIdentityShape = {
  schema: z.literal(MARKETPLACE_CATEGORY_CANDIDATE_IDENTITY_SCHEMA),
  chainId: z.literal(56),
  tokenId: tokenIdSchema,
  registryAddress: addressSchema,
  ownerAddress: addressSchema,
  observedBlock: nonNegativeSafeIntegerSchema,
  observedBlockHash: bytes32Schema,
  confirmationDepth: z.number().int().nonnegative().max(256),
  registryCodeSha256: sha256Schema,
  observedAt: unixSecondsSchema,
  identitySha256: sha256Schema,
} as const;

export const categoryCandidateIdentityArtifactSchema = z
  .object(candidateIdentityShape)
  .strict();
export type CategoryCandidateIdentityArtifact = DeepReadonly<
  z.infer<typeof categoryCandidateIdentityArtifactSchema>
>;

export function validateCandidateIdentityArtifact(input: unknown): CategoryCandidateIdentityArtifact {
  const artifact = parse(
    categoryCandidateIdentityArtifactSchema,
    input,
    "candidate identity artifact",
  );
  const { identitySha256, ...withoutDigest } = artifact;
  if (identitySha256 !== canonicalSha256(withoutDigest)) {
    fail("candidate identity digest does not match artifact");
  }
  return deepFreeze(artifact);
}

export function validateCandidateIdentityForSelector(input: {
  readonly artifact: unknown;
  readonly candidate: unknown;
}): CategoryCandidateIdentityArtifact {
  const artifact = validateCandidateIdentityArtifact(input.artifact);
  const candidate = parse(candidateSelectorSchema, input.candidate, "candidate selector");
  if (artifact.chainId !== candidate.chainId || artifact.tokenId !== candidate.tokenId) {
    fail("candidate identity artifact is bound to a different candidate");
  }
  return artifact;
}

const proxyObservationSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("none") }).strict(),
  z
    .object({
      kind: z.literal("eip1967"),
      implementationAddress: addressSchema,
      implementationCodeSha256: sha256Schema,
    })
    .strict(),
  z
    .object({
      kind: z.literal("beacon"),
      beaconAddress: addressSchema,
      beaconCodeSha256: sha256Schema,
      implementationAddress: addressSchema,
      implementationCodeSha256: sha256Schema,
    })
    .strict(),
  z
    .object({
      kind: z.literal("other-reviewed"),
      implementationAddress: addressSchema,
      implementationCodeSha256: sha256Schema,
    })
    .strict(),
]);

const targetProvenanceSchema = z
  .object({
    status: z.enum(["verified", "unendorsed"]),
    source: canonicalIdentifierSchema,
    proofSha256: sha256Schema,
  })
  .strict();

export const categoryTargetObservationSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_TARGET_OBSERVATION_SCHEMA),
    adapterId: adapterIdSchema,
    role: canonicalIdentifierSchema,
    targetAddress: addressSchema.refine(
      (value) => value !== "0x0000000000000000000000000000000000000000",
      "target address must be nonzero",
    ),
    assurance: z.enum(["protocol_instance_verified", "interface_only_unendorsed"]),
    runtimeCodeSha256: sha256Schema,
    proxy: proxyObservationSchema,
    provenance: targetProvenanceSchema,
    observedAt: unixSecondsSchema,
    observedBlock: nonNegativeSafeIntegerSchema,
    observedBlockHash: bytes32Schema,
  })
  .strict()
  .superRefine((target, context) => {
    const expectedStatus =
      target.assurance === "protocol_instance_verified" ? "verified" : "unendorsed";
    if (target.provenance.status !== expectedStatus) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["provenance", "status"],
        message: "provenance status must agree with target assurance",
      });
    }
    if (
      target.adapterId === MARKETPLACE_YIELD_ADAPTER &&
      target.assurance === "protocol_instance_verified"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["assurance"],
        message: "ERC-4626 targets are interface-only unless an approved provenance source is added",
      });
    }
    if (target.assurance === "protocol_instance_verified") {
      const source = verifiedProvenanceSource(target.adapterId);
      if (source === null || target.provenance.source !== source) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["provenance", "source"],
          message: "target provenance source is not approved for this adapter",
        });
      }
    }
  });
export type CategoryTargetObservation = DeepReadonly<
  z.infer<typeof categoryTargetObservationSchema>
>;

function expectedTargetsForScope(
  scope: CategoryScope,
): readonly Readonly<{ role: string; targetAddress: string }>[] {
  switch (scope.adapterId) {
    case MARKETPLACE_GRID_ADAPTER:
      return [{ role: "pool", targetAddress: scope.subject.poolAddress }];
    case MARKETPLACE_YIELD_ADAPTER:
      return [{ role: "vault", targetAddress: scope.subject.vaultAddress }];
    case MARKETPLACE_AAVE_HEALTH_ADAPTER:
      return [{ role: "pool", targetAddress: scope.subject.poolAddress }];
    case MARKETPLACE_VENUS_HEALTH_ADAPTER:
      return [
        { role: "borrowMarket", targetAddress: scope.subject.borrowMarketAddress },
        { role: "comptroller", targetAddress: scope.subject.comptrollerAddress },
      ];
  }
}

function targetIdentity(target: Readonly<{ role: string; targetAddress: string }>): string {
  return `${target.role}\u0000${target.targetAddress}`;
}

/** Bind contract observations to the mandate-selected targets; accounts are arguments. */
export function validateTargetObservationsForScope(input: {
  readonly scope: unknown;
  readonly targets: unknown;
}): readonly CategoryTargetObservation[] {
  const scope = parse(categoryScopeSchema, input.scope, "category scope");
  const targets = parse(
    z.array(categoryTargetObservationSchema).min(1).max(4),
    input.targets,
    "target observations",
  );
  const expected = expectedTargetsForScope(scope).map(targetIdentity);
  const actual = targets.map(targetIdentity);
  if (targets.some((target) => target.adapterId !== scope.adapterId)) {
    fail("target observations use a different adapter than the mandate scope");
  }
  if (new Set(actual).size !== actual.length) fail("target observations contain duplicates");
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail("target observations do not match the mandate-selected contract targets");
  }
  for (const target of targets) {
    if (target.assurance === "interface_only_unendorsed") {
      if (target.provenance.source !== "interface-only-unendorsed-v1") {
        fail("interface-only target provenance must use the unendorsed profile");
      }
      continue;
    }
    const expectedSource = verifiedProvenanceSource(scope.adapterId);
    if (expectedSource === null) {
      fail("this adapter has no approved protocol-instance provenance profile");
    }
    if (target.provenance.source !== expectedSource) {
      fail("verified target provenance does not match the adapter profile");
    }
  }
  return deepFreeze(targets);
}

function verifiedProvenanceSource(
  adapterId: MarketplaceCategoryAdapterId,
): string | null {
  switch (adapterId) {
    case MARKETPLACE_GRID_ADAPTER:
      return "pancakeswap-v3-factory-membership-v1";
    case MARKETPLACE_YIELD_ADAPTER:
      return null;
    case MARKETPLACE_AAVE_HEALTH_ADAPTER:
      return "aave-v3-addresses-provider-v1";
    case MARKETPLACE_VENUS_HEALTH_ADAPTER:
      return "venus-market-membership-v1";
  }
}

const readCommitmentSchema = z
  .object({
    role: canonicalIdentifierSchema,
    callId: callIdSchema,
    target: addressSchema,
    selector: bytes4Schema,
    argumentBindingSha256: sha256Schema,
    calldataSha256: sha256Schema,
    responseSha256: sha256Schema,
  })
  .strict();
export type CategoryReadCommitment = DeepReadonly<z.infer<typeof readCommitmentSchema>>;

export const categoryReadProfileSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_READ_PROFILE_SCHEMA),
    profileId: canonicalIdentifierSchema,
    adapterId: adapterIdSchema,
    reads: z.array(readCommitmentSchema).min(1).max(16),
  })
  .strict()
  .superRefine((profile, context) => {
    const keys = profile.reads.map(readCommitmentKey);
    if (new Set(keys).size !== keys.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reads"],
        message: "read commitments must be unique",
      });
    }
    const sorted = [...keys].sort();
    if (keys.some((key, index) => key !== sorted[index])) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reads"],
        message: "read commitments must use canonical order",
      });
    }
  });
export type CategoryReadProfile = DeepReadonly<z.infer<typeof categoryReadProfileSchema>>;

const staticReadDescriptorSchema = z
  .object({
    role: canonicalIdentifierSchema,
    callId: callIdSchema,
    selector: bytes4Schema,
    argumentBinding: z.enum(["none", "accountAddress"]),
  })
  .strict();

export const categoryStaticReadProfileSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_STATIC_READ_PROFILE_SCHEMA),
    profileId: canonicalIdentifierSchema,
    adapterId: adapterIdSchema,
    reads: z.array(staticReadDescriptorSchema).min(1).max(16),
  })
  .strict()
  .superRefine((profile, context) => {
    const keys = profile.reads.map(
      (read) => `${read.role}\u0000${read.callId}\u0000${read.selector}\u0000${read.argumentBinding}`,
    );
    if (new Set(keys).size !== keys.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reads"],
        message: "static read descriptors must be unique",
      });
    }
    const sorted = [...keys].sort(compareCanonicalStrings);
    if (keys.some((key, index) => key !== sorted[index])) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reads"],
        message: "static read descriptors must use canonical order",
      });
    }
  });
export type CategoryStaticReadProfile = DeepReadonly<
  z.infer<typeof categoryStaticReadProfileSchema>
>;

function readCommitmentKey(read: CategoryReadCommitment): string {
  return [
    read.role,
    read.callId,
    read.target,
    read.selector,
    read.argumentBindingSha256,
    read.calldataSha256,
    read.responseSha256,
  ].join("\u0000");
}

function canonicalReads(input: unknown): CategoryReadCommitment[] {
  const reads = parse(z.array(readCommitmentSchema).min(1).max(16), input, "read commitments");
  const keys = reads.map(readCommitmentKey);
  if (new Set(keys).size !== keys.length) fail("read commitments must be unique");
  return [...reads].sort((left, right) =>
    compareCanonicalStrings(readCommitmentKey(left), readCommitmentKey(right)),
  );
}

/** Compare the exact set of reads; array order is intentionally irrelevant. */
export function validateExactReadCommitments(input: {
  readonly expected: unknown;
  readonly actual: unknown;
}): true {
  const expected = canonicalReads(input.expected);
  const actual = canonicalReads(input.actual);
  if (canonicalJson(expected) !== canonicalJson(actual)) {
    fail("executed reads do not exactly match the committed read profile");
  }
  return true;
}

export const assertExactReadCommitments = validateExactReadCommitments;

const categoryReadDescriptors = {
  [MARKETPLACE_GRID_ADAPTER]: {
    profileId: "pancakeswap-v3-grid-observation-v1",
    reads: [{ role: "pool", callId: "slot0()", selector: "0x3850c7bd" }],
  },
  [MARKETPLACE_YIELD_ADAPTER]: {
    profileId: "erc4626-yield-observation-v1",
    reads: [
      { role: "vault", callId: "totalAssets()", selector: "0x01e1d114" },
      { role: "vault", callId: "totalSupply()", selector: "0x18160ddd" },
    ],
  },
  [MARKETPLACE_AAVE_HEALTH_ADAPTER]: {
    profileId: "aave-v3-health-observation-v1",
    reads: [
      {
        role: "pool",
        callId: "getUserAccountData(address)",
        selector: "0xbf92857c",
      },
    ],
  },
  [MARKETPLACE_VENUS_HEALTH_ADAPTER]: {
    profileId: "venus-health-observation-v1",
    reads: [
      {
        role: "borrowMarket",
        callId: "borrowBalanceStored(address)",
        selector: "0x95dd9193",
      },
      {
        role: "comptroller",
        callId: "getAccountLiquidity(address)",
        selector: "0x5ec88c79",
      },
      {
        role: "comptroller",
        callId: "getAssetsIn(address)",
        selector: "0xabfceffc",
      },
    ],
  },
} as const satisfies Readonly<
  Record<
    MarketplaceCategoryAdapterId,
    Readonly<{
      profileId: string;
      reads: readonly Readonly<{ role: string; callId: string; selector: string }>[];
    }>
  >
>;

export const CATEGORY_PRODUCTION_READ_DESCRIPTORS = deepFreeze(
  categoryReadDescriptors,
);

/** Return the immutable, target-independent read profile for one adapter. */
export function categoryStaticReadProfileForAdapter(
  adapterId: MarketplaceCategoryAdapterId,
): CategoryStaticReadProfile {
  const descriptor = CATEGORY_PRODUCTION_READ_DESCRIPTORS[adapterId];
  return deepFreeze(
    categoryStaticReadProfileSchema.parse({
      schema: MARKETPLACE_CATEGORY_STATIC_READ_PROFILE_SCHEMA,
      profileId: descriptor.profileId,
      adapterId,
      reads: descriptor.reads.map((read) => ({
        role: read.role,
        callId: read.callId,
        selector: read.selector,
        argumentBinding:
          adapterId === MARKETPLACE_AAVE_HEALTH_ADAPTER ||
          adapterId === MARKETPLACE_VENUS_HEALTH_ADAPTER
            ? ("accountAddress" as const)
            : ("none" as const),
      })),
    }),
  );
}

export function categoryStaticReadProfileForAdapterSha256(
  adapterId: MarketplaceCategoryAdapterId,
): string {
  return canonicalSha256(categoryStaticReadProfileForAdapter(adapterId));
}

/**
 * Projects a concrete observation profile into the static definition that a
 * release may safely pin. Targets, argument values, calldata digests, and RPC
 * response digests are intentionally excluded from this projection; those are
 * mandate- and block-specific evidence commitments.
 */
export function categoryStaticReadProfile(input: unknown): CategoryStaticReadProfile {
  const profile = parse(categoryReadProfileSchema, input, "category read profile");
  const descriptor = CATEGORY_PRODUCTION_READ_DESCRIPTORS[profile.adapterId];
  if (profile.profileId !== descriptor.profileId) {
    fail("read profile ID does not match the adapter's static profile");
  }
  const staticReads = descriptor.reads.map((read) => ({
    role: read.role,
    callId: read.callId,
    selector: read.selector,
    argumentBinding:
      profile.adapterId === MARKETPLACE_AAVE_HEALTH_ADAPTER ||
      profile.adapterId === MARKETPLACE_VENUS_HEALTH_ADAPTER
        ? ("accountAddress" as const)
        : ("none" as const),
  }));
  return deepFreeze(
    categoryStaticReadProfileSchema.parse({
      schema: MARKETPLACE_CATEGORY_STATIC_READ_PROFILE_SCHEMA,
      profileId: profile.profileId,
      adapterId: profile.adapterId,
      reads: staticReads,
    }),
  );
}

export function categoryStaticReadProfileSha256(input: unknown): string {
  return canonicalSha256(categoryStaticReadProfile(input));
}

/** Digest of the concrete per-observation read commitments. */
export function categoryReadCommitmentsSha256(input: unknown): string {
  const profile = parse(categoryReadProfileSchema, input, "category read profile");
  return canonicalSha256(profile.reads);
}

/** Require the exact profile, target, selector, and scope-derived calldata. */
export function validateAdapterReadProfile(input: {
  readonly profile: unknown;
  readonly scope: unknown;
}): CategoryReadProfile {
  const profile = parse(categoryReadProfileSchema, input.profile, "category read profile");
  const scope = parse(categoryScopeSchema, input.scope, "category scope");
  if (profile.adapterId !== scope.adapterId) {
    fail("read profile adapter does not match category scope");
  }
  const descriptor = CATEGORY_PRODUCTION_READ_DESCRIPTORS[profile.adapterId];
  if (profile.profileId !== descriptor.profileId) {
    fail("read profile ID does not match the adapter profile");
  }
  const expected = expectedReadsForScope(scope);
  const actual = profile.reads.map(
    ({ role, callId, target, selector, argumentBindingSha256, calldataSha256 }) => ({
      role,
      callId,
      target,
      selector,
      argumentBindingSha256,
      calldataSha256,
    }),
  );
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail("read profile does not match the adapter's exact scope-bound reads");
  }
  return deepFreeze(profile);
}

function expectedReadsForScope(scope: CategoryScope) {
  const descriptor = CATEGORY_PRODUCTION_READ_DESCRIPTORS[scope.adapterId];
  return descriptor.reads.map((read) => {
    const target = expectedTargetsForScope(scope).find(
      (candidate) => candidate.role === read.role,
    );
    if (target === undefined) fail(`read role ${read.role} has no scope target`);
    const accountAddress =
      scope.adapterId === MARKETPLACE_AAVE_HEALTH_ADAPTER ||
      scope.adapterId === MARKETPLACE_VENUS_HEALTH_ADAPTER
        ? scope.subject.accountAddress
        : undefined;
    const argumentBinding =
      accountAddress === undefined ? [] : [{ name: "accountAddress", value: accountAddress }];
    return {
      role: read.role,
      callId: read.callId,
      target: target.targetAddress,
      selector: read.selector,
      argumentBindingSha256: canonicalSha256(argumentBinding),
      calldataSha256: categoryReadCalldataSha256(read.selector, accountAddress),
    };
  });
}

export function categoryReadCalldataSha256(
  selector: string,
  accountAddress?: string,
): string {
  const selectorHex = selector.slice(2);
  const argumentHex =
    accountAddress === undefined ? "" : `${"00".repeat(12)}${accountAddress.slice(2)}`;
  return createHash("sha256")
    .update(Buffer.from(`${selectorHex}${argumentHex}`, "hex"))
    .digest("hex");
}

export function categoryReadArgumentBindingSha256(accountAddress?: string): string {
  const argumentBinding =
    accountAddress === undefined ? [] : [{ name: "accountAddress", value: accountAddress }];
  return canonicalSha256(argumentBinding);
}

const actionProfileEntrySchema = z
  .object({
    actionId: canonicalIdentifierSchema,
    targetRole: canonicalIdentifierSchema,
    callId: callIdSchema,
    selector: bytes4Schema,
    maxValueWei: uint256DecimalSchema,
  })
  .strict();

export const categoryActionProfileSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_ACTION_PROFILE_SCHEMA),
    approval: z.literal(MARKETPLACE_CATEGORY_ACTION_PROFILE_APPROVAL),
    profileId: canonicalIdentifierSchema,
    adapterId: adapterIdSchema,
    serviceMode: z.literal("transactional"),
    actions: z.array(actionProfileEntrySchema).min(1).max(64),
  })
  .strict()
  .superRefine((profile, context) => {
    const ids = profile.actions.map((action) => action.actionId);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actions"],
        message: "action profile IDs must be unique",
      });
    }
  });
export type CategoryActionProfile = DeepReadonly<z.infer<typeof categoryActionProfileSchema>>;

/** Structural draft coverage only; it is not an approved production action profile. */
export function validateActionCoverage(input: {
  readonly adapterId: MarketplaceCategoryAdapterId;
  readonly serviceMode: CategoryServiceMode;
  readonly mandatePermissions: unknown;
  readonly quotedPermissions: unknown;
  readonly mandateSpendCapUsdMicros: string;
  readonly quotedSpendCapUsdMicros: string;
  readonly actionProfile?: unknown;
}): true {
  const mandateSpendCap = parse(
    uint256DecimalSchema,
    input.mandateSpendCapUsdMicros,
    "mandate spend cap",
  );
  const quotedSpendCap = parse(
    uint256DecimalSchema,
    input.quotedSpendCapUsdMicros,
    "quoted spend cap",
  );
  const mandate = parse(z.array(actionPermissionSchema).max(64), input.mandatePermissions, "mandate action permissions");
  const quoted = parse(z.array(actionPermissionSchema).max(64), input.quotedPermissions, "quoted action permissions");
  if (input.serviceMode === "observe_only") {
    if (mandate.length !== 0 || quoted.length !== 0 || quotedSpendCap !== "0") {
      fail("observe-only service must have no actions and zero spend");
    }
    return true;
  }
  if (quoted.length === 0) fail("transactional service requires quoted actions");
  const profile = parse(categoryActionProfileSchema, input.actionProfile, "transactional action profile");
  if (profile.serviceMode !== "transactional") fail("action profile mode is invalid");
  if (profile.adapterId !== input.adapterId) fail("action profile adapter does not match the quote");
  if (BigInt(quotedSpendCap) > BigInt(mandateSpendCap)) {
    fail("quoted spend cap exceeds the mandate spend cap");
  }
  for (const action of quoted) {
    const mandateAction = mandate.find((candidate) => candidate.actionId === action.actionId);
    if (mandateAction === undefined) fail(`quoted action ${action.actionId} is not granted by the mandate`);
    if (
      mandateAction.targetRole !== action.targetRole ||
      mandateAction.target !== action.target ||
      mandateAction.callId !== action.callId ||
      mandateAction.selector !== action.selector ||
      BigInt(action.maxValueWei) > BigInt(mandateAction.maxValueWei)
    ) {
      fail(`quoted action ${action.actionId} exceeds the mandate permission`);
    }
    const profileAction = profile.actions.find((candidate) => candidate.actionId === action.actionId);
    if (
      profileAction === undefined ||
      profileAction.targetRole !== action.targetRole ||
      profileAction.callId !== action.callId ||
      profileAction.selector !== action.selector ||
      BigInt(action.maxValueWei) > BigInt(profileAction.maxValueWei)
    ) {
      fail(`quoted action ${action.actionId} is not covered by the adapter profile`);
    }
  }
  return true;
}

const candidateAcceptanceShape = {
  relation: z.literal("candidate_accepts_service_for_subject"),
  requestId: canonicalIdentifierSchema,
  mandateId: canonicalIdentifierSchema,
  category: categorySchema,
  adapterId: adapterIdSchema,
  protocol: canonicalIdentifierSchema,
  candidate: candidateSelectorSchema,
  candidateIdentitySha256: sha256Schema,
  providerAddress: addressSchema,
  providerKind: z.enum(["eoa", "erc1271"]),
  signatureMethod: z.enum(["eip191", "erc1271"]),
  quoteRequestSha256: sha256Schema,
  quoteResponseSha256: sha256Schema,
  negotiationSha256: sha256Schema,
  subjectSha256: sha256Schema,
  conditionPolicySha256: sha256Schema,
  serviceMode: serviceModeSchema,
  quoteExpiresAt: unixSecondsSchema,
} as const;

export const candidateAcceptanceSchema = z
  .object(candidateAcceptanceShape)
  .strict()
  .superRefine((acceptance, context) => {
    if (
      (acceptance.providerKind === "eoa" && acceptance.signatureMethod !== "eip191") ||
      (acceptance.providerKind === "erc1271" && acceptance.signatureMethod !== "erc1271")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["signatureMethod"],
        message: "signature method must match the provider kind",
      });
    }
  });
export type CandidateAcceptance = DeepReadonly<z.infer<typeof candidateAcceptanceSchema>>;

export function validateCandidateAcceptanceBinding(input: {
  readonly acceptance: unknown;
  readonly request: unknown;
  readonly identityArtifact: unknown;
}): CandidateAcceptance {
  const acceptance = parse(candidateAcceptanceSchema, input.acceptance, "candidate acceptance");
  const request = parse(marketplaceCategoryQuoteRequestSchema, input.request, "category quote request");
  const identity = validateCandidateIdentityForSelector({
    artifact: input.identityArtifact,
    candidate: request.candidate,
  });
  if (acceptance.quoteRequestSha256 !== canonicalSha256(request)) fail("candidate acceptance is for a different quote request");
  if (acceptance.requestId !== request.requestId || acceptance.mandateId !== request.mandateId) {
    fail("candidate acceptance request identity does not match");
  }
  if (acceptance.category !== request.category || acceptance.adapterId !== request.adapterId) {
    fail("candidate acceptance adapter identity does not match request");
  }
  if (acceptance.protocol !== request.protocol) {
    fail("candidate acceptance protocol does not match request");
  }
  if (acceptance.candidate.chainId !== request.candidate.chainId || acceptance.candidate.tokenId !== request.candidate.tokenId) {
    fail("candidate acceptance is for a different candidate");
  }
  if (acceptance.serviceMode !== request.serviceMode) fail("candidate acceptance mode does not match request");
  if (acceptance.candidateIdentitySha256 !== identity.identitySha256) {
    fail("candidate acceptance identity binding does not match verifier-owned identity");
  }
  if (acceptance.providerAddress !== identity.ownerAddress) {
    fail("candidate acceptance provider does not match verifier-observed identity owner");
  }
  if (acceptance.subjectSha256 !== canonicalSha256(request.categoryScope.subject)) fail("candidate acceptance subject binding does not match request");
  if (acceptance.conditionPolicySha256 !== canonicalSha256(request.categoryScope.conditionPolicy)) fail("candidate acceptance condition policy binding does not match request");
  if (acceptance.quoteExpiresAt > request.expiresAt) fail("candidate acceptance expires after the quote request");
  return deepFreeze(acceptance);
}

const observationReceiptSchema = z
  .object({
    status: z.literal("pass"),
    targetsSha256: sha256Schema,
    readProfile: categoryReadProfileSchema,
    artifactSha256: sha256Schema,
    evidenceSha256: sha256Schema,
    observedAt: unixSecondsSchema,
    observedBlock: nonNegativeSafeIntegerSchema,
    observedBlockHash: bytes32Schema,
  })
  .strict();

const activePreviewSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("not_applicable") }).strict(),
  z
    .object({
      status: z.literal("passed"),
      observedAt: unixSecondsSchema,
      observedBlock: nonNegativeSafeIntegerSchema,
      observedBlockHash: bytes32Schema,
    })
    .strict(),
  z.object({ status: z.literal("failed"), code: canonicalIdentifierSchema }).strict(),
  z.object({ status: z.literal("unavailable") }).strict(),
]);

const activeCandidateReportShape = {
  schema: z.literal(MARKETPLACE_ACTIVE_CANDIDATE_REPORT_SCHEMA),
  status: z.enum(["VERIFIED_HIREABLE", "INELIGIBLE", "INCONCLUSIVE", "UNAVAILABLE"]),
  scope: z.literal("evaluation_only"),
  activationAuthorization: z.literal("none"),
  reservation: z.literal("none"),
  replayPolicy: z.literal("reusable_until_expiry"),
  verifierPolicySha256: sha256Schema,
  categoryDeploymentSha256: sha256Schema,
  requestId: canonicalIdentifierSchema,
  mandateId: canonicalIdentifierSchema,
  category: categorySchema,
  adapterId: adapterIdSchema,
  protocol: canonicalIdentifierSchema,
  categoryScope: categoryScopeSchema,
  categoryScopeSha256: sha256Schema,
  candidate: candidateSelectorSchema,
  mandate: marketplaceMandateV2Schema,
  quoteRequest: marketplaceCategoryQuoteRequestSchema,
  candidateIdentity: categoryCandidateIdentityArtifactSchema,
  candidateIdentitySha256: sha256Schema,
  acceptance: candidateAcceptanceSchema,
  serviceMode: serviceModeSchema,
  targets: z.array(categoryTargetObservationSchema).min(1).max(4),
  observation: observationReceiptSchema,
  actionCoverage: z.enum(["complete", "none", "incomplete", "not_applicable"]),
  preview: activePreviewSchema,
  attestationExpiresAt: unixSecondsSchema,
  maxIdentityAgeSeconds: z.number().int().min(1).max(3_600),
  validUntil: unixSecondsSchema,
  evaluatedAt: unixSecondsSchema,
} as const;

export const activeCandidateReportSchema = z
  .object(activeCandidateReportShape)
  .strict()
  .superRefine((report, context) => {
    const registryEntry = CATEGORY_ADAPTER_REGISTRY[report.adapterId as MarketplaceCategoryAdapterId];
    if (registryEntry === undefined || registryEntry.category !== report.category) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapterId"],
        message: "report adapter/category pair is not registered",
      });
    }
    try {
      validateCategoryQuoteRequestBinding({
        request: report.quoteRequest,
        mandate: report.mandate,
      });
    } catch {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["quoteRequest"],
        message: "report quote request is not bound to its mandate",
      });
    }
    try {
      validateCandidateAcceptanceBinding({
        acceptance: report.acceptance,
        request: report.quoteRequest,
        identityArtifact: report.candidateIdentity,
      });
    } catch {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["acceptance"],
        message: "report candidate acceptance is not bound to verifier-owned identity",
      });
    }
    if (
      report.requestId !== report.quoteRequest.requestId ||
      report.mandateId !== report.mandate.mandateId ||
      report.category !== report.mandate.category ||
      report.adapterId !== report.mandate.adapterId ||
      report.protocol !== report.mandate.categoryScope.protocol ||
      report.serviceMode !== report.mandate.serviceMode ||
      report.candidate.chainId !== report.quoteRequest.candidate.chainId ||
      report.candidate.tokenId !== report.quoteRequest.candidate.tokenId
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["requestId"],
        message: "report display identity must match its mandate and quote request",
      });
    }
    if (
      canonicalJson(report.categoryScope) !==
      canonicalJson(report.mandate.categoryScope)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categoryScope"],
        message: "report category scope must be the mandate category scope",
      });
    }
    if (
      report.candidateIdentitySha256 !== report.candidateIdentity.identitySha256 ||
      report.acceptance.candidateIdentitySha256 !== report.candidateIdentity.identitySha256
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["candidateIdentitySha256"],
        message: "report identity hashes must bind the verifier-owned identity artifact",
      });
    }
    if (
      report.categoryScope.category !== report.category ||
      report.categoryScope.adapterId !== report.adapterId ||
      report.categoryScope.protocol !== report.protocol
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categoryScope"],
        message: "report category scope must match the registered adapter identity",
      });
    }
    if (report.categoryScopeSha256 !== canonicalSha256(report.categoryScope)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categoryScopeSha256"],
        message: "report category scope hash does not match",
      });
    }
    if (
      report.acceptance.subjectSha256 !== canonicalSha256(report.categoryScope.subject) ||
      report.acceptance.conditionPolicySha256 !==
        canonicalSha256(report.categoryScope.conditionPolicy)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["acceptance"],
        message: "candidate acceptance must bind the report subject and condition policy",
      });
    }
    const targetKeys = report.targets.map((target) => `${target.role}\u0000${target.targetAddress}`);
    if (new Set(targetKeys).size !== targetKeys.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["targets"],
        message: "target observations must have unique role/address pairs",
      });
    }
    const sortedTargetKeys = [...targetKeys].sort(compareCanonicalStrings);
    if (targetKeys.some((key, index) => key !== sortedTargetKeys[index])) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["targets"],
        message: "target observations must use canonical role/address order",
      });
    }
    if (report.observation.targetsSha256 !== canonicalSha256(report.targets)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["observation", "targetsSha256"],
        message: "observation target hash must bind every target observation",
      });
    }
    for (const target of report.targets) {
      if (
        target.observedAt !== report.observation.observedAt ||
        target.observedBlock !== report.observation.observedBlock ||
        target.observedBlockHash !== report.observation.observedBlockHash
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["targets"],
          message: "target identity and category observation must share one block anchor",
        });
        break;
      }
    }
    for (const read of report.observation.readProfile.reads) {
      if (
        !report.targets.some(
          (target) => target.role === read.role && target.targetAddress === read.target,
        )
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["observation", "readProfile", "reads"],
          message: "every adapter read must use an observed mandate target",
        });
        break;
      }
    }
    try {
      validateTargetObservationsForScope({
        scope: report.categoryScope,
        targets: report.targets,
      });
    } catch {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["targets"],
        message: "target observations do not match the report category scope",
      });
    }
    if (report.observation.readProfile.adapterId !== report.adapterId) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["observation", "readProfile", "adapterId"],
        message: "observation read profile must match the report adapter",
      });
    } else {
      try {
        validateAdapterReadProfile({
          profile: report.observation.readProfile,
          scope: report.categoryScope,
        });
      } catch {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["observation", "readProfile"],
          message: "observation does not use the adapter's exact read profile",
        });
      }
    }
    if (report.acceptance.serviceMode !== report.serviceMode) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["acceptance", "serviceMode"],
        message: "acceptance mode must match report mode",
      });
    }
    const identityExpiresAt =
      report.candidateIdentity.observedAt + report.maxIdentityAgeSeconds + 1;
    let expectedValidUntil: number | undefined;
    try {
      expectedValidUntil = computeCategoryValidUntil({
        attestationExpiresAt: report.attestationExpiresAt,
        quoteExpiresAt: report.acceptance.quoteExpiresAt,
        mandateExpiresAt: report.mandate.expiresAt,
        permissionExpiresAt: report.quoteRequest.permissionsExpiresAt,
        identityExpiresAt,
        evidenceObservedAt: report.observation.observedAt,
        maxEvidenceAgeSeconds: report.mandate.maxEvidenceAgeSeconds,
      });
    } catch {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["validUntil"],
        message: "report validity boundaries are invalid",
      });
    }
    if (expectedValidUntil !== undefined && report.validUntil !== expectedValidUntil) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["validUntil"],
        message: "validUntil must equal the earliest successor validity boundary",
      });
    }
    if (report.status === "VERIFIED_HIREABLE") {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["status"],
        message:
          "VERIFIED_HIREABLE remains dormant until a signed successor evaluator owns issuance",
      });
    }
    if (report.serviceMode === "observe_only") {
      if (report.actionCoverage !== "not_applicable" || report.preview.status !== "not_applicable") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["serviceMode"],
          message: "observe-only reports require not_applicable action and preview fields",
        });
      }
    } else if (report.preview.status === "not_applicable") {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["preview"],
        message: "transactional reports require a preview result",
      });
    }
  });
export type ActiveCandidateReport = DeepReadonly<
  z.infer<typeof activeCandidateReportSchema>
>;

export function validateActiveCandidateReport(input: unknown): ActiveCandidateReport {
  return deepFreeze(parse(activeCandidateReportSchema, input, "active candidate report"));
}

const releaseUnitShape = {
  schema: z.literal(MARKETPLACE_CATEGORY_RELEASE_UNIT_SCHEMA),
  adapterId: adapterIdSchema,
  category: categorySchema,
  serviceMode: serviceModeSchema,
  enabled: z.boolean(),
  verifierPolicySha256: sha256Schema,
  categoryDeploymentSha256: sha256Schema,
  quoteSchema: z.literal(MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA),
  readProfileId: canonicalIdentifierSchema,
  readProfileSha256: sha256Schema,
  actionProfileId: canonicalIdentifierSchema.nullable(),
  actionProfileSha256: sha256Schema.nullable(),
  minimumTargetAssurance: z.enum([
    "interface_only_unendorsed",
    "protocol_instance_verified",
  ]),
} as const;

export const categoryReleaseUnitSchema = z
  .object(releaseUnitShape)
  .strict()
  .superRefine((unit, context) => {
    const entry = CATEGORY_ADAPTER_REGISTRY[unit.adapterId as MarketplaceCategoryAdapterId];
    if (entry === undefined || entry.category !== unit.category) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapterId"],
        message: "release unit adapter/category pair is not registered",
      });
    }
    const descriptor = CATEGORY_PRODUCTION_READ_DESCRIPTORS[
      unit.adapterId as MarketplaceCategoryAdapterId
    ];
    if (unit.readProfileId !== descriptor.profileId) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["readProfileId"],
        message: "release unit read profile ID does not match the adapter",
      });
    }
    if (
      unit.readProfileSha256 !==
      categoryStaticReadProfileForAdapterSha256(
        unit.adapterId as MarketplaceCategoryAdapterId,
      )
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["readProfileSha256"],
        message: "release unit read profile hash does not match the adapter",
      });
    }
    if (
      unit.serviceMode === "observe_only" &&
      (unit.actionProfileId !== null || unit.actionProfileSha256 !== null)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionProfileId"],
        message: "observe-only release units cannot advertise an action profile",
      });
    }
    if (
      unit.actionProfileId === null !== (unit.actionProfileSha256 === null)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionProfileSha256"],
        message: "action profile ID and hash must be present or absent together",
      });
    }
    if (
      unit.enabled &&
      unit.serviceMode === "transactional" &&
      unit.actionProfileId === null
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionProfileId"],
        message: "transactional release units require an action profile",
      });
    }
    if (
      unit.enabled &&
      unit.serviceMode === "transactional" &&
      unit.minimumTargetAssurance !== "protocol_instance_verified"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["minimumTargetAssurance"],
        message: "enabled transactional release units require protocol-instance assurance",
      });
    }
  });
export type CategoryReleaseUnit = DeepReadonly<z.infer<typeof categoryReleaseUnitSchema>>;

export function validateCategoryReleaseUnits(
  input: unknown,
  options: { readonly requireCompleteMatrix?: boolean } = {},
): readonly CategoryReleaseUnit[] {
  const units = parse(z.array(categoryReleaseUnitSchema).min(1).max(8), input, "category release units");
  const keys = units.map((unit) => `${unit.adapterId}\u0000${unit.serviceMode}`);
  if (new Set(keys).size !== keys.length) fail("release units must be unique by adapterId and serviceMode");
  if (options.requireCompleteMatrix === true) {
    for (const adapterId of [
      MARKETPLACE_GRID_ADAPTER,
      MARKETPLACE_YIELD_ADAPTER,
      MARKETPLACE_AAVE_HEALTH_ADAPTER,
      MARKETPLACE_VENUS_HEALTH_ADAPTER,
    ] as const) {
      for (const serviceMode of ["observe_only", "transactional"] as const) {
        if (!keys.includes(`${adapterId}\u0000${serviceMode}`)) {
          fail(`release matrix is missing ${adapterId} x ${serviceMode}`);
        }
      }
    }
  }
  return deepFreeze(units);
}

export type CategoryValidityBoundaries = Readonly<{
  attestationExpiresAt: number;
  quoteExpiresAt: number;
  mandateExpiresAt: number;
  permissionExpiresAt: number;
  identityExpiresAt: number;
  evidenceObservedAt: number;
  maxEvidenceAgeSeconds: number;
}>;

const validityBoundariesSchema = z
  .object({
    attestationExpiresAt: unixSecondsSchema,
    quoteExpiresAt: unixSecondsSchema,
    mandateExpiresAt: unixSecondsSchema,
    permissionExpiresAt: unixSecondsSchema,
    identityExpiresAt: unixSecondsSchema,
    evidenceObservedAt: unixSecondsSchema,
    maxEvidenceAgeSeconds: z.number().int().min(1).max(3_600),
  })
  .strict();

export function computeCategoryValidUntil(input: unknown): number {
  const boundaries = parse(validityBoundariesSchema, input, "validity boundaries");
  const evidenceExpiry =
    boundaries.evidenceObservedAt + boundaries.maxEvidenceAgeSeconds + 1;
  if (!Number.isSafeInteger(evidenceExpiry)) fail("evidence freshness boundary exceeds safe time range");
  return Math.min(
    boundaries.attestationExpiresAt,
    boundaries.quoteExpiresAt,
    boundaries.mandateExpiresAt,
    boundaries.permissionExpiresAt,
    boundaries.identityExpiresAt,
    evidenceExpiry,
  );
}

export function remainingCategoryValiditySeconds(validUntil: number, evaluatedAt: number): number {
  if (!Number.isSafeInteger(validUntil) || !Number.isSafeInteger(evaluatedAt) || evaluatedAt < 0) {
    throw new TypeError("validity times must be safe integers");
  }
  return Math.max(0, validUntil - evaluatedAt);
}

export function hasMinimumCategoryValidity(
  validUntil: number,
  evaluatedAt: number,
  minimumRemainingSeconds: number,
): boolean {
  if (!Number.isSafeInteger(minimumRemainingSeconds) || minimumRemainingSeconds < 0) {
    throw new TypeError("minimum remaining validity must be a nonnegative safe integer");
  }
  return remainingCategoryValiditySeconds(validUntil, evaluatedAt) >= minimumRemainingSeconds;
}

export function assertMinimumCategoryValidity(input: {
  readonly validUntil: number;
  readonly evaluatedAt: number;
  readonly minimumRemainingSeconds: number;
}): true {
  if (!hasMinimumCategoryValidity(input.validUntil, input.evaluatedAt, input.minimumRemainingSeconds)) {
    fail("category report does not have the configured minimum remaining validity");
  }
  return true;
}

function parse<T>(schema: z.ZodType<T>, input: unknown, label: string): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new TypeError(`${label} is invalid: ${result.error.message}`);
  }
  return result.data;
}

function fail(message: string): never {
  throw new TypeError(message);
}
