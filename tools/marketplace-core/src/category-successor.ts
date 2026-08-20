import {
  createHash,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import { TextDecoder } from "node:util";

import { z } from "zod";

import { canonicalJson, canonicalSha256 } from "./canonical.js";
import {
  MAX_CATEGORY_IDENTITY_AGE_SECONDS,
  categoryLinkageProjectionSchema,
  validateCategoryLinkageProjection,
  type UntrustedCategoryLinkageProjection,
} from "./category-linkage.js";
import {
  categoryActionProfileSchema,
  categoryCandidateIdentityArtifactSchema,
  categoryReadProfileSchema,
  categoryReadCommitmentsSha256,
  categoryStaticReadProfileSha256,
  categoryTargetObservationSchema,
  marketplaceMandateV2Schema,
  validateActionCoverage,
  validateAdapterReadProfile,
  validateCandidateIdentityForSelector,
  validateCategoryQuoteRequestBinding,
  validateTargetObservationsForScope,
  type CategoryActionProfile,
  type CategoryCandidateIdentityArtifact,
  type CategoryReadProfile,
  type CategoryTargetObservation,
  type MarketplaceCategoryQuoteRequest,
  type MarketplaceMandateV2,
} from "./category-production.js";
import { deepFreeze, type DeepReadonly } from "./immutable.js";
import {
  addressSchema,
  bytes32Schema,
  canonicalIdentifierSchema,
  sha256Schema,
  unixSecondsSchema,
} from "./primitives.js";
import {
  MAX_MARKETPLACE_TRUST_BUNDLE_TTL_SECONDS,
  assertMarketplaceTrustResolvedTuple,
  resolveMarketplaceTrustBundleAttestationTuple,
  type MarketplaceTrustResolvedTuple,
  type VerifiedMarketplaceTrustBundle,
} from "./trust-bundle.js";
import {
  resolveMarketplaceCategoryTrustCommitment,
  type MarketplaceCategoryTrustCommitment,
} from "./category-trust-controller.js";

export const MARKETPLACE_CATEGORY_QUOTE_PROJECTION_SCHEMA =
  "mandatex.marketplace.category-quote-projection.v1" as const;
export const MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA =
  "mandatex.marketplace.category-quote-attestation.v1" as const;
export const MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE =
  "mandatex-ed25519-category-quote-v1" as const;
export const MARKETPLACE_CATEGORY_QUOTE_ISSUER =
  "mandatex-category-quote-verifier" as const;
export const MARKETPLACE_CATEGORY_QUOTE_AUDIENCE =
  "mandatex-marketplace-core-category" as const;
export const MARKETPLACE_CATEGORY_QUOTE_SIGNING_DOMAIN =
  "MandateX Marketplace Category Quote Attestation v1\0" as const;
export const MARKETPLACE_DERIVED_ACTIVE_REPORT_SCHEMA =
  "mandatex.marketplace.derived-active-candidate-report.v1" as const;

export const MAX_MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_BYTES = 131_072 as const;
export const MAX_MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_TTL_SECONDS = 300 as const;
export const MARKETPLACE_CATEGORY_IDENTITY_MAX_AGE_SECONDS =
  MAX_CATEGORY_IDENTITY_AGE_SECONDS;
export const MARKETPLACE_CATEGORY_MINIMUM_REMAINING_VALIDITY_SECONDS = 30 as const;

/**
 * The sidecars are verifier-produced, typed evidence needed to independently
 * re-enter the successor trust boundary. They are intentionally separate from
 * the compact legacy v1 evidence path and never confer activation authority.
 */
export const MARKETPLACE_CATEGORY_QUOTE_SIDECARS_SCHEMA =
  "mandatex.marketplace.category-quote-sidecars.v1" as const;

const signatureSchema = z
  .string()
  .regex(/^[a-f0-9]{128}$/, "expected a 64-byte lowercase hex signature");

const categoryPreviewSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("not_applicable") }).strict(),
  z
    .object({
      status: z.literal("passed"),
      observedAt: unixSecondsSchema,
      observedBlock: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
      observedBlockHash: bytes32Schema,
    })
    .strict(),
  z
    .object({ status: z.literal("failed"), code: canonicalIdentifierSchema })
    .strict(),
  z.object({ status: z.literal("unavailable") }).strict(),
]);

const categorySuccessorObservationSchema = z
  .object({
    status: z.literal("pass"),
    categoryDeploymentSha256: sha256Schema,
    verifierPolicySha256: sha256Schema,
    targetsSha256: sha256Schema,
    readProfileId: canonicalIdentifierSchema,
    readProfileSha256: sha256Schema,
    readCommitmentsSha256: sha256Schema,
    artifactSha256: sha256Schema,
    evidenceSha256: sha256Schema,
    observedAt: unixSecondsSchema,
    observedBlock: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    observedBlockHash: bytes32Schema,
  })
  .strict();

const categorySuccessorServiceSchema = z
  .object({
    mode: z.enum(["observe_only", "transactional"]),
    actionPermissionsSha256: sha256Schema,
    coverage: z.enum(["complete", "not_applicable", "incomplete"]),
    permissionExpiresAt: unixSecondsSchema,
    assurance: z.enum([
      "protocol_instance_verified",
      "interface_only_unendorsed",
      "mixed",
    ]),
  })
  .strict();

export const marketplaceCategoryQuoteSidecarsSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_QUOTE_SIDECARS_SCHEMA),
    candidateIdentity: categoryCandidateIdentityArtifactSchema,
    targetObservations: z.array(categoryTargetObservationSchema).min(1).max(4),
    readProfile: categoryReadProfileSchema,
    actionProfile: categoryActionProfileSchema.nullable(),
    service: categorySuccessorServiceSchema,
    observation: categorySuccessorObservationSchema,
  })
  .strict();

export type MarketplaceCategoryQuoteSidecars = DeepReadonly<
  z.infer<typeof marketplaceCategoryQuoteSidecarsSchema>
>;
export type MarketplaceCategorySuccessorObservation = DeepReadonly<
  z.infer<typeof categorySuccessorObservationSchema>
>;

export const marketplaceCategoryQuoteProjectionSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_QUOTE_PROJECTION_SCHEMA),
    linkage: categoryLinkageProjectionSchema,
    sidecars: marketplaceCategoryQuoteSidecarsSchema,
    preview: categoryPreviewSchema,
  })
  .strict()
  .superRefine((projection, context) => {
    const mode = projection.linkage.serviceMode;
    const sidecars = projection.sidecars;
    if (mode === "observe_only" && projection.preview.status !== "not_applicable") {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["preview"],
        message: "observe-only projections require a not-applicable preview",
      });
    }
    if (mode === "transactional" && projection.preview.status === "not_applicable") {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["preview"],
        message: "transactional projections require a preview result",
      });
    }
    if (
      sidecars.service.mode !== mode ||
      sidecars.service.actionPermissionsSha256 !==
        projection.linkage.actionPermissionsSha256
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "service"],
        message: "sidecar service identity must match the signed linkage",
      });
    }
    const assurances = new Set(
      sidecars.targetObservations.map((target) => target.assurance),
    );
    const expectedAssurance =
      assurances.size > 1
        ? "mixed"
        : sidecars.targetObservations[0]?.assurance;
    if (sidecars.service.assurance !== expectedAssurance) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "service", "assurance"],
        message: "sidecar assurance must summarize every target observation",
      });
    }
    if (
      mode === "observe_only" &&
      (sidecars.actionProfile !== null ||
        sidecars.service.coverage !== "not_applicable")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "service", "coverage"],
        message: "observe-only sidecars require no action profile and not-applicable coverage",
      });
    }
    if (
      sidecars.actionProfile !== null &&
      (sidecars.actionProfile.adapterId !== projection.linkage.adapterId ||
        sidecars.actionProfile.serviceMode !== mode)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "actionProfile"],
        message: "sidecar action profile must match the linkage adapter and mode",
      });
    }
    if (
      sidecars.candidateIdentity.identitySha256 !==
        projection.linkage.candidateIdentity.identitySha256 ||
      sidecars.candidateIdentity.registryAddress !==
        projection.linkage.candidateIdentity.registryAddress ||
      sidecars.candidateIdentity.ownerAddress !==
        projection.linkage.candidateIdentity.registeredOwner
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "candidateIdentity"],
        message: "candidate identity sidecar must match the signed linkage identity",
      });
    }
    if (
      canonicalSha256(sidecars.targetObservations) !==
        projection.linkage.observation.targetsSha256
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "targetObservations"],
        message: "target sidecars must match the signed target commitment",
      });
    }
    if (
      sidecars.readProfile.profileId !==
        projection.linkage.observation.readProfileId ||
      categoryStaticReadProfileSha256(sidecars.readProfile) !==
        projection.linkage.observation.readProfileSha256 ||
      categoryReadCommitmentsSha256(sidecars.readProfile) !==
        projection.linkage.observation.readCommitmentsSha256
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "readProfile"],
        message: "read-profile sidecar must match the signed read commitments",
      });
    }
    if (
      canonicalJson(sidecars.observation) !==
      canonicalJson(projection.linkage.observation)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "observation"],
        message: "observation sidecar must match the signed linkage observation",
      });
    }
    if (
      sidecars.targetObservations.some(
        (target) =>
          target.observedAt !== sidecars.observation.observedAt ||
          target.observedBlock !== sidecars.observation.observedBlock ||
          target.observedBlockHash !== sidecars.observation.observedBlockHash,
      )
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "targetObservations"],
        message: "target sidecars must share the signed observation block anchor",
      });
    }
  });

const unsignedAttestationShape = {
  schema: z.literal(MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA),
  signatureProfile: z.literal(MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE),
  issuer: z.literal(MARKETPLACE_CATEGORY_QUOTE_ISSUER),
  audience: z.literal(MARKETPLACE_CATEGORY_QUOTE_AUDIENCE),
  keyId: canonicalIdentifierSchema,
  releaseId: canonicalIdentifierSchema,
  releaseDefinitionSha256: sha256Schema,
  publicKeyFingerprintSha256: sha256Schema,
  attestationId: canonicalIdentifierSchema,
  scope: z.literal("evaluation_only"),
  activationAuthorization: z.literal("none"),
  reservation: z.literal("none"),
  replayPolicy: z.literal("reusable_until_expiry"),
  replayScope: z.literal("request_id"),
  issuedAt: unixSecondsSchema,
  expiresAt: unixSecondsSchema,
  mandateSha256: sha256Schema,
  categoryQuoteRequestSha256: sha256Schema,
  projectionSha256: sha256Schema,
  verifierPolicySha256: sha256Schema,
  categoryDeploymentSha256: sha256Schema,
  quoteVerifyingContract: addressSchema,
  projection: marketplaceCategoryQuoteProjectionSchema,
} as const;

export const marketplaceCategoryQuoteAttestationUnsignedSchema = z
  .object(unsignedAttestationShape)
  .strict();
export const marketplaceCategoryQuoteAttestationSchema = z
  .object({ ...unsignedAttestationShape, signature: signatureSchema })
  .strict();

export type MarketplaceCategoryQuoteProjection = DeepReadonly<
  z.infer<typeof marketplaceCategoryQuoteProjectionSchema>
>;
export type MarketplaceCategoryQuoteAttestationUnsigned = DeepReadonly<
  z.infer<typeof marketplaceCategoryQuoteAttestationUnsignedSchema>
>;
export type MarketplaceCategoryQuoteAttestation = DeepReadonly<
  z.infer<typeof marketplaceCategoryQuoteAttestationSchema>
>;
export type MarketplaceCategoryQuoteAttestationWire = string | Uint8Array;

export const marketplaceCategoryActiveReportSchema = z
  .object({
    schema: z.literal(MARKETPLACE_DERIVED_ACTIVE_REPORT_SCHEMA),
    status: z.enum([
      "VERIFIED_HIREABLE",
      "INELIGIBLE",
      "INCONCLUSIVE",
      "UNAVAILABLE",
    ]),
    scope: z.literal("evaluation_only"),
    activationAuthorization: z.literal("none"),
    reservation: z.literal("none"),
    replayPolicy: z.literal("reusable_until_expiry"),
    attestationSha256: sha256Schema,
    keyId: canonicalIdentifierSchema,
    releaseId: canonicalIdentifierSchema,
    releaseDefinitionSha256: sha256Schema,
    publicKeyFingerprintSha256: sha256Schema,
    verifierPolicySha256: sha256Schema,
    categoryDeploymentSha256: sha256Schema,
    requestId: canonicalIdentifierSchema,
    mandateId: canonicalIdentifierSchema,
    category: z.enum(["grid", "yield", "health"]),
    adapterId: canonicalIdentifierSchema,
    protocol: canonicalIdentifierSchema,
    candidate: z
      .object({ chainId: z.literal(56), tokenId: z.string().regex(/^(?:0|[1-9][0-9]*)$/) })
      .strict(),
    serviceMode: z.enum(["observe_only", "transactional"]),
    minimumTargetAssurance: z.enum([
      "interface_only_unendorsed",
      "protocol_instance_verified",
    ]),
    linkage: categoryLinkageProjectionSchema,
    sidecars: marketplaceCategoryQuoteSidecarsSchema,
    actionCoverage: z.enum(["complete", "not_applicable", "incomplete"]),
    preview: categoryPreviewSchema,
    validUntil: unixSecondsSchema,
    evaluatedAt: unixSecondsSchema,
  })
  .strict()
  .superRefine((report, context) => {
    if (
      report.sidecars.service.mode !== report.serviceMode ||
      report.sidecars.service.coverage !== report.actionCoverage
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sidecars", "service"],
        message: "report service sidecar must match its evaluated mode and coverage",
      });
    }
    if (
      report.status === "VERIFIED_HIREABLE" &&
      (report.validUntil - report.evaluatedAt <
        MARKETPLACE_CATEGORY_MINIMUM_REMAINING_VALIDITY_SECONDS ||
        (report.serviceMode === "transactional" &&
          (report.actionCoverage !== "complete" ||
            report.preview.status !== "passed")) ||
        (report.minimumTargetAssurance === "protocol_instance_verified" &&
          report.sidecars.targetObservations.some(
            (target) => target.assurance !== "protocol_instance_verified",
          )))
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["status"],
        message: "verified hireability requires fresh complete mode-specific evidence",
      });
    }
    if (
      report.serviceMode === "observe_only" &&
      (report.actionCoverage !== "not_applicable" ||
        report.preview.status !== "not_applicable")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["serviceMode"],
        message: "observe-only reports require not-applicable action and preview fields",
      });
    }
    if (
      report.serviceMode === "transactional" &&
      report.minimumTargetAssurance !== "protocol_instance_verified"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["minimumTargetAssurance"],
        message: "transactional reports require protocol-instance assurance",
      });
    }
  });

export type DerivedMarketplaceCategoryActiveReport = DeepReadonly<
  z.infer<typeof marketplaceCategoryActiveReportSchema>
>;

export type MarketplaceCategoryQuoteTrustStore = Readonly<{
  bundleSha256: string;
  generation: number;
  revocationEpoch: number;
  rootPublicKeyFingerprintSha256: string;
  quoteVerifyingContract: string;
}>;

type VerifiedCategoryQuoteTrustContext = Readonly<{
  bundle: VerifiedMarketplaceTrustBundle;
  quoteVerifyingContract: string;
}>;

const verifiedTrustStores = new WeakMap<
  MarketplaceCategoryQuoteTrustStore,
  VerifiedCategoryQuoteTrustContext
>();

const verifiedAttestationMarker: unique symbol = Symbol(
  "mandatex.marketplace.verified-category-quote-attestation",
);

export type VerifiedMarketplaceCategoryQuoteAttestation = Readonly<{
  envelope: MarketplaceCategoryQuoteAttestation;
  attestationSha256: string;
  projection: MarketplaceCategoryQuoteProjection;
  linkage: UntrustedCategoryLinkageProjection;
  sidecars: MarketplaceCategoryQuoteSidecars;
  trustTuple: MarketplaceTrustResolvedTuple;
  mandate: MarketplaceMandateV2;
  request: MarketplaceCategoryQuoteRequest;
  identityArtifact: ReturnType<typeof validateCandidateIdentityForSelector>;
  targetObservations: readonly CategoryTargetObservation[];
  readProfile: CategoryReadProfile;
  evaluatedAt: number;
  [verifiedAttestationMarker]: true;
}>;

const verifiedAttestations = new WeakSet<object>();

export class MarketplaceCategorySuccessorError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "MarketplaceCategorySuccessorError";
    this.code = code;
  }
}

export function createMarketplaceCategoryQuoteTrustStore(input: {
  readonly commitment: MarketplaceCategoryTrustCommitment;
}): MarketplaceCategoryQuoteTrustStore {
  assertExactKeys(input, ["commitment"], "category quote trust-store input");
  const resolved = resolveMarketplaceCategoryTrustCommitment(input.commitment);
  const verified = resolved.verified;
  const quoteVerifyingContract = addressSchema.parse(
    resolved.quoteVerifyingContract,
  );
  const store: MarketplaceCategoryQuoteTrustStore = Object.freeze({
    bundleSha256: verified.bundleSha256,
    generation: verified.envelope.generation,
    revocationEpoch: verified.envelope.revocationEpoch,
    rootPublicKeyFingerprintSha256: verified.rootPublicKeyFingerprintSha256,
    quoteVerifyingContract,
  });
  verifiedTrustStores.set(
    store,
    Object.freeze({ bundle: verified, quoteVerifyingContract }),
  );
  return store;
}

export function marketplaceCategoryQuoteAttestationSigningMessage(
  input: unknown,
): Uint8Array {
  const unsigned = marketplaceCategoryQuoteAttestationUnsignedSchema.parse(input);
  return Buffer.concat([
    Buffer.from(MARKETPLACE_CATEGORY_QUOTE_SIGNING_DOMAIN, "utf8"),
    Buffer.from(canonicalJson(unsigned), "utf8"),
  ]);
}

export function serializeMarketplaceCategoryQuoteAttestation(input: unknown): string {
  return canonicalJson(marketplaceCategoryQuoteAttestationSchema.parse(input));
}

export function verifyMarketplaceCategoryQuoteAttestation(input: {
  readonly wire: MarketplaceCategoryQuoteAttestationWire;
  readonly mandate: unknown;
  readonly request: unknown;
  readonly identityArtifact: unknown;
  readonly targetObservations: unknown;
  readonly readProfile: unknown;
  readonly trustStore: MarketplaceCategoryQuoteTrustStore;
  readonly clock: () => number;
}): VerifiedMarketplaceCategoryQuoteAttestation {
  assertExactKeys(
    input,
    [
      "clock",
      "identityArtifact",
      "mandate",
      "readProfile",
      "request",
      "targetObservations",
      "trustStore",
      "wire",
    ],
    "category quote attestation verification input",
  );
  const trustContext = verifiedTrustStores.get(input.trustStore);
  if (trustContext === undefined) {
    fail(
      "TRUST_STORE_UNVERIFIED",
      "category quote verification requires a runtime-provenance trust store",
    );
  }
  const verifiedBundle = trustContext.bundle;
  const evaluatedAt = readClock(input.clock);
  if (evaluatedAt >= verifiedBundle.envelope.expiresAt) {
    fail("TRUST_BUNDLE_EXPIRED", "category quote trust bundle has expired");
  }
  const mandate = marketplaceMandateV2Schema.parse(input.mandate);
  const request = validateCategoryQuoteRequestBinding({
    request: input.request,
    mandate,
  });
  const identityArtifact = validateCandidateIdentityForSelector({
    artifact: input.identityArtifact,
    candidate: request.candidate,
  });
  const targetObservations = validateTargetObservationsForScope({
    scope: request.categoryScope,
    targets: input.targetObservations,
  });
  const readProfile = validateAdapterReadProfile({
    profile: input.readProfile,
    scope: request.categoryScope,
  });
  const envelope = parseAttestationWire(input.wire);
  if (envelope.quoteVerifyingContract !== trustContext.quoteVerifyingContract) {
    fail(
      "QUOTE_DOMAIN_MISMATCH",
      "category quote attestation uses an untrusted verifying contract",
    );
  }
  const tuple = resolveMarketplaceTrustBundleAttestationTuple({
    verified: verifiedBundle,
    keyId: envelope.keyId,
    releaseId: envelope.releaseId,
    issuedAt: envelope.issuedAt,
    adapterId: request.adapterId,
    serviceMode: request.serviceMode,
    phase: "verification",
  });
  assertMarketplaceTrustResolvedTuple(tuple);
  assertTupleBindings(envelope, tuple, readProfile);
  assertEnvelopeBindings(envelope, mandate, request, evaluatedAt);
  const linkage = validateCategoryLinkageProjection({
    projection: envelope.projection.linkage,
    mandate,
    request,
    identityArtifact,
    targetObservations,
    readProfile,
    expectedQuoteDomain: {
      chainId: 56,
      verifyingContract: trustContext.quoteVerifyingContract,
    },
    expectedRelease: {
      categoryDeploymentSha256: tuple.release.categoryDeploymentSha256,
      verifierPolicySha256: tuple.release.verifierPolicySha256,
    },
    evaluatedAt,
  });
  const sidecars = validateSuccessorSidecars({
    sidecars: envelope.projection.sidecars,
    linkage,
    mandate,
    request,
    identityArtifact,
    targetObservations,
    readProfile,
    trustTuple: tuple,
  });
  if (envelope.projectionSha256 !== canonicalSha256(envelope.projection)) {
    fail("PROJECTION_HASH_MISMATCH", "category quote projection digest does not match");
  }
  verifyEnvelopeSignature(envelope, tuple.key.publicKey);

  const verified: VerifiedMarketplaceCategoryQuoteAttestation = Object.freeze({
    envelope: deepFreeze(envelope),
    attestationSha256: wireSha256(input.wire),
    projection: deepFreeze(envelope.projection),
    linkage,
    sidecars,
    trustTuple: tuple,
    mandate: deepFreeze(mandate),
    request: deepFreeze(request),
    identityArtifact,
    targetObservations,
    readProfile,
    evaluatedAt,
    [verifiedAttestationMarker]: true as const,
  });
  verifiedAttestations.add(verified);
  return verified;
}

export function deriveMarketplaceCategoryActiveReport(input: {
  readonly verifiedAttestation: VerifiedMarketplaceCategoryQuoteAttestation;
  readonly actionProfile: unknown | null;
  readonly clock: () => number;
}): DerivedMarketplaceCategoryActiveReport {
  assertExactKeys(
    input,
    ["actionProfile", "clock", "verifiedAttestation"],
    "derived category report input",
  );
  const verified = input.verifiedAttestation;
  if (
    verified === null ||
    typeof verified !== "object" ||
    verified[verifiedAttestationMarker] !== true ||
    !verifiedAttestations.has(verified)
  ) {
    fail(
      "ATTESTATION_PROVENANCE_INVALID",
      "derived reports require a runtime-verified category quote attestation",
    );
  }

  const evaluatedAt = readClock(input.clock);
  if (evaluatedAt !== verified.evaluatedAt) {
    fail(
      "ATTESTATION_REVERIFY_REQUIRED",
      "category reports must be derived in the same Core clock tick as attestation verification",
    );
  }
  const { envelope, linkage, sidecars, trustTuple, mandate, request } = verified;
  assertMarketplaceTrustResolvedTuple(trustTuple);
  const identityExpiresAt =
    sidecars.candidateIdentity.observedAt +
    MARKETPLACE_CATEGORY_IDENTITY_MAX_AGE_SECONDS +
    1;
  const evidenceExpiresAt =
    sidecars.observation.observedAt + mandate.maxEvidenceAgeSeconds + 1;
  const validUntil = Math.min(
    envelope.expiresAt,
    mandate.expiresAt,
    request.expiresAt,
    request.permissionsExpiresAt,
    linkage.providerAcceptance.quoteExpiresAt,
    identityExpiresAt,
    evidenceExpiresAt,
  );
  const enoughValidity =
    validUntil - evaluatedAt >=
    MARKETPLACE_CATEGORY_MINIMUM_REMAINING_VALIDITY_SECONDS;
  const actionProfile = resolveReportActionProfile(
    input.actionProfile,
    sidecars.actionProfile,
  );
  const action = deriveActionState({
    actionProfile,
    mandate,
    request,
    tuple: trustTuple,
  });
  const statusBeforeAssuranceGate = deriveStatus({
    serviceMode: request.serviceMode,
    preview: envelope.projection.preview,
    observation: linkage.observation,
    action,
    enoughValidity,
    evaluatedAt,
    maxClockSkewSeconds: mandate.maxClockSkewSeconds,
    maxEvidenceAgeSeconds: mandate.maxEvidenceAgeSeconds,
  });
  const minimumTargetAssurance =
    request.serviceMode === "transactional"
      ? "protocol_instance_verified"
      : trustTuple.adapterMode.minimumTargetAssurance;
  const meetsTargetAssurance =
    minimumTargetAssurance === "interface_only_unendorsed" ||
    sidecars.targetObservations.every(
      (target) => target.assurance === "protocol_instance_verified",
    );
  const status =
    statusBeforeAssuranceGate === "VERIFIED_HIREABLE" &&
    !meetsTargetAssurance
      ? "INCONCLUSIVE"
      : statusBeforeAssuranceGate;

  return deepFreeze(
    marketplaceCategoryActiveReportSchema.parse({
      schema: MARKETPLACE_DERIVED_ACTIVE_REPORT_SCHEMA,
      status,
      scope: envelope.scope,
      activationAuthorization: envelope.activationAuthorization,
      reservation: envelope.reservation,
      replayPolicy: envelope.replayPolicy,
      attestationSha256: verified.attestationSha256,
      keyId: envelope.keyId,
      releaseId: envelope.releaseId,
      releaseDefinitionSha256: envelope.releaseDefinitionSha256,
      publicKeyFingerprintSha256: envelope.publicKeyFingerprintSha256,
      verifierPolicySha256: envelope.verifierPolicySha256,
      categoryDeploymentSha256: envelope.categoryDeploymentSha256,
      requestId: request.requestId,
      mandateId: mandate.mandateId,
      category: request.category,
      adapterId: request.adapterId,
      protocol: request.protocol,
      candidate: request.candidate,
      serviceMode: request.serviceMode,
      minimumTargetAssurance,
      linkage,
      sidecars,
      actionCoverage: action.coverage,
      preview: envelope.projection.preview,
      validUntil,
      evaluatedAt,
    }),
  );
}

function validateSuccessorSidecars(input: {
  readonly sidecars: unknown;
  readonly linkage: UntrustedCategoryLinkageProjection;
  readonly mandate: MarketplaceMandateV2;
  readonly request: MarketplaceCategoryQuoteRequest;
  readonly identityArtifact: CategoryCandidateIdentityArtifact;
  readonly targetObservations: readonly CategoryTargetObservation[];
  readonly readProfile: CategoryReadProfile;
  readonly trustTuple: MarketplaceTrustResolvedTuple;
}): MarketplaceCategoryQuoteSidecars {
  const sidecars = marketplaceCategoryQuoteSidecarsSchema.parse(input.sidecars);
  if (
    canonicalJson(sidecars.candidateIdentity) !==
    canonicalJson(input.identityArtifact)
  ) {
    fail(
      "IDENTITY_SIDECAR_MISMATCH",
      "signed candidate identity sidecar does not match verifier-owned identity",
    );
  }
  if (
    canonicalJson(sidecars.targetObservations) !==
    canonicalJson(input.targetObservations)
  ) {
    fail(
      "TARGET_SIDECAR_MISMATCH",
      "signed target sidecars do not match verifier-owned target observations",
    );
  }
  if (canonicalJson(sidecars.readProfile) !== canonicalJson(input.readProfile)) {
    fail(
      "READ_PROFILE_SIDECAR_MISMATCH",
      "signed read-profile sidecar does not match verifier-owned reads",
    );
  }
  if (
    canonicalJson(sidecars.observation) !== canonicalJson(input.linkage.observation)
  ) {
    fail(
      "OBSERVATION_SIDECAR_MISMATCH",
      "signed observation sidecar does not match the validated linkage",
    );
  }
  if (
    sidecars.service.mode !== input.request.serviceMode ||
    sidecars.service.actionPermissionsSha256 !==
      input.request.actionPermissionsSha256 ||
    sidecars.service.permissionExpiresAt !== input.request.permissionsExpiresAt
  ) {
    fail(
      "SERVICE_SIDECAR_MISMATCH",
      "signed service sidecar does not match the mandate-bound request",
    );
  }
  const assurances = new Set(
    sidecars.targetObservations.map((target) => target.assurance),
  );
  const expectedAssurance =
    assurances.size > 1 ? "mixed" : sidecars.targetObservations[0]?.assurance;
  if (sidecars.service.assurance !== expectedAssurance) {
    fail(
      "ASSURANCE_SIDECAR_MISMATCH",
      "signed assurance summary does not match the target observations",
    );
  }
  const action = deriveActionState({
    actionProfile: sidecars.actionProfile,
    mandate: input.mandate,
    request: input.request,
    tuple: input.trustTuple,
  });
  if (sidecars.service.coverage !== action.coverage) {
    fail(
      "ACTION_COVERAGE_MISMATCH",
      "signed service coverage does not match Core's typed permission evaluation",
    );
  }
  return deepFreeze(sidecars);
}

function resolveReportActionProfile(
  input: unknown | null,
  signed: CategoryActionProfile | null,
): CategoryActionProfile | null {
  if (input === null) return signed;
  let parsed: CategoryActionProfile;
  try {
    parsed = categoryActionProfileSchema.parse(input);
  } catch (cause) {
    throw new MarketplaceCategorySuccessorError(
      "ACTION_PROFILE_INVALID",
      "derived report action profile is invalid",
      { cause },
    );
  }
  if (signed === null || canonicalJson(parsed) !== canonicalJson(signed)) {
    fail(
      "ACTION_PROFILE_SIDECAR_MISMATCH",
      "derived report action profile does not match the signed sidecar",
    );
  }
  return deepFreeze(parsed);
}

function assertTupleBindings(
  envelope: MarketplaceCategoryQuoteAttestation,
  tuple: MarketplaceTrustResolvedTuple,
  readProfile: CategoryReadProfile,
): void {
  if (tuple.authorization.channel !== "production") {
    fail("TRUST_CHANNEL_INVALID", "production reports require a production trust edge");
  }
  if (
    tuple.release.attestationSchema !== MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA ||
    tuple.release.signatureProfile !== MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE
  ) {
    fail("TRUST_RELEASE_PROFILE_MISMATCH", "trust release does not authorize this quote wire");
  }
  if (
    envelope.releaseDefinitionSha256 !== tuple.release.definitionSha256 ||
    envelope.publicKeyFingerprintSha256 !==
      tuple.key.record.publicKeyFingerprintSha256 ||
    envelope.verifierPolicySha256 !== tuple.release.verifierPolicySha256 ||
    envelope.categoryDeploymentSha256 !== tuple.release.categoryDeploymentSha256
  ) {
    fail("TRUST_TUPLE_MISMATCH", "attestation does not bind the exact resolved trust tuple");
  }
  if (
    tuple.adapterMode.readProfileId !== readProfile.profileId ||
      tuple.adapterMode.readProfileSha256 !==
      categoryStaticReadProfileSha256(readProfile)
  ) {
    fail(
      "READ_PROFILE_MISMATCH",
      "attestation reads do not match the trusted static release profile",
    );
  }
  if (
    envelope.projection.linkage.observation.readCommitmentsSha256 !==
    categoryReadCommitmentsSha256(readProfile)
  ) {
    fail(
      "READ_COMMITMENTS_MISMATCH",
      "attestation does not bind the concrete observed read commitments",
    );
  }
}

function assertEnvelopeBindings(
  envelope: MarketplaceCategoryQuoteAttestation,
  mandate: MarketplaceMandateV2,
  request: MarketplaceCategoryQuoteRequest,
  evaluatedAt: number,
): void {
  if (envelope.mandateSha256 !== canonicalSha256(mandate)) {
    fail("MANDATE_HASH_MISMATCH", "attestation mandate digest does not match");
  }
  if (envelope.categoryQuoteRequestSha256 !== canonicalSha256(request)) {
    fail("REQUEST_HASH_MISMATCH", "attestation category quote request digest does not match");
  }
  if (
    envelope.projection.linkage.requestId !== request.requestId ||
    envelope.projection.linkage.mandateId !== mandate.mandateId ||
    envelope.projection.linkage.adapterId !== request.adapterId ||
    envelope.projection.linkage.serviceMode !== request.serviceMode
  ) {
    fail("PROJECTION_BINDING_MISMATCH", "attestation projection is for a different request");
  }
  if (
    envelope.issuedAt < request.issuedAt - mandate.maxClockSkewSeconds ||
    envelope.issuedAt > evaluatedAt + mandate.maxClockSkewSeconds
  ) {
    fail("ATTESTATION_NOT_YET_VALID", "attestation issuance is outside the request clock window");
  }
  if (
    envelope.expiresAt <= envelope.issuedAt ||
    envelope.expiresAt > envelope.issuedAt + MAX_MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_TTL_SECONDS ||
    envelope.expiresAt > mandate.expiresAt ||
    envelope.expiresAt > request.expiresAt
  ) {
    fail("ATTESTATION_EXPIRY_INVALID", "attestation expiry is outside the successor lifetime");
  }
  if (envelope.expiresAt <= evaluatedAt) {
    fail("ATTESTATION_EXPIRED", "category quote attestation has expired");
  }
  if (
    envelope.projection.linkage.candidateIdentity.observedAt > envelope.issuedAt ||
    envelope.projection.linkage.observation.observedAt > envelope.issuedAt
  ) {
    fail("OBSERVATION_AFTER_ISSUANCE", "signed linkage was observed after attestation issuance");
  }
}

type DerivedActionState = Readonly<{
  coverage: "complete" | "not_applicable" | "incomplete";
  approved: boolean;
  covered: boolean;
}>;

function deriveActionState(input: {
  readonly actionProfile: unknown | null;
  readonly mandate: MarketplaceMandateV2;
  readonly request: MarketplaceCategoryQuoteRequest;
  readonly tuple: MarketplaceTrustResolvedTuple;
}): DerivedActionState {
  if (input.request.serviceMode === "observe_only") {
    if (
      input.actionProfile !== null ||
      input.tuple.adapterMode.actionProfileId !== null ||
      input.tuple.adapterMode.actionProfileSha256 !== null
    ) {
      fail("ACTION_PROFILE_UNEXPECTED", "observe-only evaluation cannot carry an action profile");
    }
    validateActionCoverage({
      adapterId: input.request.adapterId,
      serviceMode: "observe_only",
      mandatePermissions: input.mandate.actionPermissions,
      quotedPermissions: input.request.actionPermissions,
      mandateSpendCapUsdMicros: input.mandate.maxSpendUsdMicros,
      quotedSpendCapUsdMicros: input.request.maxSpendUsdMicros,
    });
    return Object.freeze({
      coverage: "not_applicable",
      approved: true,
      covered: true,
    });
  }

  let profile: CategoryActionProfile;
  try {
    profile = categoryActionProfileSchema.parse(input.actionProfile);
  } catch {
    return Object.freeze({ coverage: "incomplete", approved: false, covered: false });
  }
  if (
    input.tuple.adapterMode.actionProfileId !== profile.profileId ||
    input.tuple.adapterMode.actionProfileSha256 !== canonicalSha256(profile)
  ) {
    fail("ACTION_PROFILE_MISMATCH", "action profile does not match the trusted release");
  }
  let covered = true;
  try {
    validateActionCoverage({
      adapterId: input.request.adapterId,
      serviceMode: "transactional",
      mandatePermissions: input.mandate.actionPermissions,
      quotedPermissions: input.request.actionPermissions,
      mandateSpendCapUsdMicros: input.mandate.maxSpendUsdMicros,
      quotedSpendCapUsdMicros: input.request.maxSpendUsdMicros,
      actionProfile: profile,
    });
  } catch {
    covered = false;
  }
  const approved = profile.approval !== "draft_unapproved";
  return Object.freeze({
    coverage: covered && approved ? "complete" : "incomplete",
    approved,
    covered,
  });
}

function deriveStatus(input: {
  readonly serviceMode: "observe_only" | "transactional";
  readonly preview: z.infer<typeof categoryPreviewSchema>;
  readonly observation: UntrustedCategoryLinkageProjection["observation"];
  readonly action: DerivedActionState;
  readonly enoughValidity: boolean;
  readonly evaluatedAt: number;
  readonly maxClockSkewSeconds: number;
  readonly maxEvidenceAgeSeconds: number;
}): DerivedMarketplaceCategoryActiveReport["status"] {
  if (!input.enoughValidity) return "UNAVAILABLE";
  if (input.observation.status !== "pass") return "INELIGIBLE";
  if (input.serviceMode === "observe_only") return "VERIFIED_HIREABLE";
  if (input.preview.status === "unavailable") return "UNAVAILABLE";
  if (input.preview.status === "failed") return "INELIGIBLE";
  if (input.preview.status !== "passed") return "INCONCLUSIVE";
  if (
    input.preview.observedAt > input.evaluatedAt + input.maxClockSkewSeconds ||
    input.evaluatedAt - input.preview.observedAt > input.maxEvidenceAgeSeconds ||
    input.preview.observedAt !== input.observation.observedAt ||
    input.preview.observedBlock !== input.observation.observedBlock ||
    input.preview.observedBlockHash !== input.observation.observedBlockHash
  ) {
    return "INCONCLUSIVE";
  }
  if (!input.action.covered) return "INELIGIBLE";
  if (!input.action.approved || input.action.coverage !== "complete") {
    return "INCONCLUSIVE";
  }
  return "VERIFIED_HIREABLE";
}

function verifyEnvelopeSignature(
  envelope: MarketplaceCategoryQuoteAttestation,
  publicKey: KeyObject,
): void {
  const { signature, ...unsigned } = envelope;
  let valid = false;
  try {
    valid = verifyEd25519(
      null,
      marketplaceCategoryQuoteAttestationSigningMessage(unsigned),
      publicKey,
      Buffer.from(signature, "hex"),
    );
  } catch {
    valid = false;
  }
  if (!valid) fail("ATTESTATION_SIGNATURE_INVALID", "category quote signature is invalid");
}

function parseAttestationWire(
  wire: MarketplaceCategoryQuoteAttestationWire,
): MarketplaceCategoryQuoteAttestation {
  if (!(typeof wire === "string" || wire instanceof Uint8Array)) {
    fail("ATTESTATION_INPUT_INVALID", "attestation wire must be UTF-8 text or bytes");
  }
  const bytes = typeof wire === "string" ? Buffer.from(wire, "utf8") : Buffer.from(wire);
  if (bytes.byteLength > MAX_MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_BYTES) {
    fail("ATTESTATION_TOO_LARGE", "category quote attestation exceeds the byte limit");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (cause) {
    throw new MarketplaceCategorySuccessorError(
      "ATTESTATION_UTF8_INVALID",
      "category quote attestation is not valid UTF-8",
      { cause },
    );
  }
  if (text.charCodeAt(0) === 0xfeff) {
    fail("ATTESTATION_UTF8_INVALID", "category quote attestation must not contain a BOM");
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (cause) {
    throw new MarketplaceCategorySuccessorError(
      "ATTESTATION_JSON_INVALID",
      "category quote attestation is not valid JSON",
      { cause },
    );
  }
  const parsed = marketplaceCategoryQuoteAttestationSchema.safeParse(raw);
  if (!parsed.success) {
    throw new MarketplaceCategorySuccessorError(
      "ATTESTATION_SCHEMA_INVALID",
      "category quote attestation does not match the strict successor schema",
      { cause: parsed.error },
    );
  }
  if (canonicalJson(parsed.data) !== text) {
    fail("ATTESTATION_NONCANONICAL", "category quote attestation is not canonical JSON");
  }
  return parsed.data;
}

function wireSha256(wire: MarketplaceCategoryQuoteAttestationWire): string {
  const bytes = typeof wire === "string" ? Buffer.from(wire, "utf8") : Buffer.from(wire);
  return createHash("sha256").update(bytes).digest("hex");
}

function readClock(clock: () => number): number {
  if (typeof clock !== "function") {
    fail("CLOCK_INVALID", "category successor clock must be a function");
  }
  let value: number;
  try {
    value = clock();
  } catch (cause) {
    throw new MarketplaceCategorySuccessorError(
      "CLOCK_INVALID",
      "category successor clock failed",
      { cause },
    );
  }
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail("CLOCK_INVALID", "category successor clock returned an invalid time");
  }
  return value;
}

function assertExactKeys(
  input: unknown,
  expected: readonly string[],
  label: string,
): asserts input is Record<string, unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    fail("INPUT_INVALID", `${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    fail("INPUT_INVALID", `${label} must be a plain object`);
  }
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== "string")) {
    fail("INPUT_INVALID", `${label} must not contain symbol keys`);
  }
  const actual = (keys as string[]).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail("INPUT_INVALID", `${label} contains unexpected or missing fields`);
  }
}

function fail(code: string, message: string): never {
  throw new MarketplaceCategorySuccessorError(code, message);
}

void categoryReadProfileSchema;
void categoryTargetObservationSchema;
