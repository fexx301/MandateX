import { canonicalJson, canonicalSha256 } from "./canonical.js";
import {
  MARKETPLACE_AAVE_HEALTH_ADAPTER,
  MARKETPLACE_GRID_ADAPTER,
  MARKETPLACE_VENUS_HEALTH_ADAPTER,
  MARKETPLACE_YIELD_ADAPTER,
} from "./category-policy.js";
import {
  categoryCandidateIdentityArtifactSchema,
  categoryReadProfileSchema,
  categoryReadCommitmentsSha256,
  categoryStaticReadProfileSha256,
  categoryScopeSchema,
  categoryTargetObservationSchema,
  marketplaceCategoryQuoteRequestSchema,
  marketplaceMandateV2Schema,
  validateAdapterReadProfile,
  validateCandidateIdentityForSelector,
  validateCategoryQuoteRequestBinding,
  validateTargetObservationsForScope,
} from "./category-production.js";
import { deepFreeze, type DeepReadonly } from "./immutable.js";
import {
  addressSchema,
  blockNumberSchema,
  bytes32Schema,
  canonicalIdentifierSchema,
  sha256Schema,
  tokenIdSchema,
  unixSecondsSchema,
} from "./primitives.js";
import { z } from "zod";

/**
 * Private successor linkage projection. Parsing this wire proves no signer or
 * verifier provenance; a trusted successor evaluator must establish that first.
 */
export const MARKETPLACE_CATEGORY_LINKAGE_PROJECTION_SCHEMA =
  "mandatex.marketplace.category-linkage-projection.v1" as const;
export const MAX_CATEGORY_IDENTITY_AGE_SECONDS = 300 as const;

const adapterIdSchema = z.union([
  z.literal(MARKETPLACE_GRID_ADAPTER),
  z.literal(MARKETPLACE_YIELD_ADAPTER),
  z.literal(MARKETPLACE_AAVE_HEALTH_ADAPTER),
  z.literal(MARKETPLACE_VENUS_HEALTH_ADAPTER),
]);

const categorySchema = z.enum(["grid", "yield", "health"]);
const serviceModeSchema = z.enum(["observe_only", "transactional"]);
const providerKindSchema = z.enum(["eoa", "erc1271"]);
const signatureMethodSchema = z.enum(["eip191", "erc1271"]);

const candidateSelectorSchema = z
  .object({ chainId: z.literal(56), tokenId: tokenIdSchema })
  .strict();

const candidateIdentityProjectionSchema = z
  .object({
    proofProfile: z.literal("erc8004-owner-of-v1"),
    chainId: z.literal(56),
    tokenId: tokenIdSchema,
    registryAddress: addressSchema,
    registeredOwner: addressSchema,
    confirmationDepth: z.number().int().nonnegative().max(256),
    registryCodeSha256: sha256Schema,
    identitySha256: sha256Schema,
    observedAt: unixSecondsSchema,
    observedBlock: blockNumberSchema,
    observedBlockHash: bytes32Schema,
  })
  .strict();

export const categoryProviderAuthoritySchema = z
  .object({
    kind: z.literal("erc8004_registered_owner"),
    providerAddress: addressSchema,
    validatedSigner: addressSchema,
    providerCodeSha256: sha256Schema,
    candidateIdentitySha256: sha256Schema,
  })
  .strict();

export const categoryProviderAcceptanceSchema = z
  .object({
    relation: z.literal("candidate_accepts_service_for_subject"),
    verificationProfile: z.literal("mandatex-category-quote-verification-v1"),
    providerKind: providerKindSchema,
    signatureMethod: signatureMethodSchema,
    validatedSigner: addressSchema,
    validatedProvider: addressSchema,
    providerCodeSha256: sha256Schema,
    chainId: z.literal(56),
    verifyingContract: addressSchema,
    candidateIdentitySha256: sha256Schema,
    mandateSha256: sha256Schema,
    categoryQuoteRequestSha256: sha256Schema,
    subjectSha256: sha256Schema,
    conditionPolicySha256: sha256Schema,
    actionPermissionsSha256: sha256Schema,
    quoteNonce: canonicalIdentifierSchema,
    quoteRequestKeccak256: bytes32Schema,
    quoteResponseKeccak256: bytes32Schema,
    negotiationKeccak256: bytes32Schema,
    quoteEndpointSha256: sha256Schema,
    negotiatedAt: unixSecondsSchema,
    quoteExpiresAt: unixSecondsSchema,
  })
  .strict()
  .superRefine((acceptance, context) => {
    if (acceptance.validatedSigner !== acceptance.validatedProvider) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["validatedSigner"],
        message: "validated signer must match the validated provider",
      });
    }
    if (
      (acceptance.providerKind === "eoa" &&
        acceptance.signatureMethod !== "eip191") ||
      (acceptance.providerKind === "erc1271" &&
        acceptance.signatureMethod !== "erc1271")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["signatureMethod"],
        message: "signature method must match the provider kind",
      });
    }
    if (acceptance.quoteExpiresAt <= acceptance.negotiatedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["quoteExpiresAt"],
        message: "quote expiry must follow negotiation",
      });
    }
  });

const categoryLinkageObservationSchema = z
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
    observedBlock: blockNumberSchema,
    observedBlockHash: bytes32Schema,
  })
  .strict();

const categoryLinkageProjectionShape = {
  schema: z.literal(MARKETPLACE_CATEGORY_LINKAGE_PROJECTION_SCHEMA),
  trustStatus: z.literal("untrusted_until_successor_attestation_verified"),
  relation: z.literal("candidate_accepts_service_for_subject"),
  scope: z.literal("evaluation_only"),
  activationAuthorization: z.literal("none"),
  reservation: z.literal("none"),
  subjectSelection: z.literal("mandate_declared_exact"),
  anchorBinding: z.literal("same_canonical_block"),
  requestId: canonicalIdentifierSchema,
  mandateId: canonicalIdentifierSchema,
  mandateSha256: sha256Schema,
  categoryQuoteRequestSha256: sha256Schema,
  category: categorySchema,
  adapterId: adapterIdSchema,
  protocol: canonicalIdentifierSchema,
  candidate: candidateSelectorSchema,
  candidateIdentity: candidateIdentityProjectionSchema,
  providerAuthority: categoryProviderAuthoritySchema,
  providerAcceptance: categoryProviderAcceptanceSchema,
  categoryScope: categoryScopeSchema,
  categoryScopeSha256: sha256Schema,
  subjectSha256: sha256Schema,
  conditionPolicySha256: sha256Schema,
  serviceMode: serviceModeSchema,
  actionPermissionsSha256: sha256Schema,
  observation: categoryLinkageObservationSchema,
} as const;

function refineCategoryLinkageProjection(
  projection: z.infer<
    typeof categoryLinkageProjectionUnsignedStructuralSchema
  >,
  context: z.RefinementCtx,
): void {
  const identity = projection.candidateIdentity;
  const authority = projection.providerAuthority;
  const acceptance = projection.providerAcceptance;
  if (
    projection.candidate.chainId !== identity.chainId ||
    projection.candidate.tokenId !== identity.tokenId
  ) {
    addIssue(context, ["candidateIdentity"], "identity must match the candidate selector");
  }
  if (
    authority.providerAddress !== identity.registeredOwner ||
    authority.validatedSigner !== identity.registeredOwner ||
    acceptance.validatedProvider !== identity.registeredOwner ||
    acceptance.validatedSigner !== identity.registeredOwner
  ) {
    addIssue(
      context,
      ["providerAuthority"],
      "registered owner, provider, and validated signer must be identical",
    );
  }
  if (
    authority.candidateIdentitySha256 !== identity.identitySha256 ||
    acceptance.candidateIdentitySha256 !== identity.identitySha256
  ) {
    addIssue(
      context,
      ["candidateIdentity", "identitySha256"],
      "provider authority and acceptance must bind the candidate identity",
    );
  }
  if (authority.providerCodeSha256 !== acceptance.providerCodeSha256) {
    addIssue(
      context,
      ["providerAcceptance", "providerCodeSha256"],
      "provider authority and acceptance must bind the same observed runtime code",
    );
  }
  if (
    projection.category !== projection.categoryScope.category ||
    projection.adapterId !== projection.categoryScope.adapterId ||
    projection.protocol !== projection.categoryScope.protocol
  ) {
    addIssue(context, ["categoryScope"], "category scope identity must match the projection");
  }
  if (projection.categoryScopeSha256 !== canonicalSha256(projection.categoryScope)) {
    addIssue(context, ["categoryScopeSha256"], "category scope digest does not match");
  }
  if (projection.subjectSha256 !== canonicalSha256(projection.categoryScope.subject)) {
    addIssue(context, ["subjectSha256"], "subject digest does not match the category scope");
  }
  if (
    projection.conditionPolicySha256 !==
    canonicalSha256(projection.categoryScope.conditionPolicy)
  ) {
    addIssue(
      context,
      ["conditionPolicySha256"],
      "condition policy digest does not match the category scope",
    );
  }
  if (
    acceptance.relation !== projection.relation ||
    acceptance.mandateSha256 !== projection.mandateSha256 ||
    acceptance.categoryQuoteRequestSha256 !==
      projection.categoryQuoteRequestSha256 ||
    acceptance.subjectSha256 !== projection.subjectSha256 ||
    acceptance.conditionPolicySha256 !== projection.conditionPolicySha256 ||
    acceptance.actionPermissionsSha256 !== projection.actionPermissionsSha256
  ) {
    addIssue(
      context,
      ["providerAcceptance"],
      "provider acceptance must bind the exact mandate, request, subject, policy, and actions",
    );
  }
  if (
    identity.observedAt !== projection.observation.observedAt ||
    identity.observedBlock !== projection.observation.observedBlock ||
    identity.observedBlockHash !== projection.observation.observedBlockHash
  ) {
    addIssue(
      context,
      ["anchorBinding"],
      "candidate identity and category observation must share one canonical block anchor",
    );
  }
}

const categoryLinkageProjectionUnsignedStructuralSchema = z
  .object(categoryLinkageProjectionShape)
  .strict();

export const categoryLinkageProjectionUnsignedSchema =
  categoryLinkageProjectionUnsignedStructuralSchema.superRefine(
    refineCategoryLinkageProjection,
  );

export const categoryLinkageProjectionSchema = z
  .object({ ...categoryLinkageProjectionShape, linkageSha256: sha256Schema })
  .strict()
  .superRefine((projection, context) => {
    refineCategoryLinkageProjection(projection, context);
    const { linkageSha256, ...unsigned } = projection;
    if (linkageSha256 !== canonicalSha256(unsigned)) {
      addIssue(context, ["linkageSha256"], "linkage digest does not match the projection");
    }
  });

export type CategoryLinkageProjectionUnsigned = DeepReadonly<
  z.infer<typeof categoryLinkageProjectionUnsignedSchema>
>;
export type UntrustedCategoryLinkageProjection = DeepReadonly<
  z.infer<typeof categoryLinkageProjectionSchema>
>;
export type CategoryLinkageProviderAuthority = DeepReadonly<
  z.infer<typeof categoryProviderAuthoritySchema>
>;
export type CategoryLinkageProviderAcceptance = DeepReadonly<
  z.infer<typeof categoryProviderAcceptanceSchema>
>;
export type CategoryLinkageObservation = DeepReadonly<
  z.infer<typeof categoryLinkageObservationSchema>
>;

/**
 * Build the untrusted linkage projection from already captured source facts.
 *
 * This is intentionally a structural projector, not a trust boundary: the
 * caller must obtain identity, quote acceptance, target observations, and
 * adapter evidence through verifier-owned capabilities before calling it.
 * The resulting object remains untrusted until the successor attestation
 * evaluator validates those source facts and the signer binds the projection.
 */
export function buildCategoryLinkageProjection(input: {
  readonly mandate: unknown;
  readonly request: unknown;
  readonly candidateIdentity: unknown;
  readonly providerAcceptance: unknown;
  readonly targetObservations: unknown;
  readonly readProfile: unknown;
  readonly observation: unknown;
}): UntrustedCategoryLinkageProjection {
  const mandate = parse(marketplaceMandateV2Schema, input.mandate, "mandate v2");
  const request = validateCategoryQuoteRequestBinding({
    request: input.request,
    mandate,
  });
  const identity = validateCandidateIdentityForSelector({
    artifact: input.candidateIdentity,
    candidate: request.candidate,
  });
  const targets = validateTargetObservationsForScope({
    scope: request.categoryScope,
    targets: input.targetObservations,
  });
  const readProfile = validateAdapterReadProfile({
    profile: input.readProfile,
    scope: request.categoryScope,
  });
  const acceptance = parse(
    categoryProviderAcceptanceSchema,
    input.providerAcceptance,
    "category provider acceptance",
  );
  const observation = parse(
    categoryLinkageObservationSchema,
    input.observation,
    "category linkage observation",
  );
  const unsigned = categoryLinkageProjectionUnsignedSchema.parse({
    schema: MARKETPLACE_CATEGORY_LINKAGE_PROJECTION_SCHEMA,
    trustStatus: "untrusted_until_successor_attestation_verified",
    relation: "candidate_accepts_service_for_subject",
    scope: "evaluation_only",
    activationAuthorization: "none",
    reservation: "none",
    subjectSelection: "mandate_declared_exact",
    anchorBinding: "same_canonical_block",
    requestId: request.requestId,
    mandateId: mandate.mandateId,
    mandateSha256: canonicalSha256(mandate),
    categoryQuoteRequestSha256: canonicalSha256(request),
    category: request.category,
    adapterId: request.adapterId,
    protocol: request.protocol,
    candidate: request.candidate,
    candidateIdentity: {
      proofProfile: "erc8004-owner-of-v1",
      chainId: identity.chainId,
      tokenId: identity.tokenId,
      registryAddress: identity.registryAddress,
      registeredOwner: identity.ownerAddress,
      confirmationDepth: identity.confirmationDepth,
      registryCodeSha256: identity.registryCodeSha256,
      identitySha256: identity.identitySha256,
      observedAt: identity.observedAt,
      observedBlock: identity.observedBlock,
      observedBlockHash: identity.observedBlockHash,
    },
    providerAuthority: {
      kind: "erc8004_registered_owner",
      providerAddress: identity.ownerAddress,
      validatedSigner: identity.ownerAddress,
      providerCodeSha256: acceptance.providerCodeSha256,
      candidateIdentitySha256: identity.identitySha256,
    },
    providerAcceptance: acceptance,
    categoryScope: request.categoryScope,
    categoryScopeSha256: request.categoryScopeSha256,
    subjectSha256: canonicalSha256(request.categoryScope.subject),
    conditionPolicySha256: canonicalSha256(request.categoryScope.conditionPolicy),
    serviceMode: request.serviceMode,
    actionPermissionsSha256: request.actionPermissionsSha256,
    observation,
  });
  return deepFreeze(
    categoryLinkageProjectionSchema.parse({
      ...unsigned,
      linkageSha256: canonicalSha256(unsigned),
    }),
  );
}

const expectedQuoteDomainSchema = z
  .object({ chainId: z.literal(56), verifyingContract: addressSchema })
  .strict();

const expectedReleaseSchema = z
  .object({
    categoryDeploymentSha256: sha256Schema,
    verifierPolicySha256: sha256Schema,
  })
  .strict();

export function categoryLinkageProjectionSha256(input: unknown): string {
  return canonicalSha256(
    parse(
      categoryLinkageProjectionUnsignedSchema,
      input,
      "category linkage projection without digest",
    ),
  );
}

/**
 * Validates source binding after an outer evaluator has established signer and
 * release trust. The returned value deliberately remains typed as untrusted.
 */
export function validateCategoryLinkageProjection(input: {
  readonly projection: unknown;
  readonly mandate: unknown;
  readonly request: unknown;
  readonly identityArtifact: unknown;
  readonly targetObservations: unknown;
  readonly readProfile: unknown;
  readonly expectedQuoteDomain: unknown;
  readonly expectedRelease: unknown;
  readonly evaluatedAt: number;
}): UntrustedCategoryLinkageProjection {
  const mandate = parse(marketplaceMandateV2Schema, input.mandate, "mandate v2");
  const request = validateCategoryQuoteRequestBinding({
    request: input.request,
    mandate,
  });
  const identity = validateCandidateIdentityForSelector({
    artifact: input.identityArtifact,
    candidate: request.candidate,
  });
  const targets = validateTargetObservationsForScope({
    scope: request.categoryScope,
    targets: input.targetObservations,
  });
  const readProfile = validateAdapterReadProfile({
    profile: input.readProfile,
    scope: request.categoryScope,
  });
  const quoteDomain = parse(
    expectedQuoteDomainSchema,
    input.expectedQuoteDomain,
    "expected category quote domain",
  );
  const release = parse(
    expectedReleaseSchema,
    input.expectedRelease,
    "expected category release",
  );
  const evaluatedAt = parse(unixSecondsSchema, input.evaluatedAt, "linkage evaluation time");
  const projection = parse(
    categoryLinkageProjectionSchema,
    input.projection,
    "category linkage projection",
  );

  if (projection.mandateId !== mandate.mandateId) {
    fail("linkage mandate ID does not match the mandate");
  }
  if (projection.mandateSha256 !== canonicalSha256(mandate)) {
    fail("linkage mandate digest does not match the mandate");
  }
  if (
    projection.requestId !== request.requestId ||
    projection.categoryQuoteRequestSha256 !== canonicalSha256(request)
  ) {
    fail("linkage quote request binding does not match the request");
  }
  if (
    projection.category !== request.category ||
    projection.adapterId !== request.adapterId ||
    projection.protocol !== request.protocol ||
    projection.candidate.chainId !== request.candidate.chainId ||
    projection.candidate.tokenId !== request.candidate.tokenId ||
    projection.serviceMode !== request.serviceMode
  ) {
    fail("linkage request identity does not match the category request");
  }
  if (canonicalJson(projection.categoryScope) !== canonicalJson(request.categoryScope)) {
    fail("linkage category scope does not match the mandate-bound request");
  }
  if (
    projection.categoryScopeSha256 !== request.categoryScopeSha256 ||
    projection.subjectSha256 !== canonicalSha256(request.categoryScope.subject) ||
    projection.conditionPolicySha256 !==
      canonicalSha256(request.categoryScope.conditionPolicy) ||
    projection.actionPermissionsSha256 !== request.actionPermissionsSha256
  ) {
    fail("linkage subject, policy, or action binding does not match the request");
  }
  const projectedIdentity = projection.candidateIdentity;
  if (
    projectedIdentity.identitySha256 !== identity.identitySha256 ||
    projectedIdentity.registryAddress !== identity.registryAddress ||
    projectedIdentity.registeredOwner !== identity.ownerAddress ||
    projectedIdentity.registryCodeSha256 !== identity.registryCodeSha256 ||
    projectedIdentity.confirmationDepth !== identity.confirmationDepth ||
    projectedIdentity.observedAt !== identity.observedAt ||
    projectedIdentity.observedBlock !== identity.observedBlock ||
    projectedIdentity.observedBlockHash !== identity.observedBlockHash
  ) {
    fail("linkage candidate identity does not match verifier-observed ERC-8004 identity");
  }

  const acceptance = projection.providerAcceptance;
  if (
    acceptance.validatedSigner !== identity.ownerAddress ||
    acceptance.validatedProvider !== identity.ownerAddress ||
    projection.providerAuthority.providerAddress !== identity.ownerAddress ||
    projection.providerAuthority.validatedSigner !== identity.ownerAddress ||
    projection.providerAuthority.providerCodeSha256 !== acceptance.providerCodeSha256
  ) {
    fail("linkage provider authority is not the verifier-observed ERC-8004 owner");
  }
  if (
    acceptance.chainId !== quoteDomain.chainId ||
    acceptance.verifyingContract !== quoteDomain.verifyingContract
  ) {
    fail("linkage candidate acceptance uses the wrong quote trust domain");
  }
  if (acceptance.quoteNonce !== request.nonce) {
    fail("linkage candidate acceptance uses a different quote nonce");
  }
  if (acceptance.negotiatedAt < request.issuedAt - mandate.maxClockSkewSeconds) {
    fail("linkage candidate acceptance predates the request window");
  }
  if (acceptance.negotiatedAt > evaluatedAt + mandate.maxClockSkewSeconds) {
    fail("linkage candidate acceptance is observed in the future");
  }
  if (acceptance.quoteExpiresAt > request.expiresAt) {
    fail("linkage candidate acceptance outlives the category request");
  }
  if (acceptance.quoteExpiresAt <= evaluatedAt) {
    fail("linkage candidate acceptance has expired");
  }
  if (
    projection.observation.categoryDeploymentSha256 !==
      release.categoryDeploymentSha256 ||
    projection.observation.verifierPolicySha256 !== release.verifierPolicySha256
  ) {
    fail("linkage observation does not match the trusted release commitments");
  }
  if (projection.observation.targetsSha256 !== canonicalSha256(targets)) {
    fail("linkage target digest does not match the exact target observations");
  }
  if (
    projection.observation.readProfileId !== readProfile.profileId ||
    projection.observation.readProfileSha256 !==
      categoryStaticReadProfileSha256(readProfile)
  ) {
    fail("linkage static read-profile commitment does not match the adapter definition");
  }
  if (
    projection.observation.readCommitmentsSha256 !==
    categoryReadCommitmentsSha256(readProfile)
  ) {
    fail("linkage dynamic read commitments do not match the observed adapter reads");
  }
  for (const target of targets) {
    if (
      target.observedAt !== projection.observation.observedAt ||
      target.observedBlock !== projection.observation.observedBlock ||
      target.observedBlockHash !== projection.observation.observedBlockHash
    ) {
      fail("linkage target identity and observation must share one canonical block anchor");
    }
  }
  if (
    identity.observedAt < mandate.createdAt ||
    projection.observation.observedAt < mandate.createdAt
  ) {
    fail("linkage identity and evidence must not predate the mandate");
  }
  if (
    identity.observedAt > evaluatedAt + mandate.maxClockSkewSeconds ||
    projection.observation.observedAt > evaluatedAt + mandate.maxClockSkewSeconds
  ) {
    fail("linkage identity or evidence is observed in the future");
  }

  const identityExpiresAt = exclusiveExpiry(
    identity.observedAt,
    MAX_CATEGORY_IDENTITY_AGE_SECONDS,
    "identity",
  );
  const evidenceExpiresAt = exclusiveExpiry(
    projection.observation.observedAt,
    mandate.maxEvidenceAgeSeconds,
    "evidence",
  );
  const validUntil = Math.min(
    mandate.expiresAt,
    request.expiresAt,
    request.permissionsExpiresAt,
    acceptance.quoteExpiresAt,
    identityExpiresAt,
    evidenceExpiresAt,
  );
  if (validUntil <= evaluatedAt) {
    fail("category linkage projection has expired");
  }
  return deepFreeze(projection);
}

function exclusiveExpiry(observedAt: number, maxAgeSeconds: number, label: string): number {
  const expiry = observedAt + maxAgeSeconds + 1;
  if (!Number.isSafeInteger(expiry)) fail(`${label} expiry exceeds the safe time range`);
  return expiry;
}

function parse<T>(schema: z.ZodType<T>, input: unknown, label: string): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new TypeError(`${label} is invalid: ${result.error.message}`);
  }
  return result.data;
}

function addIssue(
  context: z.RefinementCtx,
  path: (string | number)[],
  message: string,
): void {
  context.addIssue({ code: z.ZodIssueCode.custom, path, message });
}

function fail(message: string): never {
  throw new TypeError(message);
}

void categoryCandidateIdentityArtifactSchema;
void categoryReadProfileSchema;
void categoryTargetObservationSchema;
void marketplaceCategoryQuoteRequestSchema;
