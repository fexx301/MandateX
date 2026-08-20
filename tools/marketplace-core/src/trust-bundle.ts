import {
  createHash,
  createPublicKey,
  KeyObject,
  verify as verifyEd25519,
} from "node:crypto";
import { TextDecoder } from "node:util";

import { z } from "zod";

import { canonicalJson, canonicalSha256 } from "./canonical.js";
import {
  CATEGORY_ADAPTER_REGISTRY,
  MARKETPLACE_AAVE_HEALTH_ADAPTER,
  MARKETPLACE_GRID_ADAPTER,
  MARKETPLACE_VENUS_HEALTH_ADAPTER,
  MARKETPLACE_YIELD_ADAPTER,
  type MarketplaceCategoryAdapterId,
} from "./category-policy.js";
import {
  CATEGORY_PRODUCTION_READ_DESCRIPTORS,
  categoryStaticReadProfileForAdapterSha256,
} from "./category-production.js";
import { deepFreeze, type DeepReadonly } from "./immutable.js";
import {
  canonicalIdentifierSchema,
  compareCanonicalStrings,
  sha256Schema,
  unixSecondsSchema,
} from "./primitives.js";

export const MARKETPLACE_TRUST_BUNDLE_SCHEMA =
  "mandatex.marketplace.trust-bundle.v1" as const;
export const MARKETPLACE_TRUST_KEY_SCHEMA =
  "mandatex.marketplace.trust-key.v1" as const;
export const MARKETPLACE_TRUST_RELEASE_SCHEMA =
  "mandatex.marketplace.trust-release.v1" as const;
export const MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA =
  "mandatex.marketplace.trust-key-release-authorization.v1" as const;
export const MARKETPLACE_TRUST_KEY_TOMBSTONE_SCHEMA =
  "mandatex.marketplace.trust-key-tombstone.v1" as const;
export const MARKETPLACE_TRUST_RELEASE_TOMBSTONE_SCHEMA =
  "mandatex.marketplace.trust-release-tombstone.v1" as const;
export const MARKETPLACE_TRUST_STATE_SCHEMA =
  "mandatex.marketplace.trust-state.v1" as const;
export const MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE =
  "mandatex-ed25519-trust-bundle-v1" as const;
export const MARKETPLACE_TRUST_BUNDLE_ISSUER =
  "mandatex-trust-control-plane" as const;
export const MARKETPLACE_TRUST_BUNDLE_AUDIENCE =
  "mandatex-marketplace-core" as const;
export const MARKETPLACE_TRUST_BUNDLE_SIGNING_DOMAIN =
  "MandateX Marketplace Trust Bundle v1\0" as const;
export const MAX_MARKETPLACE_TRUST_BUNDLE_BYTES = 131_072 as const;
export const MAX_MARKETPLACE_TRUST_BUNDLE_TTL_SECONDS = 604_800 as const;
export const MAX_MARKETPLACE_TRUST_OVERLAP_RECORDS = 3 as const;

const signatureSchema = z
  .string()
  .regex(/^[a-f0-9]{128}$/, "expected a 64-byte lowercase hex signature");

const canonicalBase64Schema = z
  .string()
  .min(4)
  .max(4_096)
  .regex(
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
    "expected canonical padded base64",
  );

const monotonicCounterSchema = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER);
const generationSchema = monotonicCounterSchema.min(1);
const revocationEpochSchema = monotonicCounterSchema;
const recordRevocationEpochSchema = monotonicCounterSchema.min(1).nullable();

export const marketplaceTrustLifecycleSchema = z.enum([
  "preactive",
  "active",
  "retiring",
  "retired",
  "revoked",
]);
export type MarketplaceTrustLifecycle = z.infer<
  typeof marketplaceTrustLifecycleSchema
>;

export const marketplaceTrustServiceModeSchema = z.enum([
  "observe_only",
  "transactional",
]);
export type MarketplaceTrustServiceMode = z.infer<
  typeof marketplaceTrustServiceModeSchema
>;

export const marketplaceTrustTargetAssuranceRequirementSchema = z.enum([
  "interface_only_unendorsed",
  "protocol_instance_verified",
]);
export type MarketplaceTrustTargetAssuranceRequirement = z.infer<
  typeof marketplaceTrustTargetAssuranceRequirementSchema
>;

const marketplaceTrustAdapterIdSchema = z.union([
  z.literal(MARKETPLACE_GRID_ADAPTER),
  z.literal(MARKETPLACE_YIELD_ADAPTER),
  z.literal(MARKETPLACE_AAVE_HEALTH_ADAPTER),
  z.literal(MARKETPLACE_VENUS_HEALTH_ADAPTER),
]);

export const marketplaceTrustBundleAdapterModeSchema = z
  .object({
    adapterId: marketplaceTrustAdapterIdSchema,
    serviceMode: marketplaceTrustServiceModeSchema,
    readProfileId: canonicalIdentifierSchema,
    readProfileSha256: sha256Schema,
    actionProfileId: canonicalIdentifierSchema.nullable(),
    actionProfileSha256: sha256Schema.nullable(),
    minimumTargetAssurance: marketplaceTrustTargetAssuranceRequirementSchema,
  })
  .strict()
  .superRefine((entry, context) => {
    const expectedReadProfile =
      CATEGORY_PRODUCTION_READ_DESCRIPTORS[entry.adapterId];
    if (entry.readProfileId !== expectedReadProfile.profileId) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["readProfileId"],
        message: "read profile ID is not the adapter's production profile",
      });
    }
    if (
      entry.readProfileSha256 !==
      categoryStaticReadProfileForAdapterSha256(entry.adapterId)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["readProfileSha256"],
        message: "read profile hash is not the adapter's production profile",
      });
    }
    if (
      entry.serviceMode === "observe_only" &&
      (entry.actionProfileId !== null || entry.actionProfileSha256 !== null)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionProfileId"],
        message: "observe-only adapter modes cannot bind an action profile",
      });
    }
    if (
      entry.serviceMode === "transactional" &&
      (entry.actionProfileId === null || entry.actionProfileSha256 === null)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionProfileId"],
        message: "transactional adapter modes must bind an action profile",
      });
    }
    if (
      entry.serviceMode === "transactional" &&
      entry.minimumTargetAssurance !== "protocol_instance_verified"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["minimumTargetAssurance"],
        message: "transactional adapter modes require protocol-instance assurance",
      });
    }
  });

export type MarketplaceTrustBundleAdapterMode = DeepReadonly<
  z.infer<typeof marketplaceTrustBundleAdapterModeSchema>
>;

const keyRecordShape = {
  schema: z.literal(MARKETPLACE_TRUST_KEY_SCHEMA),
  keyId: canonicalIdentifierSchema,
  algorithm: z.literal("Ed25519"),
  publicKeyEncoding: z.literal("spki-der"),
  publicKeySpkiDerBase64: canonicalBase64Schema,
  publicKeyFingerprintSha256: sha256Schema,
  lifecycle: marketplaceTrustLifecycleSchema,
  lifecycleChangedAt: unixSecondsSchema,
  notBefore: unixSecondsSchema,
  notAfter: unixSecondsSchema,
  revokedAt: unixSecondsSchema.nullable(),
  revocationEpoch: recordRevocationEpochSchema,
} as const;

export const marketplaceTrustBundleKeyRecordSchema = z
  .object(keyRecordShape)
  .strict();

const releaseDefinitionShape = {
  schema: z.literal(MARKETPLACE_TRUST_RELEASE_SCHEMA),
  releaseId: canonicalIdentifierSchema,
  attestationSchema: canonicalIdentifierSchema,
  signatureProfile: canonicalIdentifierSchema,
  verifierPolicySha256: sha256Schema,
  categoryDeploymentSha256: sha256Schema,
  enabledAdapterModes: z
    .array(marketplaceTrustBundleAdapterModeSchema)
    .min(1)
    .max(8),
} as const;

const releaseDefinitionSchema = z.object(releaseDefinitionShape).strict();

export const marketplaceTrustBundleReleaseRecordSchema = z
  .object({
    ...releaseDefinitionShape,
    definitionSha256: sha256Schema,
    lifecycle: marketplaceTrustLifecycleSchema,
    lifecycleChangedAt: unixSecondsSchema,
    notBefore: unixSecondsSchema,
    notAfter: unixSecondsSchema,
    revokedAt: unixSecondsSchema.nullable(),
    revocationEpoch: recordRevocationEpochSchema,
  })
  .strict();

export type MarketplaceTrustBundleKeyRecord = DeepReadonly<
  z.infer<typeof marketplaceTrustBundleKeyRecordSchema>
>;
export type MarketplaceTrustBundleReleaseRecord = DeepReadonly<
  z.infer<typeof marketplaceTrustBundleReleaseRecordSchema>
>;

const marketplaceTrustPolicyAdapterModeSchema = z
  .object({
    adapterId: marketplaceTrustAdapterIdSchema,
    serviceMode: marketplaceTrustServiceModeSchema,
    enabled: z.boolean(),
    readProfileId: canonicalIdentifierSchema,
    readProfileSha256: sha256Schema,
    actionProfileId: canonicalIdentifierSchema.nullable(),
    actionProfileSha256: sha256Schema.nullable(),
    minimumTargetAssurance: marketplaceTrustTargetAssuranceRequirementSchema,
  })
  .strict()
  .superRefine((entry, context) => {
    const expectedReadProfile =
      CATEGORY_PRODUCTION_READ_DESCRIPTORS[entry.adapterId];
    if (
      entry.readProfileId !== expectedReadProfile.profileId ||
      entry.readProfileSha256 !==
        categoryStaticReadProfileForAdapterSha256(entry.adapterId)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["readProfileId"],
        message: "policy mode does not bind the adapter's production read profile",
      });
    }
    if (
      entry.actionProfileId === null !== (entry.actionProfileSha256 === null)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionProfileSha256"],
        message: "action profile ID and hash must be present or absent together",
      });
    }
    if (
      entry.serviceMode === "observe_only" &&
      (entry.actionProfileId !== null || entry.actionProfileSha256 !== null)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionProfileId"],
        message: "observe-only policy modes cannot bind an action profile",
      });
    }
    if (
      entry.enabled &&
      entry.serviceMode === "transactional" &&
      (entry.actionProfileId === null || entry.actionProfileSha256 === null)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionProfileId"],
        message: "enabled transactional policy modes require an action profile",
      });
    }
    if (
      entry.enabled &&
      entry.serviceMode === "transactional" &&
      entry.minimumTargetAssurance !== "protocol_instance_verified"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["minimumTargetAssurance"],
        message: "enabled transactional policy modes require protocol-instance assurance",
      });
    }
  });

export type MarketplaceTrustPolicyAdapterMode = DeepReadonly<
  z.infer<typeof marketplaceTrustPolicyAdapterModeSchema>
>;

/**
 * Compare a complete policy-owned eight-entry matrix with the enabled mode
 * records carried by a root-signed release. Disabled policy rows are omitted
 * from the trust release by design; every enabled row must match byte-for-byte.
 */
export function assertMarketplaceTrustReleaseModeProjection(input: {
  readonly policyModes: unknown;
  readonly release: unknown;
}): true {
  const policyModes = z
    .array(marketplaceTrustPolicyAdapterModeSchema)
    .length(8)
    .parse(input.policyModes);
  const release = marketplaceTrustBundleReleaseRecordSchema.parse(input.release);
  const policyKeys = policyModes.map(
    (mode) => `${mode.adapterId}\0${mode.serviceMode}`,
  );
  if (new Set(policyKeys).size !== policyKeys.length) {
    throw new TypeError("trust policy adapter mode matrix contains duplicates");
  }
  const expectedKeys = new Set<string>();
  for (const adapterId of Object.keys(CATEGORY_ADAPTER_REGISTRY)) {
    for (const serviceMode of ["observe_only", "transactional"] as const) {
      expectedKeys.add(`${adapterId}\0${serviceMode}`);
    }
  }
  if (
    policyKeys.length !== expectedKeys.size ||
    policyKeys.some((key) => !expectedKeys.has(key))
  ) {
    throw new TypeError("trust policy adapter mode matrix is not complete");
  }
  const enabled = policyModes
    .filter((mode) => mode.enabled)
    .map(({ enabled: _enabled, ...mode }) => mode)
    .sort((left, right) =>
      `${left.adapterId}\0${left.serviceMode}`.localeCompare(
        `${right.adapterId}\0${right.serviceMode}`,
      ),
    );
  const releaseModes = [...release.enabledAdapterModes].sort((left, right) =>
    `${left.adapterId}\0${left.serviceMode}`.localeCompare(
      `${right.adapterId}\0${right.serviceMode}`,
    ),
  );
  if (canonicalJson(enabled) !== canonicalJson(releaseModes)) {
    throw new TypeError(
      "enabled successor adapter modes do not match the authorized trust release",
    );
  }
  return true;
}

const authorizationChannelSchema = z.enum(["production", "canary"]);
export type MarketplaceTrustAuthorizationChannel = z.infer<
  typeof authorizationChannelSchema
>;

export const marketplaceTrustBundleAuthorizationSchema = z
  .object({
    schema: z.literal(MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA),
    keyId: canonicalIdentifierSchema,
    releaseId: canonicalIdentifierSchema,
    channel: authorizationChannelSchema,
    notBefore: unixSecondsSchema,
    notAfter: unixSecondsSchema,
  })
  .strict();
export type MarketplaceTrustBundleAuthorization = DeepReadonly<
  z.infer<typeof marketplaceTrustBundleAuthorizationSchema>
>;

const keyTombstoneSchema = z
  .object({
    schema: z.literal(MARKETPLACE_TRUST_KEY_TOMBSTONE_SCHEMA),
    keyId: canonicalIdentifierSchema,
    publicKeySpkiDerBase64: canonicalBase64Schema,
    publicKeyFingerprintSha256: sha256Schema,
    reason: z.enum(["retired", "revoked"]),
    tombstonedAtGeneration: generationSchema,
    retainUntilGeneration: generationSchema.nullable(),
  })
  .strict()
  .superRefine((tombstone, context) => {
    if (
      tombstone.reason === "retired" &&
      (tombstone.retainUntilGeneration === null ||
        tombstone.retainUntilGeneration <= tombstone.tombstonedAtGeneration)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["retainUntilGeneration"],
        message: "retired key tombstones require a later retention floor",
      });
    }
    if (
      tombstone.reason === "revoked" &&
      tombstone.retainUntilGeneration !== null
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["retainUntilGeneration"],
        message: "revoked key tombstones are permanent",
      });
    }
  });

const releaseTombstoneSchema = z
  .object({
    schema: z.literal(MARKETPLACE_TRUST_RELEASE_TOMBSTONE_SCHEMA),
    releaseId: canonicalIdentifierSchema,
    definitionSha256: sha256Schema,
    reason: z.enum(["retired", "revoked"]),
    tombstonedAtGeneration: generationSchema,
    retainUntilGeneration: generationSchema.nullable(),
  })
  .strict()
  .superRefine((tombstone, context) => {
    if (
      tombstone.reason === "retired" &&
      (tombstone.retainUntilGeneration === null ||
        tombstone.retainUntilGeneration <= tombstone.tombstonedAtGeneration)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["retainUntilGeneration"],
        message: "retired release tombstones require a later retention floor",
      });
    }
    if (
      tombstone.reason === "revoked" &&
      tombstone.retainUntilGeneration !== null
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["retainUntilGeneration"],
        message: "revoked release tombstones are permanent",
      });
    }
  });

export const marketplaceTrustBundleUnsignedSchema = z
  .object({
    schema: z.literal(MARKETPLACE_TRUST_BUNDLE_SCHEMA),
    signatureProfile: z.literal(MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE),
    issuer: z.literal(MARKETPLACE_TRUST_BUNDLE_ISSUER),
    audience: z.literal(MARKETPLACE_TRUST_BUNDLE_AUDIENCE),
    rootKeyId: canonicalIdentifierSchema,
    generation: generationSchema,
    revocationEpoch: revocationEpochSchema,
    issuedAt: unixSecondsSchema,
    expiresAt: unixSecondsSchema,
    activeSignerKeyId: canonicalIdentifierSchema,
    activeReleaseId: canonicalIdentifierSchema,
    keys: z.array(marketplaceTrustBundleKeyRecordSchema).min(1).max(32),
    releases: z.array(marketplaceTrustBundleReleaseRecordSchema).min(1).max(16),
    authorizations: z
      .array(marketplaceTrustBundleAuthorizationSchema)
      .min(1)
      .max(64),
    keyTombstones: z.array(keyTombstoneSchema).max(64),
    releaseTombstones: z.array(releaseTombstoneSchema).max(64),
    revokedKeyFingerprints: z.array(sha256Schema).max(64),
  })
  .strict();

export const marketplaceTrustBundleSchema = z
  .object({
    ...marketplaceTrustBundleUnsignedSchema.shape,
    signature: signatureSchema,
  })
  .strict();

export const marketplaceTrustBundleRollbackFloorSchema = z
  .object({
    generation: monotonicCounterSchema,
    revocationEpoch: revocationEpochSchema,
    bundleSha256: sha256Schema.optional(),
  })
  .strict();

const durableStateShape = {
  schema: z.literal(MARKETPLACE_TRUST_STATE_SCHEMA),
  generation: monotonicCounterSchema,
  revocationEpoch: revocationEpochSchema,
  bundleSha256: sha256Schema,
  keys: z.array(marketplaceTrustBundleKeyRecordSchema).max(32),
  releases: z.array(marketplaceTrustBundleReleaseRecordSchema).max(16),
  authorizations: z.array(marketplaceTrustBundleAuthorizationSchema).max(64),
  keyTombstones: z.array(keyTombstoneSchema).max(64),
  releaseTombstones: z.array(releaseTombstoneSchema).max(64),
  revokedKeyFingerprints: z.array(sha256Schema).max(64),
} as const;

export const marketplaceTrustBundleDurableStateSchema = z
  .object(durableStateShape)
  .strict();

export type MarketplaceTrustBundleUnsigned = DeepReadonly<
  z.infer<typeof marketplaceTrustBundleUnsignedSchema>
>;
export type MarketplaceTrustBundle = DeepReadonly<
  z.infer<typeof marketplaceTrustBundleSchema>
>;
export type MarketplaceTrustBundleRollbackFloor = DeepReadonly<
  z.infer<typeof marketplaceTrustBundleRollbackFloorSchema>
>;
export type MarketplaceTrustBundleDurableState = DeepReadonly<
  z.infer<typeof marketplaceTrustBundleDurableStateSchema>
>;
export type MarketplaceTrustBundleWire = string | Uint8Array;

export type MarketplaceTrustBundleRoot = Readonly<{
  keyId: string;
  publicKeySpkiDer: Uint8Array;
  publicKeyFingerprintSha256: string;
}>;

export type ValidatedMarketplaceTrustBundleRoot = Readonly<{
  keyId: string;
  publicKey: KeyObject;
  publicKeyFingerprintSha256: string;
}>;

export type ValidatedMarketplaceTrustBundleKey = Readonly<{
  record: MarketplaceTrustBundleKeyRecord;
  publicKey: KeyObject;
}>;

export type MarketplaceTrustAuthorizedTuple = Readonly<{
  keyId: string;
  releaseId: string;
  key: ValidatedMarketplaceTrustBundleKey;
  release: MarketplaceTrustBundleReleaseRecord;
  authorization: MarketplaceTrustBundleAuthorization;
}>;

export type MarketplaceTrustResolvedTuple = Readonly<
  MarketplaceTrustAuthorizedTuple & {
    adapterMode: MarketplaceTrustBundleAdapterMode;
    issuedAt: number;
  }
>;

export type VerifiedMarketplaceTrustBundle = Readonly<{
  envelope: MarketplaceTrustBundle;
  bundleSha256: string;
  rootPublicKeyFingerprintSha256: string;
  activeTuple: MarketplaceTrustAuthorizedTuple;
  authorizedTuples: readonly MarketplaceTrustAuthorizedTuple[];
  nextState: MarketplaceTrustBundleDurableState;
}>;

const verifiedMarketplaceTrustBundles = new WeakSet<object>();
const resolvedMarketplaceTrustTuples = new WeakSet<object>();

export const marketplaceTrustBundleErrorCodeValues = [
  "TRUST_BUNDLE_ACTIVE_RELEASE_INVALID",
  "TRUST_BUNDLE_ACTIVE_SIGNER_INVALID",
  "TRUST_BUNDLE_AUTHORIZATION_INVALID",
  "TRUST_BUNDLE_EXPIRED",
  "TRUST_BUNDLE_FRESHNESS_INVALID",
  "TRUST_BUNDLE_INPUT_INVALID",
  "TRUST_BUNDLE_JSON_INVALID",
  "TRUST_BUNDLE_KEY_INVALID",
  "TRUST_BUNDLE_LIFECYCLE_INVALID",
  "TRUST_BUNDLE_NONCANONICAL",
  "TRUST_BUNDLE_NOT_YET_VALID",
  "TRUST_BUNDLE_PROFILE_INVALID",
  "TRUST_BUNDLE_RELEASE_INVALID",
  "TRUST_BUNDLE_ROLLBACK_DETECTED",
  "TRUST_BUNDLE_ROOT_INVALID",
  "TRUST_BUNDLE_ROOT_KEY_MISMATCH",
  "TRUST_BUNDLE_SCHEMA_INVALID",
  "TRUST_BUNDLE_SIGNATURE_INVALID",
  "TRUST_BUNDLE_TOO_LARGE",
  "TRUST_BUNDLE_TRANSITION_INVALID",
  "TRUST_BUNDLE_TOMBSTONE_INVALID",
  "TRUST_BUNDLE_TUPLE_INVALID",
  "TRUST_BUNDLE_UTF8_INVALID",
] as const;
export type MarketplaceTrustBundleErrorCode =
  (typeof marketplaceTrustBundleErrorCodeValues)[number];

export class MarketplaceTrustBundleError extends Error {
  readonly code: MarketplaceTrustBundleErrorCode;

  constructor(
    code: MarketplaceTrustBundleErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "MarketplaceTrustBundleError";
    this.code = code;
  }
}

export function validateMarketplaceTrustBundleRoot(
  input: MarketplaceTrustBundleRoot,
): ValidatedMarketplaceTrustBundleRoot {
  if (input === null || typeof input !== "object") {
    throw trustBundleError(
      "TRUST_BUNDLE_ROOT_INVALID",
      "trust-bundle root must be an object",
    );
  }
  if (
    typeof input.keyId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.keyId)
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_ROOT_INVALID",
      "trust-bundle root key ID is invalid",
    );
  }
  if (!(input.publicKeySpkiDer instanceof Uint8Array)) {
    throw trustBundleError(
      "TRUST_BUNDLE_ROOT_INVALID",
      "trust-bundle root Ed25519 public key must be SPKI DER bytes",
    );
  }
  if (!/^[a-f0-9]{64}$/.test(input.publicKeyFingerprintSha256)) {
    throw trustBundleError(
      "TRUST_BUNDLE_ROOT_INVALID",
      "trust-bundle root public-key fingerprint is invalid",
    );
  }

  try {
    const publicKey = parseCanonicalEd25519Spki(input.publicKeySpkiDer);
    const fingerprint = fingerprintSpki(publicKey);
    if (fingerprint !== input.publicKeyFingerprintSha256) {
      throw new TypeError("root public-key fingerprint does not match");
    }
    return Object.freeze({
      keyId: input.keyId,
      publicKey,
      publicKeyFingerprintSha256: fingerprint,
    });
  } catch (cause) {
    if (cause instanceof MarketplaceTrustBundleError) throw cause;
    throw trustBundleError(
      "TRUST_BUNDLE_ROOT_INVALID",
      "trust-bundle root Ed25519 public key is invalid",
      cause,
    );
  }
}

export function marketplaceTrustReleaseDefinitionSha256(input: unknown): string {
  const release = marketplaceTrustBundleReleaseRecordSchema.parse(input);
  return canonicalSha256(releaseDefinitionSchema.parse({
    schema: release.schema,
    releaseId: release.releaseId,
    attestationSchema: release.attestationSchema,
    signatureProfile: release.signatureProfile,
    verifierPolicySha256: release.verifierPolicySha256,
    categoryDeploymentSha256: release.categoryDeploymentSha256,
    enabledAdapterModes: release.enabledAdapterModes,
  }));
}

export function marketplaceTrustBundleSigningMessage(input: unknown): Uint8Array {
  const unsigned = marketplaceTrustBundleUnsignedSchema.parse(input);
  return Buffer.concat([
    Buffer.from(MARKETPLACE_TRUST_BUNDLE_SIGNING_DOMAIN, "utf8"),
    Buffer.from(canonicalJson(unsigned), "utf8"),
  ]);
}

export function serializeMarketplaceTrustBundle(input: unknown): string {
  return canonicalJson(marketplaceTrustBundleSchema.parse(input));
}

export function verifyMarketplaceTrustBundle(input: {
  readonly wire: MarketplaceTrustBundleWire;
  readonly root: ValidatedMarketplaceTrustBundleRoot;
  readonly evaluatedAt: number;
  readonly maxClockSkewSeconds: number;
  readonly maxBundleTtlSeconds: number;
  readonly rollbackFloor: MarketplaceTrustBundleRollbackFloor;
  readonly priorState?: MarketplaceTrustBundleDurableState;
}): VerifiedMarketplaceTrustBundle {
  assertVerificationOptions(input);
  const rollbackFloor = parseRollbackFloor(input.rollbackFloor);
  const wireText = decodeWire(input.wire);
  const raw = parseCanonicalJson(wireText);
  const parsed = marketplaceTrustBundleSchema.safeParse(raw);
  if (!parsed.success) {
    throw trustBundleError(
      "TRUST_BUNDLE_SCHEMA_INVALID",
      "trust bundle does not match the fixed v1 wire schema",
      parsed.error,
    );
  }
  const envelope = parsed.data;
  if (canonicalJson(envelope) !== wireText) {
    throw trustBundleError(
      "TRUST_BUNDLE_NONCANONICAL",
      "trust bundle is not canonical wire JSON",
    );
  }
  if (envelope.rootKeyId !== input.root.keyId) {
    throw trustBundleError(
      "TRUST_BUNDLE_ROOT_KEY_MISMATCH",
      "trust bundle does not use the pinned root key",
    );
  }

  const unsigned = unsignedBundle(envelope);
  let validSignature = false;
  try {
    validSignature = verifyEd25519(
      null,
      marketplaceTrustBundleSigningMessage(unsigned),
      input.root.publicKey,
      Buffer.from(envelope.signature, "hex"),
    );
  } catch {
    validSignature = false;
  }
  if (!validSignature) {
    throw trustBundleError(
      "TRUST_BUNDLE_SIGNATURE_INVALID",
      "trust bundle Ed25519 root signature is invalid",
    );
  }

  const bundleSha256 = createHash("sha256")
    .update(wireText, "utf8")
    .digest("hex");
  assertFreshness(envelope, input);
  assertRollbackFloor(envelope, bundleSha256, rollbackFloor);
  const validatedKeys = envelope.keys.map(validateBundleKeyRecord);
  assertCanonicalRecordSets(envelope, validatedKeys);
  assertReleaseDefinitions(envelope);
  assertRevocationState(envelope);
  assertTerminalTombstones(envelope);
  const activeTuple = assertActiveTuple(envelope, validatedKeys);
  const authorizedTuples = buildAuthorizedTuples(envelope, validatedKeys);
  const activeTupleFromSet = authorizedTuples.find(
    (tuple) =>
      tuple.keyId === activeTuple.keyId && tuple.releaseId === activeTuple.releaseId,
  );
  if (activeTupleFromSet === undefined) {
    throw trustBundleError(
      "TRUST_BUNDLE_AUTHORIZATION_INVALID",
      "active signer and release have no production authorization edge",
    );
  }
  const nextState = validateDurableTransition(
    envelope,
    bundleSha256,
    input.priorState,
  );

  const verified = Object.freeze({
    envelope: deepFreeze(envelope),
    bundleSha256,
    rootPublicKeyFingerprintSha256: input.root.publicKeyFingerprintSha256,
    activeTuple: Object.freeze(activeTupleFromSet),
    authorizedTuples: Object.freeze(
      authorizedTuples.map((tuple) => Object.freeze(tuple)),
    ),
    nextState: deepFreeze(nextState),
  });
  verifiedMarketplaceTrustBundles.add(verified);
  return verified;
}

export function assertVerifiedMarketplaceTrustBundle(
  value: unknown,
): asserts value is VerifiedMarketplaceTrustBundle {
  if (
    value === null ||
    typeof value !== "object" ||
    !verifiedMarketplaceTrustBundles.has(value)
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_INPUT_INVALID",
      "verified trust bundle must come from root-signature verification in this evaluator",
    );
  }
}

export function resolveMarketplaceTrustBundleAttestationTuple(input: {
  readonly verified: VerifiedMarketplaceTrustBundle;
  readonly keyId: string;
  readonly releaseId: string;
  readonly issuedAt: number;
  readonly adapterId: MarketplaceCategoryAdapterId;
  readonly serviceMode: MarketplaceTrustServiceMode;
  readonly phase: "issuance" | "verification";
  readonly allowCanary?: boolean;
}): MarketplaceTrustResolvedTuple {
  assertVerifiedMarketplaceTrustBundle(input.verified);
  if (!Number.isSafeInteger(input.issuedAt) || input.issuedAt <= 0) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "attestation issuance time must be a positive Unix timestamp",
    );
  }
  const tuple = input.verified.authorizedTuples.find(
    (candidate) =>
      candidate.keyId === input.keyId && candidate.releaseId === input.releaseId,
  );
  if (tuple === undefined) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "keyId and releaseId do not identify a signed authorization edge",
    );
  }
  const mode = tuple.release.enabledAdapterModes.find(
    (entry) =>
      entry.adapterId === input.adapterId &&
      entry.serviceMode === input.serviceMode,
  );
  if (mode === undefined) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "attestation adapterId and serviceMode are not enabled by the release",
    );
  }
  if (
    input.issuedAt < tuple.authorization.notBefore ||
    input.issuedAt >= tuple.authorization.notAfter ||
    input.issuedAt < tuple.key.record.notBefore ||
    input.issuedAt >= tuple.key.record.notAfter ||
    input.issuedAt < tuple.release.notBefore ||
    input.issuedAt >= tuple.release.notAfter
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "attestation issuance time is outside the signed tuple validity interval",
    );
  }

  const canary = input.allowCanary === true;
  if (tuple.authorization.channel === "canary" && !canary) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "a canary authorization requires explicit canary resolution",
    );
  }
  if (tuple.authorization.channel === "production" && canary) {
    // A production edge may be used for a canary check, but it remains a
    // production edge and is still subject to the same exact mode binding.
  }
  assertLifecycleAtTuple(
    tuple,
    input.issuedAt,
    input.phase,
    canary,
    input.verified.envelope.issuedAt,
  );
  if (
    input.phase === "issuance" &&
    input.issuedAt < input.verified.envelope.issuedAt
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "a bundle cannot authorize an attestation issued before its snapshot",
    );
  }
  if (input.issuedAt >= input.verified.envelope.expiresAt) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "attestation issuance time exceeds bundle freshness",
    );
  }
  const resolved = Object.freeze({
    ...tuple,
    adapterMode: mode,
    issuedAt: input.issuedAt,
  });
  resolvedMarketplaceTrustTuples.add(resolved);
  return resolved;
}

export function assertMarketplaceTrustResolvedTuple(
  value: unknown,
): asserts value is MarketplaceTrustResolvedTuple {
  if (
    value === null ||
    typeof value !== "object" ||
    !resolvedMarketplaceTrustTuples.has(value)
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "resolved trust tuple must come from this evaluator's verified trust bundle",
    );
  }
}

function assertLifecycleAtTuple(
  tuple: MarketplaceTrustAuthorizedTuple,
  issuedAt: number,
  phase: "issuance" | "verification",
  allowCanary: boolean,
  bundleIssuedAt: number,
): void {
  const keyLifecycle = tuple.key.record.lifecycle;
  const releaseLifecycle = tuple.release.lifecycle;
  if (keyLifecycle === "revoked" || releaseLifecycle === "revoked") {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "revoked trust material cannot authorize an attestation",
    );
  }
  if (
    keyLifecycle === "preactive" ||
    releaseLifecycle === "preactive"
  ) {
    if (!allowCanary || tuple.authorization.channel !== "canary") {
      throw trustBundleError(
        "TRUST_BUNDLE_TUPLE_INVALID",
        "preactive trust material is canary-only",
      );
    }
  }
  if (phase === "issuance") {
    if (
      keyLifecycle !== "active" &&
      keyLifecycle !== "preactive"
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TUPLE_INVALID",
        "only active or explicitly canary-preactive keys may issue",
      );
    }
    if (
      releaseLifecycle !== "active" &&
      releaseLifecycle !== "preactive"
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TUPLE_INVALID",
        "only active or explicitly canary-preactive releases may issue",
      );
    }
    if (
      tuple.key.record.lifecycleChangedAt > issuedAt ||
      tuple.release.lifecycleChangedAt > issuedAt
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TUPLE_INVALID",
        "attestation cannot be issued before signer and release activation",
      );
    }
    return;
  }
  if (
    keyLifecycle === "retiring" ||
    keyLifecycle === "retired" ||
    releaseLifecycle === "retiring" ||
    releaseLifecycle === "retired"
  ) {
    const keyTransitionInvalid =
      (keyLifecycle === "retiring" || keyLifecycle === "retired") &&
      issuedAt >= tuple.key.record.lifecycleChangedAt;
    const releaseTransitionInvalid =
      (releaseLifecycle === "retiring" || releaseLifecycle === "retired") &&
      issuedAt >= tuple.release.lifecycleChangedAt;
    if (keyTransitionInvalid || releaseTransitionInvalid || issuedAt >= bundleIssuedAt) {
      throw trustBundleError(
        "TRUST_BUNDLE_TUPLE_INVALID",
        "retiring or retired material only verifies attestations issued before transition",
      );
    }
  }
  if (
    keyLifecycle === "active" &&
    tuple.key.record.lifecycleChangedAt > issuedAt
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "attestation predates the active signer lifecycle",
    );
  }
  if (
    releaseLifecycle === "active" &&
    tuple.release.lifecycleChangedAt > issuedAt
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_TUPLE_INVALID",
      "attestation predates the active release lifecycle",
    );
  }
}

function assertVerificationOptions(input: {
  readonly root: ValidatedMarketplaceTrustBundleRoot;
  readonly evaluatedAt: number;
  readonly maxClockSkewSeconds: number;
  readonly maxBundleTtlSeconds: number;
}): void {
  if (
    input.root === null ||
    typeof input.root !== "object" ||
    typeof input.root.keyId !== "string" ||
    !(input.root.publicKey instanceof KeyObject) ||
    input.root.publicKey.type !== "public" ||
    input.root.publicKey.asymmetricKeyType !== "ed25519" ||
    !/^[a-f0-9]{64}$/.test(input.root.publicKeyFingerprintSha256)
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_INPUT_INVALID",
      "validated trust-bundle root is invalid",
    );
  }
  try {
    if (
      fingerprintSpki(input.root.publicKey) !==
      input.root.publicKeyFingerprintSha256
    ) {
      throw new TypeError("validated root public-key fingerprint does not match");
    }
  } catch (cause) {
    throw trustBundleError(
      "TRUST_BUNDLE_INPUT_INVALID",
      "validated trust-bundle root is invalid",
      cause,
    );
  }
  if (!Number.isSafeInteger(input.evaluatedAt) || input.evaluatedAt <= 0) {
    throw trustBundleError(
      "TRUST_BUNDLE_INPUT_INVALID",
      "trust-bundle evaluation time must be positive Unix seconds",
    );
  }
  if (
    !Number.isSafeInteger(input.maxClockSkewSeconds) ||
    input.maxClockSkewSeconds < 0 ||
    input.maxClockSkewSeconds > 300
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_INPUT_INVALID",
      "trust-bundle clock skew must be an integer from zero to 300 seconds",
    );
  }
  if (
    !Number.isSafeInteger(input.maxBundleTtlSeconds) ||
    input.maxBundleTtlSeconds <= 0 ||
    input.maxBundleTtlSeconds > MAX_MARKETPLACE_TRUST_BUNDLE_TTL_SECONDS
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_INPUT_INVALID",
      `trust-bundle maximum TTL must be an integer from one to ${MAX_MARKETPLACE_TRUST_BUNDLE_TTL_SECONDS} seconds`,
    );
  }
}

function assertFreshness(
  envelope: MarketplaceTrustBundle,
  input: Readonly<{
    evaluatedAt: number;
    maxClockSkewSeconds: number;
    maxBundleTtlSeconds: number;
  }>,
): void {
  if (envelope.issuedAt > input.evaluatedAt + input.maxClockSkewSeconds) {
    throw trustBundleError(
      "TRUST_BUNDLE_NOT_YET_VALID",
      "trust bundle issuance time is in the future",
    );
  }
  if (envelope.expiresAt <= envelope.issuedAt) {
    throw trustBundleError(
      "TRUST_BUNDLE_FRESHNESS_INVALID",
      "trust bundle expiry must follow issuance",
    );
  }
  if (
    envelope.expiresAt - envelope.issuedAt >
    input.maxBundleTtlSeconds
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_FRESHNESS_INVALID",
      "trust bundle exceeds the configured freshness window",
    );
  }
  if (envelope.expiresAt <= input.evaluatedAt) {
    throw trustBundleError(
      "TRUST_BUNDLE_EXPIRED",
      "trust bundle has expired",
    );
  }
}

function assertRollbackFloor(
  envelope: MarketplaceTrustBundle,
  bundleSha256: string,
  floor: z.infer<typeof marketplaceTrustBundleRollbackFloorSchema>,
): void {
  if (
    envelope.generation < floor.generation ||
    envelope.revocationEpoch < floor.revocationEpoch
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_ROLLBACK_DETECTED",
      "trust bundle is below the durable rollback floor",
    );
  }
  if (
    envelope.generation === floor.generation &&
    floor.bundleSha256 !== undefined &&
    bundleSha256 !== floor.bundleSha256
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_ROLLBACK_DETECTED",
      "trust bundle conflicts with the accepted bundle at this generation",
    );
  }
}

function assertCanonicalRecordSets(
  envelope: MarketplaceTrustBundle,
  keys: readonly ValidatedMarketplaceTrustBundleKey[],
): void {
  assertSortedUniqueIds(envelope.keys.map((record) => record.keyId), "key");
  assertSortedUniqueIds(
    envelope.releases.map((record) => record.releaseId),
    "release",
  );
  assertSortedUniqueIds(
    envelope.authorizations.map((entry) => `${entry.keyId}\0${entry.releaseId}`),
    "authorization",
  );
  assertSortedUniqueIds(
    envelope.keyTombstones.map((entry) => entry.keyId),
    "tombstone",
  );
  assertSortedUniqueIds(
    envelope.releaseTombstones.map((entry) => entry.releaseId),
    "tombstone",
  );
  assertSortedUniqueStrings(envelope.revokedKeyFingerprints, "revoked fingerprint");

  const fingerprints = new Set<string>();
  const spkiValues = new Set<string>();
  for (const key of keys) {
    if (fingerprints.has(key.record.publicKeyFingerprintSha256)) {
      throw trustBundleError(
        "TRUST_BUNDLE_KEY_INVALID",
        "trust bundle contains duplicate signer-key fingerprints",
      );
    }
    if (spkiValues.has(key.record.publicKeySpkiDerBase64)) {
      throw trustBundleError(
        "TRUST_BUNDLE_KEY_INVALID",
        "trust bundle contains duplicate signer public keys",
      );
    }
    fingerprints.add(key.record.publicKeyFingerprintSha256);
    spkiValues.add(key.record.publicKeySpkiDerBase64);
  }

  for (const release of envelope.releases) {
    const modes = release.enabledAdapterModes.map(
      (entry) => `${entry.adapterId}\0${entry.serviceMode}`,
    );
    assertSortedUniqueIds(modes, "release mode");
    for (const mode of release.enabledAdapterModes) {
      if (CATEGORY_ADAPTER_REGISTRY[mode.adapterId] === undefined) {
        throw trustBundleError(
          "TRUST_BUNDLE_PROFILE_INVALID",
          "release contains an adapter outside the Core registry",
        );
      }
    }
  }

  const liveKeyCount = envelope.keys.filter((record) =>
    record.lifecycle === "preactive" ||
    record.lifecycle === "active" ||
    record.lifecycle === "retiring"
  ).length;
  const liveReleaseCount = envelope.releases.filter((record) =>
    record.lifecycle === "preactive" ||
    record.lifecycle === "active" ||
    record.lifecycle === "retiring"
  ).length;
  if (
    liveKeyCount > MAX_MARKETPLACE_TRUST_OVERLAP_RECORDS ||
    liveReleaseCount > MAX_MARKETPLACE_TRUST_OVERLAP_RECORDS
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_LIFECYCLE_INVALID",
      "trust bundle exceeds the bounded preactive/active/retiring overlap",
    );
  }
}

function assertReleaseDefinitions(envelope: MarketplaceTrustBundle): void {
  for (const release of envelope.releases) {
    if (release.definitionSha256 !== marketplaceTrustReleaseDefinitionSha256(release)) {
      throw trustBundleError(
        "TRUST_BUNDLE_RELEASE_INVALID",
        `release ${release.releaseId} definition digest does not match its immutable fields`,
      );
    }
  }
}

function assertSortedUniqueIds(
  ids: readonly string[],
  recordType: "key" | "release" | "authorization" | "tombstone" | "release mode",
): void {
  for (let index = 1; index < ids.length; index += 1) {
    if (compareCanonicalStrings(ids[index - 1]!, ids[index]!) >= 0) {
      const code =
        recordType === "key"
          ? "TRUST_BUNDLE_KEY_INVALID"
          : recordType === "release" || recordType === "release mode"
            ? "TRUST_BUNDLE_RELEASE_INVALID"
            : recordType === "authorization"
              ? "TRUST_BUNDLE_AUTHORIZATION_INVALID"
              : "TRUST_BUNDLE_TOMBSTONE_INVALID";
      throw trustBundleError(
        code,
        `trust-bundle ${recordType} records must be sorted and unique`,
      );
    }
  }
}

function assertSortedUniqueStrings(
  values: readonly string[],
  label: string,
): void {
  for (let index = 1; index < values.length; index += 1) {
    if (compareCanonicalStrings(values[index - 1]!, values[index]!) >= 0) {
      throw trustBundleError(
        "TRUST_BUNDLE_TOMBSTONE_INVALID",
        `${label} values must be sorted and unique`,
      );
    }
  }
}

function assertRevocationState(envelope: MarketplaceTrustBundle): void {
  for (const record of [...envelope.keys, ...envelope.releases]) {
    if (
      record.notAfter <= record.notBefore ||
      record.lifecycleChangedAt < record.notBefore ||
      record.lifecycleChangedAt >= record.notAfter ||
      record.lifecycleChangedAt > envelope.expiresAt ||
      (record.lifecycle !== "preactive" &&
        record.lifecycleChangedAt > envelope.issuedAt)
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_LIFECYCLE_INVALID",
        "trust record validity and lifecycle transition bounds are invalid",
      );
    }
    if (record.lifecycle === "revoked") {
      if (
        record.revokedAt === null ||
        record.revocationEpoch === null ||
        record.revokedAt !== record.lifecycleChangedAt ||
        record.revokedAt > envelope.issuedAt ||
        record.revocationEpoch > envelope.revocationEpoch
      ) {
        throw trustBundleError(
          "TRUST_BUNDLE_LIFECYCLE_INVALID",
          "revoked records require effective revocation data covered by the bundle",
        );
      }
    } else if (
      record.revokedAt !== null ||
      record.revocationEpoch !== null
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_LIFECYCLE_INVALID",
        "non-revoked records must not carry revocation data",
      );
    }
  }
  for (const tombstone of [
    ...envelope.keyTombstones,
    ...envelope.releaseTombstones,
  ]) {
    if (tombstone.tombstonedAtGeneration > envelope.generation) {
      throw trustBundleError(
        "TRUST_BUNDLE_TOMBSTONE_INVALID",
        "tombstone cannot be dated after its containing generation",
      );
    }
  }
  const requiredRevokedFingerprints = new Set([
    ...envelope.keys
      .filter((record) => record.lifecycle === "revoked")
      .map((record) => record.publicKeyFingerprintSha256),
    ...envelope.keyTombstones
      .filter((record) => record.reason === "revoked")
      .map((record) => record.publicKeyFingerprintSha256),
  ]);
  for (const fingerprint of requiredRevokedFingerprints) {
    if (!envelope.revokedKeyFingerprints.includes(fingerprint)) {
      throw trustBundleError(
        "TRUST_BUNDLE_TOMBSTONE_INVALID",
        "every revoked key fingerprint must appear in the permanent signed tombstone set",
      );
    }
  }
}

function assertTerminalTombstones(envelope: MarketplaceTrustBundle): void {
  const keyTombstones = new Map(
    envelope.keyTombstones.map((entry) => [entry.keyId, entry]),
  );
  for (const key of envelope.keys) {
    if (key.lifecycle !== "retired" && key.lifecycle !== "revoked") continue;
    const tombstone = keyTombstones.get(key.keyId);
    if (
      tombstone === undefined ||
      tombstone.reason !== key.lifecycle ||
      tombstone.publicKeySpkiDerBase64 !== key.publicKeySpkiDerBase64 ||
      tombstone.publicKeyFingerprintSha256 !== key.publicKeyFingerprintSha256
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TOMBSTONE_INVALID",
        `terminal key ${key.keyId} requires a matching signed tombstone`,
      );
    }
  }
  const releaseTombstones = new Map(
    envelope.releaseTombstones.map((entry) => [entry.releaseId, entry]),
  );
  for (const release of envelope.releases) {
    if (release.lifecycle !== "retired" && release.lifecycle !== "revoked") {
      continue;
    }
    const tombstone = releaseTombstones.get(release.releaseId);
    if (
      tombstone === undefined ||
      tombstone.reason !== release.lifecycle ||
      tombstone.definitionSha256 !== release.definitionSha256
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TOMBSTONE_INVALID",
        `terminal release ${release.releaseId} requires a matching signed tombstone`,
      );
    }
  }
}

function validateBundleKeyRecord(
  record: MarketplaceTrustBundleKeyRecord,
): ValidatedMarketplaceTrustBundleKey {
  try {
    const der = Buffer.from(record.publicKeySpkiDerBase64, "base64");
    if (der.toString("base64") !== record.publicKeySpkiDerBase64) {
      throw new TypeError("signer SPKI is not canonical base64");
    }
    const publicKey = parseCanonicalEd25519Spki(der);
    if (fingerprintSpki(publicKey) !== record.publicKeyFingerprintSha256) {
      throw new TypeError("signer public-key fingerprint does not match");
    }
    return Object.freeze({ record, publicKey });
  } catch (cause) {
    throw trustBundleError(
      "TRUST_BUNDLE_KEY_INVALID",
      `trust-bundle signer key ${record.keyId} is invalid`,
      cause,
    );
  }
}

function assertActiveTuple(
  envelope: MarketplaceTrustBundle,
  keys: readonly ValidatedMarketplaceTrustBundleKey[],
): MarketplaceTrustAuthorizedTuple {
  const activeKeys = keys.filter(({ record }) => record.lifecycle === "active");
  const activeReleases = envelope.releases.filter(
    (record) => record.lifecycle === "active",
  );
  if (
    activeKeys.length !== 1 ||
    activeKeys[0]?.record.keyId !== envelope.activeSignerKeyId
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_ACTIVE_SIGNER_INVALID",
      "trust bundle must identify exactly one active signer key",
    );
  }
  if (
    activeReleases.length !== 1 ||
    activeReleases[0]?.releaseId !== envelope.activeReleaseId
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_ACTIVE_RELEASE_INVALID",
      "trust bundle must identify exactly one active release",
    );
  }
  const key = activeKeys[0]!;
  const release = activeReleases[0]!;
  const authorization = envelope.authorizations.find(
    (entry) =>
      entry.keyId === key.record.keyId &&
      entry.releaseId === release.releaseId &&
      entry.channel === "production",
  );
  if (authorization === undefined) {
    throw trustBundleError(
      "TRUST_BUNDLE_AUTHORIZATION_INVALID",
      "active signer and release have no production authorization edge",
    );
  }
  if (
    key.record.lifecycleChangedAt > envelope.issuedAt ||
    release.lifecycleChangedAt > envelope.issuedAt ||
    key.record.notBefore > envelope.issuedAt ||
    key.record.notAfter < envelope.expiresAt ||
    release.notBefore > envelope.issuedAt ||
    release.notAfter < envelope.expiresAt ||
    authorization.notBefore > envelope.issuedAt ||
    authorization.notAfter < envelope.expiresAt
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_AUTHORIZATION_INVALID",
      "active tuple does not cover the trust-bundle validity window",
    );
  }
  return { keyId: key.record.keyId, releaseId: release.releaseId, key, release, authorization };
}

function buildAuthorizedTuples(
  envelope: MarketplaceTrustBundle,
  keys: readonly ValidatedMarketplaceTrustBundleKey[],
): MarketplaceTrustAuthorizedTuple[] {
  const keyMap = new Map(keys.map((entry) => [entry.record.keyId, entry]));
  const releaseMap = new Map(
    envelope.releases.map((release) => [release.releaseId, release]),
  );
  const tuples: MarketplaceTrustAuthorizedTuple[] = [];
  for (const authorization of envelope.authorizations) {
    const key = keyMap.get(authorization.keyId);
    const release = releaseMap.get(authorization.releaseId);
    if (key === undefined || release === undefined) {
      throw trustBundleError(
        "TRUST_BUNDLE_AUTHORIZATION_INVALID",
        "authorization edge references an unknown key or release",
      );
    }
    if (
      authorization.notBefore >= authorization.notAfter ||
      authorization.notBefore < key.record.notBefore ||
      authorization.notAfter > key.record.notAfter ||
      authorization.notBefore < release.notBefore ||
      authorization.notAfter > release.notAfter
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_AUTHORIZATION_INVALID",
        "authorization edge exceeds the key or release validity interval",
      );
    }
    if (
      key.record.lifecycle === "revoked" ||
      release.lifecycle === "revoked"
    ) {
      continue;
    }
    if (authorization.channel === "canary") {
      const keyCanaryCompatible =
        key.record.lifecycle === "preactive" || key.record.lifecycle === "active";
      const releaseCanaryCompatible =
        release.lifecycle === "preactive" || release.lifecycle === "active";
      if (
        !keyCanaryCompatible ||
        !releaseCanaryCompatible ||
        (key.record.lifecycle !== "preactive" && release.lifecycle !== "preactive")
      ) {
        throw trustBundleError(
          "TRUST_BUNDLE_AUTHORIZATION_INVALID",
          "canary edges require preactive trust material and cannot use terminal lifecycle states",
        );
      }
    } else if (
      key.record.lifecycle === "preactive" ||
      release.lifecycle === "preactive"
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_AUTHORIZATION_INVALID",
        "preactive trust material cannot have production authorization",
      );
    }
    tuples.push({
      keyId: authorization.keyId,
      releaseId: authorization.releaseId,
      key,
      release,
      authorization,
    });
  }
  if (tuples.length === 0) {
    throw trustBundleError(
      "TRUST_BUNDLE_AUTHORIZATION_INVALID",
      "trust bundle contains no non-revoked authorization edges",
    );
  }
  return tuples;
}

function validateDurableTransition(
  envelope: MarketplaceTrustBundle,
  bundleSha256: string,
  priorStateInput: MarketplaceTrustBundleDurableState | undefined,
): MarketplaceTrustBundleDurableState {
  const currentState = stateFromEnvelope(envelope, bundleSha256);
  if (priorStateInput === undefined) return currentState;
  const parsed = marketplaceTrustBundleDurableStateSchema.safeParse(priorStateInput);
  if (!parsed.success) {
    throw trustBundleError(
      "TRUST_BUNDLE_TRANSITION_INVALID",
      "durable prior trust state is malformed",
      parsed.error,
    );
  }
  const prior = parsed.data;
  assertDurableStateConsistency(prior);
  if (envelope.generation < prior.generation || envelope.revocationEpoch < prior.revocationEpoch) {
    throw trustBundleError(
      "TRUST_BUNDLE_ROLLBACK_DETECTED",
      "trust bundle generation or revocation epoch regressed",
    );
  }
  if (envelope.generation === prior.generation) {
    if (bundleSha256 !== prior.bundleSha256) {
      throw trustBundleError(
        "TRUST_BUNDLE_ROLLBACK_DETECTED",
        "two different trust bundles claim the same generation",
      );
    }
    return currentState;
  }

  for (const fingerprint of prior.revokedKeyFingerprints) {
    if (!envelope.revokedKeyFingerprints.includes(fingerprint)) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        "a permanent revoked-key fingerprint disappeared from the signed bundle",
      );
    }
  }

  validatePriorBindings(envelope, prior);
  validateCurrentTombstones(envelope, prior);
  validateAuthorizationTransition(envelope, prior);
  const revokedFingerprints = new Set([
    ...prior.revokedKeyFingerprints,
    ...envelope.revokedKeyFingerprints,
    ...envelope.keyTombstones
      .filter((tombstone) => tombstone.reason === "revoked")
      .map((tombstone) => tombstone.publicKeyFingerprintSha256),
  ]);
  const currentFingerprints = new Set(
    envelope.keys
      .filter((key) => key.lifecycle !== "revoked")
      .map((key) => key.publicKeyFingerprintSha256),
  );
  for (const fingerprint of revokedFingerprints) {
    if (currentFingerprints.has(fingerprint)) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        "a revoked public-key fingerprint cannot re-enter the active key set",
      );
    }
  }
  const next = {
    ...currentState,
    revokedKeyFingerprints: [...revokedFingerprints].sort(compareCanonicalStrings),
  };
  return marketplaceTrustBundleDurableStateSchema.parse(next);
}

function assertDurableStateConsistency(
  state: z.infer<typeof marketplaceTrustBundleDurableStateSchema>,
): void {
  assertSortedUniqueIds(state.keys.map((record) => record.keyId), "key");
  assertSortedUniqueIds(
    state.releases.map((record) => record.releaseId),
    "release",
  );
  assertSortedUniqueIds(
    state.authorizations.map((entry) => `${entry.keyId}\0${entry.releaseId}`),
    "authorization",
  );
  assertSortedUniqueIds(
    state.keyTombstones.map((entry) => entry.keyId),
    "tombstone",
  );
  assertSortedUniqueIds(
    state.releaseTombstones.map((entry) => entry.releaseId),
    "tombstone",
  );
  assertSortedUniqueStrings(state.revokedKeyFingerprints, "revoked fingerprint");
  const keyMap = new Map(state.keys.map((record) => [record.keyId, record]));
  for (const tombstone of state.keyTombstones) {
    const key = keyMap.get(tombstone.keyId);
    if (
      key !== undefined &&
      (key.lifecycle !== tombstone.reason ||
        key.publicKeySpkiDerBase64 !== tombstone.publicKeySpkiDerBase64 ||
        key.publicKeyFingerprintSha256 !== tombstone.publicKeyFingerprintSha256)
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `durable key tombstone ${tombstone.keyId} conflicts with its record`,
      );
    }
  }
  for (const key of state.keys) {
    if (key.lifecycle === "retired" || key.lifecycle === "revoked") {
      const tombstone = state.keyTombstones.find(
        (entry) => entry.keyId === key.keyId,
      );
      if (tombstone === undefined || tombstone.reason !== key.lifecycle) {
        throw trustBundleError(
          "TRUST_BUNDLE_TRANSITION_INVALID",
          `durable terminal key ${key.keyId} lacks a matching tombstone`,
        );
      }
    }
  }
  const releaseMap = new Map(
    state.releases.map((record) => [record.releaseId, record]),
  );
  for (const tombstone of state.releaseTombstones) {
    const release = releaseMap.get(tombstone.releaseId);
    if (
      release !== undefined &&
      (release.lifecycle !== tombstone.reason ||
        release.definitionSha256 !== tombstone.definitionSha256)
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `durable release tombstone ${tombstone.releaseId} conflicts with its record`,
      );
    }
  }
  for (const release of state.releases) {
    if (release.lifecycle === "retired" || release.lifecycle === "revoked") {
      const tombstone = state.releaseTombstones.find(
        (entry) => entry.releaseId === release.releaseId,
      );
      if (tombstone === undefined || tombstone.reason !== release.lifecycle) {
        throw trustBundleError(
          "TRUST_BUNDLE_TRANSITION_INVALID",
          `durable terminal release ${release.releaseId} lacks a matching tombstone`,
        );
      }
    }
  }
  for (const key of state.keys) {
    if (
      key.lifecycle === "revoked" &&
      !state.revokedKeyFingerprints.includes(key.publicKeyFingerprintSha256)
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `durable revoked key ${key.keyId} is absent from the permanent fingerprint set`,
      );
    }
  }
}

function validatePriorBindings(
  envelope: MarketplaceTrustBundle,
  prior: z.infer<typeof marketplaceTrustBundleDurableStateSchema>,
): void {
  const currentKeys = new Map(envelope.keys.map((record) => [record.keyId, record]));
  const currentReleases = new Map(
    envelope.releases.map((record) => [record.releaseId, record]),
  );
  const priorTombstonedKeys = new Set(prior.keyTombstones.map((entry) => entry.keyId));
  const priorTombstonedReleases = new Set(
    prior.releaseTombstones.map((entry) => entry.releaseId),
  );

  for (const oldKey of prior.keys) {
    const nextKey = currentKeys.get(oldKey.keyId);
    if (nextKey === undefined) {
      const currentTombstone = envelope.keyTombstones.find(
        (entry) => entry.keyId === oldKey.keyId,
      );
      const emergencyRevocation =
        currentTombstone?.reason === "revoked" &&
        envelope.revocationEpoch > prior.revocationEpoch;
      if (
        oldKey.lifecycle !== "retired" &&
        oldKey.lifecycle !== "revoked" &&
        !emergencyRevocation
      ) {
        throw trustBundleError(
          "TRUST_BUNDLE_TRANSITION_INVALID",
          `non-terminal key ${oldKey.keyId} disappeared from durable state`,
        );
      }
      if (
        envelope.keyTombstones.find((entry) => entry.keyId === oldKey.keyId) ===
        undefined
      ) {
        throw trustBundleError(
          "TRUST_BUNDLE_TOMBSTONE_INVALID",
          `terminal key ${oldKey.keyId} disappeared without a durable tombstone`,
        );
      }
      continue;
    }
    if (
      priorTombstonedKeys.has(oldKey.keyId) &&
      nextKey.lifecycle !== "retired" &&
      nextKey.lifecycle !== "revoked"
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `tombstoned key ${oldKey.keyId} was reactivated`,
      );
    }
    if (
      nextKey.publicKeySpkiDerBase64 !== oldKey.publicKeySpkiDerBase64 ||
      nextKey.publicKeyFingerprintSha256 !== oldKey.publicKeyFingerprintSha256 ||
      nextKey.algorithm !== oldKey.algorithm ||
      nextKey.publicKeyEncoding !== oldKey.publicKeyEncoding
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `keyId ${oldKey.keyId} changed its immutable public-key binding`,
      );
    }
    validateLifecycleTransition(oldKey, nextKey, "key");
  }
  for (const oldRelease of prior.releases) {
    const nextRelease = currentReleases.get(oldRelease.releaseId);
    if (nextRelease === undefined) {
      const currentTombstone = envelope.releaseTombstones.find(
        (entry) => entry.releaseId === oldRelease.releaseId,
      );
      const emergencyRevocation =
        currentTombstone?.reason === "revoked" &&
        envelope.revocationEpoch > prior.revocationEpoch;
      if (
        oldRelease.lifecycle !== "retired" &&
        oldRelease.lifecycle !== "revoked" &&
        !emergencyRevocation
      ) {
        throw trustBundleError(
          "TRUST_BUNDLE_TRANSITION_INVALID",
          `non-terminal release ${oldRelease.releaseId} disappeared from durable state`,
        );
      }
      if (
        envelope.releaseTombstones.find(
          (entry) => entry.releaseId === oldRelease.releaseId,
        ) === undefined
      ) {
        throw trustBundleError(
          "TRUST_BUNDLE_TOMBSTONE_INVALID",
          `terminal release ${oldRelease.releaseId} disappeared without a durable tombstone`,
        );
      }
      continue;
    }
    if (
      priorTombstonedReleases.has(oldRelease.releaseId) &&
      nextRelease.lifecycle !== "retired" &&
      nextRelease.lifecycle !== "revoked"
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `tombstoned release ${oldRelease.releaseId} was reactivated`,
      );
    }
    if (
      nextRelease.definitionSha256 !== oldRelease.definitionSha256 ||
      marketplaceTrustReleaseDefinitionSha256(nextRelease) !==
        marketplaceTrustReleaseDefinitionSha256(oldRelease)
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `releaseId ${oldRelease.releaseId} changed its immutable definition`,
      );
    }
    validateLifecycleTransition(oldRelease, nextRelease, "release");
  }
  for (const key of envelope.keys) {
    if (
      priorTombstonedKeys.has(key.keyId) ||
      prior.revokedKeyFingerprints.includes(key.publicKeyFingerprintSha256)
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `key ${key.keyId} reuses a durable tombstoned identity`,
      );
    }
  }
  for (const release of envelope.releases) {
    if (priorTombstonedReleases.has(release.releaseId)) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `release ${release.releaseId} reuses a durable tombstoned identity`,
      );
    }
  }
}

function validateLifecycleTransition(
  oldRecord: Readonly<{
    lifecycle: MarketplaceTrustLifecycle;
    lifecycleChangedAt: number;
    notBefore: number;
    notAfter: number;
  }> ,
  nextRecord: Readonly<{
    lifecycle: MarketplaceTrustLifecycle;
    lifecycleChangedAt: number;
    notBefore: number;
    notAfter: number;
  }>,
  kind: "key" | "release",
): void {
  if (nextRecord.notBefore !== oldRecord.notBefore || nextRecord.notAfter > oldRecord.notAfter) {
    throw trustBundleError(
      "TRUST_BUNDLE_TRANSITION_INVALID",
      `${kind} validity cannot move backward or be extended`,
    );
  }
  const allowed: Record<MarketplaceTrustLifecycle, readonly MarketplaceTrustLifecycle[]> = {
    preactive: ["preactive", "active", "retiring", "revoked"],
    active: ["active", "retiring", "revoked"],
    retiring: ["retiring", "retired", "revoked"],
    retired: ["retired", "revoked"],
    revoked: ["revoked"],
  };
  if (!allowed[oldRecord.lifecycle].includes(nextRecord.lifecycle)) {
    throw trustBundleError(
      "TRUST_BUNDLE_TRANSITION_INVALID",
      `${kind} lifecycle transition ${oldRecord.lifecycle} -> ${nextRecord.lifecycle} is not allowed`,
    );
  }
  if (nextRecord.lifecycle === oldRecord.lifecycle) {
    if (nextRecord.lifecycleChangedAt !== oldRecord.lifecycleChangedAt) {
      throw trustBundleError(
        "TRUST_BUNDLE_TRANSITION_INVALID",
        `${kind} lifecycle timestamp changed without a lifecycle transition`,
      );
    }
  } else if (nextRecord.lifecycleChangedAt <= oldRecord.lifecycleChangedAt) {
    throw trustBundleError(
      "TRUST_BUNDLE_TRANSITION_INVALID",
      `${kind} lifecycle transition timestamp is not monotonic`,
    );
  }
}

function validateCurrentTombstones(
  envelope: MarketplaceTrustBundle,
  prior: z.infer<typeof marketplaceTrustBundleDurableStateSchema>,
): void {
  const priorKeys = new Map(prior.keys.map((record) => [record.keyId, record]));
  const priorReleases = new Map(
    prior.releases.map((record) => [record.releaseId, record]),
  );
  const currentKeys = new Map(envelope.keys.map((record) => [record.keyId, record]));
  const currentReleases = new Map(
    envelope.releases.map((record) => [record.releaseId, record]),
  );

  for (const tombstone of envelope.keyTombstones) {
    const current = currentKeys.get(tombstone.keyId);
    const old = priorKeys.get(tombstone.keyId);
    const oldTombstone = prior.keyTombstones.find(
      (entry) => entry.keyId === tombstone.keyId,
    );
    const source = current ?? old;
    if (source === undefined && oldTombstone === undefined) {
      throw trustBundleError(
        "TRUST_BUNDLE_TOMBSTONE_INVALID",
        `key tombstone ${tombstone.keyId} has no durable source record`,
      );
    }
    if (source !== undefined) {
      if (
        current !== undefined &&
        current.lifecycle !== tombstone.reason
      ) {
        throw trustBundleError(
          "TRUST_BUNDLE_TOMBSTONE_INVALID",
          `key tombstone ${tombstone.keyId} does not match current lifecycle`,
        );
      }
      if (
        source.publicKeySpkiDerBase64 !== tombstone.publicKeySpkiDerBase64 ||
        source.publicKeyFingerprintSha256 !== tombstone.publicKeyFingerprintSha256
      ) {
        throw trustBundleError(
          "TRUST_BUNDLE_TOMBSTONE_INVALID",
          `key tombstone ${tombstone.keyId} does not match its key binding`,
        );
      }
    }
    if (oldTombstone !== undefined) {
      const unchanged = canonicalJson(oldTombstone) === canonicalJson(tombstone);
      const upgradedToRevoked =
        oldTombstone.reason === "retired" &&
        tombstone.reason === "revoked" &&
        tombstone.publicKeySpkiDerBase64 === oldTombstone.publicKeySpkiDerBase64 &&
        tombstone.publicKeyFingerprintSha256 ===
          oldTombstone.publicKeyFingerprintSha256 &&
        tombstone.tombstonedAtGeneration >= oldTombstone.tombstonedAtGeneration;
      if (!unchanged && !upgradedToRevoked) {
        throw trustBundleError(
          "TRUST_BUNDLE_TOMBSTONE_INVALID",
          `key tombstone ${tombstone.keyId} changed after publication`,
        );
      }
    }
    if (current === undefined && old !== undefined) {
      if (old.lifecycle === "retired") {
        if (
          tombstone.reason !== "retired" ||
          tombstone.retainUntilGeneration === null ||
          envelope.generation < tombstone.retainUntilGeneration
        ) {
          throw trustBundleError(
            "TRUST_BUNDLE_TOMBSTONE_INVALID",
            `retired key ${tombstone.keyId} disappeared before tombstone retention elapsed`,
          );
        }
      } else if (old.lifecycle === "revoked" && tombstone.reason !== "revoked") {
        throw trustBundleError(
          "TRUST_BUNDLE_TOMBSTONE_INVALID",
          `revoked key ${tombstone.keyId} requires a permanent tombstone`,
        );
      }
    }
  }
  for (const oldTombstone of prior.keyTombstones) {
    if (
      envelope.keyTombstones.find((entry) => entry.keyId === oldTombstone.keyId) ===
      undefined
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TOMBSTONE_INVALID",
        `durable key tombstone ${oldTombstone.keyId} disappeared`,
      );
    }
  }

  for (const tombstone of envelope.releaseTombstones) {
    const current = currentReleases.get(tombstone.releaseId);
    const old = priorReleases.get(tombstone.releaseId);
    const oldTombstone = prior.releaseTombstones.find(
      (entry) => entry.releaseId === tombstone.releaseId,
    );
    const source = current ?? old;
    if (source === undefined && oldTombstone === undefined) {
      throw trustBundleError(
        "TRUST_BUNDLE_TOMBSTONE_INVALID",
        `release tombstone ${tombstone.releaseId} has no durable source record`,
      );
    }
    if (source !== undefined) {
      if (
        (current !== undefined && current.lifecycle !== tombstone.reason) ||
        source.definitionSha256 !== tombstone.definitionSha256
      ) {
        throw trustBundleError(
          "TRUST_BUNDLE_TOMBSTONE_INVALID",
          `release tombstone ${tombstone.releaseId} does not match its definition`,
        );
      }
    }
    if (oldTombstone !== undefined) {
      const unchanged = canonicalJson(oldTombstone) === canonicalJson(tombstone);
      const upgradedToRevoked =
        oldTombstone.reason === "retired" &&
        tombstone.reason === "revoked" &&
        tombstone.definitionSha256 === oldTombstone.definitionSha256 &&
        tombstone.tombstonedAtGeneration >= oldTombstone.tombstonedAtGeneration;
      if (!unchanged && !upgradedToRevoked) {
        throw trustBundleError(
          "TRUST_BUNDLE_TOMBSTONE_INVALID",
          `release tombstone ${tombstone.releaseId} changed after publication`,
        );
      }
    }
    if (current === undefined && old !== undefined) {
      if (old.lifecycle === "retired") {
        if (
          tombstone.reason !== "retired" ||
          tombstone.retainUntilGeneration === null ||
          envelope.generation < tombstone.retainUntilGeneration
        ) {
          throw trustBundleError(
            "TRUST_BUNDLE_TOMBSTONE_INVALID",
            `retired release ${tombstone.releaseId} disappeared before tombstone retention elapsed`,
          );
        }
      } else if (old.lifecycle === "revoked" && tombstone.reason !== "revoked") {
        throw trustBundleError(
          "TRUST_BUNDLE_TOMBSTONE_INVALID",
          `revoked release ${tombstone.releaseId} requires a permanent tombstone`,
        );
      }
    }
  }
  for (const oldTombstone of prior.releaseTombstones) {
    if (
      envelope.releaseTombstones.find(
        (entry) => entry.releaseId === oldTombstone.releaseId,
      ) === undefined
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_TOMBSTONE_INVALID",
        `durable release tombstone ${oldTombstone.releaseId} disappeared`,
      );
    }
  }
}

function validateAuthorizationTransition(
  envelope: MarketplaceTrustBundle,
  prior: z.infer<typeof marketplaceTrustBundleDurableStateSchema>,
): void {
  const current = new Map(
    envelope.authorizations.map((entry) => [`${entry.keyId}\0${entry.releaseId}`, entry]),
  );
  for (const old of prior.authorizations) {
    const key = `${old.keyId}\0${old.releaseId}`;
    const next = current.get(key);
    const currentKey = envelope.keys.find((record) => record.keyId === old.keyId);
    const currentRelease = envelope.releases.find(
      (record) => record.releaseId === old.releaseId,
    );
    const revoked =
      currentKey?.lifecycle === "revoked" ||
      currentRelease?.lifecycle === "revoked" ||
      envelope.keyTombstones.some(
        (entry) => entry.keyId === old.keyId && entry.reason === "revoked",
      ) ||
      envelope.releaseTombstones.some(
        (entry) => entry.releaseId === old.releaseId && entry.reason === "revoked",
      );
    if (next === undefined && old.notAfter > envelope.issuedAt && !revoked) {
      throw trustBundleError(
        "TRUST_BUNDLE_AUTHORIZATION_INVALID",
        `live authorization edge ${key} disappeared without expiry`,
      );
    }
    if (next !== undefined) {
      const promoted =
        old.channel === "canary" &&
        next.channel === "production" &&
        currentKey?.lifecycle === "active" &&
        currentRelease?.lifecycle === "active" &&
        next.notBefore >= old.notBefore &&
        next.notBefore >= currentKey.lifecycleChangedAt &&
        next.notBefore >= currentRelease.lifecycleChangedAt;
      const unchangedChannel =
        next.channel === old.channel && next.notBefore === old.notBefore;
      if ((!promoted && !unchangedChannel) || next.notAfter > old.notAfter) {
        throw trustBundleError(
          "TRUST_BUNDLE_AUTHORIZATION_INVALID",
          `authorization edge ${key} widened or changed channel without promotion`,
        );
      }
    }
  }
  const priorKeys = new Set(
    prior.authorizations.map((entry) => `${entry.keyId}\0${entry.releaseId}`),
  );
  for (const next of envelope.authorizations) {
    const key = `${next.keyId}\0${next.releaseId}`;
    if (priorKeys.has(key)) continue;
    const currentKey = envelope.keys.find((record) => record.keyId === next.keyId);
    const currentRelease = envelope.releases.find(
      (record) => record.releaseId === next.releaseId,
    );
    if (currentKey === undefined || currentRelease === undefined) continue;
    if (
      next.channel === "production" &&
      (currentKey.lifecycle !== "active" ||
        currentRelease.lifecycle !== "active" ||
        next.notBefore < currentKey.lifecycleChangedAt ||
        next.notBefore < currentRelease.lifecycleChangedAt)
    ) {
      throw trustBundleError(
        "TRUST_BUNDLE_AUTHORIZATION_INVALID",
        `new production authorization edge ${key} is not bound to active material`,
      );
    }
  }
}

function stateFromEnvelope(
  envelope: MarketplaceTrustBundle,
  bundleSha256: string,
): MarketplaceTrustBundleDurableState {
  return marketplaceTrustBundleDurableStateSchema.parse({
    schema: MARKETPLACE_TRUST_STATE_SCHEMA,
    generation: envelope.generation,
    revocationEpoch: envelope.revocationEpoch,
    bundleSha256,
    keys: envelope.keys,
    releases: envelope.releases,
    authorizations: envelope.authorizations,
    keyTombstones: envelope.keyTombstones,
    releaseTombstones: envelope.releaseTombstones,
    revokedKeyFingerprints: envelope.revokedKeyFingerprints,
  });
}

function unsignedBundle(
  envelope: MarketplaceTrustBundle,
): MarketplaceTrustBundleUnsigned {
  return marketplaceTrustBundleUnsignedSchema.parse({
    schema: envelope.schema,
    signatureProfile: envelope.signatureProfile,
    issuer: envelope.issuer,
    audience: envelope.audience,
    rootKeyId: envelope.rootKeyId,
    generation: envelope.generation,
    revocationEpoch: envelope.revocationEpoch,
    issuedAt: envelope.issuedAt,
    expiresAt: envelope.expiresAt,
    activeSignerKeyId: envelope.activeSignerKeyId,
    activeReleaseId: envelope.activeReleaseId,
    keys: envelope.keys,
    releases: envelope.releases,
    authorizations: envelope.authorizations,
    keyTombstones: envelope.keyTombstones,
    releaseTombstones: envelope.releaseTombstones,
    revokedKeyFingerprints: envelope.revokedKeyFingerprints,
  });
}

function parseRollbackFloor(
  input: MarketplaceTrustBundleRollbackFloor,
): z.infer<typeof marketplaceTrustBundleRollbackFloorSchema> {
  const result = marketplaceTrustBundleRollbackFloorSchema.safeParse(input);
  if (!result.success) {
    throw trustBundleError(
      "TRUST_BUNDLE_INPUT_INVALID",
      "trust-bundle rollback floor is invalid",
      result.error,
    );
  }
  if (result.data.generation === 0 && result.data.bundleSha256 !== undefined) {
    throw trustBundleError(
      "TRUST_BUNDLE_INPUT_INVALID",
      "a bootstrap rollback floor must not pin a bundle hash",
    );
  }
  return result.data;
}

function parseCanonicalEd25519Spki(input: Uint8Array): KeyObject {
  const suppliedDer = Buffer.from(input);
  const publicKey = createPublicKey({
    key: suppliedDer,
    format: "der",
    type: "spki",
  });
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("public key is not Ed25519");
  }
  const exported = publicKey.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(exported) || !exported.equals(suppliedDer)) {
    throw new TypeError("public key is not canonical SPKI DER");
  }
  return publicKey;
}

function fingerprintSpki(publicKey: KeyObject): string {
  const exported = publicKey.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(exported)) {
    throw new TypeError("expected SPKI DER buffer");
  }
  return createHash("sha256").update(exported).digest("hex");
}

function decodeWire(wire: MarketplaceTrustBundleWire): string {
  if (typeof wire !== "string" && !(wire instanceof Uint8Array)) {
    throw trustBundleError(
      "TRUST_BUNDLE_INPUT_INVALID",
      "trust-bundle input must be a UTF-8 string or byte array",
    );
  }
  const encodedBytes =
    typeof wire === "string" ? Buffer.byteLength(wire, "utf8") : wire.byteLength;
  if (encodedBytes > MAX_MARKETPLACE_TRUST_BUNDLE_BYTES) {
    throw trustBundleError(
      "TRUST_BUNDLE_TOO_LARGE",
      `trust bundle exceeds ${MAX_MARKETPLACE_TRUST_BUNDLE_BYTES} encoded bytes`,
    );
  }
  const bytes =
    typeof wire === "string" ? Buffer.from(wire, "utf8") : Buffer.from(wire);
  if (
    bytes.byteLength >= 3 &&
    bytes[0] === 0xef &&
    bytes[1] === 0xbb &&
    bytes[2] === 0xbf
  ) {
    throw trustBundleError(
      "TRUST_BUNDLE_NONCANONICAL",
      "trust bundle must not contain a UTF-8 byte-order mark",
    );
  }
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (typeof wire === "string" && decoded !== wire) {
      throw new TypeError("string is not stable UTF-8");
    }
    return decoded;
  } catch (cause) {
    throw trustBundleError(
      "TRUST_BUNDLE_UTF8_INVALID",
      "trust bundle is not canonical UTF-8",
      cause,
    );
  }
}

function parseCanonicalJson(wire: string): unknown {
  let raw: unknown;
  try {
    raw = JSON.parse(wire) as unknown;
  } catch (cause) {
    throw trustBundleError(
      "TRUST_BUNDLE_JSON_INVALID",
      "trust bundle is not valid JSON",
      cause,
    );
  }
  assertBoundedJsonShape(raw);
  let canonical: string;
  try {
    canonical = canonicalJson(raw);
  } catch (cause) {
    throw trustBundleError(
      "TRUST_BUNDLE_NONCANONICAL",
      "trust bundle contains unsupported canonical JSON data",
      cause,
    );
  }
  if (canonical !== wire) {
    throw trustBundleError(
      "TRUST_BUNDLE_NONCANONICAL",
      "trust bundle contains whitespace, alternate spelling, duplicate keys, or noncanonical ordering",
    );
  }
  return raw;
}

function assertBoundedJsonShape(root: unknown): void {
  const pending: Array<Readonly<{ value: unknown; depth: number }>> = [
    { value: root, depth: 0 },
  ];
  let nodes = 0;
  while (pending.length > 0) {
    const current = pending.pop()!;
    nodes += 1;
    if (nodes > 8_192 || current.depth > 32) {
      throw trustBundleError(
        "TRUST_BUNDLE_INPUT_INVALID",
        "trust-bundle JSON structure exceeds safety bounds",
      );
    }
    if (current.value === null || typeof current.value !== "object") continue;
    const values = Array.isArray(current.value)
      ? current.value
      : Object.values(current.value as Record<string, unknown>);
    for (const value of values) {
      pending.push({ value, depth: current.depth + 1 });
    }
  }
}

function trustBundleError(
  code: MarketplaceTrustBundleErrorCode,
  message: string,
  cause?: unknown,
): MarketplaceTrustBundleError {
  return new MarketplaceTrustBundleError(
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}
