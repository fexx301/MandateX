import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../src/canonical.js";
import {
  CATEGORY_PRODUCTION_READ_DESCRIPTORS,
  categoryStaticReadProfileForAdapterSha256,
} from "../src/category-production.js";
import {
  MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA,
  MARKETPLACE_TRUST_BUNDLE_AUDIENCE,
  MARKETPLACE_TRUST_BUNDLE_ISSUER,
  MARKETPLACE_TRUST_BUNDLE_SCHEMA,
  MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE,
  MARKETPLACE_TRUST_KEY_SCHEMA,
  MARKETPLACE_TRUST_KEY_TOMBSTONE_SCHEMA,
  MARKETPLACE_TRUST_RELEASE_SCHEMA,
  MARKETPLACE_TRUST_RELEASE_TOMBSTONE_SCHEMA,
  MarketplaceTrustBundleError,
  assertMarketplaceTrustReleaseModeProjection,
  assertMarketplaceTrustResolvedTuple,
  assertVerifiedMarketplaceTrustBundle,
  marketplaceTrustBundleSigningMessage,
  marketplaceTrustBundleUnsignedSchema,
  marketplaceTrustReleaseDefinitionSha256,
  resolveMarketplaceTrustBundleAttestationTuple,
  serializeMarketplaceTrustBundle,
  validateMarketplaceTrustBundleRoot,
  verifyMarketplaceTrustBundle,
  type MarketplaceTrustBundle,
  type MarketplaceTrustBundleDurableState,
  type MarketplaceTrustBundleErrorCode,
  type MarketplaceTrustBundleKeyRecord,
  type MarketplaceTrustBundleReleaseRecord,
  type MarketplaceTrustBundleUnsigned,
  type ValidatedMarketplaceTrustBundleRoot,
} from "../src/trust-bundle.js";

const ISSUED_AT = 1_000;
const EXPIRES_AT = 1_300;
const EVALUATED_AT = 1_100;
const POLICY_SHA256 = "11".repeat(32);
const DEPLOYMENT_SHA256 = "22".repeat(32);
type TestAdapterId =
  | "aave-v3-health-v1"
  | "erc4626-yield-v1"
  | "pancakeswap-v3-grid-v1"
  | "venus-health-v1";

const rootKeyPair = generateKeyPairSync("ed25519");
const signerOne = generateKeyPairSync("ed25519");
const signerTwo = generateKeyPairSync("ed25519");
const signerThree = generateKeyPairSync("ed25519");

function exportedSpki(publicKey: KeyObject): Buffer {
  const result = publicKey.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(result)) throw new Error("expected SPKI DER bytes");
  return result;
}

function fingerprint(publicKey: KeyObject): string {
  return createHash("sha256").update(exportedSpki(publicKey)).digest("hex");
}

const root = validateMarketplaceTrustBundleRoot({
  keyId: "root-production-1",
  publicKeySpkiDer: exportedSpki(rootKeyPair.publicKey),
  publicKeyFingerprintSha256: fingerprint(rootKeyPair.publicKey),
});

function keyRecord(input: {
  keyId: string;
  publicKey: KeyObject;
  lifecycle: "preactive" | "active" | "retiring" | "retired" | "revoked";
  lifecycleChangedAt?: number;
  notBefore?: number;
  notAfter?: number;
  revokedAt?: number | null;
  revocationEpoch?: number | null;
}): MarketplaceTrustBundleKeyRecord {
  return {
    schema: MARKETPLACE_TRUST_KEY_SCHEMA,
    keyId: input.keyId,
    algorithm: "Ed25519",
    publicKeyEncoding: "spki-der",
    publicKeySpkiDerBase64: exportedSpki(input.publicKey).toString("base64"),
    publicKeyFingerprintSha256: fingerprint(input.publicKey),
    lifecycle: input.lifecycle,
    lifecycleChangedAt: input.lifecycleChangedAt ?? 900,
    notBefore: input.notBefore ?? 800,
    notAfter: input.notAfter ?? 2_000,
    revokedAt: input.revokedAt ?? null,
    revocationEpoch: input.revocationEpoch ?? null,
  };
}

function mode(
  adapterId: TestAdapterId,
  serviceMode: "observe_only" | "transactional",
  action = serviceMode === "transactional",
  minimumTargetAssurance =
    serviceMode === "transactional"
      ? "protocol_instance_verified" as const
      : "interface_only_unendorsed" as const,
) {
  return {
    adapterId,
    serviceMode,
    readProfileId: CATEGORY_PRODUCTION_READ_DESCRIPTORS[adapterId].profileId,
    readProfileSha256: categoryStaticReadProfileForAdapterSha256(adapterId),
    actionProfileId: action ? `${adapterId}-action-v1` : null,
    actionProfileSha256: action ? "44".repeat(32) : null,
    minimumTargetAssurance,
  } as const;
}

const DEFAULT_MODES = [
  mode("aave-v3-health-v1", "observe_only"),
  mode("aave-v3-health-v1", "transactional"),
  mode("erc4626-yield-v1", "observe_only"),
  mode("pancakeswap-v3-grid-v1", "observe_only"),
  mode("venus-health-v1", "observe_only"),
] as const;

const ALL_MODE_ADAPTERS = [
  "aave-v3-health-v1",
  "erc4626-yield-v1",
  "pancakeswap-v3-grid-v1",
  "venus-health-v1",
] as const;

function completePolicyModes(release: MarketplaceTrustBundleReleaseRecord) {
  return ALL_MODE_ADAPTERS.flatMap((adapterId) =>
    (["observe_only", "transactional"] as const).map((serviceMode) => {
      const enabled = release.enabledAdapterModes.find(
        (mode) =>
          mode.adapterId === adapterId && mode.serviceMode === serviceMode,
      );
      if (enabled !== undefined) return { ...enabled, enabled: true };
      return {
        adapterId,
        serviceMode,
        enabled: false,
        readProfileId: CATEGORY_PRODUCTION_READ_DESCRIPTORS[adapterId].profileId,
        readProfileSha256:
          categoryStaticReadProfileForAdapterSha256(adapterId),
        actionProfileId: null,
        actionProfileSha256: null,
        minimumTargetAssurance:
          serviceMode === "transactional"
            ? ("protocol_instance_verified" as const)
            : ("interface_only_unendorsed" as const),
      };
    }),
  );
}

function releaseRecord(input: {
  releaseId: string;
  lifecycle: "preactive" | "active" | "retiring" | "retired" | "revoked";
  lifecycleChangedAt?: number;
  notBefore?: number;
  notAfter?: number;
  revokedAt?: number | null;
  revocationEpoch?: number | null;
  enabledAdapterModes?: MarketplaceTrustBundleReleaseRecord["enabledAdapterModes"];
}): MarketplaceTrustBundleReleaseRecord {
  const partial = {
    schema: MARKETPLACE_TRUST_RELEASE_SCHEMA,
    releaseId: input.releaseId,
    attestationSchema: "mandatex.marketplace.category-quote-attestation.v1",
    signatureProfile: "mandatex-ed25519-category-quote-v1",
    verifierPolicySha256: POLICY_SHA256,
    categoryDeploymentSha256: DEPLOYMENT_SHA256,
    enabledAdapterModes: input.enabledAdapterModes ?? [...DEFAULT_MODES],
    definitionSha256: "00".repeat(32),
    lifecycle: input.lifecycle,
    lifecycleChangedAt: input.lifecycleChangedAt ?? 900,
    notBefore: input.notBefore ?? 800,
    notAfter: input.notAfter ?? 2_000,
    revokedAt: input.revokedAt ?? null,
    revocationEpoch: input.revocationEpoch ?? null,
  };
  return {
    ...partial,
    definitionSha256: marketplaceTrustReleaseDefinitionSha256(partial),
  };
}

function authorization(
  keyId: string,
  releaseId: string,
  channel: "production" | "canary" = "production",
  notBefore = 800,
  notAfter = 1_900,
) {
  return {
    schema: MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA,
    keyId,
    releaseId,
    channel,
    notBefore,
    notAfter,
  } as const;
}

function unsignedBundle(
  overrides: Partial<MarketplaceTrustBundleUnsigned> = {},
): MarketplaceTrustBundleUnsigned {
  return marketplaceTrustBundleUnsignedSchema.parse({
    schema: MARKETPLACE_TRUST_BUNDLE_SCHEMA,
    signatureProfile: MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE,
    issuer: MARKETPLACE_TRUST_BUNDLE_ISSUER,
    audience: MARKETPLACE_TRUST_BUNDLE_AUDIENCE,
    rootKeyId: root.keyId,
    generation: 7,
    revocationEpoch: 2,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    activeSignerKeyId: "signer-k1",
    activeReleaseId: "release-r1",
    keys: [
      keyRecord({ keyId: "signer-k1", publicKey: signerOne.publicKey, lifecycle: "active" }),
      keyRecord({
        keyId: "signer-k2",
        publicKey: signerTwo.publicKey,
        lifecycle: "preactive",
        lifecycleChangedAt: 1_150,
      }),
    ],
    releases: [
      releaseRecord({ releaseId: "release-r1", lifecycle: "active" }),
      releaseRecord({
        releaseId: "release-r2",
        lifecycle: "preactive",
        lifecycleChangedAt: 1_150,
      }),
    ],
    authorizations: [
      authorization("signer-k1", "release-r1"),
      authorization("signer-k2", "release-r2", "canary"),
    ],
    keyTombstones: [],
    releaseTombstones: [],
    revokedKeyFingerprints: [],
    ...overrides,
  });
}

function signedWire(
  overrides: Partial<MarketplaceTrustBundleUnsigned> = {},
  privateKey: KeyObject = rootKeyPair.privateKey,
): string {
  const unsigned = unsignedBundle(overrides);
  const signature = sign(
    null,
    marketplaceTrustBundleSigningMessage(unsigned),
    privateKey,
  ).toString("hex");
  return serializeMarketplaceTrustBundle({ ...unsigned, signature });
}

function verify(
  wire = signedWire(),
  overrides: Partial<{
    evaluatedAt: number;
    maxClockSkewSeconds: number;
    maxBundleTtlSeconds: number;
    rollbackFloor: { generation: number; revocationEpoch: number; bundleSha256?: string };
    priorState: MarketplaceTrustBundleDurableState;
  }> = {},
) {
  const base = {
    wire,
    root,
    evaluatedAt: overrides.evaluatedAt ?? EVALUATED_AT,
    maxClockSkewSeconds: overrides.maxClockSkewSeconds ?? 30,
    maxBundleTtlSeconds: overrides.maxBundleTtlSeconds ?? 600,
    rollbackFloor: overrides.rollbackFloor ?? { generation: 6, revocationEpoch: 1 },
  };
  return overrides.priorState === undefined
    ? verifyMarketplaceTrustBundle(base)
    : verifyMarketplaceTrustBundle({ ...base, priorState: overrides.priorState });
}

function hasCode(code: MarketplaceTrustBundleErrorCode) {
  return (error: unknown): boolean =>
    error instanceof MarketplaceTrustBundleError && error.code === code;
}

function mutateWire(
  wire: string,
  mutate: (envelope: Record<string, any>) => void,
): string {
  const envelope = JSON.parse(wire) as Record<string, any>;
  mutate(envelope);
  return canonicalJson(envelope);
}

function resignRaw(envelope: Record<string, any>): string {
  const unsigned = marketplaceTrustBundleUnsignedSchema.parse({
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
  envelope.signature = sign(
    null,
    marketplaceTrustBundleSigningMessage(unsigned),
    rootKeyPair.privateKey,
  ).toString("hex");
  return canonicalJson(envelope);
}

test("root signature validates strict records and returns only signed authorization edges", () => {
  const verified = verify();
  assert.doesNotThrow(() => assertVerifiedMarketplaceTrustBundle(verified));
  assert.equal(verified.activeTuple.keyId, "signer-k1");
  assert.equal(verified.activeTuple.releaseId, "release-r1");
  assert.deepEqual(
    verified.authorizedTuples.map((tuple) => `${tuple.keyId}:${tuple.releaseId}`),
    ["signer-k1:release-r1", "signer-k2:release-r2"],
  );
  assert.equal(
    verified.authorizedTuples.some(
      (tuple) => tuple.keyId === "signer-k1" && tuple.releaseId === "release-r2",
    ),
    false,
  );
  assert.equal(Object.isFrozen(verified.nextState), true);
  assert.throws(
    () => assertVerifiedMarketplaceTrustBundle({ ...verified }),
    hasCode("TRUST_BUNDLE_INPUT_INVALID"),
  );
});

test("exact attestation tuple resolution binds key, release, time, adapter, mode, and profile", () => {
  const verified = verify();
  const resolved = resolveMarketplaceTrustBundleAttestationTuple({
    verified,
    keyId: "signer-k1",
    releaseId: "release-r1",
    issuedAt: 1_100,
    adapterId: "aave-v3-health-v1",
    serviceMode: "observe_only",
    phase: "issuance",
  });
  assert.doesNotThrow(() => assertMarketplaceTrustResolvedTuple(resolved));
  assert.equal(resolved.adapterMode.readProfileId, "aave-v3-health-observation-v1");
  assert.equal(
    resolved.adapterMode.minimumTargetAssurance,
    "interface_only_unendorsed",
  );
  assert.throws(
    () => assertMarketplaceTrustResolvedTuple({ ...resolved }),
    hasCode("TRUST_BUNDLE_TUPLE_INVALID"),
  );
  assert.throws(
    () =>
      resolveMarketplaceTrustBundleAttestationTuple({
        verified: { ...verified },
        keyId: "signer-k1",
        releaseId: "release-r1",
        issuedAt: 1_100,
        adapterId: "aave-v3-health-v1",
        serviceMode: "observe_only",
        phase: "issuance",
      }),
    hasCode("TRUST_BUNDLE_INPUT_INVALID"),
  );
  assert.throws(
    () =>
      resolveMarketplaceTrustBundleAttestationTuple({
        verified,
        keyId: "signer-k1",
        releaseId: "release-r2",
        issuedAt: 1_100,
        adapterId: "aave-v3-health-v1",
        serviceMode: "observe_only",
        phase: "issuance",
      }),
    hasCode("TRUST_BUNDLE_TUPLE_INVALID"),
  );
  assert.throws(
    () =>
      resolveMarketplaceTrustBundleAttestationTuple({
        verified,
        keyId: "signer-k1",
        releaseId: "release-r1",
        issuedAt: 1_100,
        adapterId: "venus-health-v1",
        serviceMode: "transactional",
        phase: "issuance",
      }),
    hasCode("TRUST_BUNDLE_TUPLE_INVALID"),
  );
});

test("preactive is an explicit canary state and cannot issue production attestations", () => {
  const verified = verify();
  assert.throws(
    () =>
      resolveMarketplaceTrustBundleAttestationTuple({
        verified,
        keyId: "signer-k2",
        releaseId: "release-r2",
        issuedAt: 1_200,
        adapterId: "venus-health-v1",
        serviceMode: "observe_only",
        phase: "issuance",
      }),
    hasCode("TRUST_BUNDLE_TUPLE_INVALID"),
  );
  const canary = resolveMarketplaceTrustBundleAttestationTuple({
    verified,
    keyId: "signer-k2",
    releaseId: "release-r2",
    issuedAt: 1_200,
    adapterId: "venus-health-v1",
    serviceMode: "observe_only",
    phase: "issuance",
    allowCanary: true,
  });
  assert.equal(canary.key.record.lifecycle, "preactive");
});

test("lifecycle transitions support preactive, active, retiring, retired, and revoked", () => {
  const first = verify();
  const rotatedUnsigned = unsignedBundle({
    generation: 8,
    issuedAt: 1_200,
    expiresAt: 1_500,
    activeSignerKeyId: "signer-k2",
    activeReleaseId: "release-r2",
    keys: [
      keyRecord({ keyId: "signer-k1", publicKey: signerOne.publicKey, lifecycle: "retiring", lifecycleChangedAt: 1_200 }),
      keyRecord({ keyId: "signer-k2", publicKey: signerTwo.publicKey, lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    releases: [
      releaseRecord({ releaseId: "release-r1", lifecycle: "retiring", lifecycleChangedAt: 1_200 }),
      releaseRecord({ releaseId: "release-r2", lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    authorizations: [
      authorization("signer-k1", "release-r1", "production", 800, 1_300),
      authorization("signer-k2", "release-r2", "production", 1_200),
    ],
  });
  const rotated = verify(
    signedWire(rotatedUnsigned),
    { evaluatedAt: 1_250, priorState: first.nextState },
  );
  assert.equal(rotated.activeTuple.keyId, "signer-k2");
  assert.equal(rotated.activeTuple.releaseId, "release-r2");
  const oldAttestation = resolveMarketplaceTrustBundleAttestationTuple({
    verified: rotated,
    keyId: "signer-k1",
    releaseId: "release-r1",
    issuedAt: 1_150,
    adapterId: "aave-v3-health-v1",
    serviceMode: "observe_only",
    phase: "verification",
  });
  assert.equal(oldAttestation.key.record.lifecycle, "retiring");
  assert.throws(
    () =>
      resolveMarketplaceTrustBundleAttestationTuple({
        verified: rotated,
        keyId: "signer-k1",
        releaseId: "release-r1",
        issuedAt: 1_200,
        adapterId: "aave-v3-health-v1",
        serviceMode: "observe_only",
        phase: "verification",
      }),
    hasCode("TRUST_BUNDLE_TUPLE_INVALID"),
  );

  const retiredUnsigned = unsignedBundle({
    generation: 9,
    issuedAt: 1_400,
    expiresAt: 1_700,
    activeSignerKeyId: "signer-k2",
    activeReleaseId: "release-r2",
    keys: [
      keyRecord({ keyId: "signer-k1", publicKey: signerOne.publicKey, lifecycle: "retired", lifecycleChangedAt: 1_300 }),
      keyRecord({ keyId: "signer-k2", publicKey: signerTwo.publicKey, lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    releases: [
      releaseRecord({ releaseId: "release-r1", lifecycle: "retired", lifecycleChangedAt: 1_300 }),
      releaseRecord({ releaseId: "release-r2", lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    authorizations: [authorization("signer-k2", "release-r2", "production", 1_200)],
    keyTombstones: [
      {
        schema: MARKETPLACE_TRUST_KEY_TOMBSTONE_SCHEMA,
        keyId: "signer-k1",
        publicKeySpkiDerBase64: keyRecord({ keyId: "signer-k1", publicKey: signerOne.publicKey, lifecycle: "retired" }).publicKeySpkiDerBase64,
        publicKeyFingerprintSha256: fingerprint(signerOne.publicKey),
        reason: "retired",
        tombstonedAtGeneration: 9,
        retainUntilGeneration: 11,
      },
    ],
    releaseTombstones: [
      {
        schema: MARKETPLACE_TRUST_RELEASE_TOMBSTONE_SCHEMA,
        releaseId: "release-r1",
        definitionSha256: releaseRecord({ releaseId: "release-r1", lifecycle: "retired", lifecycleChangedAt: 1_300 }).definitionSha256,
        reason: "retired",
        tombstonedAtGeneration: 9,
        retainUntilGeneration: 11,
      },
    ],
  });
  const retired = verify(
    signedWire(retiredUnsigned),
    { evaluatedAt: 1_450, priorState: rotated.nextState },
  );
  assert.equal(retired.envelope.keys[0]?.lifecycle, "retired");

  const beforeRetention = unsignedBundle({
    generation: 10,
    issuedAt: 1_500,
    expiresAt: 1_800,
    activeSignerKeyId: "signer-k2",
    activeReleaseId: "release-r2",
    keys: [
      keyRecord({ keyId: "signer-k2", publicKey: signerTwo.publicKey, lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    releases: [
      releaseRecord({ releaseId: "release-r2", lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    authorizations: [authorization("signer-k2", "release-r2", "production", 1_200)],
    keyTombstones: retiredUnsigned.keyTombstones,
    releaseTombstones: retiredUnsigned.releaseTombstones,
  });
  assert.throws(
    () => verify(signedWire(beforeRetention), { evaluatedAt: 1_550, priorState: retired.nextState }),
    hasCode("TRUST_BUNDLE_TOMBSTONE_INVALID"),
  );
  const afterRetention = verify(
    signedWire({ ...beforeRetention, generation: 11 }),
    { evaluatedAt: 1_550, priorState: retired.nextState },
  );
  assert.deepEqual(afterRetention.envelope.keys.map((key) => key.keyId), ["signer-k2"]);

  const reactivated = unsignedBundle({
    generation: 10,
    issuedAt: 1_500,
    expiresAt: 1_800,
    activeSignerKeyId: "signer-k1",
    activeReleaseId: "release-r1",
    keys: [
      keyRecord({ keyId: "signer-k1", publicKey: signerOne.publicKey, lifecycle: "active", lifecycleChangedAt: 1_500 }),
      keyRecord({ keyId: "signer-k2", publicKey: signerTwo.publicKey, lifecycle: "retiring", lifecycleChangedAt: 1_500 }),
    ],
    releases: [
      releaseRecord({ releaseId: "release-r1", lifecycle: "active", lifecycleChangedAt: 1_500 }),
      releaseRecord({ releaseId: "release-r2", lifecycle: "retiring", lifecycleChangedAt: 1_500 }),
    ],
    authorizations: [authorization("signer-k1", "release-r1", "production", 1_500)],
    keyTombstones: retiredUnsigned.keyTombstones,
    releaseTombstones: retiredUnsigned.releaseTombstones,
  });
  assert.throws(
    () => verify(signedWire(reactivated), { evaluatedAt: 1_550, priorState: retired.nextState }),
    hasCode("TRUST_BUNDLE_TRANSITION_INVALID"),
  );
  assert.throws(
    () =>
      resolveMarketplaceTrustBundleAttestationTuple({
        verified: retired,
        keyId: "signer-k1",
        releaseId: "release-r1",
        issuedAt: 1_250,
        adapterId: "aave-v3-health-v1",
        serviceMode: "observe_only",
        phase: "verification",
      }),
    hasCode("TRUST_BUNDLE_TUPLE_INVALID"),
  );
});

test("durable state prevents immutable rebinding, premature disappearance, and tombstone loss", () => {
  const first = verify();
  const changed = unsignedBundle({
    generation: 8,
    issuedAt: 1_200,
    expiresAt: 1_500,
    keys: [
      keyRecord({ keyId: "signer-k1", publicKey: signerThree.publicKey, lifecycle: "active" }),
      keyRecord({ keyId: "signer-k2", publicKey: signerTwo.publicKey, lifecycle: "preactive", lifecycleChangedAt: 1_150 }),
    ],
  });
  assert.throws(
    () => verify(signedWire(changed), { priorState: first.nextState, evaluatedAt: 1_250 }),
    hasCode("TRUST_BUNDLE_TRANSITION_INVALID"),
  );

  const changedRelease = releaseRecord({ releaseId: "release-r1", lifecycle: "active" });
  const changedModes = changedRelease.enabledAdapterModes.map((entry, index) =>
    index === 0
      ? {
          ...entry,
          minimumTargetAssurance: "protocol_instance_verified" as const,
        }
      : entry,
  );
  const reboundRelease = releaseRecord({
    releaseId: "release-r1",
    lifecycle: "active",
    enabledAdapterModes: changedModes,
  });
  assert.throws(
    () =>
      verify(
        signedWire({
          generation: 8,
          issuedAt: 1_200,
          expiresAt: 1_500,
          releases: [
            reboundRelease,
            releaseRecord({ releaseId: "release-r2", lifecycle: "preactive", lifecycleChangedAt: 1_150 }),
          ],
        }),
        { priorState: first.nextState, evaluatedAt: 1_250 },
      ),
    hasCode("TRUST_BUNDLE_TRANSITION_INVALID"),
  );

  const retiring = unsignedBundle({
    generation: 8,
    issuedAt: 1_200,
    expiresAt: 1_500,
    keys: [
      keyRecord({ keyId: "signer-k1", publicKey: signerOne.publicKey, lifecycle: "retiring", lifecycleChangedAt: 1_200 }),
      keyRecord({ keyId: "signer-k2", publicKey: signerTwo.publicKey, lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    releases: [
      releaseRecord({ releaseId: "release-r1", lifecycle: "retiring", lifecycleChangedAt: 1_200 }),
      releaseRecord({ releaseId: "release-r2", lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    activeSignerKeyId: "signer-k2",
    activeReleaseId: "release-r2",
    authorizations: [
      authorization("signer-k1", "release-r1", "production", 800, 1_300),
      authorization("signer-k2", "release-r2", "production", 1_200),
    ],
  });
  const next = verify(signedWire(retiring), { priorState: first.nextState, evaluatedAt: 1_250 });
  const prematurelyMissing = unsignedBundle({
    generation: 9,
    issuedAt: 1_300,
    expiresAt: 1_600,
    activeSignerKeyId: "signer-k2",
    activeReleaseId: "release-r2",
    keys: [keyRecord({ keyId: "signer-k2", publicKey: signerTwo.publicKey, lifecycle: "active", lifecycleChangedAt: 1_200 })],
    releases: [releaseRecord({ releaseId: "release-r2", lifecycle: "active", lifecycleChangedAt: 1_200 })],
    authorizations: [authorization("signer-k2", "release-r2", "production", 1_200)],
  });
  assert.throws(
    () => verify(signedWire(prematurelyMissing), { priorState: next.nextState, evaluatedAt: 1_350 }),
    hasCode("TRUST_BUNDLE_TRANSITION_INVALID"),
  );
});

test("revoked fingerprints remain permanent tombstones and cannot be reused", () => {
  const first = verify();
  const revokedKey = keyRecord({
    keyId: "signer-k1",
    publicKey: signerOne.publicKey,
    lifecycle: "revoked",
    lifecycleChangedAt: 1_100,
    revokedAt: 1_100,
    revocationEpoch: 3,
  });
  const rotated = unsignedBundle({
    generation: 8,
    revocationEpoch: 3,
    issuedAt: 1_200,
    expiresAt: 1_500,
    activeSignerKeyId: "signer-k2",
    activeReleaseId: "release-r2",
    keys: [
      revokedKey,
      keyRecord({ keyId: "signer-k2", publicKey: signerTwo.publicKey, lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    releases: [
      releaseRecord({ releaseId: "release-r1", lifecycle: "revoked", lifecycleChangedAt: 1_100, revokedAt: 1_100, revocationEpoch: 3 }),
      releaseRecord({ releaseId: "release-r2", lifecycle: "active", lifecycleChangedAt: 1_200 }),
    ],
    authorizations: [authorization("signer-k2", "release-r2", "production", 1_200)],
    keyTombstones: [
      {
        schema: MARKETPLACE_TRUST_KEY_TOMBSTONE_SCHEMA,
        keyId: "signer-k1",
        publicKeySpkiDerBase64: revokedKey.publicKeySpkiDerBase64,
        publicKeyFingerprintSha256: revokedKey.publicKeyFingerprintSha256,
        reason: "revoked",
        tombstonedAtGeneration: 8,
        retainUntilGeneration: null,
      },
    ],
    releaseTombstones: [
      {
        schema: MARKETPLACE_TRUST_RELEASE_TOMBSTONE_SCHEMA,
        releaseId: "release-r1",
        definitionSha256: releaseRecord({ releaseId: "release-r1", lifecycle: "revoked", lifecycleChangedAt: 1_100, revokedAt: 1_100, revocationEpoch: 3 }).definitionSha256,
        reason: "revoked",
        tombstonedAtGeneration: 8,
        retainUntilGeneration: null,
      },
    ],
    revokedKeyFingerprints: [fingerprint(signerOne.publicKey)],
  });
  const verified = verify(signedWire(rotated), { priorState: first.nextState, evaluatedAt: 1_250 });
  assert.deepEqual(verified.nextState.revokedKeyFingerprints, [fingerprint(signerOne.publicKey)]);
  const reused = unsignedBundle({
    generation: 9,
    revocationEpoch: 3,
    issuedAt: 1_300,
    expiresAt: 1_600,
    activeSignerKeyId: "signer-k3",
    activeReleaseId: "release-r2",
    keys: [
      keyRecord({ keyId: "signer-k2", publicKey: signerTwo.publicKey, lifecycle: "retiring", lifecycleChangedAt: 1_300 }),
      keyRecord({ keyId: "signer-k3", publicKey: signerOne.publicKey, lifecycle: "active", lifecycleChangedAt: 1_300 }),
    ],
    releases: [releaseRecord({ releaseId: "release-r2", lifecycle: "active", lifecycleChangedAt: 1_200 })],
    authorizations: [authorization("signer-k3", "release-r2", "production", 1_300)],
    keyTombstones: rotated.keyTombstones,
    releaseTombstones: rotated.releaseTombstones,
    revokedKeyFingerprints: [fingerprint(signerOne.publicKey)],
  });
  assert.throws(
    () => verify(signedWire(reused), { priorState: verified.nextState, evaluatedAt: 1_350 }),
    hasCode("TRUST_BUNDLE_TRANSITION_INVALID"),
  );
});

test("release definitions bind exact registry adapters and read/action profile digests", () => {
  const envelope = JSON.parse(signedWire()) as Record<string, any>;
  envelope.releases[0].enabledAdapterModes[0].adapterId = "unknown-adapter";
  assert.throws(() => serializeMarketplaceTrustBundle(envelope), /invalid_literal|Invalid input/);

  const invalidModeEnvelope = JSON.parse(signedWire()) as Record<string, any>;
  invalidModeEnvelope.releases[0].enabledAdapterModes[0].actionProfileId = "unexpected-action";
  assert.throws(() => serializeMarketplaceTrustBundle(invalidModeEnvelope), /observe-only/);

  const invalidAssuranceEnvelope = JSON.parse(signedWire()) as Record<string, any>;
  invalidAssuranceEnvelope.releases[0].enabledAdapterModes[0].minimumTargetAssurance =
    "self_attested";
  assert.throws(
    () => serializeMarketplaceTrustBundle(invalidAssuranceEnvelope),
    /Invalid enum value|Invalid option|invalid_value/,
  );

  const definition = JSON.parse(signedWire()) as Record<string, any>;
  definition.releases[0].definitionSha256 = "55".repeat(32);
  assert.throws(() => verify(resignRaw(definition)), hasCode("TRUST_BUNDLE_RELEASE_INVALID"));
});

test("complete policy modes project exactly to the signed enabled release modes", () => {
  const release = releaseRecord({ releaseId: "release-r1", lifecycle: "active" });
  const policyModes = completePolicyModes(release);
  assert.equal(
    assertMarketplaceTrustReleaseModeProjection({ policyModes, release }),
    true,
  );

  for (const mutation of [
    { readProfileSha256: "55".repeat(32) },
    { actionProfileSha256: "66".repeat(32) },
    { minimumTargetAssurance: "protocol_instance_verified" as const },
    { enabled: false },
  ]) {
    const changed = policyModes.map((mode, index) =>
      index === 0 ? { ...mode, ...mutation } : mode,
    );
    assert.throws(
      () => assertMarketplaceTrustReleaseModeProjection({ policyModes: changed, release }),
      /policy mode|action profile|enabled successor adapter modes/,
    );
  }
  assert.throws(
    () =>
      assertMarketplaceTrustReleaseModeProjection({
        policyModes: policyModes.slice(0, 7),
        release,
      }),
    /8 element|length|matrix/,
  );
});

test("freshness, rollback, root revalidation, signature, and canonical wire fail closed", () => {
  assert.throws(
    () => verify(signedWire({ issuedAt: 1_200 }), { evaluatedAt: 1_100 }),
    hasCode("TRUST_BUNDLE_NOT_YET_VALID"),
  );
  assert.throws(
    () => verify(signedWire(), { evaluatedAt: EXPIRES_AT }),
    hasCode("TRUST_BUNDLE_EXPIRED"),
  );
  assert.throws(
    () => verify(signedWire(), { rollbackFloor: { generation: 8, revocationEpoch: 2 } }),
    hasCode("TRUST_BUNDLE_ROLLBACK_DETECTED"),
  );
  assert.throws(
    () => verify(JSON.stringify(JSON.parse(signedWire()), null, 2)),
    hasCode("TRUST_BUNDLE_NONCANONICAL"),
  );
  const forgedRoot = { ...root, publicKey: signerOne.publicKey } as ValidatedMarketplaceTrustBundleRoot;
  assert.throws(
    () => verifyMarketplaceTrustBundle({
      wire: signedWire({}, signerOne.privateKey),
      root: forgedRoot,
      evaluatedAt: EVALUATED_AT,
      maxClockSkewSeconds: 30,
      maxBundleTtlSeconds: 600,
      rollbackFloor: { generation: 6, revocationEpoch: 1 },
    }),
    hasCode("TRUST_BUNDLE_INPUT_INVALID"),
  );
  assert.throws(
    () => verify(mutateWire(signedWire(), (envelope) => { envelope.generation = 8; })),
    hasCode("TRUST_BUNDLE_SIGNATURE_INVALID"),
  );
});

test("serialization and signing message are deterministic", () => {
  const wire = signedWire();
  const parsed = JSON.parse(wire) as MarketplaceTrustBundle;
  assert.equal(serializeMarketplaceTrustBundle(parsed), wire);
  const unsigned = unsignedBundle();
  const message = marketplaceTrustBundleSigningMessage(unsigned);
  assert.equal(
    message.subarray(message.byteLength - Buffer.byteLength(canonicalJson(unsigned))).toString(),
    canonicalJson(unsigned),
  );
});
