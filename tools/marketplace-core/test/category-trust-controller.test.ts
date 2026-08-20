import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import test from "node:test";

import { canonicalSha256 } from "../src/canonical.js";
import { MARKETPLACE_GRID_ADAPTER } from "../src/category-policy.js";
import { categoryStaticReadProfileForAdapterSha256 } from "../src/category-production.js";
import {
  createMarketplaceCategoryTrustController,
  createMarketplaceCategoryTrustStateStore,
  resolveMarketplaceCategoryTrustControllerRoot,
  type MarketplaceCategoryTrustCasInput,
  type MarketplaceCategoryTrustStateStore,
} from "../src/category-trust-controller.js";
import {
  MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE,
  createMarketplaceCategoryQuoteTrustStore,
} from "../src/category-successor.js";
import {
  MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA,
  MARKETPLACE_TRUST_BUNDLE_AUDIENCE,
  MARKETPLACE_TRUST_BUNDLE_ISSUER,
  MARKETPLACE_TRUST_BUNDLE_SCHEMA,
  MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE,
  MARKETPLACE_TRUST_KEY_SCHEMA,
  MARKETPLACE_TRUST_RELEASE_SCHEMA,
  marketplaceTrustBundleDurableStateSchema,
  marketplaceTrustBundleSigningMessage,
  marketplaceTrustBundleUnsignedSchema,
  marketplaceTrustReleaseDefinitionSha256,
  serializeMarketplaceTrustBundle,
  type MarketplaceTrustBundleDurableState,
  type MarketplaceTrustBundleUnsigned,
} from "../src/trust-bundle.js";

const COMMERCE = `0x${"44".repeat(20)}`;
const POLICY_SHA256 = "11".repeat(32);
const DEPLOYMENT_SHA256 = "22".repeat(32);
const READ_PROFILE_SHA256 = categoryStaticReadProfileForAdapterSha256(
  MARKETPLACE_GRID_ADAPTER,
);
const rootKeys = generateKeyPairSync("ed25519");
const signerKeys = generateKeyPairSync("ed25519");

test("trust state commits before use and restart is exactly idempotent", async () => {
  const memory = memoryStore();
  const controller = makeController(memory.store);
  const wire = signedBundleWire();
  const commitment = await controller.prepare({ bundleWire: wire });

  assert.equal(memory.casCalls(), 1);
  assert.equal(memory.snapshot().stateSha256, commitment.stateSha256);
  assert.doesNotThrow(() =>
    createMarketplaceCategoryQuoteTrustStore({ commitment }),
  );
  assert.throws(
    () =>
      createMarketplaceCategoryQuoteTrustStore({
        commitment: { ...commitment },
      }),
    /exact durable controller commit/,
  );

  const restarted = makeController(memory.store);
  const replay = await restarted.prepare({ bundleWire: wire });
  assert.equal(replay.stateSha256, commitment.stateSha256);
  assert.equal(memory.casCalls(), 1);
});

test("a lost CAS response recovers only from an exact authoritative read", async () => {
  const memory = memoryStore({ loseNextResponse: true });
  const commitment = await makeController(memory.store).prepare({
    bundleWire: signedBundleWire(),
  });
  assert.equal(memory.snapshot().stateSha256, commitment.stateSha256);
  assert.equal(memory.casCalls(), 1);
});

test("same-state races converge and same-generation conflicts fail closed", async () => {
  const memory = memoryStore();
  const controller = makeController(memory.store);
  const wire = signedBundleWire();
  const [first, second] = await Promise.all([
    controller.prepare({ bundleWire: wire }),
    controller.prepare({ bundleWire: wire }),
  ]);
  assert.equal(first.stateSha256, second.stateSha256);
  assert.ok(memory.casCalls() >= 1);

  await assert.rejects(
    controller.prepare({ bundleWire: signedBundleWire({ expiresAt: 1_450 }) }),
    /same generation|different trust bundles|generation/i,
  );
});

test("conflicting CAS state, corruption, and fabricated stores fail closed", async () => {
  let state: MarketplaceTrustBundleDurableState | undefined;
  let stateSha256: string | undefined;
  const conflicting = createMarketplaceCategoryTrustStateStore({
    load: async () => ({ state, stateSha256 }),
    compareAndSwap: async (raw) => {
      const input = raw as MarketplaceCategoryTrustCasInput;
      state = marketplaceTrustBundleDurableStateSchema.parse({
        ...input.nextState,
        generation: input.generation + 1,
        bundleSha256: "ff".repeat(32),
      });
      stateSha256 = canonicalSha256(state);
      return receipt("conflict", input, state);
    },
    withRevision: async (_expected, operation) => operation(),
  });
  await assert.rejects(
    makeController(conflicting).prepare({ bundleWire: signedBundleWire() }),
    /CAS conflict/,
  );

  const corrupted = createMarketplaceCategoryTrustStateStore({
    load: async () => ({
      state: marketplaceTrustBundleDurableStateSchema.parse(state),
      stateSha256: "00".repeat(32),
    }),
    compareAndSwap: async () => {
      throw new Error("must not write corrupt state");
    },
    withRevision: async (_expected, operation) => operation(),
  });
  await assert.rejects(
    makeController(corrupted).prepare({ bundleWire: signedBundleWire() }),
    /digest does not match/,
  );
});

test("issuance permits are single-use and fenced against trust advancement", async () => {
  const memory = memoryStore();
  const controller = makeController(memory.store);
  const wire = signedBundleWire();
  const permit = await controller.issuePermit({
    bundleWire: wire,
    keyId: "signer-k1",
    releaseId: "release-r1",
    adapterId: MARKETPLACE_GRID_ADAPTER,
    serviceMode: "observe_only",
    issuedAt: 1_150,
  });
  let calls = 0;
  const result = await controller.withPermit(permit, async (tuple) => {
    calls += 1;
    assert.equal(tuple.keyId, "signer-k1");
    assert.equal(tuple.adapterMode.adapterId, MARKETPLACE_GRID_ADAPTER);
    return "signed" as const;
  });
  assert.equal(result, "signed");
  assert.equal(calls, 1);
  await assert.rejects(
    controller.withPermit(permit, async () => "reused"),
    /provenance/,
  );

  const stalePermit = await controller.issuePermit({
    bundleWire: wire,
    keyId: "signer-k1",
    releaseId: "release-r1",
    adapterId: MARKETPLACE_GRID_ADAPTER,
    serviceMode: "observe_only",
    issuedAt: 1_151,
  });
  memory.advance();
  let staleCalls = 0;
  await assert.rejects(
    controller.withPermit(stalePermit, async () => {
      staleCalls += 1;
      return "unsafe";
    }),
    /revision|stale/,
  );
  assert.equal(staleCalls, 0);
});

test("trust advancement cannot cross an in-flight issuance fence", async () => {
  const memory = memoryStore();
  const controller = makeController(memory.store);
  const permit = await controller.issuePermit({
    bundleWire: signedBundleWire(),
    keyId: "signer-k1",
    releaseId: "release-r1",
    adapterId: MARKETPLACE_GRID_ADAPTER,
    serviceMode: "observe_only",
    issuedAt: 1_150,
  });
  let entered!: () => void;
  const enteredPromise = new Promise<void>((resolve) => {
    entered = resolve;
  });
  let release!: () => void;
  const releasePromise = new Promise<void>((resolve) => {
    release = resolve;
  });
  const signing = controller.withPermit(permit, async () => {
    entered();
    await releasePromise;
    return "signed" as const;
  });
  await enteredPromise;

  let advanced = false;
  const advancement = memory.advanceAsync().then(() => {
    advanced = true;
  });
  await Promise.resolve();
  assert.equal(advanced, false);
  release();
  assert.equal(await signing, "signed");
  await advancement;
  assert.equal(advanced, true);
});

test("controller root identity is factory-branded and immutable", () => {
  const memory = memoryStore();
  const controller = makeController(memory.store);
  assert.deepEqual(resolveMarketplaceCategoryTrustControllerRoot(controller), {
    keyId: "root-k1",
    publicKeyFingerprintSha256: fingerprint(rootKeys.publicKey),
  });
  assert.throws(
    () =>
      resolveMarketplaceCategoryTrustControllerRoot({
        ...controller,
      }),
    /Core factory/,
  );
});

function makeController(stateStore: MarketplaceCategoryTrustStateStore) {
  return createMarketplaceCategoryTrustController({
    root: {
      keyId: "root-k1",
      publicKeySpkiDer: exportedSpki(rootKeys.publicKey),
      publicKeyFingerprintSha256: fingerprint(rootKeys.publicKey),
    },
    quoteVerifyingContract: COMMERCE,
    rollbackFloor: { generation: 0, revocationEpoch: 0 },
    stateStore,
    clock: () => 1_150,
  });
}

function signedBundleWire(
  overrides: Partial<MarketplaceTrustBundleUnsigned> = {},
): string {
  const releasePartial = {
    schema: MARKETPLACE_TRUST_RELEASE_SCHEMA,
    releaseId: "release-r1",
    attestationSchema: MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA,
    signatureProfile: MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE,
    verifierPolicySha256: POLICY_SHA256,
    categoryDeploymentSha256: DEPLOYMENT_SHA256,
    enabledAdapterModes: [
      {
        adapterId: MARKETPLACE_GRID_ADAPTER,
        serviceMode: "observe_only" as const,
        readProfileId: "pancakeswap-v3-grid-observation-v1",
        readProfileSha256: READ_PROFILE_SHA256,
        actionProfileId: null,
        actionProfileSha256: null,
        minimumTargetAssurance: "interface_only_unendorsed" as const,
      },
    ],
    definitionSha256: "00".repeat(32),
    lifecycle: "active" as const,
    lifecycleChangedAt: 900,
    notBefore: 800,
    notAfter: 2_000,
    revokedAt: null,
    revocationEpoch: null,
  };
  const release = {
    ...releasePartial,
    definitionSha256: marketplaceTrustReleaseDefinitionSha256(releasePartial),
  };
  const unsigned = marketplaceTrustBundleUnsignedSchema.parse({
    schema: MARKETPLACE_TRUST_BUNDLE_SCHEMA,
    signatureProfile: MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE,
    issuer: MARKETPLACE_TRUST_BUNDLE_ISSUER,
    audience: MARKETPLACE_TRUST_BUNDLE_AUDIENCE,
    rootKeyId: "root-k1",
    generation: 1,
    revocationEpoch: 0,
    issuedAt: 1_000,
    expiresAt: 1_500,
    activeSignerKeyId: "signer-k1",
    activeReleaseId: "release-r1",
    keys: [
      {
        schema: MARKETPLACE_TRUST_KEY_SCHEMA,
        keyId: "signer-k1",
        algorithm: "Ed25519",
        publicKeyEncoding: "spki-der",
        publicKeySpkiDerBase64: exportedSpki(signerKeys.publicKey).toString(
          "base64",
        ),
        publicKeyFingerprintSha256: fingerprint(signerKeys.publicKey),
        lifecycle: "active",
        lifecycleChangedAt: 900,
        notBefore: 800,
        notAfter: 2_000,
        revokedAt: null,
        revocationEpoch: null,
      },
    ],
    releases: [release],
    authorizations: [
      {
        schema: MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA,
        keyId: "signer-k1",
        releaseId: "release-r1",
        channel: "production",
        notBefore: 800,
        notAfter: 1_900,
      },
    ],
    keyTombstones: [],
    releaseTombstones: [],
    revokedKeyFingerprints: [],
    ...overrides,
  });
  return serializeMarketplaceTrustBundle({
    ...unsigned,
    signature: sign(
      null,
      marketplaceTrustBundleSigningMessage(unsigned),
      rootKeys.privateKey,
    ).toString("hex"),
  });
}

function memoryStore(options: { loseNextResponse?: boolean } = {}) {
  let state: MarketplaceTrustBundleDurableState | undefined;
  let stateSha256: string | undefined;
  let casCalls = 0;
  let loseNextResponse = options.loseNextResponse === true;
  let tail = Promise.resolve();

  async function exclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
    let release!: () => void;
    const previous = tail;
    tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  const store = createMarketplaceCategoryTrustStateStore({
    load: async () => ({ state, stateSha256 }),
    compareAndSwap: async (raw) =>
      exclusive(async () => {
        casCalls += 1;
        const input = raw as MarketplaceCategoryTrustCasInput;
        if (input.expectedStateSha256 !== stateSha256) {
          return receipt("conflict", input, state);
        }
        if (stateSha256 === input.nextStateSha256) {
          return receipt("already_committed", input, state);
        }
        state = input.nextState;
        stateSha256 = input.nextStateSha256;
        const committed = receipt("committed", input, state);
        if (loseNextResponse) {
          loseNextResponse = false;
          throw new Error("commit response was lost");
        }
        return committed;
      }),
    withRevision: async (expected, operation) =>
      exclusive(async () => {
        if (stateSha256 !== expected) {
          throw new Error("trust revision fence rejected stale state");
        }
        return operation();
      }),
  });

  return {
    store,
    casCalls: () => casCalls,
    snapshot: () => ({ state, stateSha256 }),
    advance: () => {
      assert.ok(state);
      state = marketplaceTrustBundleDurableStateSchema.parse({
        ...state,
        generation: state.generation + 1,
        bundleSha256: "ee".repeat(32),
      });
      stateSha256 = canonicalSha256(state);
    },
    advanceAsync: () =>
      exclusive(async () => {
        assert.ok(state);
        state = marketplaceTrustBundleDurableStateSchema.parse({
          ...state,
          generation: state.generation + 1,
          bundleSha256: "dd".repeat(32),
        });
        stateSha256 = canonicalSha256(state);
      }),
  };
}

function receipt(
  status: "committed" | "already_committed" | "conflict",
  input: MarketplaceCategoryTrustCasInput,
  state: MarketplaceTrustBundleDurableState | undefined,
) {
  return {
    status,
    expectedStateSha256: input.expectedStateSha256,
    committedStateSha256:
      state === undefined ? undefined : canonicalSha256(state),
    bundleSha256: state?.bundleSha256,
    generation: state?.generation,
    revocationEpoch: state?.revocationEpoch,
  };
}

function exportedSpki(key: KeyObject): Buffer {
  const exported = key.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(exported)) throw new TypeError("expected SPKI DER");
  return exported;
}

function fingerprint(key: KeyObject): string {
  return createHash("sha256").update(exportedSpki(key)).digest("hex");
}
