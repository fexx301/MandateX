import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign as signEd25519,
} from "node:crypto";
import test from "node:test";

import { MarketplaceServiceError } from "../src/errors.js";
import {
  MANAGED_ED25519_RAW_MESSAGE_PROFILE,
  MAX_MANAGED_ED25519_MESSAGE_BYTES,
  assertManagedEd25519Signer,
  createManagedEd25519Signer,
} from "../src/managed-ed25519-signer.js";

function keyMaterial() {
  const pair = generateKeyPairSync("ed25519");
  const spki = pair.publicKey.export({ format: "der", type: "spki" });
  assert.ok(Buffer.isBuffer(spki));
  return {
    ...pair,
    spki,
    fingerprint: createHash("sha256").update(spki).digest("hex"),
  };
}

function options(
  material = keyMaterial(),
  overrides: Readonly<Record<string, unknown>> = {},
) {
  return {
    keyId: "managed-ed25519-test-1",
    custody: "non_exportable_managed" as const,
    backendProfile: "test-external-provider-v1",
    publicKeySpkiDer: Uint8Array.from(material.spki),
    publicKeyFingerprintSha256: material.fingerprint,
    signRaw: async (message: Uint8Array) =>
      signEd25519(null, message, material.privateKey),
    ...overrides,
  };
}

test("managed signer signs exact raw bytes and locally verifies the result", async () => {
  const material = keyMaterial();
  let observed: Uint8Array | undefined;
  const signer = createManagedEd25519Signer(
    options(material, {
      signRaw: async (message: Uint8Array) => {
        observed = Uint8Array.from(message);
        message[0] = (message[0] ?? 0) ^ 0xff;
        return signEd25519(null, observed, material.privateKey);
      },
    }),
  );
  const message = Buffer.from("MandateX exact signing bytes", "utf8");
  const signed = await signer.sign(message);

  assert.deepEqual(Array.from(observed ?? []), Array.from(message));
  assert.equal(signed.signature.byteLength, 64);
  assert.equal(signed.signatureHex.length, 128);
  assert.equal(signed.signatureProfile, MANAGED_ED25519_RAW_MESSAGE_PROFILE);
  assert.equal(signed.publicKeyFingerprintSha256, material.fingerprint);
  assertManagedEd25519Signer(signer);

  const firstKey = signer.publicKeySpkiDer;
  firstKey[0] = (firstKey[0] ?? 0) ^ 0xff;
  assert.deepEqual(
    Array.from(signer.publicKeySpkiDer),
    Array.from(material.spki),
  );
  const firstSignature = signed.signature;
  firstSignature[0] = (firstSignature[0] ?? 0) ^ 0xff;
  assert.equal(signed.signatureHex, Buffer.from(signed.signature).toString("hex"));
});

test("wrong-key, prehashed, malformed, and provider failures fail closed", async () => {
  const trusted = keyMaterial();
  const wrong = keyMaterial();
  const message = Buffer.from("raw-message", "utf8");

  for (const signRaw of [
    async (value: Uint8Array) => signEd25519(null, value, wrong.privateKey),
    async (value: Uint8Array) =>
      signEd25519(
        null,
        createHash("sha256").update(value).digest(),
        trusted.privateKey,
      ),
    async () => new Uint8Array(63),
    async () => {
      throw new Error("provider unavailable");
    },
  ]) {
    const signer = createManagedEd25519Signer(options(trusted, { signRaw }));
    await assert.rejects(
      signer.sign(message),
      (error: unknown) =>
        error instanceof MarketplaceServiceError &&
        error.code === "SIGNING_FAILED",
    );
  }
});

test("configuration is public-only, strict, copied, and factory branded", async () => {
  const material = keyMaterial();
  const mutable = options(material);
  const signer = createManagedEd25519Signer(mutable);
  mutable.publicKeySpkiDer[0] = (mutable.publicKeySpkiDer[0] ?? 0) ^ 0xff;
  mutable.signRaw = async () => Buffer.alloc(64);
  const signed = await signer.sign(Buffer.from("captured", "utf8"));
  assert.equal(signed.signature.byteLength, 64);

  assert.throws(
    () =>
      createManagedEd25519Signer({
        ...options(material),
        privateKeyPkcs8Der: new Uint8Array(48),
      } as never),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "MANAGED_SIGNER_INVALID",
  );
  assert.throws(
    () =>
      assertManagedEd25519Signer({
        keyId: signer.keyId,
        custody: signer.custody,
        backendProfile: signer.backendProfile,
        signatureProfile: signer.signatureProfile,
        publicKeyFingerprintSha256: signer.publicKeyFingerprintSha256,
        publicKeySpkiDer: signer.publicKeySpkiDer,
        sign: signer.sign,
      }),
    /factory/,
  );
});

test("key identity, custody, and message bounds are enforced before provider use", async () => {
  const material = keyMaterial();
  let calls = 0;
  const signRaw = async (message: Uint8Array) => {
    calls += 1;
    return signEd25519(null, message, material.privateKey);
  };
  assert.throws(
    () =>
      createManagedEd25519Signer(
        options(material, { publicKeyFingerprintSha256: "00".repeat(32) }),
      ),
    /fingerprint/,
  );
  assert.throws(
    () => createManagedEd25519Signer(options(material, { custody: "software" })),
    /custody/,
  );

  const signer = createManagedEd25519Signer(options(material, { signRaw }));
  await assert.rejects(signer.sign(new Uint8Array(0)), /1-262144/);
  await assert.rejects(
    signer.sign(new Uint8Array(MAX_MANAGED_ED25519_MESSAGE_BYTES + 1)),
    /1-262144/,
  );
  assert.equal(calls, 0);
});
