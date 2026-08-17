import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import test from "node:test";

import {
  MARKETPLACE_ATTESTATION_AUDIENCE,
  MARKETPLACE_ATTESTATION_ISSUER,
  MARKETPLACE_ATTESTATION_SIGNATURE_PROFILE,
  MARKETPLACE_EVALUATION_ATTESTATION_SCHEMA,
  MAX_MARKETPLACE_ATTESTATION_BYTES,
  canonicalJson,
  canonicalSha256,
  createMarketplaceCoreV2,
  displaySafeQuoteProjectionPayloadSchema,
  marketplaceEvaluationAttestationSigningMessage,
  marketplaceEvaluationAttestationUnsignedSchema,
  marketplaceMandateSchema,
  serializeMarketplaceEvaluationAttestation,
  type MarketplaceAttestationTrust,
  type MarketplaceCoreError,
  type MarketplaceErrorCode,
  type MarketplaceEvaluationAttestationUnsigned,
} from "../src/index.js";
import {
  createTestMarketplaceCore,
  rawMandate,
  rawProjection,
} from "./fixtures.js";

const POLICY_SHA256 = "99".repeat(32);
const KEY_ID = "verifier-production-1";
const ISSUED_AT = 1_120;
const EXPIRES_AT = 1_400;
const EVALUATED_AT = 1_150;

const signingKeyPair = generateKeyPairSync("ed25519");
const publicKeySpkiDer = signingKeyPair.publicKey.export({
  format: "der",
  type: "spki",
});
if (!Buffer.isBuffer(publicKeySpkiDer)) {
  throw new Error("expected Ed25519 SPKI DER bytes");
}
const publicKeyFingerprintSha256 = createHash("sha256")
  .update(publicKeySpkiDer)
  .digest("hex");

function pinnedTrust(
  overrides: Partial<MarketplaceAttestationTrust> = {},
): MarketplaceAttestationTrust {
  return {
    keyId: KEY_ID,
    publicKeySpkiDer: new Uint8Array(publicKeySpkiDer),
    publicKeyFingerprintSha256,
    verifierPolicySha256: POLICY_SHA256,
    ...overrides,
  };
}

function parsedMandate() {
  return marketplaceMandateSchema.parse(rawMandate());
}

function parsedPayload() {
  return displaySafeQuoteProjectionPayloadSchema.parse(rawProjection());
}

type UnsignedOverrides = Partial<
  Omit<MarketplaceEvaluationAttestationUnsigned, "payload">
> & {
  readonly payload?: unknown;
};

function unsignedAttestation(
  overrides: UnsignedOverrides = {},
): MarketplaceEvaluationAttestationUnsigned {
  const payload = displaySafeQuoteProjectionPayloadSchema.parse(
    overrides.payload ?? parsedPayload(),
  );
  return marketplaceEvaluationAttestationUnsignedSchema.parse({
    schema: MARKETPLACE_EVALUATION_ATTESTATION_SCHEMA,
    signatureProfile: MARKETPLACE_ATTESTATION_SIGNATURE_PROFILE,
    issuer: MARKETPLACE_ATTESTATION_ISSUER,
    audience: MARKETPLACE_ATTESTATION_AUDIENCE,
    keyId: KEY_ID,
    attestationId: "018f4f5e-7d2d-7d6b-8fb8-35c1b79275a1",
    scope: "evaluation_only",
    activationAuthorization: "none",
    reservation: "none",
    replayPolicy: "reusable_until_expiry",
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    mandateSha256: canonicalSha256(parsedMandate()),
    payloadSha256: canonicalSha256(payload),
    verifierPolicySha256: POLICY_SHA256,
    payload,
    ...overrides,
  });
}

function signedWire(
  overrides: UnsignedOverrides = {},
  privateKey: KeyObject = signingKeyPair.privateKey,
): string {
  const unsigned = unsignedAttestation(overrides);
  const signature = sign(
    null,
    marketplaceEvaluationAttestationSigningMessage(unsigned),
    privateKey,
  ).toString("hex");
  return serializeMarketplaceEvaluationAttestation({
    ...unsigned,
    signature,
  });
}

function makeCore(
  options: Readonly<{
    now?: number;
    maxClockSkewSeconds?: number;
    trust?: MarketplaceAttestationTrust;
  }> = {},
) {
  let now = options.now ?? EVALUATED_AT;
  const core = createMarketplaceCoreV2({
    attestationTrust: options.trust ?? pinnedTrust(),
    maxClockSkewSeconds: options.maxClockSkewSeconds ?? 30,
    clock: () => now,
  });
  return {
    core,
    setClock(value: number) {
      now = value;
    },
  };
}

function hasCode(code: MarketplaceErrorCode) {
  return (error: unknown): boolean =>
    error instanceof Error &&
    "code" in error &&
    (error as MarketplaceCoreError).code === code;
}

function evaluateWire(wire: string | Uint8Array, now = EVALUATED_AT) {
  return makeCore({ now }).core.evaluateMarketplaceV2({
    mandate: rawMandate(),
    attestations: [wire],
  });
}

function mutateCanonicalWire(
  wire: string,
  mutate: (envelope: Record<string, any>) => void,
): string {
  const envelope = JSON.parse(wire) as Record<string, any>;
  mutate(envelope);
  return canonicalJson(envelope);
}

test("v2 evaluates a canonical Ed25519 attestation with legacy decision parity", () => {
  const wire = signedWire();
  const v2 = evaluateWire(Buffer.from(wire, "utf8"));

  const legacy = createTestMarketplaceCore(ISSUED_AT);
  const captured = legacy.ingress.capture(parsedPayload());
  legacy.setClock(EVALUATED_AT);
  const v1 = legacy.core.evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [captured],
  });

  assert.deepEqual(v2, v1);
  assert.equal(v2.decisions[0]?.outcome, "eligible");
  assert.equal(Object.isFrozen(v2), true);
  assert.equal(Object.isFrozen(v2.quotes[0]?.categoryEvidence), true);
});

test("the signing byte profile has a locked golden vector", () => {
  const message = marketplaceEvaluationAttestationSigningMessage(
    unsignedAttestation(),
  );
  assert.equal(
    createHash("sha256").update(message).digest("hex"),
    "fea2d743f84005421aba7a2788b8c919bf0ab557bae7f5ce19a92b4470e7231b",
  );
});

test("a serialized attestation verifies in a separate evaluator process", () => {
  const childScript = `
    import { createMarketplaceCoreV2 } from "./src/index.ts";
    const trust = JSON.parse(process.env.MANDATEX_TEST_TRUST);
    const core = createMarketplaceCoreV2({
      attestationTrust: {
        ...trust,
        publicKeySpkiDer: Buffer.from(trust.publicKeySpkiBase64, "base64"),
      },
      maxClockSkewSeconds: 30,
      clock: () => ${EVALUATED_AT},
    });
    const result = core.evaluateMarketplaceV2({
      mandate: JSON.parse(process.env.MANDATEX_TEST_MANDATE),
      attestations: [process.env.MANDATEX_TEST_WIRE],
    });
    process.stdout.write(result.receipt.receiptId);
  `;
  const child = spawnSync(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "--eval", childScript],
    {
      cwd: new URL("..", import.meta.url),
      encoding: "utf8",
      env: {
        ...process.env,
        MANDATEX_TEST_TRUST: JSON.stringify({
          keyId: KEY_ID,
          publicKeySpkiBase64: publicKeySpkiDer.toString("base64"),
          publicKeyFingerprintSha256,
          verifierPolicySha256: POLICY_SHA256,
        }),
        MANDATEX_TEST_MANDATE: JSON.stringify(rawMandate()),
        MANDATEX_TEST_WIRE: signedWire(),
      },
    },
  );
  assert.equal(child.status, 0, child.stderr);
  assert.match(child.stdout, /^[a-f0-9]{64}$/);
});

test("signed metadata and nested payload tampering abort the full evaluation", () => {
  const wire = signedWire();
  const metadataTamper = mutateCanonicalWire(wire, (envelope) => {
    envelope.attestationId = "tampered-attestation";
  });
  assert.throws(
    () => evaluateWire(metadataTamper),
    hasCode("ATTESTATION_SIGNATURE_INVALID"),
  );

  const payloadTamper = mutateCanonicalWire(wire, (envelope) => {
    envelope.payload.estimates.gasUsdMicros = "11";
    envelope.payloadSha256 = canonicalSha256(envelope.payload);
  });
  assert.throws(
    () => evaluateWire(payloadTamper),
    hasCode("ATTESTATION_SIGNATURE_INVALID"),
  );
});

test("fixed authority and replay claims cannot be changed", () => {
  const cases = [
    ["issuer", "other-verifier"],
    ["audience", "other-core"],
    ["scope", "activation"],
    ["activationAuthorization", "granted"],
    ["reservation", "reserved"],
    ["replayPolicy", "single_use"],
    ["signatureProfile", "other-profile"],
  ] as const;
  for (const [field, value] of cases) {
    const tampered = mutateCanonicalWire(signedWire(), (envelope) => {
      envelope[field] = value;
    });
    assert.throws(
      () => evaluateWire(tampered),
      hasCode("ATTESTATION_SCHEMA_INVALID"),
      field,
    );
  }
});

test("pinned key, fingerprint, policy, mandate, and payload hashes are enforced", () => {
  assert.throws(
    () =>
      makeCore({
        trust: pinnedTrust({ publicKeyFingerprintSha256: "00".repeat(32) }),
      }),
    hasCode("ATTESTATION_TRUST_INVALID"),
  );

  const otherKeys = generateKeyPairSync("ed25519");
  const otherDer = otherKeys.publicKey.export({ format: "der", type: "spki" });
  assert.ok(Buffer.isBuffer(otherDer));
  const wrongKeyCore = makeCore({
    trust: pinnedTrust({
      publicKeySpkiDer: otherDer,
      publicKeyFingerprintSha256: createHash("sha256")
        .update(otherDer)
        .digest("hex"),
    }),
  });
  assert.throws(
    () =>
      wrongKeyCore.core.evaluateMarketplaceV2({
        mandate: rawMandate(),
        attestations: [signedWire()],
      }),
    hasCode("ATTESTATION_SIGNATURE_INVALID"),
  );

  const wrongKeyId = mutateCanonicalWire(signedWire(), (envelope) => {
    envelope.keyId = "verifier-production-2";
  });
  assert.throws(
    () => evaluateWire(wrongKeyId),
    hasCode("ATTESTATION_KEY_MISMATCH"),
  );

  const wrongPolicy = mutateCanonicalWire(signedWire(), (envelope) => {
    envelope.verifierPolicySha256 = "88".repeat(32);
  });
  assert.throws(
    () => evaluateWire(wrongPolicy),
    hasCode("ATTESTATION_POLICY_MISMATCH"),
  );

  const wrongMandate = mutateCanonicalWire(signedWire(), (envelope) => {
    envelope.mandateSha256 = "77".repeat(32);
  });
  assert.throws(
    () => evaluateWire(wrongMandate),
    hasCode("ATTESTATION_MANDATE_HASH_MISMATCH"),
  );

  const wrongPayload = mutateCanonicalWire(signedWire(), (envelope) => {
    envelope.payloadSha256 = "66".repeat(32);
  });
  assert.throws(
    () => evaluateWire(wrongPayload),
    hasCode("ATTESTATION_PAYLOAD_HASH_MISMATCH"),
  );
});

test("TTL, clock skew, payload expiry, and observation chronology are enforced", () => {
  assert.doesNotThrow(() =>
    evaluateWire(
      signedWire({ issuedAt: EVALUATED_AT + 30, expiresAt: 1_400 }),
    ),
  );
  assert.throws(
    () =>
      evaluateWire(
        signedWire({ issuedAt: EVALUATED_AT + 31, expiresAt: 1_400 }),
      ),
    hasCode("ATTESTATION_NOT_YET_VALID"),
  );
  assert.throws(
    () => evaluateWire(signedWire({ expiresAt: ISSUED_AT + 301 })),
    hasCode("ATTESTATION_TTL_EXCEEDED"),
  );
  assert.throws(
    () => evaluateWire(signedWire({ expiresAt: ISSUED_AT })),
    hasCode("ATTESTATION_EXPIRY_INVALID"),
  );
  assert.throws(
    () => evaluateWire(signedWire({ expiresAt: 1_501 })),
    hasCode("ATTESTATION_TTL_EXCEEDED"),
  );

  const shortPayload = structuredClone(parsedPayload()) as any;
  shortPayload.expiresAt = 1_200;
  assert.throws(
    () =>
      evaluateWire(
        signedWire({
          payload: shortPayload,
          payloadSha256: canonicalSha256(shortPayload),
          expiresAt: 1_201,
        }),
      ),
    hasCode("ATTESTATION_EXPIRY_INVALID"),
  );

  const futureEvidence = structuredClone(parsedPayload()) as any;
  futureEvidence.observedAt = ISSUED_AT + 1;
  assert.throws(
    () => evaluateWire(signedWire({ payload: futureEvidence })),
    hasCode("ATTESTATION_OBSERVATION_AFTER_ISSUANCE"),
  );
});

test("canonical wire rejects size, UTF-8, whitespace, duplicate keys, and numeric spelling", () => {
  assert.throws(
    () => evaluateWire(new Uint8Array(MAX_MARKETPLACE_ATTESTATION_BYTES + 1)),
    hasCode("ATTESTATION_TOO_LARGE"),
  );
  assert.throws(
    () => evaluateWire(Uint8Array.from([0xc3, 0x28])),
    hasCode("ATTESTATION_UTF8_INVALID"),
  );
  assert.throws(
    () => evaluateWire("{"),
    hasCode("ATTESTATION_JSON_INVALID"),
  );
  assert.throws(
    () => evaluateWire(`${signedWire()}\n`),
    hasCode("ATTESTATION_NONCANONICAL"),
  );
  assert.throws(
    () => evaluateWire(`\uFEFF${signedWire()}`),
    hasCode("ATTESTATION_NONCANONICAL"),
  );
  assert.throws(
    () =>
      evaluateWire(
        Buffer.concat([
          Buffer.from([0xef, 0xbb, 0xbf]),
          Buffer.from(signedWire(), "utf8"),
        ]),
      ),
    hasCode("ATTESTATION_NONCANONICAL"),
  );

  const duplicateKey = signedWire().replace(
    `"schema":"${MARKETPLACE_EVALUATION_ATTESTATION_SCHEMA}"`,
    `"schema":"${MARKETPLACE_EVALUATION_ATTESTATION_SCHEMA}","schema":"${MARKETPLACE_EVALUATION_ATTESTATION_SCHEMA}"`,
  );
  assert.throws(
    () => evaluateWire(duplicateKey),
    hasCode("ATTESTATION_NONCANONICAL"),
  );

  const alternateNumber = signedWire().replace(
    `"issuedAt":${ISSUED_AT}`,
    '"issuedAt":1.12e3',
  );
  assert.throws(
    () => evaluateWire(alternateNumber),
    hasCode("ATTESTATION_NONCANONICAL"),
  );

  const alternateUnicodeEscape = signedWire().replace(
    "Rebalance",
    "\\u0052ebalance",
  );
  assert.throws(
    () => evaluateWire(alternateUnicodeEscape),
    hasCode("ATTESTATION_NONCANONICAL"),
  );

  const unknownField = mutateCanonicalWire(signedWire(), (envelope) => {
    envelope.algorithm = "Ed25519";
  });
  assert.throws(
    () => evaluateWire(unknownField),
    hasCode("ATTESTATION_SCHEMA_INVALID"),
  );
});

test("attestations are reusable until expiry and re-enter the live clock", () => {
  const evaluator = makeCore();
  const wire = signedWire();
  const first = evaluator.core.evaluateMarketplaceV2({
    mandate: rawMandate(),
    attestations: [wire],
  });
  const separateEvaluator = makeCore();
  assert.deepEqual(
    separateEvaluator.core.evaluateMarketplaceV2({
      mandate: rawMandate(),
      attestations: [wire],
    }),
    first,
  );
  evaluator.setClock(EXPIRES_AT - 1);
  const second = evaluator.core.evaluateMarketplaceV2({
    mandate: rawMandate(),
    attestations: [wire],
  });
  assert.notEqual(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(second.receipt.evaluatedAt, EXPIRES_AT - 1);

  evaluator.setClock(EXPIRES_AT);
  assert.throws(
    () =>
      evaluator.core.evaluateMarketplaceV2({
        mandate: rawMandate(),
        attestations: [wire],
      }),
    hasCode("ATTESTATION_EXPIRED"),
  );
});

test("v2 rejects oversized batches before parsing and duplicate candidates after verification", () => {
  const evaluator = makeCore().core;
  assert.throws(
    () =>
      evaluator.evaluateMarketplaceV2({
        mandate: rawMandate(),
        attestations: Array.from({ length: 9 }, () => "not-json"),
      }),
    hasCode("CANDIDATE_LIMIT_EXCEEDED"),
  );

  assert.throws(
    () =>
      evaluator.evaluateMarketplaceV2({
        mandate: rawMandate(),
        attestations: [
          signedWire(),
          signedWire({ attestationId: "second-attestation" }),
        ],
      }),
    hasCode("DUPLICATE_CANDIDATE"),
  );
});

test("factory trust is copied and v2 exposes no legacy capture fallback", () => {
  const trust = pinnedTrust();
  const evaluator = makeCore({ trust }).core;
  (trust as any).keyId = "mutated";
  (trust.publicKeySpkiDer as Uint8Array).fill(0);

  assert.equal(Object.keys(evaluator).join(","), "evaluateMarketplaceV2");
  assert.equal("evaluateMarketplace" in evaluator, false);
  const result = evaluator.evaluateMarketplaceV2({
    mandate: rawMandate(),
    attestations: [signedWire()],
  });
  assert.equal(result.decisions[0]?.outcome, "eligible");
  assert.throws(() => {
    (result.quotes[0] as any).quoteId = "mutated";
  });
});
