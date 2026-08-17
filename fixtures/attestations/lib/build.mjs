// Generates MandateX evaluation-attestation fixture vectors.
//
// Run:  node fixtures/attestations/lib/build.mjs
//
// Emits, all byte-reproducible from the deterministic dev key:
//   keys/dev-signer.public.json   pinned trust material for a test evaluator
//   vectors/valid/*.json          attestations that MUST verify
//   vectors/invalid/*.json        attestations that MUST be rejected
//   golden/signing-bytes.json     exact signing bytes, for cross-implementation check
//   manifest.json                 counts and time anchor
//
// Contract: tools/marketplace-core/EVALUATION_ATTESTATION_V2.md (frozen).
//
// EXPECTED ERROR CODES come from the real implementation in
// tools/marketplace-core/src/attestation.ts, and each vector targets ONE check.
// verifyMarketplaceEvaluationAttestation runs its checks in a fixed order, so a
// vector with two defects only ever reports the earlier one. That order is:
// byte length -> BOM -> UTF-8 -> JSON parse -> bounded shape -> canonical bytes
// -> schema -> keyId -> policy hash -> clock skew -> issuance in future ->
// expiry after issuance -> TTL -> outlives quote -> expired -> mandate hash ->
// payload hash -> observation chronology -> SIGNATURE LAST.
//
// The signature being verified last is why the adversarial vectors below are
// signed correctly over their own bytes: a malicious envelope must be stopped by
// a rule, and a test that passes only because the signature broke proves nothing.

import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, findIntegerLikeKeys } from "./canonical.mjs";
import { devKeyPair, signBytes, verifyBytes, sha256Hex } from "./signer.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

// ── Fixed constants from the frozen contract ────────────────────────────────
const SCHEMA = "mandatex.marketplace.evaluation-attestation.v1";
const SIGNATURE_PROFILE = "mandatex-ed25519-v1";
const ISSUER = "mandatex-agent-supply-verifier";
const AUDIENCE = "mandatex-marketplace-core";
const SIGNING_DOMAIN = "MandateX Marketplace Evaluation Attestation v1\0";
const MAX_BYTES = 131_072;
const MAX_TTL_SECONDS = 300;

// ── Time anchor ─────────────────────────────────────────────────────────────
// Every payload observation must be <= issuedAt, and the attestation must expire
// no later than min(issuedAt + 300, payload.expiresAt).
const T0 = 1_786_900_000; // issuedAt for the baseline vector
const OBSERVED = T0 - 30; // evidence observed 30s before issuance
const QUOTE_EXPIRES = T0 + 600; // quote payload lives 10 minutes
const ATTESTATION_EXPIRES = T0 + MAX_TTL_SECONDS; // 300s, and <= QUOTE_EXPIRES
const SKEW = 30; // matches the mandate's maxClockSkewSeconds

const ADDRESSES = Object.freeze({
  owner: "0x1111111111111111111111111111111111111111",
  publisher: "0x2222222222222222222222222222222222222222",
  pool: "0x3333333333333333333333333333333333333333",
  manager: "0x4444444444444444444444444444444444444444",
  usdt: "0x5555555555555555555555555555555555555555",
});
const BLOCK_HASH = `0x${"ab".repeat(32)}`;

// Stand-in for the deployed verifier's policy hash. The real value is pinned into
// the evaluator image; fixtures only need issuer and evaluator to agree.
const VERIFIER_POLICY_SHA256 = sha256Hex("mandatex-fixture-verifier-policy-v1");

// ── Mandate ─────────────────────────────────────────────────────────────────
// Written in already-normalized form: lowercase addresses, sorted single-element
// arrays. marketplaceMandateSchema applies .toLowerCase() and .transform(sortUnique),
// and Core hashes the PARSED mandate — so if this object were not already
// normalized, our mandateSha256 would not match Core's. crosscheck.mjs asserts
// canonicalJson(parse(mandate)) === canonicalJson(mandate) rather than assuming it.
function buildMandate() {
  return {
    schema: "mandatex.marketplace.mandate.v1",
    mandateId: "mandate-demo",
    category: "rebalancing",
    chainId: 56,
    createdAt: T0 - 600,
    expiresAt: T0 + 3_600,
    maxClockSkewSeconds: SKEW,
    maxEvidenceAgeSeconds: 300,
    maxPreviewAgeSeconds: 300,
    budgets: {
      maxAgentFeeUsdMicros: "0",
      maxGasUsdMicros: "50",
      maxSlippageBps: 50,
      maxExposureUsdMicros: "1000000",
    },
    permissions: {
      allowedProtocols: ["pancakeswap-v3"],
      allowedContracts: [ADDRESSES.manager],
      allowedCalls: ["decreaseLiquidity(uint256)"],
      maxSpendUsdMicros: "1000000",
      expiresAt: T0 + 3_600,
    },
    rebalancing: {
      position: {
        protocol: "pancakeswap-v3",
        poolAddress: ADDRESSES.pool,
        positionManagerAddress: ADDRESSES.manager,
        tokenId: "7",
      },
      approvedLowerTick: -100,
      approvedUpperTick: 100,
      targetWidthTicks: 100,
      triggerMode: "boundary_proximity",
      triggerDistanceTicks: 10,
    },
  };
}

// ── Display-safe projection payload ─────────────────────────────────────────
// Mirrors displaySafeQuoteProjectionPayloadShape. The payload schema imposes NO
// chronology rules — those live in assertObservationChronology, which is why the
// backdated-evidence vectors below are a distinct attack class.
function buildPayload(options = {}) {
  const observedAt = options.observedAt ?? OBSERVED;
  return {
    sourceCommitments: {
      quoteValidationSha256: options.quoteCommitment ?? "11".repeat(32),
      previewValidationSha256: options.previewCommitment ?? "22".repeat(32),
    },
    quoteId: options.quoteId ?? "quote-a",
    mandateId: "mandate-demo",
    category: "rebalancing",
    candidate: {
      chainId: 56,
      tokenId: options.tokenId ?? "7",
      owner: ADDRESSES.owner,
      publisher: ADDRESSES.publisher,
      taskInterface: "erc8183",
    },
    observedAt,
    observedBlock: options.observedBlock ?? 123,
    observedBlockHash: BLOCK_HASH,
    expiresAt: options.quoteExpiresAt ?? QUOTE_EXPIRES,
    proposedAction:
      options.proposedAction ?? "Rebalance the bounded PancakeSwap V3 position.",
    price: {
      // "0" is the normalized zero fee. A nonzero agent fee currently yields an
      // inconclusive finding upstream, so scored fixtures keep zero.
      amountAtomic: options.amountAtomic ?? "0",
      currency: ADDRESSES.usdt,
    },
    estimates: {
      gasUsdMicros: options.gasUsdMicros ?? "10",
      slippageBps: options.slippageBps ?? 5,
      exposureUsdMicros: options.exposureUsdMicros ?? "100",
      observedAt: options.estimatesObservedAt ?? observedAt,
    },
    permissions: {
      contracts: [ADDRESSES.manager],
      calls: ["decreaseLiquidity(uint256)"],
      spendCapUsdMicros: "100",
      expiresAt: T0 + 3_600,
    },
    verification: {
      identity: "pass",
      publisher: "pass",
      endpoint: "pass",
      taskInterface: "pass",
      category: "pass",
      quoteCompleteness: "pass",
    },
    preview: {
      status: "passed",
      observedAt: options.previewObservedAt ?? observedAt,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
    },
    reputation: {
      scoreBps: options.reputationScoreBps ?? 8_700,
      sampleSize: options.sampleSize ?? 20,
      evidenceConfidenceBps: options.evidenceConfidenceBps ?? 9_000,
      observedAt: options.reputationObservedAt ?? observedAt,
    },
    categoryEvidence: {
      category: "rebalancing",
      protocol: "pancakeswap-v3",
      position: {
        poolAddress: ADDRESSES.pool,
        positionManagerAddress: ADDRESSES.manager,
        tokenId: "7",
      },
      observedAt: options.categoryEvidenceObservedAt ?? observedAt,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
      currentTick: 19,
      tickSpacing: 10,
      currentLowerTick: -20,
      currentUpperTick: 20,
      proposedLowerTick: -30,
      proposedUpperTick: 70,
      trigger: {
        fired: true,
        reason: "near_range_boundary",
        distanceToBoundaryTicks: 1,
      },
    },
  };
}

// ── Envelope assembly ───────────────────────────────────────────────────────
const key = devKeyPair();
const mandate = buildMandate();
const MANDATE_SHA256 = sha256Hex(canonicalJson(mandate));

function buildUnsigned({
  payload,
  issuedAt = T0,
  expiresAt = ATTESTATION_EXPIRES,
  attestationId = "018f4f5e-7d2d-7d6b-8fb8-35c1b79275a1",
  overrides,
}) {
  return {
    schema: SCHEMA,
    signatureProfile: SIGNATURE_PROFILE,
    issuer: ISSUER,
    audience: AUDIENCE,
    keyId: key.keyId,
    attestationId,
    scope: "evaluation_only",
    activationAuthorization: "none",
    reservation: "none",
    replayPolicy: "reusable_until_expiry",
    issuedAt,
    expiresAt,
    mandateSha256: MANDATE_SHA256,
    payloadSha256: sha256Hex(canonicalJson(payload)),
    verifierPolicySha256: VERIFIER_POLICY_SHA256,
    payload,
    // Applied last so adversarial vectors can replace even the fixed literals.
    ...overrides,
  };
}

function signingMessage(unsigned) {
  return Buffer.concat([
    Buffer.from(SIGNING_DOMAIN, "utf8"),
    Buffer.from(canonicalJson(unsigned), "utf8"),
  ]);
}

/**
 * Sign an envelope over its own canonical bytes.
 *
 * Deliberately does NOT schema-validate first: adversarial vectors need a
 * correctly signed malicious envelope so that only a rule can reject them.
 */
function sign(unsigned) {
  const message = signingMessage(unsigned);
  const signature = signBytes(message, key.privateKey);
  if (!verifyBytes(message, signature, key.publicKey)) {
    throw new Error("self-check failed: freshly produced signature does not verify");
  }
  const envelope = { ...unsigned, signature };
  return { envelope, message, wire: canonicalJson(envelope) };
}

// ── Vector emission ─────────────────────────────────────────────────────────
const valid = [];
const invalid = [];
const golden = [];

function emitValid({ name, description, unsigned, evaluatedAt = T0 }) {
  const { envelope, message, wire } = sign(unsigned);

  // Self-checks. A fixture that violates its own contract is worse than none.
  const assert = (ok, why) => {
    if (!ok) throw new Error(`${name}: ${why}`);
  };
  assert(Buffer.byteLength(wire, "utf8") <= MAX_BYTES, "exceeds byte limit");
  assert(wire === wire.trim(), "wire has surrounding whitespace");
  assert(envelope.expiresAt > envelope.issuedAt, "expiry not after issuance");
  assert(envelope.expiresAt - envelope.issuedAt <= MAX_TTL_SECONDS, "TTL over 300s");
  assert(envelope.expiresAt <= envelope.payload.expiresAt, "outlives quote payload");
  assert(envelope.issuedAt <= evaluatedAt + SKEW, "issued too far in the future");
  assert(envelope.expiresAt > evaluatedAt, "already expired at evaluatedAt");
  for (const [label, observedAt] of [
    ["observedAt", envelope.payload.observedAt],
    ["estimates", envelope.payload.estimates.observedAt],
    ["preview", envelope.payload.preview.observedAt],
    ["reputation", envelope.payload.reputation.observedAt],
    ["categoryEvidence", envelope.payload.categoryEvidence.observedAt],
  ]) {
    assert(observedAt <= envelope.issuedAt, `${label} observation follows issuance`);
  }
  assert(
    findIntegerLikeKeys(envelope).length === 0,
    "integer-like keys would break portable key ordering",
  );

  valid.push({
    name,
    description,
    expectedResult: "accept",
    evaluatedAt,
    maxClockSkewSeconds: SKEW,
    mandate,
    wire,
    wireSha256: sha256Hex(wire),
    wireByteLength: Buffer.byteLength(wire, "utf8"),
  });
  golden.push({
    name,
    signingMessageSha256: sha256Hex(message),
    signingMessageByteLength: message.length,
    signatureHex: envelope.signature,
  });
}

function emitInvalid({
  name,
  description,
  attackClass,
  expectedCode,
  wire,
  notes,
  evaluatedAt = T0,
}) {
  invalid.push({
    name,
    description,
    attackClass,
    expectedResult: "reject",
    expectedCode,
    evaluatedAt,
    maxClockSkewSeconds: SKEW,
    mandate,
    // Stored as an exact string, never re-parsed: byte-level defects
    // (whitespace, BOM, duplicate keys, key order) would not survive a
    // parse/serialize round-trip.
    wire,
    wireSha256: sha256Hex(wire),
    wireByteLength: Buffer.byteLength(wire, "utf8"),
    ...(notes ? { notes } : {}),
  });
}

// ═══ VALID ══════════════════════════════════════════════════════════════════
emitValid({
  name: "baseline",
  description:
    "Clean rebalancing quote: zero fee, fresh evidence, preview passed, maximum TTL.",
  unsigned: buildUnsigned({ payload: buildPayload() }),
});

emitValid({
  name: "competing-quote-b",
  description:
    "Second candidate for comparison views: different quote and token, higher gas and " +
    "slippage, lower reputation.",
  unsigned: buildUnsigned({
    payload: buildPayload({
      quoteId: "quote-b",
      tokenId: "8",
      gasUsdMicros: "18",
      slippageBps: 12,
      reputationScoreBps: 7_400,
      sampleSize: 11,
    }),
    attestationId: "018f4f5e-7d2d-7d6b-8fb8-35c1b79275a2",
  }),
});

emitValid({
  name: "competing-quote-c-older-evidence",
  description:
    "Third candidate with evidence observed 200s before issuance. Exercises the freshness " +
    "factor, one of the few ranking inputs that actually varies between candidates. " +
    "Eligibility here is clock-dependent: the mandate allows 300s of evidence age, so this " +
    "vector stops being eligible once evaluatedAt passes T0 + 100.",
  unsigned: buildUnsigned({
    payload: buildPayload({
      quoteId: "quote-c",
      tokenId: "9",
      observedAt: T0 - 200,
      reputationScoreBps: 8_100,
    }),
    attestationId: "018f4f5e-7d2d-7d6b-8fb8-35c1b79275a3",
  }),
});

emitValid({
  name: "boundary-min-ttl",
  description: "Shortest legal validity window: expiresAt is exactly issuedAt + 1.",
  unsigned: buildUnsigned({ payload: buildPayload(), expiresAt: T0 + 1 }),
});

emitValid({
  name: "boundary-max-ttl",
  description: "Longest legal validity window: expiresAt is exactly issuedAt + 300.",
  unsigned: buildUnsigned({ payload: buildPayload(), expiresAt: T0 + MAX_TTL_SECONDS }),
});

// ═══ INVALID ════════════════════════════════════════════════════════════════

// ── Authority escalation: the confused-deputy class this contract exists to stop.
for (const [field, value, label] of [
  ["scope", "activation", "scope-claims-activation"],
  ["activationAuthorization", "granted", "activation-authorization-granted"],
  ["reservation", "held", "reservation-held"],
  ["replayPolicy", "single_use", "replay-policy-single-use"],
]) {
  emitInvalid({
    name: label,
    description: `Correctly signed envelope claiming ${field} = "${value}".`,
    attackClass: "authority-escalation",
    expectedCode: "ATTESTATION_SCHEMA_INVALID",
    wire: sign(buildUnsigned({ payload: buildPayload(), overrides: { [field]: value } })).wire,
    notes:
      "The signature is valid, so only the fixed-literal schema constraint can reject this. " +
      "If it verifies, an evaluation-only artifact has been escalated into activation authority.",
  });
}

// ── Identity and routing confusion.
for (const [field, value, label, code, note] of [
  ["issuer", "mandatex-attacker", "wrong-issuer", "ATTESTATION_SCHEMA_INVALID", undefined],
  [
    "audience", "mandatex-other-service", "wrong-audience", "ATTESTATION_SCHEMA_INVALID",
    "Audience binding stops an attestation minted for another consumer being replayed here.",
  ],
  [
    "schema", "mandatex.marketplace.evaluation-attestation.v2", "wrong-schema",
    "ATTESTATION_SCHEMA_INVALID", undefined,
  ],
  [
    "signatureProfile", "mandatex-hmac-v1", "wrong-signature-profile",
    "ATTESTATION_SCHEMA_INVALID",
    "Algorithm-confusion probe: no attestation-supplied value may select verification code. " +
      "The profile is a fixed literal, so Ed25519 is chosen by the schema, never by the envelope.",
  ],
  [
    "keyId", "some-other-key-1", "key-id-mismatch", "ATTESTATION_KEY_MISMATCH",
    "A schema-valid identifier, so this one reaches the pinned-key comparison.",
  ],
]) {
  emitInvalid({
    name: label,
    description: `Correctly signed envelope with ${field} = "${value}".`,
    attackClass: "identity-confusion",
    expectedCode: code,
    wire: sign(buildUnsigned({ payload: buildPayload(), overrides: { [field]: value } })).wire,
    notes: note,
  });
}

// ── Hash-binding failures.
const WRONG_HASH = sha256Hex("not-the-right-preimage");
for (const [field, label, code] of [
  ["mandateSha256", "mandate-hash-mismatch", "ATTESTATION_MANDATE_HASH_MISMATCH"],
  ["payloadSha256", "payload-hash-mismatch", "ATTESTATION_PAYLOAD_HASH_MISMATCH"],
  ["verifierPolicySha256", "policy-hash-mismatch", "ATTESTATION_POLICY_MISMATCH"],
]) {
  emitInvalid({
    name: label,
    description: `Correctly signed envelope whose ${field} does not match its subject.`,
    attackClass: "binding-failure",
    expectedCode: code,
    wire: sign(buildUnsigned({ payload: buildPayload(), overrides: { [field]: WRONG_HASH } })).wire,
  });
}

// ── Payload tampering, in both orders.
// The pair matters: payloadSha256 is checked BEFORE the signature, so tampering
// without repairing the hash never reaches the signature check at all. Only the
// second vector proves the signature itself is load-bearing.
{
  const tamperedPayload = buildPayload({ gasUsdMicros: "1", slippageBps: 0 });
  const honest = buildUnsigned({ payload: buildPayload() });

  emitInvalid({
    name: "payload-tampered-hash-stale",
    description:
      "Payload replaced with a cheaper quote and the envelope re-signed, but payloadSha256 " +
      "still describes the original payload.",
    attackClass: "binding-failure",
    expectedCode: "ATTESTATION_PAYLOAD_HASH_MISMATCH",
    wire: sign({ ...honest, payload: tamperedPayload }).wire,
    notes: "Proves payloadSha256 is recomputed and compared, not merely well-formed.",
  });

  emitInvalid({
    name: "payload-tampered-hash-updated",
    description:
      "Payload replaced with a cheaper quote AND payloadSha256 corrected to match, but the " +
      "original signature retained.",
    attackClass: "signature",
    expectedCode: "ATTESTATION_SIGNATURE_INVALID",
    wire: canonicalJson({
      ...sign(honest).envelope,
      payload: tamperedPayload,
      payloadSha256: sha256Hex(canonicalJson(tamperedPayload)),
    }),
    notes:
      "The highest-value tampering vector. Every hash inside the envelope is internally " +
      "consistent, so the signature is the only thing standing between a forged quote and " +
      "the comparison view.",
  });
}

// ── Time-rule violations. Each isolates one check in the fixed order.
for (const [label, issuedAt, expiresAt, evaluatedAt, code, description] of [
  ["ttl-exceeded", T0, T0 + MAX_TTL_SECONDS + 1, T0, "ATTESTATION_TTL_EXCEEDED",
    "TTL is 301 seconds, one second over the ceiling."],
  ["expiry-before-issuance", T0, T0 - 1, T0, "ATTESTATION_EXPIRY_INVALID",
    "expiresAt precedes issuedAt."],
  ["expiry-equals-issuance", T0, T0, T0, "ATTESTATION_EXPIRY_INVALID",
    "Zero-length validity window."],
  ["expired", T0, T0 + MAX_TTL_SECONDS, T0 + 400, "ATTESTATION_EXPIRED",
    "Structurally valid attestation evaluated 100 seconds after it expired."],
  ["issued-in-future", T0 + 400, T0 + 500, T0, "ATTESTATION_NOT_YET_VALID",
    "issuedAt is 400 seconds ahead of the evaluator clock, well beyond the 30s skew."],
]) {
  emitInvalid({
    name: label,
    description,
    attackClass: "time-rule",
    expectedCode: code,
    evaluatedAt,
    wire: sign(buildUnsigned({ payload: buildPayload(), issuedAt, expiresAt })).wire,
  });
}

// ── Attestation outliving the quote it describes.
emitInvalid({
  name: "outlives-quote-expiry",
  description: "Attestation valid until +120s while its quote payload expires at +60s.",
  attackClass: "time-rule",
  expectedCode: "ATTESTATION_EXPIRY_INVALID",
  wire: sign(
    buildUnsigned({ payload: buildPayload({ quoteExpiresAt: T0 + 60 }), expiresAt: T0 + 120 }),
  ).wire,
  notes:
    "Without this rule a cached attestation could outlive its quote and present a dead price " +
    "as live — exactly the failure mode reusable_until_expiry invites.",
});

// ── Backdated evidence: inflating the freshness ranking factor.
for (const [option, label] of [
  ["observedAt", "observation-after-issuance"],
  ["estimatesObservedAt", "estimates-observed-after-issuance"],
  ["previewObservedAt", "preview-observed-after-issuance"],
  ["reputationObservedAt", "reputation-observed-after-issuance"],
  ["categoryEvidenceObservedAt", "category-evidence-observed-after-issuance"],
]) {
  emitInvalid({
    name: label,
    description: `Payload ${option} is 60 seconds AFTER issuedAt.`,
    attackClass: "freshness-forgery",
    expectedCode: "ATTESTATION_OBSERVATION_AFTER_ISSUANCE",
    wire: sign(buildUnsigned({ payload: buildPayload({ [option]: T0 + 60 }) })).wire,
    notes:
      "Freshness is a scored ranking input, so future-dated evidence is a ranking attack, " +
      "not merely a bookkeeping error.",
  });
}

// ── Signature failures.
{
  const { envelope } = sign(buildUnsigned({ payload: buildPayload() }));
  const lastNibble = envelope.signature.slice(-1);

  emitInvalid({
    name: "signature-bit-flipped",
    description: "Final nibble of an otherwise valid signature altered.",
    attackClass: "signature",
    expectedCode: "ATTESTATION_SIGNATURE_INVALID",
    wire: canonicalJson({
      ...envelope,
      signature: envelope.signature.slice(0, -1) + (lastNibble === "0" ? "1" : "0"),
    }),
  });

  emitInvalid({
    name: "signature-all-zero",
    description: "Schema-valid 128-hex-character signature of all zeroes.",
    attackClass: "signature",
    expectedCode: "ATTESTATION_SIGNATURE_INVALID",
    wire: canonicalJson({ ...envelope, signature: "0".repeat(128) }),
  });
}

// ── Domain-separator omission: signed over canonical JSON with no domain prefix.
{
  const unsigned = buildUnsigned({ payload: buildPayload() });
  const noDomain = Buffer.from(canonicalJson(unsigned), "utf8");
  emitInvalid({
    name: "signed-without-domain-separator",
    description: "Signature computed over canonical JSON only, omitting the domain separator.",
    attackClass: "signature",
    expectedCode: "ATTESTATION_SIGNATURE_INVALID",
    wire: canonicalJson({ ...unsigned, signature: signBytes(noDomain, key.privateKey) }),
    notes:
      "Guards cross-protocol reuse: without the domain prefix, a signature the same key " +
      "produced in another MandateX context could be replayed as an attestation.",
  });
}

// ── Signature computed over the SIGNED envelope rather than the unsigned one.
{
  const unsigned = buildUnsigned({ payload: buildPayload() });
  const selfReferential = { ...unsigned, signature: "0".repeat(128) };
  const message = Buffer.concat([
    Buffer.from(SIGNING_DOMAIN, "utf8"),
    Buffer.from(canonicalJson(selfReferential), "utf8"),
  ]);
  emitInvalid({
    name: "signed-over-signed-envelope",
    description:
      "Signature computed over an envelope that already contained a signature field, rather " +
      "than over the unsigned envelope.",
    attackClass: "signature",
    expectedCode: "ATTESTATION_SIGNATURE_INVALID",
    wire: canonicalJson({ ...unsigned, signature: signBytes(message, key.privateKey) }),
    notes:
      "Pins the signing input to the unsigned envelope. A signer that got this wrong would " +
      "produce attestations no evaluator could verify, so this is a signer-conformance vector.",
  });
}

// ── Noncanonical wire encodings. Byte-level, so these are built as text.
{
  const { envelope, wire } = sign(buildUnsigned({ payload: buildPayload() }));

  // Reversed key order, built by re-inserting keys in descending order rather
  // than by string slicing: the envelope contains both "signature" and
  // "signatureProfile", and other keys sort after both, so an index-based splice
  // silently drops fields instead of reordering them.
  const descending = {};
  for (const field of Object.keys(envelope).sort().reverse()) {
    descending[field] = envelope[field];
  }

  for (const [name, text, description, note] of [
    ["noncanonical-pretty-printed", JSON.stringify(JSON.parse(wire), null, 2),
      "Indented human-readable JSON with identical semantic content.", undefined],
    ["noncanonical-trailing-newline", `${wire}\n`,
      "Canonical bytes plus a single trailing newline.",
      "The likeliest accidental failure: any tool that writes a text file politely."],
    ["noncanonical-leading-whitespace", ` ${wire}`,
      "Canonical bytes with one leading space.", undefined],
    ["noncanonical-bom-prefix", `﻿${wire}`,
      "UTF-8 byte-order mark prefixed to canonical bytes.",
      "Rejected during byte decoding, before any parsing."],
    ["noncanonical-key-order", JSON.stringify(descending),
      "Identical fields and values, keys in descending rather than ascending order.", undefined],
    ["noncanonical-duplicate-key", `${wire.slice(0, -1)},"scope":"activation"}`,
      'A second "scope" key appended after the canonical body.',
      "The most dangerous encoding vector. JSON.parse silently keeps the LAST duplicate, so a " +
        "lenient parser reads scope=activation while the signature only ever covered " +
        "scope=evaluation_only. Canonical-byte comparison is what closes this."],
  ]) {
    emitInvalid({
      name,
      description,
      attackClass: "noncanonical-encoding",
      expectedCode: "ATTESTATION_NONCANONICAL",
      wire: text,
      notes: note,
    });
  }
}

// ── Oversize: must be rejected on byte length BEFORE parsing.
emitInvalid({
  name: "oversize-before-parse",
  description: `Wire exceeds the ${MAX_BYTES}-byte ceiling. Deliberately not schema-valid.`,
  attackClass: "resource-exhaustion",
  expectedCode: "ATTESTATION_TOO_LARGE",
  wire: canonicalJson({ filler: "x".repeat(MAX_BYTES + 64) }),
  notes:
    "Contract rule: enforce the byte limit before parsing. Rejection must not require parsing " +
    "an attacker-sized document, so this vector needs no valid envelope at all.",
});

// ── Malformed input that must not reach the schema.
emitInvalid({
  name: "not-json",
  description: "Plain text that is not JSON at all.",
  attackClass: "malformed-input",
  expectedCode: "ATTESTATION_JSON_INVALID",
  wire: "this is not an attestation",
});

emitInvalid({
  name: "json-scalar-not-object",
  description: "Valid canonical JSON that is a bare string rather than an envelope object.",
  attackClass: "malformed-input",
  expectedCode: "ATTESTATION_SCHEMA_INVALID",
  wire: '"evaluation_only"',
});

// ── Emit ────────────────────────────────────────────────────────────────────
rmSync(join(ROOT, "vectors"), { recursive: true, force: true });
mkdirSync(join(ROOT, "vectors", "valid"), { recursive: true });
mkdirSync(join(ROOT, "vectors", "invalid"), { recursive: true });
mkdirSync(join(ROOT, "keys"), { recursive: true });
mkdirSync(join(ROOT, "golden"), { recursive: true });

const write = (path, value) =>
  writeFileSync(join(ROOT, path), `${JSON.stringify(value, null, 2)}\n`, "utf8");

for (const vector of valid) write(join("vectors", "valid", `${vector.name}.json`), vector);
for (const vector of invalid) write(join("vectors", "invalid", `${vector.name}.json`), vector);

write(join("keys", "dev-signer.public.json"), {
  WARNING:
    "TEST KEY ONLY. The private half is a hardcoded constant in lib/signer.mjs and is public " +
    "to anyone who can read this repository. Never pin this key in a deployed evaluator.",
  keyId: key.keyId,
  algorithm: "ed25519",
  publicKeySpkiDerHex: key.spkiDer.toString("hex"),
  publicKeyFingerprintSha256: key.fingerprintSha256,
  verifierPolicySha256: VERIFIER_POLICY_SHA256,
  usage:
    "validateMarketplaceAttestationTrust({ keyId, publicKeySpkiDer: " +
    "Buffer.from(publicKeySpkiDerHex, 'hex'), publicKeyFingerprintSha256, verifierPolicySha256 })",
});

write(join("golden", "signing-bytes.json"), {
  purpose:
    "Locks the exact signing bytes required by EVALUATION_ATTESTATION_V2.md before the real " +
    "signer service is deployed. Produced by an INDEPENDENT canonicalizer (lib/canonical.mjs), " +
    "not by marketplace-core. Any signer implementation, in any language, must reproduce these " +
    "digests exactly or its signatures will be rejected.",
  signingDomain: SIGNING_DOMAIN,
  signingDomainHex: Buffer.from(SIGNING_DOMAIN, "utf8").toString("hex"),
  construction:
    "ed25519(privateKey, utf8(signingDomain) || utf8(canonicalJson(unsignedEnvelope)))",
  keyId: key.keyId,
  publicKeyFingerprintSha256: key.fingerprintSha256,
  mandateSha256: MANDATE_SHA256,
  vectors: golden,
});

const byAttackClass = {};
for (const vector of invalid) {
  byAttackClass[vector.attackClass] = (byAttackClass[vector.attackClass] ?? 0) + 1;
}

write("manifest.json", {
  generatedFrom: "fixtures/attestations/lib/build.mjs",
  contract: "tools/marketplace-core/EVALUATION_ATTESTATION_V2.md",
  deterministic: true,
  keyId: key.keyId,
  publicKeyFingerprintSha256: key.fingerprintSha256,
  timeAnchor: {
    issuedAt: T0,
    evidenceObservedAt: OBSERVED,
    quoteExpiresAt: QUOTE_EXPIRES,
    maxClockSkewSeconds: SKEW,
  },
  counts: { valid: valid.length, invalid: invalid.length, byAttackClass },
});

console.log(`valid vectors:   ${String(valid.length).padStart(3)}`);
console.log(`invalid vectors: ${String(invalid.length).padStart(3)}`);
for (const [attackClass, count] of Object.entries(byAttackClass)) {
  console.log(`    ${attackClass.padEnd(26)} ${count}`);
}
console.log(`\ndev key fingerprint: ${key.fingerprintSha256}`);
console.log(`mandate sha256:      ${MANDATE_SHA256}`);
console.log(`baseline signing bytes sha256: ${golden[0].signingMessageSha256}`);
