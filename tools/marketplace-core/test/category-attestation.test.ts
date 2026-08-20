import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";

import {
  MARKETPLACE_CATEGORY_ATTESTATION_AUDIENCE,
  MARKETPLACE_CATEGORY_ATTESTATION_EVIDENCE_MODE,
  MARKETPLACE_CATEGORY_ATTESTATION_ISSUER,
  MARKETPLACE_CATEGORY_ATTESTATION_SCHEMA,
  MARKETPLACE_CATEGORY_ATTESTATION_SIGNATURE_PROFILE,
  MARKETPLACE_CATEGORY_CONDITION_RECEIPT_SCHEMA,
  canonicalSha256,
  createMarketplaceCategoryConditionEvaluator,
  marketplaceCategoryAttestationSigningMessage,
  marketplaceCategoryEvaluationRequestSchema,
  serializeMarketplaceCategoryAttestation,
  type MarketplaceCategoryAttestationUnsigned,
} from "../src/index.js";

const BLOCK_HASH = "0x" + "ab".repeat(32);
const DEPLOYMENT_HASH = "11".repeat(32);
const POLICY_HASH = "22".repeat(32);
const ARTIFACT_HASH = "33".repeat(32);
const EVIDENCE_HASH = "44".repeat(32);

test("category condition evaluator verifies a bound grid attestation", () => {
  const request = makeRequest("grid");
  const keyPair = generateKeyPairSync("ed25519");
  const publicKeySpkiDer = keyPair.publicKey.export({
    format: "der",
    type: "spki",
  });
  assert.ok(Buffer.isBuffer(publicKeySpkiDer));
  const unsigned = makeUnsigned(request);
  const signature = sign(
    null,
    marketplaceCategoryAttestationSigningMessage(unsigned),
    keyPair.privateKey,
  ).toString("hex");
  const attestation = {
    ...unsigned,
    signature,
  };
  const wire = serializeMarketplaceCategoryAttestation(attestation);

  const evaluator = createMarketplaceCategoryConditionEvaluator({
    attestationTrust: {
      keyId: "category-test-key",
      publicKeySpkiDer: Uint8Array.from(publicKeySpkiDer),
      publicKeyFingerprintSha256: sha256Bytes(publicKeySpkiDer),
      verifierPolicySha256: POLICY_HASH,
      categoryDeploymentSha256: DEPLOYMENT_HASH,
    },
    maxClockSkewSeconds: 30,
    clock: () => 1_120,
  });
  const receipt = evaluator.evaluateCategoryCondition({
    request,
    attestation: wire,
  });

  assert.equal(receipt.schema, MARKETPLACE_CATEGORY_CONDITION_RECEIPT_SCHEMA);
  assert.equal(receipt.status, "category_condition_satisfied");
  assert.equal(receipt.adapterId, "pancakeswap-v3-grid-v1");
  assert.deepEqual(receipt.candidate, { chainId: 56, tokenId: "7" });
  assert.equal(receipt.scope, "evaluation_only");
  assert.equal(receipt.activationAuthorization, "none");
  assert.equal(receipt.reservation, "none");
  assert.equal(receipt.evidenceMode, "verifier_commitment_only");
  assert.equal(receipt.replayPolicy, "reusable_until_expiry");
  assert.equal(receipt.replayScope, "request_id");
  assert.equal(receipt.issuedAt, 1_100);
  assert.equal(receipt.expiresAt, 1_300);
  assert.equal(receipt.validUntil, 1_300);
  assert.equal(receipt.requestId, request.requestId);
  assert.equal(receipt.mandateId, request.mandate.mandateId);
  assert.equal(receipt.category, "grid");
  assert.equal(receipt.evidenceSchema, request.evidenceSchema);
  assert.equal(receipt.protocol, request.protocol);
  assert.equal(receipt.deploymentSha256, DEPLOYMENT_HASH);
  assert.equal(receipt.verifierPolicySha256, POLICY_HASH);
  assert.equal(receipt.artifactSha256, ARTIFACT_HASH);
  assert.equal(receipt.evidenceSha256, EVIDENCE_HASH);
  assert.equal(receipt.observedAt, 1_100);
  assert.equal(receipt.observedBlock, 123);
  assert.equal(receipt.observedBlockHash, BLOCK_HASH);
  assert.equal(receipt.evaluatedAt, 1_120);
  assert.equal(receipt.attestationSha256, canonicalSha256(attestation));
  assert.equal(Object.isFrozen(receipt), true);
  assert.equal(Object.isFrozen(receipt.candidate), true);
});

test("category receipt validity is exclusive and reusable wire re-enters Core time", () => {
  const request = makeRequest("grid", { maxEvidenceAgeSeconds: 50 });
  const keyPair = generateKeyPairSync("ed25519");
  const wire = serializeSigned(makeUnsigned(request), keyPair);
  const trust = makeTrust(keyPair);

  const atLastFreshSecond = createMarketplaceCategoryConditionEvaluator({
    attestationTrust: trust,
    maxClockSkewSeconds: 30,
    clock: () => 1_150,
  }).evaluateCategoryCondition({ request, attestation: wire });
  assert.equal(atLastFreshSecond.evaluatedAt, 1_150);
  assert.equal(atLastFreshSecond.expiresAt, 1_300);
  assert.equal(atLastFreshSecond.validUntil, 1_151);

  const replayed = createMarketplaceCategoryConditionEvaluator({
    attestationTrust: trust,
    maxClockSkewSeconds: 30,
    clock: () => 1_149,
  }).evaluateCategoryCondition({ request, attestation: wire });
  assert.equal(replayed.evaluatedAt, 1_149);
  assert.equal(replayed.validUntil, 1_151);
  assert.equal(replayed.attestationSha256, atLastFreshSecond.attestationSha256);

  assertCoreError(
    () =>
      createMarketplaceCategoryConditionEvaluator({
        attestationTrust: trust,
        maxClockSkewSeconds: 30,
        clock: () => 1_151,
      }).evaluateCategoryCondition({ request, attestation: wire }),
    "CATEGORY_ATTESTATION_EVIDENCE_STALE",
  );
});

test("category evaluation enforces mandate, observation, and expiry boundaries", () => {
  const request = makeRequest("grid");
  const keyPair = generateKeyPairSync("ed25519");
  const trust = makeTrust(keyPair);

  const preMandate = makeUnsigned(request);
  assertCoreError(
    () =>
      evaluateCategoryAt(
        request,
        serializeSigned(
          {
            ...preMandate,
            payload: { ...preMandate.payload, observedAt: 999 },
          },
          keyPair,
        ),
        trust,
        1_120,
      ),
    "CATEGORY_ATTESTATION_EVIDENCE_STALE",
  );

  const afterIssuance = makeUnsigned(request);
  assertCoreError(
    () =>
      evaluateCategoryAt(
        request,
        serializeSigned(
          {
            ...afterIssuance,
            payload: { ...afterIssuance.payload, observedAt: 1_101 },
          },
          keyPair,
        ),
        trust,
        1_120,
      ),
    "ATTESTATION_OBSERVATION_AFTER_ISSUANCE",
  );

  const beforeMandateEvaluation = makeUnsigned(request);
  assertCoreError(
    () =>
      evaluateCategoryAt(
        request,
        serializeSigned(
          {
            ...beforeMandateEvaluation,
            issuedAt: 1_000,
            payload: {
              ...beforeMandateEvaluation.payload,
              observedAt: 1_000,
            },
          },
          keyPair,
        ),
        trust,
        999,
      ),
    "EVALUATED_AT_INVALID",
  );

  const futureObservation = makeUnsigned(request);
  assertCoreError(
    () =>
      evaluateCategoryAt(
        request,
        serializeSigned(
          {
            ...futureObservation,
            issuedAt: 1_151,
            payload: { ...futureObservation.payload, observedAt: 1_151 },
          },
          keyPair,
        ),
        trust,
        1_120,
        300,
      ),
    "ATTESTATION_NOT_YET_VALID",
  );

  const wire = serializeSigned(makeUnsigned(request), keyPair);
  assert.equal(evaluateCategoryAt(request, wire, trust, 1_299).evaluatedAt, 1_299);
  assertCoreError(
    () => evaluateCategoryAt(request, wire, trust, 1_300),
    "ATTESTATION_EXPIRED",
  );
});

test("category requests distinguish the two health adapter IDs", () => {
  const aave = makeRequest("aave");
  const venus = makeRequest("venus");
  assert.equal(aave.category, "health");
  assert.equal(aave.adapterId, "aave-v3-health-v1");
  assert.equal(venus.category, "health");
  assert.equal(venus.adapterId, "venus-health-v1");
  assert.notEqual(aave.evidenceSchema, venus.evidenceSchema);
});

test("category attestation rejects a request or subject swap", () => {
  const request = makeRequest("grid");
  const unsigned = makeUnsigned(request);
  const keyPair = generateKeyPairSync("ed25519");
  const wire = serializeSigned(unsigned, keyPair);
  const trust = makeTrust(keyPair);
  const evaluator = createMarketplaceCategoryConditionEvaluator({
    attestationTrust: trust,
    maxClockSkewSeconds: 30,
    clock: () => 1_120,
  });

  const changedCandidate = {
    ...request,
    candidate: { ...request.candidate, tokenId: "8" },
  };
  assert.throws(
    () =>
      evaluator.evaluateCategoryCondition({
        request: changedCandidate,
        attestation: wire,
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "CATEGORY_ATTESTATION_REQUEST_HASH_MISMATCH",
  );

  const changedSubjectUnsigned = {
    ...unsigned,
    payload: {
      ...unsigned.payload,
      subjectSha256: "55".repeat(32),
    },
  };
  const changedSubjectWire = serializeSigned(changedSubjectUnsigned, keyPair);
  assert.throws(
    () =>
      evaluator.evaluateCategoryCondition({
        request,
        attestation: changedSubjectWire,
      }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "CATEGORY_ATTESTATION_SUBJECT_MISMATCH",
  );
});

function makeRequest(
  adapter: "grid" | "aave" | "venus",
  overrides: Readonly<{ maxEvidenceAgeSeconds?: number }> = {},
): ReturnType<typeof marketplaceCategoryEvaluationRequestSchema.parse> {
  const raw = {
    schema: "mandatex.marketplace.mandate.v1",
    mandateId: "category-mandate",
    category: adapter === "grid" ? "grid" : "health",
    chainId: 56,
    createdAt: 1_000,
    expiresAt: 2_000,
    maxClockSkewSeconds: 30,
    maxEvidenceAgeSeconds: overrides.maxEvidenceAgeSeconds ?? 300,
    maxPreviewAgeSeconds: 300,
    budgets: {
      maxAgentFeeUsdMicros: "0",
      maxGasUsdMicros: "50",
      maxSlippageBps: 50,
      maxExposureUsdMicros: "1000000",
    },
    permissions: {
      allowedProtocols: ["pancakeswap-v3"],
      allowedContracts: ["0x4444444444444444444444444444444444444444"],
      allowedCalls: ["read"],
      maxSpendUsdMicros: "1000000",
      expiresAt: 1_900,
    },
  };
  const candidate = {
    chainId: 56 as const,
    tokenId: "7",
    owner: "0x1111111111111111111111111111111111111111",
    publisher: "0x2222222222222222222222222222222222222222",
    taskInterface: "a2a" as const,
  };
  if (adapter === "grid") {
    return marketplaceCategoryEvaluationRequestSchema.parse({
      schema: "mandatex.marketplace.category-evaluation-request.v1",
      requestId: "category-request",
      mandate: raw,
      candidate,
      adapterId: "pancakeswap-v3-grid-v1",
      category: "grid",
      evidenceSchema: "mandatex.category.grid-evidence.v1",
      protocol: "pancakeswap-v3",
      subject: { poolAddress: "0x3333333333333333333333333333333333333333" },
      policy: { lowerTick: -100, upperTick: 100 },
    });
  }
  if (adapter === "aave") {
    return marketplaceCategoryEvaluationRequestSchema.parse({
      schema: "mandatex.marketplace.category-evaluation-request.v1",
      requestId: "category-request",
      mandate: { ...raw, category: "health" },
      candidate,
      adapterId: "aave-v3-health-v1",
      category: "health",
      evidenceSchema: "mandatex.category.health-evidence.v1",
      protocol: "aave-v3",
      subject: {
        poolAddress: "0x3333333333333333333333333333333333333333",
        accountAddress: "0x4444444444444444444444444444444444444444",
      },
      policy: { minHealthFactorScaled: "1100000000000000000" },
    });
  }
  return marketplaceCategoryEvaluationRequestSchema.parse({
    schema: "mandatex.marketplace.category-evaluation-request.v1",
    requestId: "category-request",
    mandate: { ...raw, category: "health" },
    candidate,
    adapterId: "venus-health-v1",
    category: "health",
    evidenceSchema: "mandatex.category.venus-health-evidence.v1",
    protocol: "venus",
    subject: {
      comptrollerAddress: "0x3333333333333333333333333333333333333333",
      accountAddress: "0x4444444444444444444444444444444444444444",
      borrowMarketAddress: "0x5555555555555555555555555555555555555555",
    },
    policy: { minLiquidityUsdScaled: "1000" },
  });
}

function makeUnsigned(
  request: ReturnType<typeof marketplaceCategoryEvaluationRequestSchema.parse>,
): MarketplaceCategoryAttestationUnsigned {
  return {
    schema: MARKETPLACE_CATEGORY_ATTESTATION_SCHEMA,
    signatureProfile: MARKETPLACE_CATEGORY_ATTESTATION_SIGNATURE_PROFILE,
    issuer: MARKETPLACE_CATEGORY_ATTESTATION_ISSUER,
    audience: MARKETPLACE_CATEGORY_ATTESTATION_AUDIENCE,
    keyId: "category-test-key",
    attestationId: "category-attestation",
    scope: "evaluation_only",
    activationAuthorization: "none",
    reservation: "none",
    replayPolicy: "reusable_until_expiry",
    replayScope: "request_id",
    evidenceMode: MARKETPLACE_CATEGORY_ATTESTATION_EVIDENCE_MODE,
    issuedAt: 1_100,
    expiresAt: 1_300,
    mandateSha256: canonicalSha256(request.mandate),
    requestSha256: canonicalSha256(request),
    verifierPolicySha256: POLICY_HASH,
    payload: {
      schema: "mandatex.marketplace.category-condition-payload.v1",
      requestId: request.requestId,
      mandateId: request.mandate.mandateId,
      category: request.category,
      candidate: {
        chainId: request.candidate.chainId,
        tokenId: request.candidate.tokenId,
      },
      adapterId: request.adapterId,
      evidenceSchema: request.evidenceSchema,
      protocol: request.protocol,
      subjectSha256: canonicalSha256(request.subject),
      policySha256: canonicalSha256(request.policy),
      deploymentSha256: DEPLOYMENT_HASH,
      artifactSha256: ARTIFACT_HASH,
      evidenceSha256: EVIDENCE_HASH,
      observedAt: 1_100,
      observedBlock: 123,
      observedBlockHash: BLOCK_HASH,
      status: "pass",
    },
  };
}

function makeTrust(
  keyPair: Readonly<{ publicKey: KeyObject; privateKey: KeyObject }>,
) {
  const der = keyPair.publicKey.export({ format: "der", type: "spki" });
  assert.ok(Buffer.isBuffer(der));
  return {
    keyId: "category-test-key",
    publicKeySpkiDer: Uint8Array.from(der),
    publicKeyFingerprintSha256: sha256Bytes(der),
    verifierPolicySha256: POLICY_HASH,
    categoryDeploymentSha256: DEPLOYMENT_HASH,
  };
}

function serializeSigned(
  unsigned: MarketplaceCategoryAttestationUnsigned,
  keyPair: Readonly<{ publicKey: KeyObject; privateKey: KeyObject }>,
): string {
  return serializeMarketplaceCategoryAttestation({
    ...unsigned,
    signature: sign(
      null,
      marketplaceCategoryAttestationSigningMessage(unsigned),
      keyPair.privateKey,
    ).toString("hex"),
  });
}

function sha256Bytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function evaluateCategoryAt(
  request: ReturnType<typeof marketplaceCategoryEvaluationRequestSchema.parse>,
  attestation: string,
  trust: ReturnType<typeof makeTrust>,
  evaluatedAt: number,
  maxClockSkewSeconds = 30,
) {
  return createMarketplaceCategoryConditionEvaluator({
    attestationTrust: trust,
    maxClockSkewSeconds,
    clock: () => evaluatedAt,
  }).evaluateCategoryCondition({ request, attestation });
}

function assertCoreError(operation: () => unknown, code: string): void {
  assert.throws(
    operation,
    (error: unknown) =>
      error instanceof Error && "code" in error && error.code === code,
  );
}
