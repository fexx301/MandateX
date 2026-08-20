import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  canonicalSha256,
  createMarketplaceCategoryConditionEvaluator,
  marketplaceCategoryEvaluationRequestSchema,
  type MarketplaceCategoryEvaluationRequest,
} from "@mandatex/marketplace-core";
import {
  validateTransportRoute,
  type BoundedHttpResponse,
  type TransportRoute,
} from "@mandatex/agent-supply-verifier";
import { encodeAbiParameters, parseAbiParameters, type Hex } from "viem";

import {
  createMarketplaceCategoryVerifierRuntime,
  marketplaceVerifierPolicyV2Sha256,
} from "../src/index.js";
import {
  createMarketplaceCategoryIssuer,
  type MarketplaceCategoryIssuerOptions,
} from "../src/category-issuer.js";
import { MarketplaceServiceError } from "../src/errors.js";
import {
  CATEGORY_ACCOUNT,
  CATEGORY_BORROW_MARKET,
  CATEGORY_COMPTROLLER,
  categoryDeployment,
} from "./category-fixture.js";

const POLICY_IDENTITY = Object.freeze({
  passivePolicyFingerprint: "aa".repeat(32),
  trustPolicySha256: "bb".repeat(32),
});
const ANCHOR_HASH = `0x${"c".repeat(64)}`;
const EVALUATED_AT = 1_725_000_000;
const REQUEST_CREATED_AT = EVALUATED_AT - 100;

test("Venus runtime -> private issuer -> signed wire is accepted by Core", async () => {
  const fixture = createFixture();
  const issued = await fixture.issuer.evaluateAndAttestCategory(fixture.request);

  assert.equal("status" in issued, false);
  if ("status" in issued) return;
  assert.equal(issued.attestation.payload.adapterId, "venus-health-v1");
  assert.equal(issued.attestation.payload.protocol, "venus");
  assert.equal(issued.attestation.payload.status, "pass");
  assert.equal(issued.attestation.issuedAt, EVALUATED_AT);
  assert.equal(issued.attestation.expiresAt, EVALUATED_AT + 300);
  assert.equal(issued.wire.endsWith("\n"), false);

  const evaluator = createMarketplaceCategoryConditionEvaluator({
    attestationTrust: fixture.trust,
    maxClockSkewSeconds: 30,
    clock: () => EVALUATED_AT + 1,
  });
  const receipt = evaluator.evaluateCategoryCondition({
    request: fixture.request,
    attestation: issued.wire,
  });

  assert.equal(receipt.status, "category_condition_satisfied");
  assert.equal(receipt.category, "health");
  assert.equal(receipt.adapterId, "venus-health-v1");
  assert.deepEqual(receipt.candidate, { chainId: 56, tokenId: "7" });
  assert.equal(receipt.requestId, fixture.request.requestId);

  const staleEvaluator = createMarketplaceCategoryConditionEvaluator({
    attestationTrust: fixture.trust,
    maxClockSkewSeconds: 30,
    clock: () => EVALUATED_AT + 111,
  });
  await assertCoreError(
    () =>
      staleEvaluator.evaluateCategoryCondition({
        request: fixture.request,
        attestation: issued.wire,
      }),
    "CATEGORY_ATTESTATION_EVIDENCE_STALE",
  );
});

test("production issuer evaluates a static-only deployment from the mandate scope", async () => {
  const fixture = createFixture({ staticOnly: true });
  const issued = await fixture.issuer.evaluateAndAttestCategory(fixture.request);
  assert.equal("status" in issued, false, JSON.stringify(issued));
  if ("status" in issued) return;
  assert.equal(issued.attestation.payload.adapterId, "venus-health-v1");
  assert.equal(issued.attestation.payload.subjectSha256, canonicalSha256(fixture.request.subject));
});

test("category issuer snapshots options and recursively freezes its result", async () => {
  const fixture = createFixture();
  const mutable = fixture.options as unknown as Record<string, unknown>;
  const originalKey = fixture.options.privateKeyPkcs8Der[0];
  const originalClock = fixture.options.clock;
  const originalUuid = fixture.options.randomUUID;

  mutable.clock = () => EVALUATED_AT + 200;
  mutable.randomUUID = () => "mutated-attestation-id";
  mutable.keyId = "mutated-key";
  mutable.verifierPolicySha256 = "dd".repeat(32);
  fixture.options.privateKeyPkcs8Der[0] = (originalKey ?? 0) ^ 0xff;
  const firstTrust = fixture.issuer.pinnedTrust;
  const publicKeyByte = firstTrust.publicKeySpkiDer[0];
  firstTrust.publicKeySpkiDer[0] = (publicKeyByte ?? 0) ^ 0xff;

  const issued = await fixture.issuer.evaluateAndAttestCategory(fixture.request);
  assert.equal("status" in issued, false);
  if ("status" in issued) return;
  assert.equal(issued.attestation.issuedAt, originalClock());
  assert.equal(issued.attestation.attestationId, originalUuid());
  assert.equal(issued.attestation.keyId, "category-test-key");
  assert.equal(
    fixture.issuer.pinnedTrust.publicKeySpkiDer[0],
    publicKeyByte,
  );
  assert.equal(Object.isFrozen(issued), true);
  assert.equal(Object.isFrozen(issued.request), true);
  assert.equal(Object.isFrozen(issued.request.mandate), true);
  assert.equal(Object.isFrozen(issued.request.mandate.permissions), true);
  assert.equal(
    Object.isFrozen(issued.request.mandate.permissions.allowedContracts),
    true,
  );
  assert.equal(Object.isFrozen(issued.request.candidate), true);
  assert.equal(Object.isFrozen(issued.request.subject), true);
  assert.equal(Object.isFrozen(issued.request.policy), true);
  assert.equal(Object.isFrozen(issued.attestation), true);
  assert.equal(Object.isFrozen(issued.attestation.payload), true);
  assert.equal(Object.isFrozen(issued.attestation.payload.candidate), true);
});

test("executed fail and unknown results fail closed before UUID generation", async () => {
  let failUuidCalls = 0;
  const failed = createFixture({
    transportOptions: { liquidity: 500n * 10n ** 18n },
    randomUUID: () => {
      failUuidCalls += 1;
      throw new Error("fail path must not request an attestation UUID");
    },
  });
  await assertServiceError(
    failed.issuer.evaluateAndAttestCategory(failed.request),
    "VERIFIER_EVALUATION_FAILED",
  );
  assert.equal(failUuidCalls, 0);

  let unknownUuidCalls = 0;
  const unknown = createFixture({
    transportOptions: { borrowBalance: 0n },
    randomUUID: () => {
      unknownUuidCalls += 1;
      throw new Error("unknown path must not request an attestation UUID");
    },
  });
  await assertServiceError(
    unknown.issuer.evaluateAndAttestCategory(unknown.request),
    "VERIFIER_EVALUATION_FAILED",
  );
  assert.equal(unknownUuidCalls, 0);
});

test("runtime inconclusive outcomes return not_attested before UUID generation", async () => {
  let unavailableUuidCalls = 0;
  const unavailable = createFixture({
    transportOptions: { chainId: "0x1" },
    randomUUID: () => {
      unavailableUuidCalls += 1;
      throw new Error("inconclusive path must not request an attestation UUID");
    },
  });
  const unavailableResult = await unavailable.issuer.evaluateAndAttestCategory(
    unavailable.request,
  );
  assert.equal("status" in unavailableResult, true);
  if ("status" in unavailableResult) {
    assert.equal(unavailableResult.status, "not_attested");
    assert.equal(unavailableResult.category, "health");
    assert.equal(unavailableResult.adapterId, "venus-health-v1");
    assert.equal(unavailableResult.code, "CATEGORY_BLOCK_PIN_UNAVAILABLE");
    assert.equal("wire" in unavailableResult, false);
    assert.equal(Object.isFrozen(unavailableResult), true);
  }
  assert.equal(unavailableUuidCalls, 0);

  let reorgUuidCalls = 0;
  const reorged = createFixture({
    transportOptions: { reorgOnFinalCheck: true },
    randomUUID: () => {
      reorgUuidCalls += 1;
      throw new Error("reorg path must not request an attestation UUID");
    },
  });
  const reorgResult = await reorged.issuer.evaluateAndAttestCategory(
    reorged.request,
  );
  assert.equal("status" in reorgResult, true);
  if ("status" in reorgResult) {
    assert.equal(reorgResult.status, "not_attested");
    assert.equal(reorgResult.code, "CATEGORY_BLOCK_NONCANONICAL");
    assert.equal("wire" in reorgResult, false);
  }
  assert.equal(reorgUuidCalls, 0);
});

test("issuer rejects stale, pre-mandate, and future evidence before signing", async () => {
  const stale = createFixture({
    request: makeRequest({ maxEvidenceAgeSeconds: 5 }),
  });
  await assertServiceError(
    stale.issuer.evaluateAndAttestCategory(stale.request),
    "ATTESTATION_EXPIRY_INVALID",
  );

  const preMandate = createFixture({
    request: makeRequest({ createdAt: EVALUATED_AT - 5 }),
  });
  await assertServiceError(
    preMandate.issuer.evaluateAndAttestCategory(preMandate.request),
    "ATTESTATION_EXPIRY_INVALID",
  );

  const future = createFixture({
    issuerClock: EVALUATED_AT - 20,
    runtimeClock: EVALUATED_AT - 20,
  });
  await assertServiceError(
    future.issuer.evaluateAndAttestCategory(future.request),
    "CLOCK_INVALID",
  );
});

test("issuer rejects invalid UUID and clock values", async () => {
  const invalidUuid = createFixture({ issuerUuid: "not-a-uuid" });
  await assertServiceError(
    invalidUuid.issuer.evaluateAndAttestCategory(invalidUuid.request),
    "ATTESTATION_SIGNER_INVALID",
  );

  const invalidClock = createFixture({ issuerClock: 0 });
  await assertServiceError(
    invalidClock.issuer.evaluateAndAttestCategory(invalidClock.request),
    "CLOCK_INVALID",
  );

  const throwingUuid = createFixture({
    randomUUID: () => {
      throw new Error("uuid unavailable");
    },
  });
  await assertServiceError(
    throwingUuid.issuer.evaluateAndAttestCategory(throwingUuid.request),
    "ATTESTATION_SIGNER_INVALID",
  );

  const throwingClock = createFixture({
    clock: () => {
      throw new Error("clock unavailable");
    },
  });
  await assertServiceError(
    throwingClock.issuer.evaluateAndAttestCategory(throwingClock.request),
    "CLOCK_INVALID",
  );
});

test("Core rejects a tampered signature and a request-bound candidate swap", async () => {
  const fixture = createFixture();
  const issued = await fixture.issuer.evaluateAndAttestCategory(fixture.request);
  assert.equal("status" in issued, false);
  if ("status" in issued) return;

  const evaluator = createMarketplaceCategoryConditionEvaluator({
    attestationTrust: fixture.trust,
    maxClockSkewSeconds: 30,
    clock: () => EVALUATED_AT + 1,
  });
  await assertCoreError(
    () =>
      evaluator.evaluateCategoryCondition({
        request: fixture.request,
        attestation: issued.wire.replace("{", "{ "),
      }),
    "ATTESTATION_NONCANONICAL",
  );

  const tamperedWire = issued.wire.replace(
    `"signature":"${issued.attestation.signature}"`,
    `"signature":"${issued.attestation.signature.slice(0, -1)}${issued.attestation.signature.endsWith("0") ? "1" : "0"}"`,
  );
  await assertCoreError(
    () =>
      evaluator.evaluateCategoryCondition({
        request: fixture.request,
        attestation: tamperedWire,
      }),
    "ATTESTATION_SIGNATURE_INVALID",
  );

  const changedRequest = makeRequest({ tokenId: "8" });
  await assertCoreError(
    () =>
      evaluator.evaluateCategoryCondition({
        request: changedRequest,
        attestation: issued.wire,
      }),
    "CATEGORY_ATTESTATION_REQUEST_HASH_MISMATCH",
  );
});

type FixtureOverrides = Readonly<{
  readonly request?: MarketplaceCategoryEvaluationRequest;
  readonly issuerClock?: number;
  readonly issuerUuid?: string;
  readonly runtimeClock?: number;
  readonly clock?: () => number;
  readonly randomUUID?: () => string;
  readonly transportOptions?: TransportOptions;
  readonly staticOnly?: boolean;
}>;

function createFixture(overrides: FixtureOverrides = {}) {
  const deployment = categoryDeployment();
  if (overrides.staticOnly) {
    for (const entry of deployment.adapters) {
      delete (entry as { configuration?: unknown }).configuration;
    }
  }
  const policyIdentity = {
    ...POLICY_IDENTITY,
    categoryAdapterDeployment: deployment,
  };
  const policySha256 = marketplaceVerifierPolicyV2Sha256(policyIdentity);
  const routes: TransportRoute[] = [];
  const runtime = createMarketplaceCategoryVerifierRuntime({
    policyIdentity,
    deployment,
    verifierPolicySha256: policySha256,
    transport: categoryTransport(routes, overrides.transportOptions),
    clock: () => overrides.runtimeClock ?? EVALUATED_AT,
    randomUUID: () => "category-runtime-test-id",
  });
  const keyPair = generateKeyPairSync("ed25519");
  const privateKeyPkcs8Der = keyPair.privateKey.export({
    format: "der",
    type: "pkcs8",
  });
  assert.ok(Buffer.isBuffer(privateKeyPkcs8Der));
  const options: MarketplaceCategoryIssuerOptions = {
    verifier: runtime,
    keyId: "category-test-key",
    privateKeyPkcs8Der: Uint8Array.from(privateKeyPkcs8Der),
    verifierPolicySha256: policySha256,
    categoryDeploymentSha256: runtime.deploymentSha256,
    clock: overrides.clock ?? (() => overrides.issuerClock ?? EVALUATED_AT),
    randomUUID:
      overrides.randomUUID ??
      (() => overrides.issuerUuid ?? "018f4f5e-7d2d-7d6b-8fb8-35c1b79275a1"),
  };
  const issuer = createMarketplaceCategoryIssuer(options);
  return {
    issuer,
    options,
    request: overrides.request ?? makeRequest(),
    trust: issuer.pinnedTrust,
    routes,
  };
}

function makeRequest(
  overrides: Readonly<{
    readonly createdAt?: number;
    readonly maxEvidenceAgeSeconds?: number;
    readonly tokenId?: string;
  }> = {},
): MarketplaceCategoryEvaluationRequest {
  return marketplaceCategoryEvaluationRequestSchema.parse({
    schema: "mandatex.marketplace.category-evaluation-request.v1",
    requestId: "issuer-category-request",
    mandate: {
      schema: "mandatex.marketplace.mandate.v1",
      mandateId: "issuer-category-mandate",
      category: "health",
      chainId: 56,
      createdAt: overrides.createdAt ?? REQUEST_CREATED_AT,
      expiresAt: EVALUATED_AT + 600,
      maxClockSkewSeconds: 30,
      maxEvidenceAgeSeconds: overrides.maxEvidenceAgeSeconds ?? 120,
      maxPreviewAgeSeconds: 300,
      budgets: {
        maxAgentFeeUsdMicros: "0",
        maxGasUsdMicros: "50000000",
        maxSlippageBps: 50,
        maxExposureUsdMicros: "1000000",
      },
      permissions: {
        allowedProtocols: ["venus"],
        allowedContracts: [CATEGORY_COMPTROLLER, CATEGORY_BORROW_MARKET],
        allowedCalls: ["read"],
        maxSpendUsdMicros: "1000000",
        expiresAt: EVALUATED_AT + 500,
      },
    },
    candidate: {
      chainId: 56,
      tokenId: overrides.tokenId ?? "7",
      owner: "0x1111111111111111111111111111111111111111",
      publisher: "0x2222222222222222222222222222222222222222",
      taskInterface: "a2a",
    },
    adapterId: "venus-health-v1",
    category: "health",
    evidenceSchema: "mandatex.category.venus-health-evidence.v1",
    protocol: "venus",
    subject: {
      comptrollerAddress: CATEGORY_COMPTROLLER,
      accountAddress: CATEGORY_ACCOUNT,
      borrowMarketAddress: CATEGORY_BORROW_MARKET,
    },
    policy: { minLiquidityUsdScaled: "1000000000000000000000" },
  });
}

async function assertServiceError(
  promise: Promise<unknown>,
  code: MarketplaceServiceError["code"],
): Promise<void> {
  await assert.rejects(
    promise,
    (error: unknown) =>
      error instanceof MarketplaceServiceError && error.code === code,
  );
}

async function assertCoreError(
  operation: () => unknown,
  code: string,
): Promise<void> {
  assert.throws(operation, (error: unknown) => {
    return error instanceof Error && "code" in error && error.code === code;
  });
}

type TransportOptions = Readonly<{
  readonly chainId?: string;
  readonly liquidity?: bigint;
  readonly borrowBalance?: bigint;
  readonly reorgOnFinalCheck?: boolean;
}>;

function categoryTransport(
  routes: TransportRoute[],
  options: TransportOptions = {},
) {
  let blockHeaderReads = 0;
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      validateTransportRoute(route);
      routes.push(route);
      if (route.kind !== "bsc-category-rpc") {
        throw new Error(`unexpected category route ${route.kind}`);
      }
      const request = JSON.parse(route.body) as {
        readonly id: string;
        readonly params: readonly unknown[];
      };
      let result: unknown;
      switch (route.purpose) {
        case "chain-id":
          result = options.chainId ?? "0x38";
          break;
        case "head-block-number":
          result = "0x66";
          break;
        case "block-header":
          blockHeaderReads += 1;
          result = {
            number: "0x64",
            hash:
              options.reorgOnFinalCheck && blockHeaderReads === 2
                ? `0x${"d".repeat(64)}`
                : ANCHOR_HASH,
            timestamp: `0x${(EVALUATED_AT - 10).toString(16)}`,
          };
          break;
        case "state-read": {
          const call = request.params[0] as { readonly data: string };
          switch (call.data.slice(0, 10)) {
            case "0x5ec88c79":
              result = encode("uint256,uint256,uint256", [
                0n,
                options.liquidity ?? 5_000n * 10n ** 18n,
                0n,
              ]);
              break;
            case "0xabfceffc":
              result = encode("address[]", [
                [
                  "0x7777777777777777777777777777777777777777",
                  "0x8888888888888888888888888888888888888888",
                ],
              ]);
              break;
            case "0x95dd9193":
              result = encode("uint256,uint256,uint256", [
                options.borrowBalance ?? 4_200n * 10n ** 18n,
                0n,
                0n,
              ]);
              break;
            default:
              throw new Error(`unexpected category selector ${call.data.slice(0, 10)}`);
          }
          break;
        }
      }
      return boundedJsonResponse({ jsonrpc: "2.0", id: request.id, result });
    },
  };
}

function encode(types: string, values: readonly unknown[]): Hex {
  return encodeAbiParameters(parseAbiParameters(types), values as never);
}

function boundedJsonResponse(value: unknown): BoundedHttpResponse {
  const body = Buffer.from(JSON.stringify(value));
  return {
    status: 200,
    contentType: "application/json",
    retryAfter: null,
    rateLimitRemaining: null,
    body,
    responseSha256: createHash("sha256").update(body).digest("hex"),
    resolvedAddress: "93.184.216.34",
    startedAt: new Date(EVALUATED_AT * 1_000).toISOString(),
    finishedAt: new Date(EVALUATED_AT * 1_000 + 10).toISOString(),
    latencyMs: 10,
  };
}
