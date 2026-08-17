import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { createMarketplaceCoreV2 } from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "../src/errors.js";
import {
  buildDisplaySafeProjectionPayload,
  createMarketplaceAttestationSigner,
} from "../src/issuer.js";
import { createMarketplaceVerifierRuntime } from "../src/runtime.js";
import {
  ISSUED_AT,
  VERIFIER_POLICY_SHA256,
  fixtureRequest,
  fixtureSuccess,
  refreshArtifactCommitments,
} from "./fixture.js";
import {
  brandedVerifierFixture,
  verifierInvocationFixture,
  verifierPolicySha256ForInvocation,
} from "./verifier-fixture.js";

function signerOptions(overrides: Readonly<Record<string, unknown>> = {}) {
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateKeyPkcs8Der = privateKey.export({
    format: "der",
    type: "pkcs8",
  });
  assert.ok(Buffer.isBuffer(privateKeyPkcs8Der));
  return {
    keyId: "verifier-service-test-1",
    privateKeyPkcs8Der,
    verifierPolicySha256: VERIFIER_POLICY_SHA256,
    clock: () => ISSUED_AT,
    randomUUID: () => "018f4f5e-7d2d-7d6b-8fb8-35c1b79275a1",
    ...overrides,
  };
}

test("a genuine verifier success signs decimal and Unicode evidence accepted by Core", async () => {
  const fixture = await brandedVerifierFixture();
  const signer = createMarketplaceAttestationSigner(
    signerOptions({ verifierPolicySha256: fixture.verifierPolicySha256 }),
  );
  const issued = signer.issueVerified(fixture.request, fixture.result);

  assert.equal(issued.wire.endsWith("\n"), false);
  assert.equal(issued.attestation.scope, "evaluation_only");
  assert.equal(issued.attestation.activationAuthorization, "none");
  assert.equal(issued.attestation.reservation, "none");
  assert.equal(issued.attestation.replayPolicy, "reusable_until_expiry");
  assert.equal(issued.attestation.expiresAt, ISSUED_AT + 300);
  assert.equal(
    JSON.stringify(issued).includes(
      fixture.request.candidate.transactionPlan.data,
    ),
    false,
  );
  assert.equal("artifact" in issued, false);
  assert.ok(Object.isFrozen(issued));
  assert.ok(Object.isFrozen(issued.payload));

  const core = createMarketplaceCoreV2({
    attestationTrust: signer.pinnedTrust,
    maxClockSkewSeconds: 30,
    clock: () => ISSUED_AT + 1,
  });
  const evaluation = core.evaluateMarketplaceV2({
    mandate: issued.mandate,
    attestations: [issued.wire],
  });
  assert.equal(evaluation.quotes.length, 1);
  assert.equal(evaluation.decisions.length, 1);
  assert.equal(evaluation.receipt.evaluatedAt, ISSUED_AT + 1);
});

test("pinned trust returns defensive public-key copies", () => {
  const signer = createMarketplaceAttestationSigner(signerOptions());
  const first = signer.pinnedTrust;
  const original = first.publicKeySpkiDer[0];
  first.publicKeySpkiDer[0] = (original ?? 0) ^ 0xff;
  const second = signer.pinnedTrust;
  assert.equal(second.publicKeySpkiDer[0], original);
});

test("the signer rejects forged, cloned, and tampered verifier results", async () => {
  const fixture = await brandedVerifierFixture();
  const signer = createMarketplaceAttestationSigner(
    signerOptions({ verifierPolicySha256: fixture.verifierPolicySha256 }),
  );
  const cloned = structuredClone(fixture.result);
  assert.throws(
    () => signer.issueVerified(fixture.request, cloned),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ARTIFACT_INTEGRITY_INVALID",
  );

  const divergent = fixture.result as unknown as {
    preview: { snapshot: { pool: { currentTick: number } } };
  };
  divergent.preview.snapshot.pool.currentTick += 1;
  assert.throws(
    () => signer.issueVerified(fixture.request, fixture.result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ARTIFACT_INTEGRITY_INVALID",
  );

  const freshFixture = await brandedVerifierFixture();
  const tampered = structuredClone(
    freshFixture.result,
  ) as typeof freshFixture.result;
  (tampered.artifact as { prospectiveReplayKey: string }).prospectiveReplayKey =
    "d".repeat(64);
  assert.throws(
    () => signer.issueVerified(freshFixture.request, tampered),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ARTIFACT_INTEGRITY_INVALID",
  );
});

test("the signer captures its issuance clock and rejects future evidence", async () => {
  const fixture = await brandedVerifierFixture();
  const mutableOptions = signerOptions({
    verifierPolicySha256: fixture.verifierPolicySha256,
  });
  const signer = createMarketplaceAttestationSigner(mutableOptions);
  mutableOptions.clock = () => ISSUED_AT + 1_000;
  const issued = signer.issueVerified(fixture.request, fixture.result);
  assert.equal(issued.attestation.issuedAt, ISSUED_AT);

  const earlySigner = createMarketplaceAttestationSigner(
    signerOptions({
      verifierPolicySha256: fixture.verifierPolicySha256,
      clock: () => ISSUED_AT - 1,
    }),
  );
  assert.throws(
    () => earlySigner.issueVerified(fixture.request, fixture.result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError && error.code === "CLOCK_INVALID",
  );
});

test("policy mismatch and expired evidence fail before signing", async () => {
  const fixture = await brandedVerifierFixture();
  const wrongPolicySigner = createMarketplaceAttestationSigner(
    signerOptions({ verifierPolicySha256: "cc".repeat(32) }),
  );
  assert.throws(
    () => wrongPolicySigner.issueVerified(fixture.request, fixture.result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "VERIFIER_POLICY_MISMATCH",
  );

  const expiredSigner = createMarketplaceAttestationSigner(
    signerOptions({
      verifierPolicySha256: fixture.verifierPolicySha256,
      clock: () => ISSUED_AT + 601,
    }),
  );
  assert.throws(
    () => expiredSigner.issueVerified(fixture.request, fixture.result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ATTESTATION_EXPIRY_INVALID",
  );
});

test("candidate and transaction-plan mismatches fail before signing", async () => {
  const fixture = await brandedVerifierFixture();
  const signer = createMarketplaceAttestationSigner(
    signerOptions({ verifierPolicySha256: fixture.verifierPolicySha256 }),
  );
  assert.throws(
    () =>
      signer.issueVerified(
        {
          ...fixture.request,
          candidate: {
            ...fixture.request.candidate,
            selector: { chainId: 56, tokenId: "2" },
          },
        },
        fixture.result,
      ),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ARTIFACT_MISMATCH",
  );

  assert.throws(
    () =>
      signer.issueVerified(
        {
          ...fixture.request,
          candidate: {
            ...fixture.request.candidate,
            transactionPlan: {
              ...fixture.request.candidate.transactionPlan,
              from: "0x2222222222222222222222222222222222222222",
            },
          },
        },
        fixture.result,
      ),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ARTIFACT_INTEGRITY_INVALID",
  );
});

test("unsafe preview block numbers fail closed during projection mapping", () => {
  const request = fixtureRequest();
  const result = structuredClone(fixtureSuccess(request));
  const unsafeBlock = (BigInt(Number.MAX_SAFE_INTEGER) + 1n).toString();
  const mutable = result as unknown as {
    preview: { snapshot: { pin: { observedBlockNumber: string } } };
    artifact: {
      evidence: {
        preview: {
          freshSnapshot: {
            snapshot: { pin: { observedBlockNumber: string } };
          };
        };
      };
    };
  };
  mutable.preview.snapshot.pin.observedBlockNumber = unsafeBlock;
  mutable.artifact.evidence.preview.freshSnapshot.snapshot.pin.observedBlockNumber =
    unsafeBlock;
  refreshArtifactCommitments(result);

  assert.throws(
    () => buildDisplaySafeProjectionPayload(request, result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError && error.code === "MAPPING_FAILED",
  );
});

test("the public runtime has no generic artifact-signing method", async () => {
  let attestationIds = 0;
  const transport = {
    async request(): Promise<never> {
      throw new Error("test transport unavailable");
    },
  };
  const verifier = verifierInvocationFixture(transport);
  const runtime = createMarketplaceVerifierRuntime({
    ...signerOptions({
      verifierPolicySha256: verifierPolicySha256ForInvocation(verifier),
      randomUUID: () => {
        attestationIds += 1;
        return "018f4f5e-7d2d-7d6b-8fb8-35c1b79275a1";
      },
    }),
    verifier,
  });
  assert.equal("issue" in runtime, false);
  assert.equal("issueVerified" in runtime, false);

  await assert.rejects(
    runtime.evaluateAndAttest({
      request: fixtureRequest(),
      artifact: fixtureSuccess().artifact,
    } as never),
    (error: unknown) =>
      error instanceof MarketplaceServiceError && error.code === "REQUEST_INVALID",
  );

  const result = await runtime.evaluateAndAttest({ request: fixtureRequest() });
  assert.equal(result.outcome, "not_attested");
  assert.equal(attestationIds, 0);
});

test("runtime detaches nested verifier configuration and transport methods", async () => {
  let originalCalls = 0;
  let replacementCalls = 0;
  const originalTransport = {
    async request(): Promise<never> {
      originalCalls += 1;
      throw new Error("original transport unavailable");
    },
  };
  const verifier = verifierInvocationFixture(originalTransport);
  const runtime = createMarketplaceVerifierRuntime({
    ...signerOptions({
      verifierPolicySha256: verifierPolicySha256ForInvocation(verifier),
    }),
    verifier,
  });

  const mutable = verifier as unknown as {
    manifest: { candidates: Array<{ expectedName: string }> };
    passiveReport: { candidates: Array<{ expectedName: string }> };
    trustFile: { candidates: Array<{ quoteEndpoint: string }> };
    now: () => Date;
    transport: { request: (route: unknown) => Promise<never> };
  };
  mutable.manifest.candidates[0]!.expectedName = "mutated manifest";
  mutable.passiveReport.candidates[0]!.expectedName = "mutated report";
  mutable.trustFile.candidates[0]!.quoteEndpoint = "https://evil.example/";
  mutable.now = () => new Date((ISSUED_AT + 10_000) * 1_000);
  mutable.transport.request = async () => {
    replacementCalls += 1;
    throw new Error("replacement transport must stay unused");
  };

  const result = await runtime.evaluateAndAttest({ request: fixtureRequest() });
  assert.equal(result.outcome, "not_attested");
  assert.equal(originalCalls, 1);
  assert.equal(replacementCalls, 0);
});

test("runtime rejects accessor-based verifier configuration", () => {
  const transport = {
    async request(): Promise<never> {
      throw new Error("unused");
    },
  };
  const verifier = verifierInvocationFixture(transport);
  const accessorVerifier = Object.create(null) as Record<string, unknown>;
  for (const key of [
    "now",
    "passiveReport",
    "randomUUID",
    "transport",
    "trustFile",
  ]) {
    Object.defineProperty(accessorVerifier, key, {
      enumerable: true,
      value: (verifier as Record<string, unknown>)[key],
    });
  }
  Object.defineProperty(accessorVerifier, "manifest", {
    enumerable: true,
    get: () => verifier.manifest,
  });
  assert.throws(
    () =>
      createMarketplaceVerifierRuntime({
        ...signerOptions({
          verifierPolicySha256: verifierPolicySha256ForInvocation(verifier),
        }),
        verifier: accessorVerifier as never,
      }),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "VERIFIER_CONFIGURATION_INVALID",
  );
});

test("runtime rejects a policy hash that does not match fixed verifier inputs", () => {
  const verifier = verifierInvocationFixture({
    async request(): Promise<never> {
      throw new Error("unused");
    },
  });
  assert.throws(
    () =>
      createMarketplaceVerifierRuntime({
        ...signerOptions({ verifierPolicySha256: "cc".repeat(32) }),
        verifier,
      }),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "VERIFIER_CONFIGURATION_INVALID",
  );
});
