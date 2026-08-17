import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { createMarketplaceCoreV2 } from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "../src/errors.js";
import { createMarketplaceAttestationSigner } from "../src/issuer.js";
import { createMarketplaceVerifierRuntime } from "../src/runtime.js";
import {
  ISSUED_AT,
  VERIFIER_POLICY_SHA256,
  fixtureRequest,
  fixtureSuccess,
  refreshArtifactCommitments,
} from "./fixture.js";

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

test("an immediate verifier success signs canonical v2 wire accepted by Core", () => {
  const signer = createMarketplaceAttestationSigner(signerOptions());
  const request = fixtureRequest();
  const issued = signer.issueVerified(request, fixtureSuccess(request));

  assert.equal(issued.wire.endsWith("\n"), false);
  assert.equal(issued.attestation.scope, "evaluation_only");
  assert.equal(issued.attestation.activationAuthorization, "none");
  assert.equal(issued.attestation.reservation, "none");
  assert.equal(issued.attestation.replayPolicy, "reusable_until_expiry");
  assert.equal(issued.attestation.expiresAt, ISSUED_AT + 300);
  assert.equal(
    JSON.stringify(issued).includes(request.candidate.transactionPlan.data),
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

test("recomputed artifact commitments cannot hide divergence from verifier success", () => {
  const signer = createMarketplaceAttestationSigner(signerOptions());
  const request = fixtureRequest();
  const result = structuredClone(fixtureSuccess(request));
  const mutable = result as unknown as {
    preview: { snapshot: unknown };
    artifact: {
      evidence: {
        preview: {
          freshSnapshot: {
            snapshot: { pool: { currentTick: number } };
          };
        };
      };
    };
  };
  mutable.artifact.evidence.preview.freshSnapshot.snapshot = structuredClone(
    mutable.preview.snapshot,
  ) as { pool: { currentTick: number } };
  mutable.artifact.evidence.preview.freshSnapshot.snapshot.pool.currentTick += 1;
  refreshArtifactCommitments(result);

  assert.throws(
    () => signer.issueVerified(request, result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ARTIFACT_INTEGRITY_INVALID",
  );
});

test("the signer refuses evidence observed after its issuance clock", () => {
  const signer = createMarketplaceAttestationSigner(signerOptions());
  const request = fixtureRequest();
  const result = structuredClone(fixtureSuccess(request));
  const mutable = result as unknown as {
    preview: { snapshot: { pin: { observedAt: string } } };
    artifact: {
      evidence: {
        preview: { freshSnapshot: { snapshot: { pin: { observedAt: string } } } };
      };
    };
  };
  mutable.preview.snapshot.pin.observedAt = (ISSUED_AT + 1).toString();
  mutable.artifact.evidence.preview.freshSnapshot.snapshot.pin.observedAt =
    (ISSUED_AT + 1).toString();
  refreshArtifactCommitments(result);

  assert.throws(
    () => signer.issueVerified(request, result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError && error.code === "CLOCK_INVALID",
  );
});

test("policy mismatch and expired evidence fail before signing", () => {
  const request = fixtureRequest();
  const result = fixtureSuccess(request);
  const wrongPolicySigner = createMarketplaceAttestationSigner(
    signerOptions({ verifierPolicySha256: "cc".repeat(32) }),
  );
  assert.throws(
    () => wrongPolicySigner.issueVerified(request, result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "VERIFIER_POLICY_MISMATCH",
  );

  const expiredSigner = createMarketplaceAttestationSigner(
    signerOptions({ clock: () => ISSUED_AT + 601 }),
  );
  assert.throws(
    () => expiredSigner.issueVerified(request, result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ATTESTATION_EXPIRY_INVALID",
  );
});

test("candidate and transaction-plan mismatches fail before signing", () => {
  const signer = createMarketplaceAttestationSigner(signerOptions());
  const request = fixtureRequest();
  const result = fixtureSuccess(request);
  assert.throws(
    () =>
      signer.issueVerified(
        {
          ...request,
          candidate: {
            ...request.candidate,
            selector: { chainId: 56, tokenId: "2" },
          },
        },
        result,
      ),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ARTIFACT_MISMATCH",
  );

  assert.throws(
    () =>
      signer.issueVerified(
        {
          ...request,
          candidate: {
            ...request.candidate,
            transactionPlan: {
              ...request.candidate.transactionPlan,
              from: "0x2222222222222222222222222222222222222222",
            },
          },
        },
        result,
      ),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ARTIFACT_INTEGRITY_INVALID",
  );
});

test("unsafe preview block numbers fail closed during projection mapping", () => {
  const signer = createMarketplaceAttestationSigner(signerOptions());
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
    () => signer.issueVerified(request, result),
    (error: unknown) =>
      error instanceof MarketplaceServiceError && error.code === "MAPPING_FAILED",
  );
});

test("the public runtime has no generic artifact-signing method", async () => {
  let attestationIds = 0;
  const runtime = createMarketplaceVerifierRuntime(
    {
      ...signerOptions({
        randomUUID: () => {
          attestationIds += 1;
          return "018f4f5e-7d2d-7d6b-8fb8-35c1b79275a1";
        },
      }),
      verifier: {
        manifest: {},
        passiveReport: {},
        transport: {},
        trustFile: {},
      } as never,
    },
  );
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

  await assert.rejects(
    runtime.evaluateAndAttest({
      request: fixtureRequest(),
    }),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "VERIFIER_EVALUATION_FAILED",
  );
  assert.equal(attestationIds, 0);
});
