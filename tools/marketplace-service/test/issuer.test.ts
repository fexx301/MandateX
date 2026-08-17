import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { createMarketplaceCoreV2 } from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "../src/errors.js";
import {
  buildDisplaySafeProjectionPayload,
  createMarketplaceAttestationSigner,
} from "../src/issuer.js";
import { createMarketplaceVerifierRuntime } from "../src/index.js";
import {
  ISSUED_AT,
  VERIFIER_POLICY_SHA256,
  fixtureRequest,
  fixtureSuccess,
  refreshArtifactCommitments,
} from "./fixture.js";
import {
  brandedVerifierFixture,
  DEFAULT_FRESH_BLOCK_HASH,
  DEFAULT_SIGNED_BLOCK_HASH,
  defaultRuntimeFixture,
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

test("the public runtime completes the default bounded preview path accepted by Core", async () => {
  const fixture = await defaultRuntimeFixture();
  const runtime = createMarketplaceVerifierRuntime({
    ...signerOptions({ verifierPolicySha256: fixture.verifierPolicySha256 }),
    verifier: fixture.verifier,
  });

  const result = await runtime.evaluateAndAttest({ request: fixture.request });
  assert.equal(result.outcome, "attested");
  if (result.outcome !== "attested") return;
  assert.equal(result.payload.preview.status, "passed");
  assert.equal(result.payload.categoryEvidence.category, "rebalancing");
  if (result.payload.categoryEvidence.category === "rebalancing") {
    assert.equal(result.payload.categoryEvidence.currentTick, 96);
    assert.equal(result.payload.categoryEvidence.proposedLowerTick, 0);
    assert.equal(result.payload.categoryEvidence.proposedUpperTick, 200);
  }

  const routeKinds = fixture.routes.map((route) => route.kind);
  assert.deepEqual(new Set(routeKinds), new Set(["a2a-quote", "bsc-preview-rpc"]));
  assert.equal(fixture.routes.length, 71);
  const previewPurposes = fixture.routes.flatMap((route) =>
    route.kind === "bsc-preview-rpc" ? [route.purpose] : [],
  );
  for (const required of [
    "chain-id",
    "head-block-number",
    "block-header",
    "contract-code",
    "state-read",
    "simulation",
  ] as const) {
    assert.ok(previewPurposes.includes(required), `missing ${required} route`);
  }
  const purposeCounts = Object.fromEntries(
    [
      "chain-id",
      "head-block-number",
      "block-header",
      "contract-code",
      "state-read",
      "simulation",
    ].map((purpose) => [
      purpose,
      previewPurposes.filter((observed) => observed === purpose).length,
    ]),
  );
  assert.deepEqual(purposeCounts, {
    "chain-id": 2,
    "head-block-number": 1,
    "block-header": 6,
    "contract-code": 16,
    "state-read": 44,
    simulation: 1,
  });

  const signedSnapshotPurposes = [
    "chain-id",
    "block-header",
    ...Array.from({ length: 6 }, () => "contract-code"),
    ...Array.from({ length: 13 }, () => "state-read"),
    ...Array.from({ length: 2 }, () => "contract-code"),
    ...Array.from({ length: 9 }, () => "state-read"),
    "block-header",
  ];
  const freshSnapshotPurposes = [
    "chain-id",
    "head-block-number",
    ...signedSnapshotPurposes.slice(1),
  ];
  assert.deepEqual(
    fixture.routes.map((route) =>
      route.kind === "bsc-preview-rpc" ? route.purpose : route.kind,
    ),
    [
      "a2a-quote",
      ...signedSnapshotPurposes,
      ...freshSnapshotPurposes,
      "simulation",
      "block-header",
      "block-header",
    ],
  );

  const previewRoutes = fixture.routes.filter(
    (route): route is Extract<typeof route, { kind: "bsc-preview-rpc" }> =>
      route.kind === "bsc-preview-rpc",
  );
  const signedSnapshotRoutes = previewRoutes.slice(0, 33);
  const freshSnapshotRoutes = previewRoutes.slice(33, 67);
  for (const route of [...signedSnapshotRoutes, ...freshSnapshotRoutes]) {
    if (route.purpose === "contract-code" || route.purpose === "state-read") {
      assert.equal(
        route.approvedBlockHash,
        signedSnapshotRoutes.includes(route)
          ? DEFAULT_SIGNED_BLOCK_HASH
          : DEFAULT_FRESH_BLOCK_HASH,
      );
    }
  }

  const simulation = previewRoutes[67];
  assert.equal(simulation?.purpose, "simulation");
  if (!simulation || simulation.purpose !== "simulation") return;
  assert.equal(simulation.approvedBlockHash, DEFAULT_FRESH_BLOCK_HASH);
  const simulationRequest = JSON.parse(simulation.body) as {
    params: readonly [
      Record<string, unknown>,
      { readonly blockHash: string; readonly requireCanonical: boolean },
    ];
  };
  assert.equal(simulationRequest.params[1].blockHash, DEFAULT_FRESH_BLOCK_HASH);
  assert.equal(simulationRequest.params[1].requireCanonical, true);

  assert.deepEqual(
    previewRoutes
      .filter((route) => route.purpose === "block-header")
      .map((route) => route.approvedBlockNumber),
    ["0x64", "0x64", "0x67", "0x67", "0x64", "0x67"],
  );

  const core = createMarketplaceCoreV2({
    attestationTrust: runtime.pinnedTrust,
    maxClockSkewSeconds: 30,
    clock: () => ISSUED_AT + 1,
  });
  const evaluation = core.evaluateMarketplaceV2({
    mandate: result.mandate,
    attestations: [result.wire],
  });
  assert.equal(evaluation.decisions[0]?.outcome, "eligible");
  assert.equal(evaluation.receipt.summary.eligible, 1);
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

test("signer and runtime reject future policy fields instead of silently ignoring them", () => {
  const verifier = verifierInvocationFixture({
    async request(): Promise<never> {
      throw new Error("unused");
    },
  });
  assert.throws(
    () =>
      createMarketplaceVerifierRuntime({
        ...signerOptions({
          verifierPolicySha256: verifierPolicySha256ForInvocation(verifier),
          categoryDeploymentSha256: "00".repeat(32),
        }),
        verifier,
      } as never),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "VERIFIER_CONFIGURATION_INVALID",
  );
  assert.throws(
    () =>
      createMarketplaceAttestationSigner({
        ...signerOptions(),
        categoryDeploymentSha256: "00".repeat(32),
      } as never),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ATTESTATION_SIGNER_INVALID",
  );
});

test("signer rejects missing and non-string key IDs at construction", () => {
  for (const keyId of [undefined, null, 7] as const) {
    const options = signerOptions({ keyId });
    assert.throws(
      () => createMarketplaceAttestationSigner(options as never),
      (error: unknown) =>
        error instanceof MarketplaceServiceError &&
        error.code === "ATTESTATION_SIGNER_INVALID",
    );
  }
});
