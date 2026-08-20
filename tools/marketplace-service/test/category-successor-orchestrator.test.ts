import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson } from "@mandatex/marketplace-core";

import {
  deriveAttestationExpiry,
  deriveCategoryQuoteChallengeWindow,
} from "../src/category-successor-orchestrator.js";
import { MarketplaceServiceError } from "../src/errors.js";
import {
  ADAPTER_CASES,
  createSuccessorFixture,
  type SuccessorAdapterId,
} from "./category-successor-fixture.js";

const baseRequest = {
  expiresAt: 1_000 + 240,
  permissionsExpiresAt: 1_000 + 180,
} as never;

test("successor quote challenge derives its window from the current clock", () => {
  let now = 1_000;
  const first = deriveCategoryQuoteChallengeWindow(baseRequest, () => now);
  assert.deepEqual(first, {
    issuedAt: 1_000,
    expiresAt: 1_000 + 240,
    permissionsExpiresAt: 1_000 + 180,
  });

  now = 1_050;
  const second = deriveCategoryQuoteChallengeWindow(baseRequest, () => now);
  assert.equal(second.issuedAt, 1_050);
  assert.equal(second.expiresAt, 1_000 + 240);
  assert.equal(second.permissionsExpiresAt, 1_000 + 180);
});

test("successor quote challenge rejects an expired current-clock window", () => {
  assert.throws(
    () =>
      deriveCategoryQuoteChallengeWindow(
        { expiresAt: 1_010, permissionsExpiresAt: 1_010 } as never,
        () => 1_010,
      ),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ATTESTATION_EXPIRY_INVALID",
  );
});

const expiryInput: any = {
  issuedAt: 1_000,
  mandate: { expiresAt: 2_000, maxEvidenceAgeSeconds: 1_000 },
  request: { expiresAt: 2_000, permissionsExpiresAt: 2_000 } as never,
  quoteExpiresAt: 2_000,
  identityObservedAt: 1_000,
  evidenceObservedAt: 1_000,
  tuple: {
    authorization: { notAfter: 2_000 },
    key: { record: { notAfter: 2_000 } },
    release: { notAfter: 2_000 },
  },
} as never;

test("successor attestation expiry enforces minimum remaining validity", () => {
  assert.throws(
    () =>
      deriveAttestationExpiry({
        ...expiryInput,
        quoteExpiresAt: 1_029,
      }),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ATTESTATION_EXPIRY_INVALID",
  );

  assert.equal(
    deriveAttestationExpiry({ ...expiryInput, quoteExpiresAt: 1_030 }),
    1_030,
  );
});

function serviceErrorWithCode(code: string) {
  return (error: unknown): error is MarketplaceServiceError =>
    error instanceof MarketplaceServiceError && error.code === code;
}

function quoteRoute(fixture: ReturnType<typeof createSuccessorFixture>) {
  const route = fixture.routes.find((candidate) => candidate.kind === "a2a-quote");
  assert.ok(route, "successor issuance must make one A2A quote request");
  return route;
}

function issueResult(
  fixture: ReturnType<typeof createSuccessorFixture>,
  adapterId: SuccessorAdapterId,
) {
  return fixture.orchestrator.issue(fixture.makeIssueInput(adapterId));
}

function wireText(wire: string | Uint8Array): string {
  return typeof wire === "string" ? wire : new TextDecoder().decode(wire);
}

function collectRequestedBlockHashes(
  fixture: ReturnType<typeof createSuccessorFixture>,
): string[] {
  const hashes: string[] = [];
  for (const route of fixture.routes) {
    if ("approvedBlockHash" in route) hashes.push(route.approvedBlockHash);
    if (!("body" in route)) continue;
    const body = JSON.parse(route.body) as { params?: unknown };
    const visit = (value: unknown): void => {
      if (value === null || typeof value !== "object") return;
      if (Array.isArray(value)) {
        for (const item of value) visit(item);
        return;
      }
      for (const [key, child] of Object.entries(value)) {
        if (key === "blockHash" && typeof child === "string") hashes.push(child);
        else visit(child);
      }
    };
    visit(body.params);
  }
  return hashes;
}

for (const { adapterId } of ADAPTER_CASES) {
  test(`successor orchestrator issues observe-only attestations for ${adapterId}`, async () => {
    const fixture = createSuccessorFixture();
    const result = await issueResult(fixture, adapterId);

    assert.equal(result.status, "issued");
    assert.equal(result.attestationId, "attestation-1");
    const envelope = JSON.parse(wireText(result.wire)) as any;
    assert.equal(envelope.scope, "evaluation_only");
    assert.equal(envelope.activationAuthorization, "none");
    assert.equal(envelope.reservation, "none");
    assert.equal(envelope.replayPolicy, "reusable_until_expiry");
    assert.equal(envelope.projection.linkage.adapterId, adapterId);
    assert.equal(envelope.projection.linkage.serviceMode, "observe_only");
    assert.equal(
      envelope.projection.linkage.categoryScope.evidenceSchema,
      ADAPTER_CASES.find((entry) => entry.adapterId === adapterId)!.category ===
        "grid"
        ? "mandatex.category.grid-evidence.v1"
        : ADAPTER_CASES.find((entry) => entry.adapterId === adapterId)!.category ===
            "yield"
          ? "mandatex.category.yield-evidence.v1"
          : adapterId === "venus-health-v1"
            ? "mandatex.category.venus-health-evidence.v1"
            : "mandatex.category.health-evidence.v1",
    );
    assert.equal(fixture.counters.attestationUuidCalls, 1);
    assert.equal(fixture.counters.signerCalls, 1);
    assert.equal(fixture.counters.commitCalls, 1);
  });
}

test("successor quote transport is exact and its body is canonical", async () => {
  const fixture = createSuccessorFixture();
  await issueResult(fixture, "pancakeswap-v3-grid-v1");
  const route = quoteRoute(fixture);
  assert.equal(route.method, "POST");
  assert.equal(route.url, fixture.quoteEndpoint);
  assert.equal(route.approvedUrl, fixture.quoteEndpoint);
  assert.equal(route.rpcMethod, "message/send");
  assert.equal(route.body, canonicalJson(JSON.parse(route.body) as never));
  const body = JSON.parse(route.body) as any;
  assert.equal(body.jsonrpc, "2.0");
  assert.equal(body.method, "message/send");
  assert.equal(body.params.message.parts[0].data.skill, "negotiate");
  const challenge = body.params.message.parts[0].data.challenge;
  assert.equal(
    challenge.verifyingContract,
    fixture.verifier.policy.successorPolicy.quote.domain.verifyingContract,
  );
  assert.equal(
    challenge.quoteEndpointSha256,
    fixture.verifier.policy.successorPolicy.quote.endpointSha256,
  );
  assert.equal(challenge.adapterId, "pancakeswap-v3-grid-v1");
  assert.equal(challenge.scope, "evaluation_only");
  assert.equal(challenge.activationAuthorization, "none");
  assert.equal(challenge.reservation, "none");
  assert.equal(challenge.replayPolicy, "reusable_until_expiry");
});

test("successor identity, target, and adapter reads use one opaque canonical snapshot", async () => {
  const fixture = createSuccessorFixture();
  const result = await issueResult(fixture, "venus-health-v1");
  assert.equal(result.status, "issued");
  const expectedHash = (result as any).projection.linkage.observation.observedBlockHash;
  const hashes = collectRequestedBlockHashes(fixture);
  assert.ok(hashes.length >= 8, "fixture should exercise identity, target, and category reads");
  assert.deepEqual([...new Set(hashes)], [expectedHash]);
  assert.ok(fixture.routes.some((route) => route.kind === "bsc-rpc"));
  assert.ok(fixture.routes.some((route) => route.kind === "bsc-category-target-rpc"));
  assert.ok(fixture.routes.some((route) => route.kind === "bsc-category-rpc"));
});

test("malformed quote response fails before UUID generation or signing", async () => {
  const fixture = createSuccessorFixture({ malformedQuote: true });
  await assert.rejects(
    issueResult(fixture, "pancakeswap-v3-grid-v1"),
    serviceErrorWithCode("ARTIFACT_MISMATCH"),
  );
  assert.equal(fixture.counters.attestationUuidCalls, 0);
  assert.equal(fixture.counters.signerCalls, 0);
});

test("adapter failure fails before UUID generation or signing", async () => {
  const fixture = createSuccessorFixture({ adapterPass: false });
  const result = await issueResult(fixture, "pancakeswap-v3-grid-v1");
  assert.equal(result.status, "not_attested");
  assert.equal(result.code, "GRID_SPOT_OUTSIDE_BAND");
  assert.equal(fixture.counters.attestationUuidCalls, 0);
  assert.equal(fixture.counters.signerCalls, 0);
});

test("canonicality loss at the pre-sign fence fails without UUID or signing", async () => {
  const fixture = createSuccessorFixture({ canonicalityLoss: true });
  const result = await issueResult(fixture, "pancakeswap-v3-grid-v1");
  assert.equal(result.status, "not_attested");
  assert.equal(result.code, "CATEGORY_BLOCK_NONCANONICAL");
  assert.equal(fixture.counters.attestationUuidCalls, 0);
  assert.equal(fixture.counters.signerCalls, 0);
  assert.equal(fixture.counters.commitCalls, 0);
  assert.equal(fixture.counters.releaseCalls, 1);
});

test("late canonicality loss never commits a signed record", async () => {
  const fixture = createSuccessorFixture({ reorgAtHeaderCall: 4 });
  const result = await issueResult(fixture, "pancakeswap-v3-grid-v1");
  assert.equal(result.status, "not_attested");
  assert.equal(result.code, "CATEGORY_BLOCK_NONCANONICAL");
  assert.equal(fixture.counters.commitCalls, 0);
  assert.equal(fixture.counters.releaseCalls, 1);
  assert.equal(fixture.issuance.record(), undefined);
  assert.equal(fixture.counters.attestationUuidCalls, 1);
  assert.equal(fixture.counters.signerCalls, 1);
});

test("ambiguous commit releases by token without deleting the written record", async () => {
  const fixture = createSuccessorFixture({ commitFailureAfterWrite: true });
  await assert.rejects(
    issueResult(fixture, "pancakeswap-v3-grid-v1"),
    serviceErrorWithCode("IDEMPOTENCY_STORE_INVALID"),
  );
  assert.equal(fixture.counters.commitCalls, 1);
  assert.equal(fixture.counters.releaseCalls, 1);
  assert.ok(fixture.issuance.record());
});

test("duplicate existing issuance returns the exact stored wire without a second signature", async () => {
  const firstFixture = createSuccessorFixture();
  const first = await issueResult(firstFixture, "pancakeswap-v3-grid-v1");
  assert.equal(first.status, "issued");
  const replayFixture = createSuccessorFixture({
    reservationMode: "existing",
    existingRecord: firstFixture.issuance.record(),
  });
  const replay = await issueResult(replayFixture, "pancakeswap-v3-grid-v1");
  assert.equal(replay.status, "issued");
  assert.equal(replay.wire, first.wire);
  assert.equal(replay.attestationId, first.attestationId);
  assert.equal(replayFixture.counters.attestationUuidCalls, 0);
  assert.equal(replayFixture.counters.signerCalls, 0);
  assert.equal(replayFixture.counters.commitCalls, 0);
});

test("in-progress reservation rejects without UUID generation or signing", async () => {
  const fixture = createSuccessorFixture({ reservationMode: "in_progress" });
  await assert.rejects(
    issueResult(fixture, "pancakeswap-v3-grid-v1"),
    serviceErrorWithCode("ISSUANCE_IN_PROGRESS"),
  );
  assert.equal(fixture.counters.attestationUuidCalls, 0);
  assert.equal(fixture.counters.signerCalls, 0);
});

test("trust advancement between preparation and permit use fails closed before UUID or signing", async () => {
  const fixture = createSuccessorFixture({ advanceTrustBeforePermitUse: true });
  await assert.rejects(
    issueResult(fixture, "pancakeswap-v3-grid-v1"),
    serviceErrorWithCode("ISSUANCE_CONFLICT"),
  );
  assert.equal(fixture.counters.attestationUuidCalls, 0);
  assert.equal(fixture.counters.signerCalls, 0);
  assert.equal(fixture.counters.releaseCalls, 1);
});

test("constructor rejects a trust-controller root that differs from policy", () => {
  assert.throws(
    () => createSuccessorFixture({ trustRootMismatch: true }),
    serviceErrorWithCode("VERIFIER_CONFIGURATION_INVALID"),
  );
});

for (const legacyQuoteOverride of ["endpoint", "verifying_contract"] as const) {
  test(`constructor rejects the removed runtime quote ${legacyQuoteOverride} override`, () => {
    assert.throws(
      () => createSuccessorFixture({ legacyQuoteOverride }),
      serviceErrorWithCode("REQUEST_INVALID"),
    );
  });
}

test("prepared issuance rejects a trust-controller quote domain that differs from policy", async () => {
  const fixture = createSuccessorFixture({ trustQuoteDomainMismatch: true });
  await assert.rejects(
    issueResult(fixture, "pancakeswap-v3-grid-v1"),
    serviceErrorWithCode("ISSUANCE_CONFLICT"),
  );
  assert.equal(fixture.counters.attestationUuidCalls, 0);
  assert.equal(fixture.counters.signerCalls, 0);
  assert.equal(fixture.counters.releaseCalls, 1);
});

test("prepared issuance rejects a signed release whose mode projection differs from policy", async () => {
  const fixture = createSuccessorFixture({ trustReleaseModeMismatch: true });
  await assert.rejects(
    issueResult(fixture, "pancakeswap-v3-grid-v1"),
    serviceErrorWithCode("ISSUANCE_CONFLICT"),
  );
  assert.equal(fixture.counters.attestationUuidCalls, 0);
  assert.equal(fixture.counters.signerCalls, 0);
  assert.equal(fixture.counters.releaseCalls, 1);
});

test("stored issuance recovery rechecks the policy-bound trust-controller quote domain", async () => {
  const source = createSuccessorFixture();
  const issued = await issueResult(source, "pancakeswap-v3-grid-v1");
  assert.equal(issued.status, "issued");
  const replay = createSuccessorFixture({
    reservationMode: "existing",
    existingRecord: source.issuance.record(),
    trustQuoteDomainMismatch: true,
  });
  await assert.rejects(
    issueResult(replay, "pancakeswap-v3-grid-v1"),
    serviceErrorWithCode("ISSUANCE_CONFLICT"),
  );
  assert.equal(replay.counters.attestationUuidCalls, 0);
  assert.equal(replay.counters.signerCalls, 0);
});

test("stored issuance recovery rejects an attestation from another authorized release", async () => {
  const releaseOne = createSuccessorFixture();
  const issuedOne = await issueResult(releaseOne, "pancakeswap-v3-grid-v1");
  assert.equal(issuedOne.status, "issued");

  const releaseTwo = createSuccessorFixture({
    releaseId: "fixture-release-r2",
  });
  const issuedTwo = await issueResult(releaseTwo, "pancakeswap-v3-grid-v1");
  assert.equal(issuedTwo.status, "issued");

  const recordOne = JSON.parse(JSON.stringify(releaseOne.issuance.record())) as any;
  const recordTwo = JSON.parse(JSON.stringify(releaseTwo.issuance.record())) as any;
  assert.deepEqual(recordTwo.projection, recordOne.projection);
  const substitutedRecord = {
    ...recordTwo,
    idempotencyKey: recordOne.idempotencyKey,
  };
  const replay = createSuccessorFixture({
    reservationMode: "existing",
    existingRecord: substitutedRecord,
  });
  await assert.rejects(
    issueResult(replay, "pancakeswap-v3-grid-v1"),
    serviceErrorWithCode("IDEMPOTENCY_STORE_INVALID"),
  );
  assert.equal(replay.counters.attestationUuidCalls, 0);
  assert.equal(replay.counters.signerCalls, 0);
});

for (const tamper of ["target", "sidecar"] as const) {
  test(`stored ${tamper} tampering is rejected without a new UUID or signature`, async () => {
    const source = createSuccessorFixture();
    const issued = await issueResult(source, "pancakeswap-v3-grid-v1");
    assert.equal(issued.status, "issued");
    const record = JSON.parse(JSON.stringify(source.issuance.record())) as any;
    if (tamper === "target") {
      record.projection.sidecars.targetObservations[0].targetAddress =
        "0x9999999999999999999999999999999999999999";
    } else {
      record.projection.sidecars.observation.evidenceSha256 = "ff".repeat(32);
    }
    const replay = createSuccessorFixture({
      reservationMode: "existing",
      existingRecord: record,
    });
    await assert.rejects(
      issueResult(replay, "pancakeswap-v3-grid-v1"),
      serviceErrorWithCode("IDEMPOTENCY_STORE_INVALID"),
    );
    assert.equal(replay.counters.attestationUuidCalls, 0);
    assert.equal(replay.counters.signerCalls, 0);
  });
}
