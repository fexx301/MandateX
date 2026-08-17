import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { deflateRawSync } from "node:zlib";

import { privateKeyToAccount } from "viem/accounts";
import {
  encodeFunctionData,
  encodeFunctionResult,
  type Hex,
} from "viem";

import { DEFAULT_CHAIN_PROFILE, POLICY_FINGERPRINT } from "../src/policy.js";
import { buildReport, type CandidateReportInput } from "../src/report.js";
import {
  manifestFileSchema,
  type ManifestFile,
  type RunReport,
} from "../src/schema.js";
import {
  MIN_QUOTE_REMAINING_SECONDS,
  QUOTE_TRUST_SCHEMA,
  quoteMandatexRebalanceMandateSchema,
  quoteTrustFileSchema,
  type QuoteAcceptedEnvelope,
  type QuoteMandatexRebalanceMandate,
  type QuoteTrustFile,
} from "../src/quotes/schema.js";
import {
  canonicalQuoteJson,
  computeQuoteNegotiationHash,
  computeQuoteRequestHash,
  computeQuoteResponseHash,
} from "../src/quotes/protocol.js";
import type {
  ReplayMetadata,
  ReplayStore,
} from "../src/quotes/replay.js";
import {
  QuotePreflightError,
  preflightTrustedQuote,
  validateTrustedQuote,
} from "../src/quotes/validate.js";
import type {
  BoundedHttpResponse,
  TransportRoute,
} from "../src/transport/http.js";
import {
  previewCollectAbi,
  previewDecreaseLiquidityAbi,
  previewMintAbi,
  previewMulticallAbi,
} from "../src/preview/plan.js";
import {
  BSC_PANCAKE_V3,
  type PancakeStateResult,
  type PancakeStateSnapshot,
} from "../src/preview/pancake.js";
import { PreviewSimulationError } from "../src/preview/rpc.js";
import { marketplacePreviewEvaluationArtifactSchema } from "../src/preview/schema.js";
import {
  assertTrustedMarketplaceEvaluationSuccess,
  serializeMarketplacePreviewEvaluationArtifact,
  validateTrustedPreview,
  validateTrustedPreviewForActivation,
  validateTrustedPreviewForMarketplaceEvaluation,
} from "../src/preview/validate.js";

const NOW = new Date("2026-08-16T12:00:00.000Z");
const PROVIDER = `0x${"1".repeat(40)}`;
const OTHER_PROVIDER = `0x${"2".repeat(40)}`;
const OTHER_REGISTRY = `0x${"9".repeat(40)}`;
const COMMERCE = `0x${"3".repeat(40)}`;
const BLOCK_HASH = `0x${"a".repeat(64)}`;
const CODE_HASH = "b".repeat(64);
const RESPONSE_HASH = "c".repeat(64);
const TEST_PRIVATE_KEY = `0x${"11".repeat(32)}` as const;
const TEST_ACCOUNT = privateKeyToAccount(TEST_PRIVATE_KEY);
const NOW_SECONDS = Math.floor(NOW.valueOf() / 1_000);
const POSITION_MANAGER =
  "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364";
const REQUIRED_CALLS = [
  "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
  "collect((uint256,address,uint128,uint128))",
  "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
] as const;

test("candidate-scoped preflight ignores unrelated inconclusive candidates", () => {
  const fixture = validFixture(true);
  assert.equal(fixture.report.runStatus, "inconclusive");

  const context = preflightTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    now: () => NOW,
  });

  assert.equal(context.passiveCandidate.status, "REGISTERED_ONLY");
  assert.equal(context.trust.expectedProvider, PROVIDER);
  assert.equal(context.trust.commerceContract, COMMERCE);
  assert.equal(context.passiveReportSha256.length, 64);
  assert.equal(context.passiveCandidateSha256.length, 64);
  assert.equal(context.trustPolicySha256.length, 64);
  assert.equal(context.quoteEndpointSha256.length, 64);
});

test("preflight fails closed on policy, gate, freshness, endpoint, and provider conflicts", () => {
  const cases: ReadonlyArray<{
    name: string;
    expected: QuotePreflightError["code"];
    mutate: (fixture: ReturnType<typeof validFixture>) => void;
  }> = [
    {
      name: "policy fingerprint",
      expected: "PASSIVE_POLICY_MISMATCH",
      mutate: (fixture) => {
        fixture.report = { ...fixture.report, policyFingerprint: "f".repeat(64) };
      },
    },
    {
      name: "chain profile",
      expected: "CHAIN_PROFILE_MISMATCH",
      mutate: (fixture) => {
        fixture.report = {
          ...fixture.report,
          chainProfile: { ...fixture.report.chainProfile, name: "other-profile" },
        };
      },
    },
    {
      name: "candidate status",
      expected: "CANDIDATE_NOT_REGISTERED",
      mutate: (fixture) => {
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          status: "UNAVAILABLE",
        }));
      },
    },
    {
      name: "required gate state",
      expected: "PASSIVE_GATE_NOT_PASSED",
      mutate: (fixture) => {
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          gates: candidate.gates.map((gate) =>
            gate.gate === "endpoint_health" ? { ...gate, state: "fail" } : gate,
          ),
        }));
      },
    },
    {
      name: "duplicate required gate",
      expected: "PASSIVE_GATE_DUPLICATE",
      mutate: (fixture) => {
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          gates: [
            ...candidate.gates,
            {
              gate: "endpoint_health",
              state: "pass",
              evidence: ["detected"],
              evidenceRefs: ["card.http"],
            },
          ],
        }));
      },
    },
    {
      name: "active quote gate in passive report",
      expected: "PASSIVE_QUOTE_GATE_NOT_UNKNOWN",
      mutate: (fixture) => {
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          gates: candidate.gates.map((gate) =>
            gate.gate === "quote_signature" ? { ...gate, state: "pass" } : gate,
          ),
        }));
      },
    },
    {
      name: "stale card observation",
      expected: "PASSIVE_OBSERVATION_STALE",
      mutate: (fixture) => {
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          card: {
            ...candidate.card!,
            observedAt: "2026-08-16T11:00:00.000Z",
          },
        }));
      },
    },
    {
      name: "future chain observation",
      expected: "PASSIVE_OBSERVATION_IN_FUTURE",
      mutate: (fixture) => {
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          chain: {
            ...candidate.chain!,
            observedAt: "2026-08-16T12:01:00.000Z",
          },
        }));
      },
    },
    {
      name: "trusted card URL",
      expected: "CARD_ENDPOINT_MISMATCH",
      mutate: (fixture) => {
        fixture.trustFile = quoteTrustFileSchema.parse({
          ...fixture.trustFile,
          candidates: fixture.trustFile.candidates.map((entry) => ({
            ...entry,
            cardUrl: "https://agent.example/other-card.json",
          })),
        });
      },
    },
    {
      name: "trusted service URL",
      expected: "QUOTE_ENDPOINT_MISMATCH",
      mutate: (fixture) => {
        fixture.trustFile = quoteTrustFileSchema.parse({
          ...fixture.trustFile,
          candidates: fixture.trustFile.candidates.map((entry) => ({
            ...entry,
            quoteEndpoint: "https://agent.example/quote",
          })),
        });
      },
    },
    {
      name: "negotiate skill",
      expected: "NEGOTIATE_SKILL_MISSING",
      mutate: (fixture) => {
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          card: { ...candidate.card!, skills: [] },
        }));
      },
    },
    {
      name: "trusted provider",
      expected: "TRUSTED_PROVIDER_CONFLICT",
      mutate: (fixture) => {
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          scan: { ...candidate.scan!, agentWallet: OTHER_PROVIDER },
        }));
      },
    },
    {
      name: "trusted category",
      expected: "TRUSTED_CATEGORY_CONFLICT",
      mutate: (fixture) => {
        fixture.manifest = {
          ...fixture.manifest,
          candidates: fixture.manifest.candidates.map((candidate) => ({
            ...candidate,
            categories: ["yield"],
          })),
        };
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          categories: ["yield"],
        }));
      },
    },
    {
      name: "registry owner",
      expected: "TRUSTED_PROVIDER_CONFLICT",
      mutate: (fixture) => {
        fixture.report = replaceSelectedCandidate(fixture.report, (candidate) => ({
          ...candidate,
          chain: { ...candidate.chain!, owner: OTHER_PROVIDER },
        }));
      },
    },
  ];

  for (const scenario of cases) {
    const fixture = validFixture();
    scenario.mutate(fixture);
    assert.throws(
      () =>
        preflightTrustedQuote({
          manifest: fixture.manifest,
          passiveReport: fixture.report,
          trustFile: fixture.trustFile,
          candidate: { chainId: 56, tokenId: "1" },
          now: () => NOW,
        }),
      (error: unknown) =>
        error instanceof QuotePreflightError && error.code === scenario.expected,
      scenario.name,
    );
  }
});

test("validateTrustedQuote performs exactly one POST and claims a verified quote", async () => {
  const fixture = validFixture(false, TEST_ACCOUNT.address.toLowerCase());
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("claimed");

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    transport: quoteTransport(routes, (requestId) =>
      successA2aResponse(requestId, envelope),
    ),
    replayStore: replay,
    now: () => NOW,
    randomUUID: sequentialId(),
  });

  assert.equal(sidecar.outcome, "valid");
  assert.equal(sidecar.replayStatus, "claimed");
  assert.equal(sidecar.expectedProvider, TEST_ACCOUNT.address.toLowerCase());
  assert.equal(routes.filter((route) => route.kind === "a2a-quote").length, 1);
  assert.equal(routes.filter((route) => route.kind === "bsc-rpc").length, 0);
  assert.equal(replay.prepareCalls, 1);
  assert.equal(replay.claims.length, 1);
  assert.equal(replay.claims[0]?.claimedAt, sidecar.observedAt);
  assert.equal(JSON.stringify(sidecar).includes("provider_sig"), false);
  assert.equal(JSON.stringify(sidecar).includes("mandate_id"), false);
});

test("trusted quote preflight rejects non-executable signed ranges before replay", async (t) => {
  const scenarios: ReadonlyArray<
    Readonly<{
      name: string;
      mutateMandate?: (mandate: QuoteMandatexRebalanceMandate) => void;
      proposal?: Readonly<{
        proposedLowerTick: number;
        proposedUpperTick: number;
      }>;
    }>
  > = [
    {
      name: "nondivisible target width",
      mutateMandate: (mandate) => {
        mandate.range_policy.target_width_ticks = 205;
      },
    },
    {
      name: "unaligned executable endpoints",
      proposal: { proposedLowerTick: 5, proposedUpperTick: 205 },
    },
    {
      name: "legacy outward-rounded width",
      proposal: { proposedLowerTick: -10, proposedUpperTick: 200 },
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const fixture = validFixture(false, TEST_ACCOUNT.address.toLowerCase());
      const mandate = validMandate();
      scenario.mutateMandate?.(mandate);
      const envelope = await signedEnvelope(mandate, scenario.proposal);
      const replay = memoryReplayStore("claimed");

      const sidecar = await validateTrustedQuote({
        manifest: fixture.manifest,
        passiveReport: fixture.report,
        trustFile: fixture.trustFile,
        candidate: { chainId: 56, tokenId: "1" },
        mandate,
        transport: quoteTransport([], (requestId) =>
          successA2aResponse(requestId, envelope),
        ),
        replayStore: replay,
        now: () => NOW,
        randomUUID: sequentialId(),
      });

      assert.equal(sidecar.outcome, "invalid");
      assert.equal(sidecar.errorCode, "SIGNED_TASK_INVALID");
      assert.equal(sidecar.gates.quotePolicy, "fail");
      assert.equal(replay.claims.length, 0);
    });
  }
});

test("a rejected pre-replay preview gate consumes no replay claim", async () => {
  const fixture = validFixture(false, TEST_ACCOUNT.address.toLowerCase());
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("claimed");
  let gateCalls = 0;

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    transport: quoteTransport(routes, (requestId) =>
      successA2aResponse(requestId, envelope),
    ),
    replayStore: replay,
    now: () => NOW,
    randomUUID: sequentialId(),
    preReplayGate: async (input) => {
      gateCalls += 1;
      assert.equal(input.binding.signedTask.mandate.mandate_id, mandate.mandate_id);
      assert.equal(input.context.trust.expectedProvider, TEST_ACCOUNT.address.toLowerCase());
      return { outcome: "invalid", errorCode: "PREVIEW_GATE_REJECTED" };
    },
  });

  assert.equal(sidecar.outcome, "invalid");
  assert.equal(sidecar.errorCode, "PREVIEW_GATE_REJECTED");
  assert.equal(sidecar.replayStatus, "not_attempted");
  assert.equal(sidecar.gates.quoteSignature, "pass");
  assert.equal(sidecar.gates.quotePolicy, "pass");
  assert.equal(gateCalls, 1);
  assert.equal(replay.claims.length, 0);
  assert.equal(routes.filter((route) => route.kind === "a2a-quote").length, 1);
});

test("the final temporal gate still runs after a passing preview gate", async () => {
  const fixture = validFixture(false, TEST_ACCOUNT.address.toLowerCase());
  const mandate = validMandate();
  const nearExpiry = NOW_SECONDS + MIN_QUOTE_REMAINING_SECONDS + 1;
  const envelope = await signedEnvelope(mandate, {
    quoteExpiresAt: nearExpiry,
  });
  const replay = memoryReplayStore("claimed");
  const decisionTime = new Date(NOW.valueOf() + 2_000);
  let previewPassed = false;

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    transport: quoteTransport([], (requestId) =>
      successA2aResponse(requestId, envelope),
    ),
    replayStore: replay,
    now: sequentialClock(NOW, NOW, decisionTime),
    randomUUID: sequentialId(),
    preReplayGate: async () => {
      previewPassed = true;
      return { outcome: "pass" };
    },
  });

  assert.equal(previewPassed, true);
  assert.equal(sidecar.outcome, "invalid");
  assert.equal(sidecar.errorCode, "QUOTE_POLICY_REJECTED");
  assert.equal(sidecar.observedAt, decisionTime.toISOString());
  assert.equal(replay.claims.length, 0);
});

test("trusted preview binds one quote, two state snapshots, and one simulation before replay", async () => {
  const provider = TEST_ACCOUNT.address.toLowerCase() as `0x${string}`;
  const fixture = validFixture(false, provider);
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const transactionPlan = previewTransactionPlan(provider);
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("claimed");
  const snapshots = previewSnapshots(provider);
  let stateCalls = 0;
  let simulationCalls = 0;
  let canonicalityCalls = 0;

  const sidecar = await validateTrustedPreview(
    {
      manifest: fixture.manifest,
      passiveReport: fixture.report,
      trustFile: fixture.trustFile,
      candidate: { chainId: 56, tokenId: "1" },
      mandate,
      transactionPlan,
      transport: quoteTransport(routes, (requestId) =>
        successA2aResponse(requestId, envelope),
      ),
      replayStore: replay,
      now: () => NOW,
      randomUUID: sequentialId(),
    },
    {
      stateVerifier: async (options): Promise<PancakeStateResult> => {
        stateCalls += 1;
        return {
          status: "verified",
          snapshot:
            options.target?.mode === "exact" ? snapshots.signed : snapshots.fresh,
        };
      },
      simulate: async () => {
        simulationCalls += 1;
        return {
          rawResult: previewSimulationResult(),
          requestSha256: "d".repeat(64),
          responseSha256: "e".repeat(64),
        };
      },
      assertCanonical: async () => {
        canonicalityCalls += 1;
      },
    },
  );

  assert.equal(sidecar.outcome, "preview_simulation_passed");
  assert.equal(sidecar.classification, "PREVIEW_SIMULATION_PASSED");
  assert.equal(sidecar.quote.outcome, "valid");
  assert.equal(sidecar.quote.replayStatus, "claimed");
  assert.equal(stateCalls, 2);
  assert.equal(simulationCalls, 1);
  assert.equal(canonicalityCalls, 2);
  assert.equal(replay.claims.length, 1);
  assert.equal(routes.filter((route) => route.kind === "a2a-quote").length, 1);
  assert.equal(JSON.stringify(sidecar).includes(transactionPlan.data), false);
  assert.equal(JSON.stringify(sidecar).includes("amount0Desired"), false);
  assert.equal(JSON.stringify(sidecar).includes("VERIFIED_HIREABLE"), false);
});

test("marketplace evaluation is replay-free, canonical, and retains both snapshots", async () => {
  const provider = TEST_ACCOUNT.address.toLowerCase() as `0x${string}`;
  const fixture = validFixture(false, provider);
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const transactionPlan = previewTransactionPlan(provider);
  const snapshots = previewSnapshots(provider);
  const routes: TransportRoute[] = [];
  let replayPrepareCalls = 0;
  let replayClaimCalls = 0;
  let replayCommitCalls = 0;
  const supplied = {
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    transactionPlan,
    transport: quoteTransport(routes, (requestId) =>
      successA2aResponse(requestId, envelope),
    ),
    now: () => NOW,
    randomUUID: sequentialId(),
    replayStore: {
      async prepare() {
        replayPrepareCalls += 1;
      },
      async claim() {
        replayClaimCalls += 1;
        return "claimed" as const;
      },
    },
    replayCommit: async () => {
      replayCommitCalls += 1;
      return "created" as const;
    },
  };

  const result = await validateTrustedPreviewForMarketplaceEvaluation(
    supplied,
    passingPreviewDependencies(snapshots),
  );

  assert.equal(result.outcome, "verified_unreserved");
  if (result.outcome !== "verified_unreserved") return;
  assert.equal(result.scope, "evaluation_only");
  assert.equal(result.actionability, "unreserved");
  assert.equal(result.artifact.scope, "evaluation_only");
  assert.equal(result.artifact.actionability, "unreserved");
  assert.equal(result.artifact.outcome, "verified_unreserved");
  assert.equal(result.artifact.replayStatus, "not_attempted");
  assert.equal(replayPrepareCalls, 0);
  assert.equal(replayClaimCalls, 0);
  assert.equal(replayCommitCalls, 0);
  assert.equal(result.signedSnapshot.pin.observedBlockNumber, "100");
  assert.equal(result.preview.snapshot.pin.observedBlockNumber, "103");
  assert.deepEqual(
    result.artifact.evidence.preview.signedSnapshot.snapshot,
    snapshots.signed,
  );
  assert.deepEqual(
    result.artifact.evidence.preview.freshSnapshot.snapshot,
    snapshots.fresh,
  );
  assert.notEqual(
    result.artifact.evidence.preview.signedSnapshot.snapshotSha256,
    result.artifact.evidence.preview.freshSnapshot.snapshotSha256,
  );
  assert.doesNotThrow(() => JSON.stringify(result.artifact));
  assert.deepEqual(
    marketplacePreviewEvaluationArtifactSchema.parse(result.artifact),
    result.artifact,
  );
  assert.equal(
    serializeMarketplacePreviewEvaluationArtifact(result.artifact),
    `${canonicalQuoteJson(result.artifact)}\n`,
  );
  assert.equal(
    result.artifact.commitments.quoteEvidenceSha256,
    createHash("sha256")
      .update(canonicalQuoteJson(result.artifact.evidence.quote))
      .digest("hex"),
  );
  assert.equal(
    result.artifact.commitments.previewEvidenceSha256,
    createHash("sha256")
      .update(canonicalQuoteJson(result.artifact.evidence.preview))
      .digest("hex"),
  );
  assert.doesNotThrow(() =>
    assertTrustedMarketplaceEvaluationSuccess(result),
  );
  assert.throws(
    () =>
      assertTrustedMarketplaceEvaluationSuccess(structuredClone(result)),
    /not produced by trusted validation/,
  );
  const originalReplayKey = result.artifact.prospectiveReplayKey;
  const mutableArtifact = result.artifact as {
    prospectiveReplayKey: string;
  };
  mutableArtifact.prospectiveReplayKey = "d".repeat(64);
  assert.throws(
    () => assertTrustedMarketplaceEvaluationSuccess(result),
    /changed after validation/,
  );
  mutableArtifact.prospectiveReplayKey = originalReplayKey;
  assert.doesNotThrow(() =>
    assertTrustedMarketplaceEvaluationSuccess(result),
  );
  assert.equal(routes.filter((route) => route.kind === "a2a-quote").length, 1);
});

test("marketplace evaluation never returns success for refusal, preview failure, or final-time failure", async () => {
  const provider = TEST_ACCOUNT.address.toLowerCase() as `0x${string}`;
  const cases = ["refused", "invalid", "inconclusive", "final_time"] as const;

  for (const scenario of cases) {
    const fixture = validFixture(false, provider);
    const mandate = validMandate();
    const snapshots = previewSnapshots(provider);
    const nearExpiry = NOW_SECONDS + MIN_QUOTE_REMAINING_SECONDS + 1;
    const envelope = await signedEnvelope(
      mandate,
      scenario === "final_time" ? { quoteExpiresAt: nearExpiry } : {},
    );
    const refusedResponse = (requestId: string) => ({
      jsonrpc: "2.0",
      id: requestId,
      result: {
        kind: "message",
        role: "agent",
        messageId: "server-message",
        parts: [
          {
            kind: "data",
            data: {
              request: {},
              request_hash: "",
              response: {
                accepted: false,
                reason_code: "0x06",
                reason: "unsupported category",
              },
              response_hash: "",
              negotiation_hash: "",
              provider_sig: "",
            },
          },
        ],
      },
    });
    const result = await validateTrustedPreviewForMarketplaceEvaluation(
      {
        manifest: fixture.manifest,
        passiveReport: fixture.report,
        trustFile: fixture.trustFile,
        candidate: { chainId: 56, tokenId: "1" },
        mandate,
        transactionPlan: previewTransactionPlan(
          provider,
          scenario === "final_time"
            ? BigInt(nearExpiry)
            : BigInt(NOW_SECONDS + 300),
        ),
        transport: quoteTransport([], (requestId) =>
          scenario === "refused"
            ? refusedResponse(requestId)
            : successA2aResponse(requestId, envelope),
        ),
        now:
          scenario === "final_time"
            ? sequentialClock(NOW, NOW, NOW, new Date(NOW.valueOf() + 2_000))
            : () => NOW,
        randomUUID: sequentialId(),
      },
      {
        stateVerifier: async (options): Promise<PancakeStateResult> => {
          if (scenario === "inconclusive") {
            return {
              status: "inconclusive",
              code: "RPC_UNAVAILABLE",
              message: "state RPC unavailable",
              attempts: 1,
            };
          }
          return {
            status: "verified",
            snapshot:
              options.target?.mode === "exact"
                ? snapshots.signed
                : snapshots.fresh,
          };
        },
        simulate: async () => {
          if (scenario === "invalid") {
            throw new PreviewSimulationError("reverted", {
              requestSha256: "d".repeat(64),
              responseSha256: "e".repeat(64),
            });
          }
          return {
            rawResult: previewSimulationResult(),
            requestSha256: "d".repeat(64),
            responseSha256: "e".repeat(64),
          };
        },
        assertCanonical: async () => undefined,
      },
    );

    assert.notEqual(result.outcome, "verified_unreserved", scenario);
    assert.equal("artifact" in result, false, scenario);
    if (result.outcome !== "verified_unreserved") {
      assert.equal(result.quote.replayStatus, "not_attempted", scenario);
      assert.notEqual(result.quote.outcome, "valid", scenario);
    }
  }
});

test("activation preview still claims replay and excludes the signed snapshot extension", async () => {
  const provider = TEST_ACCOUNT.address.toLowerCase() as `0x${string}`;
  const fixture = validFixture(false, provider);
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const replay = memoryReplayStore("claimed");
  const snapshots = previewSnapshots(provider);

  const result = await validateTrustedPreviewForActivation(
    {
      manifest: fixture.manifest,
      passiveReport: fixture.report,
      trustFile: fixture.trustFile,
      candidate: { chainId: 56, tokenId: "1" },
      mandate,
      transactionPlan: previewTransactionPlan(provider),
      transport: quoteTransport([], (requestId) =>
        successA2aResponse(requestId, envelope),
      ),
      replayStore: replay,
      now: () => NOW,
      randomUUID: sequentialId(),
    },
    passingPreviewDependencies(snapshots),
  );

  assert.equal(result.sidecar.outcome, "preview_simulation_passed");
  assert.equal(result.sidecar.quote.replayStatus, "claimed");
  assert.equal(replay.prepareCalls, 1);
  assert.equal(replay.claims.length, 1);
  assert.ok(result.projection);
  assert.equal("signedSnapshot" in result.projection.preview, false);
});

test("trusted preview rechecks the transaction deadline at replay decision time", async () => {
  const provider = TEST_ACCOUNT.address.toLowerCase() as `0x${string}`;
  const fixture = validFixture(false, provider);
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const replay = memoryReplayStore("claimed");
  const snapshots = previewSnapshots(provider);
  const decisionTime = new Date(NOW.valueOf() + 1_500);

  const sidecar = await validateTrustedPreview(
    {
      manifest: fixture.manifest,
      passiveReport: fixture.report,
      trustFile: fixture.trustFile,
      candidate: { chainId: 56, tokenId: "1" },
      mandate,
      transactionPlan: previewTransactionPlan(
        provider,
        BigInt(NOW_SECONDS + 31),
      ),
      transport: quoteTransport([], (requestId) =>
        successA2aResponse(requestId, envelope),
      ),
      replayStore: replay,
      now: sequentialClock(NOW, NOW, NOW, decisionTime),
      randomUUID: sequentialId(),
    },
    {
      stateVerifier: async (options): Promise<PancakeStateResult> => ({
        status: "verified",
        snapshot:
          options.target?.mode === "exact" ? snapshots.signed : snapshots.fresh,
      }),
      simulate: async () => ({
        rawResult: previewSimulationResult(),
        requestSha256: "d".repeat(64),
        responseSha256: "e".repeat(64),
      }),
      assertCanonical: async () => undefined,
    },
  );

  assert.equal(sidecar.outcome, "invalid");
  assert.equal(sidecar.errorCode, "PREVIEW_EXPIRED");
  assert.equal(sidecar.gates.transactionPolicy, "fail");
  assert.equal(sidecar.gates.evmSimulation, "pass");
  assert.equal(sidecar.quote.replayStatus, "not_attempted");
  assert.equal(replay.claims.length, 0);
});

test("trusted preview preserves invalid artifacts for final quote and authority expiry", async () => {
  const provider = TEST_ACCOUNT.address.toLowerCase() as `0x${string}`;
  const nearExpiry = NOW_SECONDS + MIN_QUOTE_REMAINING_SECONDS + 1;

  for (const field of ["quote", "mandate", "permissions"] as const) {
    const fixture = validFixture(false, provider);
    const base = validMandate();
    const mandate = quoteMandatexRebalanceMandateSchema.parse({
      ...base,
      expires_at: field === "mandate" ? nearExpiry : base.expires_at,
      permissions: {
        ...base.permissions,
        expires_at:
          field === "mandate" || field === "permissions"
            ? nearExpiry
            : base.permissions.expires_at,
      },
    });
    const envelope = await signedEnvelope(mandate, {
      quoteExpiresAt: nearExpiry,
    });
    const replay = memoryReplayStore("claimed");
    const snapshots = previewSnapshots(provider);
    const decisionTime = new Date(NOW.valueOf() + 2_000);
    let simulationCalls = 0;

    const sidecar = await validateTrustedPreview(
      {
        manifest: fixture.manifest,
        passiveReport: fixture.report,
        trustFile: fixture.trustFile,
        candidate: { chainId: 56, tokenId: "1" },
        mandate,
        transactionPlan: previewTransactionPlan(
          provider,
          BigInt(nearExpiry),
        ),
        transport: quoteTransport([], (requestId) =>
          successA2aResponse(requestId, envelope),
        ),
        replayStore: replay,
        now: sequentialClock(NOW, NOW, NOW, decisionTime),
        randomUUID: sequentialId(),
      },
      {
        stateVerifier: async (options): Promise<PancakeStateResult> => ({
          status: "verified",
          snapshot:
            options.target?.mode === "exact" ? snapshots.signed : snapshots.fresh,
        }),
        simulate: async () => {
          simulationCalls += 1;
          return {
            rawResult: previewSimulationResult(),
            requestSha256: "d".repeat(64),
            responseSha256: "e".repeat(64),
          };
        },
        assertCanonical: async () => undefined,
      },
    );

    assert.equal(simulationCalls, 1, field);
    assert.equal(sidecar.outcome, "invalid", field);
    assert.equal(sidecar.errorCode, "PREVIEW_EXPIRED", field);
    assert.equal(sidecar.gates.transactionPolicy, "fail", field);
    assert.equal(sidecar.gates.evmSimulation, "pass", field);
    assert.equal(sidecar.quote.replayStatus, "not_attempted", field);
    assert.equal(replay.claims.length, 0, field);
  }
});

test("trusted preview records definitive simulation failures and consumes no replay", async () => {
  const provider = TEST_ACCOUNT.address.toLowerCase() as `0x${string}`;
  for (const failure of ["reverted", "malformed"] as const) {
    const fixture = validFixture(false, provider);
    const mandate = validMandate();
    const envelope = await signedEnvelope(mandate);
    const replay = memoryReplayStore("claimed");
    const snapshots = previewSnapshots(provider);

    const sidecar = await validateTrustedPreview(
      {
        manifest: fixture.manifest,
        passiveReport: fixture.report,
        trustFile: fixture.trustFile,
        candidate: { chainId: 56, tokenId: "1" },
        mandate,
        transactionPlan: previewTransactionPlan(provider),
        transport: quoteTransport([], (requestId) =>
          successA2aResponse(requestId, envelope),
        ),
        replayStore: replay,
        now: () => NOW,
        randomUUID: sequentialId(),
      },
      {
        stateVerifier: async (options): Promise<PancakeStateResult> => ({
          status: "verified",
          snapshot:
            options.target?.mode === "exact" ? snapshots.signed : snapshots.fresh,
        }),
        simulate: async () => {
          if (failure === "reverted") {
            throw new PreviewSimulationError("reverted", {
              requestSha256: "d".repeat(64),
              responseSha256: "e".repeat(64),
            });
          }
          return {
            rawResult: "0x1234",
            requestSha256: "d".repeat(64),
            responseSha256: "e".repeat(64),
          };
        },
        assertCanonical: async () => undefined,
      },
    );

    assert.equal(
      sidecar.errorCode,
      failure === "reverted"
        ? "EVM_SIMULATION_REVERTED"
        : "EVM_SIMULATION_INVALID",
    );
    assert.equal(sidecar.gates.evmSimulation, "fail");
    assert.equal(sidecar.quote.replayStatus, "not_attempted");
    assert.equal(replay.claims.length, 0);
  }
});

test("trusted preview rechecks the signed block after simulation", async () => {
  const provider = TEST_ACCOUNT.address.toLowerCase() as `0x${string}`;
  const fixture = validFixture(false, provider);
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const replay = memoryReplayStore("claimed");
  const snapshots = previewSnapshots(provider);
  const checkedBlocks: string[] = [];

  const sidecar = await validateTrustedPreview(
    {
      manifest: fixture.manifest,
      passiveReport: fixture.report,
      trustFile: fixture.trustFile,
      candidate: { chainId: 56, tokenId: "1" },
      mandate,
      transactionPlan: previewTransactionPlan(provider),
      transport: quoteTransport([], (requestId) =>
        successA2aResponse(requestId, envelope),
      ),
      replayStore: replay,
      now: () => NOW,
      randomUUID: sequentialId(),
    },
    {
      stateVerifier: async (options): Promise<PancakeStateResult> => ({
        status: "verified",
        snapshot:
          options.target?.mode === "exact" ? snapshots.signed : snapshots.fresh,
      }),
      simulate: async () => ({
        rawResult: previewSimulationResult(),
        requestSha256: "d".repeat(64),
        responseSha256: "e".repeat(64),
      }),
      assertCanonical: async ({ blockNumber }) => {
        checkedBlocks.push(blockNumber);
        if (blockNumber === snapshots.signed.pin.observedBlockNumber) {
          throw new Error("signed block was reorganized");
        }
      },
    },
  );

  assert.deepEqual(checkedBlocks, [snapshots.signed.pin.observedBlockNumber]);
  assert.equal(sidecar.outcome, "inconclusive");
  assert.equal(sidecar.errorCode, "PREVIEW_STATE_UNAVAILABLE");
  assert.equal(sidecar.quote.replayStatus, "not_attempted");
  assert.equal(replay.claims.length, 0);
});

test("ERC-1271 quote validation checks code and signature at the passive block", async () => {
  const fixture = validFixture();
  fixture.trustFile = quoteTrustFileSchema.parse({
    ...fixture.trustFile,
    candidates: fixture.trustFile.candidates.map((entry) => ({
      ...entry,
      providerKind: "erc1271",
    })),
  });
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const routes: TransportRoute[] = [];

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    replayStore: memoryReplayStore("claimed"),
    transport: erc1271QuoteTransport(routes, envelope),
    now: () => NOW,
    randomUUID: sequentialId(),
  });

  assert.equal(sidecar.outcome, "valid");
  assert.equal(sidecar.signatureMethod, "erc1271");
  assert.equal(routes.filter((route) => route.kind === "a2a-quote").length, 1);
  assert.deepEqual(
    routes
      .filter((route) => route.kind === "bsc-quote-rpc")
      .map((route) => route.rpcMethod),
    ["eth_getCode", "eth_call"],
  );
});

test("expired mandate authority fails before replay preparation or quote network calls", async () => {
  for (const field of ["mandate", "permissions"] as const) {
    const fixture = validFixture();
    const base = validMandate();
    const mandate = quoteMandatexRebalanceMandateSchema.parse({
      ...base,
      expires_at: field === "mandate" ? NOW_SECONDS : base.expires_at,
      permissions: {
        ...base.permissions,
        expires_at:
          field === "mandate" || field === "permissions"
            ? NOW_SECONDS
            : base.permissions.expires_at,
      },
    });
    const routes: TransportRoute[] = [];
    const replay = memoryReplayStore("claimed");

    await assert.rejects(
      validateTrustedQuote({
        manifest: fixture.manifest,
        passiveReport: fixture.report,
        trustFile: fixture.trustFile,
        candidate: { chainId: 56, tokenId: "1" },
        mandate,
        transport: quoteTransport(routes, () => ({})),
        replayStore: replay,
        now: () => NOW,
        randomUUID: sequentialId(),
      }),
      (error: unknown) =>
        error instanceof QuotePreflightError && error.code === "MANDATE_EXPIRED",
      field,
    );
    assert.equal(replay.prepareCalls, 0, field);
    assert.equal(routes.length, 0, field);
  }
});

test("final decision time rejects a quote that expires during ERC-1271 verification", async () => {
  const fixture = validFixture();
  fixture.trustFile = quoteTrustFileSchema.parse({
    ...fixture.trustFile,
    candidates: fixture.trustFile.candidates.map((entry) => ({
      ...entry,
      providerKind: "erc1271",
    })),
  });
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate, {
    quoteExpiresAt:
      NOW_SECONDS + MIN_QUOTE_REMAINING_SECONDS + 1,
  });
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("claimed");
  const decisionTime = new Date(NOW.valueOf() + 2_000);

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    replayStore: replay,
    transport: erc1271QuoteTransport(routes, envelope),
    now: sequentialClock(NOW, NOW, decisionTime),
    randomUUID: sequentialId(),
  });

  assert.equal(sidecar.outcome, "invalid");
  assert.equal(sidecar.errorCode, "QUOTE_POLICY_REJECTED");
  assert.equal(sidecar.observedAt, decisionTime.toISOString());
  assert.equal(replay.claims.length, 0);
  assert.deepEqual(
    routes
      .filter((route) => route.kind === "bsc-quote-rpc")
      .map((route) => route.rpcMethod),
    ["eth_getCode", "eth_call"],
  );
});

test("final decision time rechecks mandate and permission expiry before replay", async () => {
  for (const field of ["mandate", "permissions"] as const) {
    const fixture = validFixture(false, TEST_ACCOUNT.address.toLowerCase());
    const base = validMandate();
    const nearExpiry = NOW_SECONDS + MIN_QUOTE_REMAINING_SECONDS + 1;
    const mandate = quoteMandatexRebalanceMandateSchema.parse({
      ...base,
      expires_at: field === "mandate" ? nearExpiry : base.expires_at,
      permissions: {
        ...base.permissions,
        expires_at: nearExpiry,
      },
    });
    const envelope = await signedEnvelope(mandate, {
      quoteExpiresAt: nearExpiry,
    });
    const routes: TransportRoute[] = [];
    const replay = memoryReplayStore("claimed");
    const decisionTime = new Date(NOW.valueOf() + 2_000);

    const sidecar = await validateTrustedQuote({
      manifest: fixture.manifest,
      passiveReport: fixture.report,
      trustFile: fixture.trustFile,
      candidate: { chainId: 56, tokenId: "1" },
      mandate,
      transport: quoteTransport(routes, (requestId) =>
        successA2aResponse(requestId, envelope),
      ),
      replayStore: replay,
      now: sequentialClock(NOW, NOW, decisionTime),
      randomUUID: sequentialId(),
    });

    assert.equal(sidecar.outcome, "invalid", field);
    assert.equal(sidecar.errorCode, "QUOTE_POLICY_REJECTED", field);
    assert.equal(sidecar.observedAt, decisionTime.toISOString(), field);
    assert.equal(replay.claims.length, 0, field);
  }
});

test("final decision time rechecks signed evidence freshness before replay", async () => {
  const fixture = validFixture(false, TEST_ACCOUNT.address.toLowerCase());
  const base = validMandate();
  const mandate = quoteMandatexRebalanceMandateSchema.parse({
    ...base,
    max_evidence_age_seconds: 5,
    execution_estimate: {
      ...base.execution_estimate,
      observed_at: NOW_SECONDS,
    },
  });
  const envelope = await signedEnvelope(mandate, {
    evidenceObservedAt: NOW_SECONDS - 4,
  });
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("claimed");
  const decisionTime = new Date(NOW.valueOf() + 2_000);

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    transport: quoteTransport(routes, (requestId) =>
      successA2aResponse(requestId, envelope),
    ),
    replayStore: replay,
    now: sequentialClock(NOW, NOW, decisionTime),
    randomUUID: sequentialId(),
  });

  assert.equal(sidecar.outcome, "invalid");
  assert.equal(sidecar.errorCode, "MANDATE_BINDING_MISMATCH");
  assert.equal(sidecar.observedAt, decisionTime.toISOString());
  assert.equal(replay.claims.length, 0);
});

test("final decision time rechecks outbound estimate freshness before replay", async () => {
  const fixture = validFixture(false, TEST_ACCOUNT.address.toLowerCase());
  const base = validMandate();
  const mandate = quoteMandatexRebalanceMandateSchema.parse({
    ...base,
    max_evidence_age_seconds: 5,
    execution_estimate: {
      ...base.execution_estimate,
      observed_at: NOW_SECONDS - 4,
    },
  });
  const envelope = await signedEnvelope(mandate, {
    evidenceObservedAt: NOW_SECONDS,
  });
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("claimed");
  const decisionTime = new Date(NOW.valueOf() + 2_000);

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    transport: quoteTransport(routes, (requestId) =>
      successA2aResponse(requestId, envelope),
    ),
    replayStore: replay,
    now: sequentialClock(NOW, NOW, decisionTime),
    randomUUID: sequentialId(),
  });

  assert.equal(sidecar.outcome, "invalid");
  assert.equal(sidecar.errorCode, "QUOTE_POLICY_REJECTED");
  assert.equal(sidecar.observedAt, decisionTime.toISOString());
  assert.equal(replay.claims.length, 0);
});

test("final decision time rechecks passive evidence freshness before replay", async () => {
  const fixture = validFixture(false, TEST_ACCOUNT.address.toLowerCase());
  fixture.trustFile = quoteTrustFileSchema.parse({
    ...fixture.trustFile,
    candidates: fixture.trustFile.candidates.map((entry) => ({
      ...entry,
      maxPassiveAgeSeconds: 31,
    })),
  });
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("claimed");
  const decisionTime = new Date(NOW.valueOf() + 2_000);

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    transport: quoteTransport(routes, (requestId) =>
      successA2aResponse(requestId, envelope),
    ),
    replayStore: replay,
    now: sequentialClock(NOW, NOW, decisionTime),
    randomUUID: sequentialId(),
  });

  assert.equal(sidecar.outcome, "invalid");
  assert.equal(sidecar.errorCode, "PASSIVE_PREFLIGHT_FAILED");
  assert.equal(sidecar.gates.passivePreflight, "fail");
  assert.equal(sidecar.observedAt, decisionTime.toISOString());
  assert.equal(replay.claims.length, 0);
});

test("duplicate replay returns an invalid sidecar without a second quote POST", async () => {
  const fixture = validFixture(false, TEST_ACCOUNT.address.toLowerCase());
  const mandate = validMandate();
  const envelope = await signedEnvelope(mandate);
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("duplicate");

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    transport: quoteTransport(routes, (requestId) =>
      successA2aResponse(requestId, envelope),
    ),
    replayStore: replay,
    now: () => NOW,
    randomUUID: sequentialId(),
  });

  assert.equal(sidecar.outcome, "invalid");
  assert.equal(sidecar.errorCode, "REPLAY_DETECTED");
  assert.equal(sidecar.replayStatus, "duplicate");
  assert.equal(sidecar.gates.replay, "fail");
  assert.equal(routes.filter((route) => route.kind === "a2a-quote").length, 1);
});

test("remote refusal is auditable but never reaches signature or replay validation", async () => {
  const fixture = validFixture();
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("claimed");
  const mandate = validMandate();

  const sidecar = await validateTrustedQuote({
    manifest: fixture.manifest,
    passiveReport: fixture.report,
    trustFile: fixture.trustFile,
    candidate: { chainId: 56, tokenId: "1" },
    mandate,
    transport: quoteTransport(routes, (requestId) => ({
      jsonrpc: "2.0",
      id: requestId,
      result: {
        kind: "message",
        role: "agent",
        messageId: "server-message",
        parts: [
          {
            kind: "data",
            data: {
              request: {},
              request_hash: "",
              response: {
                accepted: false,
                reason_code: "0x06",
                reason: "unsupported category",
              },
              response_hash: "",
              negotiation_hash: "",
              provider_sig: "",
              mandatex: {
                eligible: false,
                refusal: {
                  code: "UNSUPPORTED_CATEGORY",
                  message: "unsupported category",
                },
              },
            },
          },
        ],
      },
    })),
    replayStore: replay,
    now: () => NOW,
    randomUUID: sequentialId(),
  });

  assert.equal(sidecar.outcome, "refused");
  assert.equal(sidecar.refusalCode, "UNSUPPORTED_CATEGORY");
  assert.equal(sidecar.gates.quoteSignature, "unknown");
  assert.equal(replay.claims.length, 0);
  assert.equal(routes.filter((route) => route.kind === "a2a-quote").length, 1);
});

test("preflight and replay preparation failures perform zero network calls", async () => {
  const invalid = validFixture();
  invalid.report = replaceSelectedCandidate(invalid.report, (candidate) => ({
    ...candidate,
    status: "UNAVAILABLE",
  }));
  const invalidRoutes: TransportRoute[] = [];
  const invalidReplay = memoryReplayStore("claimed");

  await assert.rejects(
    validateTrustedQuote({
      manifest: invalid.manifest,
      passiveReport: invalid.report,
      trustFile: invalid.trustFile,
      candidate: { chainId: 56, tokenId: "1" },
      mandate: validMandate(),
      transport: quoteTransport(invalidRoutes, () => ({})),
      replayStore: invalidReplay,
      now: () => NOW,
      randomUUID: sequentialId(),
    }),
    (error: unknown) =>
      error instanceof QuotePreflightError &&
      error.code === "CANDIDATE_NOT_REGISTERED",
  );
  assert.equal(invalidReplay.prepareCalls, 0);
  assert.equal(invalidRoutes.length, 0);

  const fixture = validFixture();
  const prepareRoutes: TransportRoute[] = [];
  const unavailableReplay: ReplayStore = {
    async prepare() {
      throw new Error("unavailable");
    },
    async claim() {
      throw new Error("unreachable");
    },
  };
  await assert.rejects(
    validateTrustedQuote({
      manifest: fixture.manifest,
      passiveReport: fixture.report,
      trustFile: fixture.trustFile,
      candidate: { chainId: 56, tokenId: "1" },
      mandate: validMandate(),
      transport: quoteTransport(prepareRoutes, () => ({})),
      replayStore: unavailableReplay,
      now: () => NOW,
      randomUUID: sequentialId(),
    }),
    (error: unknown) =>
      error instanceof QuotePreflightError &&
      error.code === "REPLAY_STORE_UNAVAILABLE",
  );
  assert.equal(prepareRoutes.length, 0);
});

test("trusted registry tampering fails closed before replay or quote network calls", async () => {
  const fixture = validFixture();
  fixture.trustFile = quoteTrustFileSchema.parse({
    ...fixture.trustFile,
    candidates: fixture.trustFile.candidates.map((entry) => ({
      ...entry,
      registryAddress: OTHER_REGISTRY,
    })),
  });
  const routes: TransportRoute[] = [];
  const replay = memoryReplayStore("claimed");

  await assert.rejects(
    validateTrustedQuote({
      manifest: fixture.manifest,
      passiveReport: fixture.report,
      trustFile: fixture.trustFile,
      candidate: { chainId: 56, tokenId: "1" },
      mandate: validMandate(),
      transport: quoteTransport(routes, () => ({})),
      replayStore: replay,
      now: () => NOW,
      randomUUID: sequentialId(),
    }),
    (error: unknown) =>
      error instanceof QuotePreflightError &&
      error.code === "TRUSTED_REGISTRY_CONFLICT",
  );
  assert.equal(replay.prepareCalls, 0);
  assert.equal(routes.length, 0);
});

function validFixture(
  includeUnrelatedInconclusive = false,
  provider = PROVIDER,
): {
  manifest: ManifestFile;
  report: RunReport;
  trustFile: QuoteTrustFile;
} {
  const manifest = manifestFileSchema.parse({
    version: 1,
    candidates: [
      manifestCandidate("1", "agent"),
      ...(includeUnrelatedInconclusive
        ? [manifestCandidate("2", "other")]
        : []),
    ],
  });
  const selected = selectedReportCandidate(provider);
  const report = buildReport({
    generatedAt: "2026-08-16T11:59:45.000Z",
    chainProfile: DEFAULT_CHAIN_PROFILE,
    policyFingerprint: POLICY_FINGERPRINT,
    candidates: [
      selected,
      ...(includeUnrelatedInconclusive
        ? [
            {
              ...baseReportCandidate("2", "other"),
              status: "INCONCLUSIVE" as const,
            },
          ]
        : []),
    ],
  });
  const trustFile = quoteTrustFileSchema.parse({
    schema: QUOTE_TRUST_SCHEMA,
    candidates: [
      {
        chainId: 56,
        registryAddress: DEFAULT_CHAIN_PROFILE.registryAddress,
        tokenId: "1",
        category: "rebalancing",
        cardUrl: "https://agent.example/.well-known/agent-card.json",
        quoteEndpoint: "https://agent.example/",
        expectedProvider: provider,
        providerKind: "eoa",
        commerceContract: COMMERCE,
        protocol: {
          a2a: "0.3.x",
          method: "message/send",
          skill: "negotiate",
          signature: "eip191-negotiation-hash-string",
          signedTaskCodec: "mandatex-rebalance:v1",
        },
        maxPassiveAgeSeconds: 300,
        maxQuoteTtlSeconds: 900,
        maxClockSkewSeconds: 30,
        allowedCurrencies: [COMMERCE],
        maxPrice: "1000000000000000000",
      },
    ],
  });
  return { manifest, report, trustFile };
}

function manifestCandidate(tokenId: string, host: string) {
  return {
    chainId: 56,
    tokenId,
    expectedName: `${host} candidate`,
    expectedEndpoint: `https://${host}.example/.well-known/agent-card.json`,
    expectedOrigin: `https://${host}.example`,
    categories: ["rebalancing"],
    source: "8004scan" as const,
  };
}

function baseReportCandidate(
  tokenId: string,
  host: string,
): CandidateReportInput {
  return {
    chainId: 56,
    tokenId,
    expectedName: `${host} candidate`,
    expectedEndpoint: `https://${host}.example/.well-known/agent-card.json`,
    expectedOrigin: `https://${host}.example`,
    categories: ["rebalancing"],
  };
}

function selectedReportCandidate(provider = PROVIDER): CandidateReportInput {
  return {
    ...baseReportCandidate("1", "agent"),
    status: "REGISTERED_ONLY",
    gates: [
      passGate("manifest_identity", "claimed", "manifest.candidate"),
      passGate("bsc_chain", "verified", "chain.owner-of"),
      passGate("token_ownership", "verified", "chain.owner-of"),
      passGate("endpoint_origin", "claimed", "manifest.candidate"),
      passGate("endpoint_health", "detected", "card.http"),
      passGate("task_interface", "detected", "card.http"),
      {
        gate: "quote_signature",
        state: "unknown",
        evidence: [],
        evidenceRefs: [],
      },
    ],
    chain: {
      chainId: 56,
      registryAddress: DEFAULT_CHAIN_PROFILE.registryAddress,
      tokenId: "1",
      owner: provider,
      observedBlock: 100,
      observedBlockHash: BLOCK_HASH,
      confirmationDepth: 2,
      registryCodeHash: CODE_HASH,
      observedAt: "2026-08-16T11:59:30.000Z",
      responseHash: RESPONSE_HASH,
    },
    card: {
      url: "https://agent.example/",
      observedAt: "2026-08-16T11:59:35.000Z",
      responseHash: RESPONSE_HASH,
      protocolVersion: "0.3.0",
      preferredTransport: "JSONRPC",
      skills: [
        {
          id: "negotiate",
          name: "Negotiate",
          description: "Return a signed quote.",
          tags: ["erc8183"],
          inputModes: ["application/json"],
          outputModes: ["application/json"],
        },
      ],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
    scan: {
      indexed: true,
      observedAt: "2026-08-16T11:59:25.000Z",
      agentWallet: provider,
    },
  };
}

function validMandate(): QuoteMandatexRebalanceMandate {
  return quoteMandatexRebalanceMandateSchema.parse({
    version: "1",
    mandate_id: "mandate-1",
    category: "rebalancing",
    chain_id: 56,
    protocol: "pancakeswap-v3",
    expires_at: NOW_SECONDS + 3_600,
    max_evidence_age_seconds: 120,
    position: {
      pool_address: `0x${"4".repeat(40)}`,
      position_manager_address: POSITION_MANAGER,
      token_id: "9",
    },
    range_policy: {
      approved_lower_tick: -400,
      approved_upper_tick: 400,
      target_width_ticks: 200,
      trigger_mode: "boundary_proximity",
      trigger_distance_ticks: 20,
      max_delivery_tick_drift: 10,
    },
    limits: {
      max_gas_usd: 10,
      max_slippage_bps: 50,
      max_exposure_usd: 1_000,
    },
    execution_estimate: {
      gas_usd: 5,
      slippage_bps: 20,
      exposure_usd: 500,
      observed_at: NOW_SECONDS - 30,
      source_url: "https://evidence.example/estimate",
    },
    permissions: {
      allowed_contracts: [POSITION_MANAGER],
      allowed_calls: [...REQUIRED_CALLS],
      spend_cap_usd: 500,
      expires_at: NOW_SECONDS + 1_800,
    },
  });
}

async function signedEnvelope(
  mandate: QuoteMandatexRebalanceMandate,
  options: Readonly<{
    quoteExpiresAt?: number;
    evidenceObservedAt?: number;
    proposedLowerTick?: number;
    proposedUpperTick?: number;
  }> = {},
): Promise<QuoteAcceptedEnvelope> {
  const signedTask = {
    schema: "mandatex.rebalance.quote.v1",
    mandate,
    evidence: {
      network: "bsc-mainnet",
      chain_id: 56,
      snapshot_head_block: 102,
      confirmation_depth_blocks: 2,
      observed_block: 100,
      observed_block_hash: `0x${"d".repeat(64)}`,
      observed_at: options.evidenceObservedAt ?? NOW_SECONDS - 20,
      pool_address: `0x${"4".repeat(40)}`,
      position_manager_address: POSITION_MANAGER,
      position_token_id: "9",
      position_owner: TEST_ACCOUNT.address,
      token0: `0x${"7".repeat(40)}`,
      token1: `0x${"8".repeat(40)}`,
      token0_decimals: 18,
      token1_decimals: 18,
      fee: 500,
      tick_spacing: 10,
      current_tick: 95,
      sqrt_price_x96: "79228162514264337593543950336",
      approximate_token1_per_token0: "1",
      position_tick_lower: -100,
      position_tick_upper: 100,
      pool_liquidity: "1000000",
      position_liquidity: "1000",
      sources: [
        {
          type: "onchain",
          url: "https://bscscan.com/block/100",
          observed_block: 100,
        },
      ],
    },
    proposal: {
      execution_mode: "simulation",
      proposed_lower_tick: options.proposedLowerTick ?? 0,
      proposed_upper_tick: options.proposedUpperTick ?? 200,
      trigger: {
        fired: true,
        reason: "near_range_boundary",
        distance_to_boundary_ticks: 5,
      },
      estimated_gas_usd: 5,
      estimated_slippage_bps: 20,
      estimated_exposure_usd: 500,
      estimate_source_url: "https://evidence.example/estimate",
      permissions: {
        contracts: [POSITION_MANAGER],
        calls: [...REQUIRED_CALLS],
        spend_cap_usd: 500,
        expires_at: mandate.permissions.expires_at,
      },
      break_even: {
        status: "not_calculated",
        reason: "not required for test",
      },
    },
    eligibility: {
      eligible: true,
      checked_at: NOW_SECONDS - 10,
      checks: ["range", "permissions"],
    },
  };
  const taskDescription = `mandatex-rebalance:v1:${deflateRawSync(
    Buffer.from(canonicalQuoteJson(signedTask), "utf8"),
  ).toString("base64url")}`;
  const request = {
    task_description: taskDescription,
    terms: {
      deliverables: "rebalance position",
      quality_standards: "match the signed mandate",
      evaluation_required: true,
      evaluator_type: "uma_oov3",
      success_criteria: ["position is rebalanced"],
    },
  };
  const response = {
    accepted: true as const,
    terms: {
      ...request.terms,
      price: "1000",
      currency: COMMERCE,
    },
    estimated_completion_seconds: 300,
    quote_expires_at: options.quoteExpiresAt ?? NOW_SECONDS + 600,
    negotiated_at: NOW_SECONDS,
  };
  let envelope: QuoteAcceptedEnvelope = {
    request,
    request_hash: computeQuoteRequestHash(request),
    response,
    response_hash: computeQuoteResponseHash(response),
    negotiation_hash: `0x${"0".repeat(64)}`,
    provider_sig: "0x00",
    chain_id: 56,
    verifying_contract: COMMERCE,
  };
  envelope = {
    ...envelope,
    negotiation_hash: computeQuoteNegotiationHash(envelope),
  };
  return {
    ...envelope,
    provider_sig: await TEST_ACCOUNT.signMessage({
      message: envelope.negotiation_hash,
    }),
  };
}

function previewTransactionPlan(
  provider: `0x${string}`,
  deadline = BigInt(NOW_SECONDS + 300),
) {
  const maxUint128 = (1n << 128n) - 1n;
  const calls: [Hex, Hex, Hex] = [
    encodeFunctionData({
      abi: previewDecreaseLiquidityAbi,
      functionName: "decreaseLiquidity",
      args: [
        {
          tokenId: 9n,
          liquidity: 1_000n,
          amount0Min: 896n,
          amount1Min: 1_791n,
          deadline,
        },
      ],
    }),
    encodeFunctionData({
      abi: previewCollectAbi,
      functionName: "collect",
      args: [
        {
          tokenId: 9n,
          recipient: provider,
          amount0Max: maxUint128,
          amount1Max: maxUint128,
        },
      ],
    }),
    encodeFunctionData({
      abi: previewMintAbi,
      functionName: "mint",
      args: [
        {
          token0: `0x${"7".repeat(40)}`,
          token1: `0x${"8".repeat(40)}`,
          fee: 500,
          tickLower: 0,
          tickUpper: 200,
          amount0Desired: 1_000n,
          amount1Desired: 2_000n,
          amount0Min: 995n,
          amount1Min: 1_990n,
          recipient: provider,
          deadline,
        },
      ],
    }),
  ];
  return {
    schema: "mandatex.rebalance.transaction-plan.v1" as const,
    chainId: 56 as const,
    from: provider,
    to: POSITION_MANAGER,
    valueWei: "0",
    data: encodeFunctionData({
      abi: previewMulticallAbi,
      functionName: "multicall",
      args: [calls],
    }),
  };
}

function previewSimulationResult(): Hex {
  const decrease = encodeFunctionResult({
    abi: previewDecreaseLiquidityAbi,
    functionName: "decreaseLiquidity",
    result: [900n, 1_800n],
  });
  const collect = encodeFunctionResult({
    abi: previewCollectAbi,
    functionName: "collect",
    result: [1_000n, 2_000n],
  });
  const mint = encodeFunctionResult({
    abi: previewMintAbi,
    functionName: "mint",
    result: [10n, 500n, 1_000n, 2_000n],
  });
  return encodeFunctionResult({
    abi: previewMulticallAbi,
    functionName: "multicall",
    result: [decrease, collect, mint],
  });
}

function previewSnapshots(provider: string): Readonly<{
  signed: PancakeStateSnapshot;
  fresh: PancakeStateSnapshot;
}> {
  const signed = previewSnapshot({
    provider,
    mode: "exact",
    head: null,
    block: "100",
    blockHash: `0x${"d".repeat(64)}`,
    timestamp: (NOW_SECONDS - 20).toString(),
    currentTick: 95,
    poolLiquidity: "1000000",
  });
  const fresh = previewSnapshot({
    provider,
    mode: "fresh",
    head: "105",
    block: "103",
    blockHash: `0x${"f".repeat(64)}`,
    timestamp: NOW_SECONDS.toString(),
    currentTick: 96,
    poolLiquidity: "1000100",
  });
  return { signed, fresh };
}

function passingPreviewDependencies(
  snapshots: ReturnType<typeof previewSnapshots>,
): NonNullable<
  Parameters<typeof validateTrustedPreviewForMarketplaceEvaluation>[1]
> {
  return {
    stateVerifier: async (options): Promise<PancakeStateResult> => ({
      status: "verified",
      snapshot:
        options.target?.mode === "exact" ? snapshots.signed : snapshots.fresh,
    }),
    simulate: async () => ({
      rawResult: previewSimulationResult(),
      requestSha256: "d".repeat(64),
      responseSha256: "e".repeat(64),
    }),
    assertCanonical: async () => undefined,
  };
}

function previewSnapshot(input: {
  provider: string;
  mode: "exact" | "fresh";
  head: string | null;
  block: string;
  blockHash: string;
  timestamp: string;
  currentTick: number;
  poolLiquidity: string;
}): PancakeStateSnapshot {
  const pool = `0x${"4".repeat(40)}`;
  const token0 = `0x${"7".repeat(40)}`;
  const token1 = `0x${"8".repeat(40)}`;
  const code = { bytes: 4, sha256: "a".repeat(64) };
  const emptyCode = { bytes: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" };
  return {
    chainId: 56,
    pin: {
      mode: input.mode,
      headBlockNumber: input.head,
      observedBlockNumber: input.block,
      observedBlockHash: input.blockHash,
      observedAt: input.timestamp,
      confirmationDepth: input.mode === "fresh" ? 2 : null,
      requireCanonical: true,
      attempts: 1,
    },
    identity: {
      registryAddress: BSC_PANCAKE_V3.erc8004Registry,
      registryCode: code,
      agentTokenId: "1",
      expectedProvider: input.provider,
      currentOwner: input.provider,
      providerCode: emptyCode,
    },
    deployments: {
      factory: { address: BSC_PANCAKE_V3.factory, code },
      deployer: { address: BSC_PANCAKE_V3.deployer, code },
      positionManager: {
        address: POSITION_MANAGER,
        code,
        factory: BSC_PANCAKE_V3.factory,
        deployer: BSC_PANCAKE_V3.deployer,
      },
    },
    pool: {
      address: pool,
      code,
      factory: BSC_PANCAKE_V3.factory,
      token0,
      token1,
      fee: 500,
      tickSpacing: 10,
      sqrtPriceX96: "79228162514264337593543950336",
      currentTick: input.currentTick,
      observationIndex: 1,
      observationCardinality: 2,
      observationCardinalityNext: 3,
      feeProtocol: 0,
      unlocked: true,
      liquidity: input.poolLiquidity,
    },
    position: {
      tokenId: "9",
      owner: input.provider,
      approved: "0x0000000000000000000000000000000000000000",
      caller: input.provider,
      callerApprovedForAll: false,
      callerCanManage: true,
      nonce: "0",
      operator: "0x0000000000000000000000000000000000000000",
      token0,
      token1,
      fee: 500,
      tickLower: -100,
      tickUpper: 100,
      liquidity: "1000",
      feeGrowthInside0LastX128: "0",
      feeGrowthInside1LastX128: "0",
      tokensOwed0: "0",
      tokensOwed1: "0",
    },
    tokens: {
      token0: {
        address: token0,
        code,
        decimals: 18,
        callerBalance: "10000",
        callerAllowanceToPositionManager: "10000",
      },
      token1: {
        address: token1,
        code,
        decimals: 18,
        callerBalance: "20000",
        callerAllowanceToPositionManager: "20000",
      },
    },
  };
}

function successA2aResponse(
  requestId: string,
  envelope: QuoteAcceptedEnvelope,
): unknown {
  return {
    jsonrpc: "2.0",
    id: requestId,
    result: {
      kind: "message",
      role: "agent",
      messageId: "server-message",
      parts: [{ kind: "data", data: envelope }],
    },
  };
}

function quoteTransport(
  routes: TransportRoute[],
  respond: (requestId: string) => unknown,
): { request(route: TransportRoute): Promise<BoundedHttpResponse> } {
  return {
    async request(route) {
      routes.push(route);
      if (route.kind !== "a2a-quote") {
        throw new Error(`unexpected route ${route.kind}`);
      }
      const request = JSON.parse(route.body) as { id: string };
      const body = Buffer.from(JSON.stringify(respond(request.id)));
      return boundedResponse(body);
    },
  };
}

function erc1271QuoteTransport(
  routes: TransportRoute[],
  envelope: QuoteAcceptedEnvelope,
): { request(route: TransportRoute): Promise<BoundedHttpResponse> } {
  return {
    async request(route) {
      routes.push(route);
      if (route.kind !== "a2a-quote" && route.kind !== "bsc-quote-rpc") {
        throw new Error(`unexpected route ${route.kind}`);
      }
      const request = JSON.parse(route.body) as {
        id: string;
        method: string;
        params?: unknown[];
      };
      if (route.kind === "a2a-quote") {
        return boundedResponse(
          Buffer.from(JSON.stringify(successA2aResponse(request.id, envelope))),
        );
      }
      assert.deepEqual(request.params?.[1], {
        blockHash: BLOCK_HASH,
        requireCanonical: true,
      });
      const result =
        request.method === "eth_getCode"
          ? "0x6000"
          : encodeFunctionResult({
              abi: [
                {
                  type: "function",
                  name: "isValidSignature",
                  stateMutability: "view",
                  inputs: [
                    { name: "hash", type: "bytes32" },
                    { name: "signature", type: "bytes" },
                  ],
                  outputs: [{ name: "magicValue", type: "bytes4" }],
                },
              ] as const,
              functionName: "isValidSignature",
              result: "0x1626ba7e",
            });
      return boundedResponse(
        Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: request.id, result })),
      );
    },
  };
}

function boundedResponse(body: Buffer): BoundedHttpResponse {
  return {
    status: 200,
    contentType: "application/json",
    retryAfter: null,
    rateLimitRemaining: null,
    body,
    responseSha256: createHash("sha256").update(body).digest("hex"),
    resolvedAddress: "93.184.216.34",
    startedAt: "2026-08-16T12:00:00.000Z",
    finishedAt: "2026-08-16T12:00:00.010Z",
    latencyMs: 10,
  };
}

function memoryReplayStore(result: "claimed" | "duplicate"): ReplayStore & {
  prepareCalls: number;
  claims: ReplayMetadata[];
} {
  return {
    prepareCalls: 0,
    claims: [],
    async prepare() {
      this.prepareCalls += 1;
    },
    async claim(_key, metadata) {
      this.claims.push(metadata);
      return result;
    },
  };
}

function sequentialId(): () => string {
  let count = 0;
  return () => `quote-id-${++count}`;
}

function sequentialClock(...times: Date[]): () => Date {
  let index = 0;
  return () => times[Math.min(index++, times.length - 1)]!;
}

function passGate(
  gate: "manifest_identity" | "bsc_chain" | "token_ownership" | "endpoint_origin" | "endpoint_health" | "task_interface",
  evidence: "claimed" | "detected" | "verified",
  evidenceRef: string,
) {
  return {
    gate,
    state: "pass" as const,
    evidence: [evidence],
    evidenceRefs: [evidenceRef],
  };
}

function replaceSelectedCandidate(
  report: RunReport,
  update: (candidate: RunReport["candidates"][number]) => RunReport["candidates"][number],
): RunReport {
  return {
    ...report,
    candidates: report.candidates.map((candidate) =>
      candidate.chainId === 56 && candidate.tokenId === "1"
        ? update(candidate)
        : candidate,
    ),
  };
}
