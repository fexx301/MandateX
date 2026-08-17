import assert from "node:assert/strict";
import test from "node:test";

import {
  manifestFileSchema,
  parseAgentCard,
  type GateResult,
  type SourceObservation,
} from "../src/schema.js";
import {
  buildReport,
  classifyCandidate,
  redactError,
  redactErrorMessage,
  serializeReport,
  type CandidateReportInput,
} from "../src/report.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const ADDRESS_A = `0x${"1".repeat(40)}`;
const ADDRESS_B = `0x${"2".repeat(40)}`;

test("manifest parsing enforces the curated canonical origin and deterministic order", () => {
  const manifest = manifestFileSchema.parse({
    version: 1,
    candidates: [
      {
        chainId: 56,
        tokenId: "10",
        expectedName: "Ten",
        expectedEndpoint: "https://ten.example/.well-known/agent-card.json",
        expectedOrigin: "https://ten.example",
        categories: ["yield", "rebalancing"],
        source: "8004scan",
      },
      {
        chainId: 56,
        tokenId: "2",
        expectedName: "Two",
        expectedEndpoint: "https://two.example/.well-known/agent-card.json",
        expectedOrigin: "https://two.example",
        categories: ["rebalancing"],
        source: "8004scan",
      },
    ],
  });

  assert.deepEqual(manifest.candidates.map((candidate) => candidate.tokenId), ["2", "10"]);
  assert.deepEqual(manifest.candidates[1]?.categories, ["rebalancing", "yield"]);

  for (const invalid of [
    {
      expectedEndpoint: "http://two.example/.well-known/agent-card.json",
      expectedOrigin: "http://two.example",
    },
    {
      expectedEndpoint: "https://127.0.0.1/.well-known/agent-card.json",
      expectedOrigin: "https://127.0.0.1",
    },
    {
      expectedEndpoint: "https://other.example/.well-known/agent-card.json",
      expectedOrigin: "https://two.example",
    },
  ]) {
    assert.equal(
      manifestFileSchema.safeParse({
        version: 1,
        candidates: [
          {
            chainId: 56,
            tokenId: "2",
            expectedName: "Two",
            categories: ["rebalancing"],
            source: "8004scan",
            ...invalid,
          },
        ],
      }).success,
      false,
    );
  }
});

test("source timestamps accept microseconds and normalize to milliseconds", async () => {
  const { isoUtcSchema } = await import("../src/schema.js");
  assert.equal(
    isoUtcSchema.parse("2026-08-16T07:05:24.796646Z"),
    "2026-08-16T07:05:24.796Z",
  );
});

test("Agent Card parsing retains declared evidence without allowing an origin expansion", () => {
  const input = {
    name: "Rebalancer",
    description: "Passive card fixture",
    url: "https://agent.example/",
    version: "1.0.0",
    protocolVersion: "0.3.0",
    preferredTransport: "JSONRPC",
    capabilities: { streaming: false },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills: [
      {
        id: "notify_funded",
        name: "Notify funded",
        description: "Declared only; never invoked",
        tags: ["erc8183", "rebalancing"],
        inputModes: ["application/json"],
        outputModes: ["application/json"],
      },
      {
        id: "negotiate",
        name: "Negotiate",
        description: "Declared only; never invoked",
        tags: ["rebalancing"],
        inputModes: ["application/json"],
        outputModes: ["application/json"],
      },
    ],
  };

  const parsed = parseAgentCard(input, "https://agent.example");
  assert.deepEqual(parsed.skills.map((skill) => skill.id), ["negotiate", "notify_funded"]);
  assert.throws(() => parseAgentCard({ ...input, url: "https://other.example/" }, "https://agent.example"));
  assert.throws(() => parseAgentCard({ ...input, protocolVersion: "0.4.0" }, "https://agent.example"));
});

test("passive candidate classification follows explicit precedence and never promotes hireability", () => {
  const endpointFailure: GateResult = {
    gate: "endpoint_health",
    state: "fail",
    evidence: ["detected"],
    evidenceRefs: ["card.http"],
  };
  const rpcError: GateResult = {
    gate: "bsc_chain",
    state: "error",
    evidence: [],
    evidenceRefs: [],
  };

  assert.equal(classifyCandidate({ gates: [endpointFailure] }), "UNAVAILABLE");
  assert.equal(classifyCandidate({ gates: [endpointFailure, rpcError] }), "INCONCLUSIVE");
  assert.equal(classifyCandidate({ sourceError: true, definitiveIdentityFailure: true }), "INCONCLUSIVE");
  assert.equal(classifyCandidate({}), "REGISTERED_ONLY");
  assert.notEqual(classifyCandidate({}), "VERIFIED_HIREABLE");
});

test("report serialization is deterministic and redacts diagnostic material", () => {
  const sourceA: SourceObservation = {
    source: "8004scan",
    disposition: "success",
    startedAt: "2026-08-16T10:00:00.000Z",
    endedAt: "2026-08-16T10:00:00.100Z",
    latencyMs: 100,
    status: "ok",
    responseHash: HASH_A,
    httpStatus: 200,
    origin: "https://8004scan.io",
  };
  const sourceB: SourceObservation = {
    source: "agent_card",
    disposition: "definitive_failure",
    startedAt: "2026-08-16T10:00:01.000Z",
    endedAt: "2026-08-16T10:00:01.020Z",
    latencyMs: 20,
    status: "http_error",
    error: redactError(
      "ENDPOINT_HTTP_ERROR",
      new Error("GET https://agent.example/card?api_key=secret Authorization: Bearer abc.def"),
    ),
  };

  const candidateTwo: CandidateReportInput = {
    chainId: 56,
    tokenId: "2",
    expectedName: "Two",
    expectedEndpoint: "https://two.example/.well-known/agent-card.json",
    expectedOrigin: "https://two.example",
    categories: ["yield", "rebalancing"],
    provider: "MandateX reference cohort",
    teamOperatedReference: true,
    sources: [sourceB, sourceA],
    evidence: [
      {
        id: "z-evidence",
        level: "claimed",
        source: "manifest",
        claim: "approved candidate",
        observedAt: "2026-08-16T10:00:00.000Z",
      },
      {
        id: "a-evidence",
        level: "verified",
        source: "bsc_rpc",
        claim: "owner at pinned block",
        observedAt: "2026-08-16T10:00:00.000Z",
        responseHash: HASH_B,
      },
    ],
    gates: [
      { gate: "transaction_preview", state: "unknown", evidence: [], evidenceRefs: [] },
      { gate: "manifest_identity", state: "pass", evidence: ["claimed"], evidenceRefs: ["z-evidence"] },
    ],
    addresses: [ADDRESS_B, ADDRESS_A, ADDRESS_B],
    scan: {
      indexed: true,
      observedAt: "2026-08-16T10:00:00.000Z",
      responseHash: HASH_A,
      claimedName: "Two",
      description: "Claimed discovery metadata",
      creatorAddress: ADDRESS_A,
      agentWallet: null,
      isVerifiedByScan: true,
      isEndpointVerifiedByScan: false,
      endpointVerificationDomain: "two.example",
      endpointVerificationError: "probe https://internal.example/?api_key=secret failed",
      endpointLastCheckedAt: "2026-08-16T09:59:00.000Z",
      isActive: true,
      x402Supported: false,
      feedbackCount: 4,
      averageScore: 88.5,
      healthScore: null,
      healthCheckedAt: null,
      updatedAt: "2026-08-16T09:58:00.000Z",
      supportedProtocols: ["x402", "a2a"],
    },
  };
  const candidateTen: CandidateReportInput = {
    chainId: 56,
    tokenId: "10",
    expectedName: "Ten",
    expectedEndpoint: "https://ten.example/.well-known/agent-card.json",
    expectedOrigin: "https://ten.example",
    categories: ["rebalancing"],
  };

  const first = buildReport({
    generatedAt: "2026-08-16T10:02:00Z",
    sources: [sourceB, sourceA],
    candidates: [candidateTen, candidateTwo],
  });
  const second = buildReport({
    generatedAt: new Date("2026-08-16T10:02:00.000Z"),
    sources: [sourceA, sourceB],
    candidates: [
      { ...candidateTwo, categories: [...candidateTwo.categories].reverse(), sources: [sourceA, sourceB] },
      candidateTen,
    ],
  });

  const firstJson = serializeReport(first);
  const secondJson = serializeReport(second);
  assert.equal(firstJson, secondJson);
  assert.deepEqual(first.candidates.map((candidate) => candidate.tokenId), ["2", "10"]);
  assert.equal(first.candidates[0]?.status, "UNAVAILABLE");
  assert.equal(first.candidates[0]?.provider, "MandateX reference cohort");
  assert.equal(first.candidates[0]?.teamOperatedReference, true);
  assert.deepEqual(first.candidates[0]?.scan?.supportedProtocols, ["a2a", "x402"]);
  assert.equal(first.runStatus, "complete");
  assert.equal(firstJson.includes("secret"), false);
  assert.equal(firstJson.includes("abc.def"), false);
  assert.equal(firstJson.includes("agent.example/card"), false);
});

test("redaction removes URLs, authorization values, provider keys, and private-key-like values", () => {
  const message = redactErrorMessage(
    `request https://provider.example/v1?token=raw Authorization: Bearer abc api_key=topsecret sk_${"x".repeat(24)} 0x${"f".repeat(64)}`,
  );
  assert.equal(message.includes("provider.example"), false);
  assert.equal(message.includes("topsecret"), false);
  assert.equal(message.includes("abc"), false);
  assert.equal(message.includes("sk_"), false);
  assert.equal(message.includes("ffff"), false);
});

test("passive report serialization rejects the reserved hireable status", () => {
  const report = buildReport({
    generatedAt: "2026-08-16T10:00:00.000Z",
    candidates: [
      {
        chainId: 56,
        tokenId: "1",
        expectedName: "Candidate",
        expectedEndpoint: "https://candidate.example/.well-known/agent-card.json",
        expectedOrigin: "https://candidate.example",
        categories: ["rebalancing"],
      },
    ],
  });
  const unsafe = {
    ...report,
    candidates: [{ ...report.candidates[0]!, status: "VERIFIED_HIREABLE" as const }],
  };
  assert.throws(() => serializeReport(unsafe), /unreachable/i);
});
