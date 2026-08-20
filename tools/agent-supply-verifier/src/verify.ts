import { createHash } from "node:crypto";

import {
  buildReport,
  classifyCandidate,
  redactError,
  type CandidateReportInput,
} from "./report.js";
import {
  DEFAULT_CHAIN_PROFILE,
  DEFAULT_POLICY,
  DEFAULT_SOURCE_BUDGETS,
  computePolicyFingerprint,
} from "./policy.js";
import {
  type EvidenceRecord,
  type GateResult,
  type ManifestCandidate,
  type ManifestFile,
  type ReportErrorCode,
  type SourceObservation,
} from "./schema.js";
import {
  fetchScanAgentDetail,
  type ScanDetailResult,
  type ScanAgentDetail,
} from "./sources/8004scan.js";
import {
  BSC_MAINNET,
  verifyErc8004Ownership,
  type Erc8004Result,
} from "./sources/erc8004.js";
import {
  probeAgentCard,
  type AgentCardResult,
  type DetectedAgentCard,
} from "./probes/a2a.js";
import { inspectPassiveErc8183 } from "./probes/erc8183.js";
import type { PinnedHttpsTransport } from "./transport/http.js";

export interface VerifyManifestOptions {
  readonly manifest: ManifestFile;
  readonly transport: Pick<PinnedHttpsTransport, "request">;
  readonly now?: () => Date;
}

export async function verifyManifest(options: VerifyManifestOptions) {
  const now = options.now ?? (() => new Date());
  const candidates: CandidateReportInput[] = [];
  let stopAfterRateLimit = false;

  for (const candidate of options.manifest.candidates) {
    if (stopAfterRateLimit) {
      candidates.push(buildBudgetInconclusiveCandidate(candidate, now));
      continue;
    }
    const result = await verifyCandidate({
      candidate,
      transport: options.transport,
      now,
    });
    candidates.push(result.report);
    if (result.rateLimited) stopAfterRateLimit = true;
  }

  return buildReport({
    generatedAt: now(),
    chainProfile: DEFAULT_CHAIN_PROFILE,
    policy: DEFAULT_POLICY,
    policyFingerprint: computePolicyFingerprint(DEFAULT_POLICY),
    budgets: DEFAULT_SOURCE_BUDGETS,
    sources: candidates.flatMap((candidate) => candidate.sources ?? []),
    candidates,
  });
}

async function verifyCandidate(options: {
  candidate: ManifestCandidate;
  transport: Pick<PinnedHttpsTransport, "request">;
  now: () => Date;
}): Promise<{ report: CandidateReportInput; rateLimited: boolean }> {
  const { candidate, transport, now } = options;
  const runStartedAt = now().toISOString();

  const manifestSource = makeManifestSource(candidate, runStartedAt);
  const evidence: EvidenceRecord[] = [
    {
      id: "manifest.candidate",
      level: "claimed",
      source: "manifest",
      claim: "Candidate identity and endpoint are operator allowlisted.",
      observedAt: runStartedAt,
    },
  ];
  const gates: GateResult[] = [
    gate("manifest_identity", "pass", ["claimed"], ["manifest.candidate"]),
    gate("endpoint_origin", "pass", ["claimed"], ["manifest.candidate"]),
    gate("endpoint_operator_binding", "unknown", [], [], "No cryptographic endpoint binding in passive v1."),
    gate("quote_signature", "unknown", [], [], "No active quote probe in passive v1."),
    gate("category_evidence", "unknown", [], [], "Category adapters are deferred."),
    gate("mandate_policy", "unknown", [], [], "No mandate or permission policy was evaluated."),
    gate("transaction_preview", "unknown", [], [], "No transaction preview was attempted."),
  ];
  const errors: ReturnType<typeof redactError>[] = [];
  const sources: SourceObservation[] = [manifestSource];
  let scanResult: ScanDetailResult;
  let chainResult: Erc8004Result;
  let cardResult: AgentCardResult;

  scanResult = await fetchScanAgentDetail({
    transport,
    chainId: candidate.chainId,
    tokenId: candidate.tokenId,
  });
  sources.push(scanSourceObservation(scanResult, now));
  applyScanEvidence(candidate, scanResult, evidence, gates, errors, now);
  if (
    scanResult.status === "inconclusive" &&
    scanResult.code === "SCAN_RATE_LIMITED"
  ) {
    gates.push(
      gate("bsc_chain", "unknown", [], [], "Run stopped after the scan rate budget was exhausted."),
      gate("token_ownership", "unknown", [], [], "Run stopped after the scan rate budget was exhausted."),
      gate("endpoint_health", "unknown", [], [], "Run stopped after the scan rate budget was exhausted."),
      gate("task_interface", "unknown", [], [], "Run stopped after the scan rate budget was exhausted."),
    );
    return {
      report: {
        chainId: candidate.chainId,
        tokenId: candidate.tokenId,
        expectedName: candidate.expectedName,
        expectedEndpoint: candidate.expectedEndpoint,
        expectedOrigin: candidate.expectedOrigin,
        categories: candidate.categories,
        ...(candidate.provider === undefined ? {} : { provider: candidate.provider }),
        ...(candidate.teamOperatedReference === undefined
          ? {}
          : { teamOperatedReference: candidate.teamOperatedReference }),
        status: "INCONCLUSIVE",
        sources,
        evidence,
        gates,
        errors,
      },
      rateLimited: true,
    };
  }

  chainResult = await verifyErc8004Ownership({
    transport,
    chainId: candidate.chainId,
    tokenId: candidate.tokenId,
    registryAddress: BSC_MAINNET.registryAddress,
  });
  sources.push(chainSourceObservation(chainResult, now));
  applyChainEvidence(chainResult, evidence, gates, errors, now);

  cardResult = await probeAgentCard({
    transport,
    endpoint: candidate.expectedEndpoint,
    expectedOrigin: candidate.expectedOrigin,
  });
  sources.push(cardSourceObservation(cardResult, candidate.expectedOrigin, now));
  applyCardEvidence(cardResult, gates, evidence, errors, now);

  const erc8183 = inspectPassiveErc8183(
    cardResult.status === "detected" ? cardResult.card : null,
  );
  if (erc8183.declared) {
    evidence.push({
      id: "card.erc8183-declaration",
      level: "claimed",
      source: "agent_card",
      claim: "Agent Card declares an ERC-8183-related skill.",
      observedAt: cardObservedAt(cardResult, now),
      ...(cardResult.status === "detected" && cardResult.observation.responseSha256 !== null
        ? { responseHash: cardResult.observation.responseSha256 }
        : {}),
      details: {
        activeProbePerformed: false,
        skillIds: [...erc8183.skillIds],
      },
    });
  }

  applyCrossSourceComparisons(candidate, scanResult, chainResult, evidence, gates, now);

  const sourceError = sources.some((source) => source.disposition === "inconclusive");
  const endpointFailure = cardResult.status === "unavailable";
  const identityFailure = chainResult.status === "unavailable";
  const classifiedStatus = classifyCandidate({
    sources,
    gates,
    sourceError,
    rpcError: chainResult.status === "inconclusive",
    endpointFailure,
    identityFailure,
  });
  if (classifiedStatus === "VERIFIED_HIREABLE") {
    throw new Error("passive v1 classification attempted an unreachable status");
  }
  const status = classifiedStatus;

  if (status === "INCONCLUSIVE") {
    errors.push(redactError("SOURCE_UNAVAILABLE", "One or more verifier dependencies were inconclusive."));
  }

  const scan = scanObservation(scanResult, now);
  const chain = chainObservation(chainResult, now);
  const card = cardObservation(cardResult, now);
  const owner = chainResult.status === "verified" ? chainResult.snapshot.ownerAddress : undefined;
  const addresses = [
    owner,
    scanResult.status === "ok" ? scanResult.detail.ownerAddress : null,
    scanResult.status === "ok" ? scanResult.detail.creatorAddress : null,
    scanResult.status === "ok" ? scanResult.detail.agentWallet : null,
  ].filter((address): address is string => address !== null && address !== undefined);

  const report: CandidateReportInput = {
    chainId: candidate.chainId,
    tokenId: candidate.tokenId,
    expectedName: candidate.expectedName,
    expectedEndpoint: candidate.expectedEndpoint,
    expectedOrigin: candidate.expectedOrigin,
    categories: candidate.categories,
    ...(candidate.provider === undefined ? {} : { provider: candidate.provider }),
    ...(candidate.teamOperatedReference === undefined
      ? {}
      : { teamOperatedReference: candidate.teamOperatedReference }),
    status,
    sources,
    evidence,
    gates,
    errors,
    ...(scan === undefined ? {} : { scan }),
    ...(chain === undefined ? {} : { chain }),
    ...(card === undefined ? {} : { card }),
    ...(owner === undefined ? {} : { owner }),
    addresses,
  };

  return {
    report,
    rateLimited: scanResult.status === "inconclusive" && scanResult.code === "SCAN_RATE_LIMITED",
  };
}

function buildBudgetInconclusiveCandidate(
  candidate: ManifestCandidate,
  now: () => Date,
): CandidateReportInput {
  const observedAt = now().toISOString();
  const source: SourceObservation = {
    source: "verifier",
    disposition: "inconclusive",
    startedAt: observedAt,
    endedAt: observedAt,
    latencyMs: 0,
    status: "budget_exceeded",
    error: redactError("BUDGET_EXCEEDED", "Live source budget stopped this candidate."),
  };
  return {
    chainId: candidate.chainId,
    tokenId: candidate.tokenId,
    expectedName: candidate.expectedName,
    expectedEndpoint: candidate.expectedEndpoint,
    expectedOrigin: candidate.expectedOrigin,
    categories: candidate.categories,
    ...(candidate.provider === undefined ? {} : { provider: candidate.provider }),
    ...(candidate.teamOperatedReference === undefined
      ? {}
      : { teamOperatedReference: candidate.teamOperatedReference }),
    status: "INCONCLUSIVE",
    sources: [source],
    evidence: [],
    gates: [
      gate("manifest_identity", "pass", ["claimed"], []),
      gate("scan_detail", "error", [], [], "Source request budget was exhausted.", "BUDGET_EXCEEDED"),
    ],
    errors: [source.error!],
  };
}

function makeManifestSource(candidate: ManifestCandidate, timestamp: string): SourceObservation {
  return {
    source: "manifest",
    disposition: "success",
    startedAt: timestamp,
    endedAt: timestamp,
    latencyMs: 0,
    status: "allowlisted",
    responseHash: createHash("sha256")
      .update(
        JSON.stringify({
          chainId: candidate.chainId,
          tokenId: candidate.tokenId,
          expectedEndpoint: candidate.expectedEndpoint,
          categories: candidate.categories,
        }),
      )
      .digest("hex"),
  };
}

function scanSourceObservation(result: ScanDetailResult, now: () => Date): SourceObservation {
  const observation = result.observation;
  const startedAt = observation.startedAt ?? now().toISOString();
  const endedAt = observation.finishedAt ?? startedAt;
  const base: SourceObservation = {
    source: "8004scan",
    disposition: result.status === "ok" ? "success" : result.status === "not_indexed" ? "mismatch" : "inconclusive",
    startedAt,
    endedAt,
    latencyMs: observation.latencyMs ?? 0,
    status: result.status,
    ...(observation.responseSha256 === null ? {} : { responseHash: observation.responseSha256 }),
    ...(observation.httpStatus === null ? {} : { httpStatus: observation.httpStatus }),
    origin: "https://8004scan.io",
  };
  if (result.status === "inconclusive") {
    return {
      ...base,
      error: redactError(scanErrorCode(result.code), result.message),
    };
  }
  return base;
}

function chainSourceObservation(result: Erc8004Result, now: () => Date): SourceObservation {
  const calls = result.status === "verified" ? result.snapshot.calls : result.calls;
  const first = calls[0];
  const last = calls[calls.length - 1];
  const startedAt = first?.startedAt ?? now().toISOString();
  const endedAt = last?.finishedAt ?? startedAt;
  const responseHash = aggregateHashes(calls.map((call) => call.responseSha256));
  const base: SourceObservation = {
    source: "bsc_rpc",
    disposition: result.status === "verified" ? "success" : result.status === "unavailable" ? "definitive_failure" : "inconclusive",
    startedAt,
    endedAt,
    latencyMs: calls.reduce((total, call) => total + call.latencyMs, 0),
    status: result.status,
    ...(responseHash === undefined ? {} : { responseHash }),
    origin: "https://bsc-dataseed.binance.org",
  };
  if (result.status === "verified") {
    return {
      ...base,
      observedBlock: safeBlockNumber(result.snapshot.observedBlockNumber),
      observedBlockHash: result.snapshot.observedBlockHash,
      confirmationDepth: result.snapshot.confirmationDepth,
      registryAddress: result.snapshot.registryAddress,
    };
  }
  return {
    ...base,
    error: redactError(ercErrorCode(result), result.message),
  };
}

function cardSourceObservation(
  result: AgentCardResult,
  origin: string,
  now: () => Date,
): SourceObservation {
  const observation = result.observation;
  const startedAt = observation.startedAt ?? now().toISOString();
  const endedAt = observation.finishedAt ?? startedAt;
  const base: SourceObservation = {
    source: "agent_card",
    disposition: result.status === "detected" ? "success" : result.status === "unavailable" ? "definitive_failure" : "inconclusive",
    startedAt,
    endedAt,
    latencyMs: observation.latencyMs ?? 0,
    status: result.status,
    ...(observation.responseSha256 === null ? {} : { responseHash: observation.responseSha256 }),
    ...(observation.httpStatus === null ? {} : { httpStatus: observation.httpStatus }),
    origin,
  };
  if (result.status === "detected") return base;
  return {
    ...base,
    error: redactError(cardErrorCode(result), result.message),
  };
}

function applyScanEvidence(
  candidate: ManifestCandidate,
  result: ScanDetailResult,
  evidence: EvidenceRecord[],
  gates: GateResult[],
  errors: ReturnType<typeof redactError>[],
  now: () => Date,
): void {
  if (result.status === "ok") {
    const observedAt = result.observation.finishedAt ?? now().toISOString();
    const responseHash = result.observation.responseSha256;
    evidence.push({
      id: "scan.detail",
      level: "claimed",
      source: "8004scan",
      claim: "8004scan returned bounded discovery metadata for the candidate.",
      observedAt,
      ...(responseHash === null ? {} : { responseHash }),
      details: {
        name: result.detail.name,
        ownerAddress: result.detail.ownerAddress,
        endpoint: result.detail.agentCardEndpoint,
        isVerifiedByScan: result.detail.isVerifiedByScan,
        isEndpointVerifiedByScan: result.detail.isEndpointVerifiedByScan,
      },
    });
    gates.push(gate("scan_detail", "pass", ["claimed", "detected"], ["scan.detail"]));
    return;
  }
  if (result.status === "not_indexed") {
    evidence.push({
      id: "scan.not-indexed",
      level: "claimed",
      source: "8004scan",
      claim: "8004scan did not index this manifest identity at observation time.",
      observedAt: result.observation.finishedAt ?? now().toISOString(),
      ...(result.observation.responseSha256 === null ? {} : { responseHash: result.observation.responseSha256 }),
    });
    gates.push(gate("scan_detail", "unknown", ["claimed"], ["scan.not-indexed"], "Scan absence does not override on-chain identity."));
    return;
  }
  const error = redactError(scanErrorCode(result.code), result.message);
  errors.push(error);
  gates.push(gate("scan_detail", "error", [], [], result.message, error.code));
  void candidate;
}

function applyChainEvidence(
  result: Erc8004Result,
  evidence: EvidenceRecord[],
  gates: GateResult[],
  errors: ReturnType<typeof redactError>[],
  now: () => Date,
): void {
  if (result.status === "verified") {
    const snapshot = result.snapshot;
    const observedAt = snapshot.calls.at(-1)?.finishedAt ?? now().toISOString();
    const responseHash = aggregateHashes(snapshot.calls.map((call) => call.responseSha256));
    evidence.push({
      id: "chain.owner-of",
      level: "verified",
      source: "bsc_rpc",
      claim: "ERC-8004 ownerOf matched at a canonical BSC block snapshot.",
      observedAt,
      ...(responseHash === undefined ? {} : { responseHash }),
      observedBlock: safeBlockNumber(snapshot.observedBlockNumber),
      observedBlockHash: snapshot.observedBlockHash,
      details: {
        owner: snapshot.ownerAddress,
        registry: snapshot.registryAddress,
        confirmationDepth: snapshot.confirmationDepth,
        registryCodeSha256: snapshot.registryCodeSha256,
      },
    });
    gates.push(gate("bsc_chain", "pass", ["verified"], ["chain.owner-of"]));
    gates.push(gate("token_ownership", "pass", ["verified"], ["chain.owner-of"]));
    return;
  }
  const error = redactError(ercErrorCode(result), result.message);
  errors.push(error);
  if (result.status === "unavailable") {
    gates.push(gate("bsc_chain", "unknown", [], [], "Chain snapshot was not retained after token absence."));
    gates.push(gate("token_ownership", "fail", [], [], result.message, error.code));
  } else {
    gates.push(gate("bsc_chain", "error", [], [], result.message, error.code));
    gates.push(gate("token_ownership", "error", [], [], result.message, error.code));
  }
}

function applyCardEvidence(
  result: AgentCardResult,
  gates: GateResult[],
  evidence: EvidenceRecord[],
  errors: ReturnType<typeof redactError>[],
  now: () => Date,
): void {
  if (result.status === "detected") {
    const observedAt = result.observation.finishedAt ?? now().toISOString();
    const responseHash = result.observation.responseSha256;
    evidence.push({
      id: "card.http",
      level: "detected",
      source: "agent_card",
      claim: "Manifest-approved Agent Card returned compatible A2A metadata.",
      observedAt,
      ...(responseHash === null ? {} : { responseHash }),
      details: {
        protocolVersion: result.card.protocolVersion,
        preferredTransport: result.card.preferredTransport,
        skillIds: result.card.skills.map((skill) => skill.id),
      },
    });
    gates.push(gate("endpoint_health", "pass", ["detected"], ["card.http"]));
    gates.push(gate("task_interface", "pass", ["detected"], ["card.http"], "A2A metadata detected; callable task behavior is not verified."));
    return;
  }
  const error = redactError(cardErrorCode(result), result.message);
  errors.push(error);
  if (result.status === "unavailable") {
    gates.push(gate("endpoint_health", "fail", [], [], result.message, error.code));
    gates.push(gate("task_interface", "fail", [], [], result.message, error.code));
  } else {
    gates.push(gate("endpoint_health", "error", [], [], result.message, error.code));
    gates.push(gate("task_interface", "error", [], [], result.message, error.code));
  }
}

function applyCrossSourceComparisons(
  candidate: ManifestCandidate,
  scanResult: ScanDetailResult,
  chainResult: Erc8004Result,
  evidence: EvidenceRecord[],
  gates: GateResult[],
  now: () => Date,
): void {
  if (scanResult.status !== "ok" || chainResult.status !== "verified") return;

  const observedAt = chainResult.snapshot.calls.at(-1)?.finishedAt ?? now().toISOString();
  const claimedOwner = scanResult.detail.ownerAddress;
  const verifiedOwner = chainResult.snapshot.ownerAddress;
  if (claimedOwner !== null) {
    const ownerMatches = claimedOwner === verifiedOwner;
    evidence.push({
      id: "identity.owner-comparison",
      level: "detected",
      source: "verifier",
      claim: ownerMatches
        ? "8004scan owner claim matches the canonical ERC-8004 owner read."
        : "8004scan owner claim does not match the canonical ERC-8004 owner read.",
      observedAt,
      details: {
        claimedOwner,
        verifiedOwner,
        matches: ownerMatches,
      },
    });
    if (!ownerMatches) {
      const scanGate = gates.find((gateResult) => gateResult.gate === "scan_detail");
      if (scanGate !== undefined) {
        scanGate.note = "8004scan owner claim mismatched canonical chain ownership; chain evidence is authoritative.";
      }
    }
  }

  const claimedEndpoint = scanResult.detail.agentCardEndpoint;
  if (claimedEndpoint !== null) {
    const endpointMatches = claimedEndpoint === candidate.expectedEndpoint;
    evidence.push({
      id: "identity.endpoint-comparison",
      level: "detected",
      source: "verifier",
      claim: endpointMatches
        ? "8004scan endpoint claim matches the manifest-approved origin and path."
        : "8004scan endpoint claim differs from the manifest-approved endpoint.",
      observedAt,
      details: {
        claimedEndpoint,
        approvedEndpoint: candidate.expectedEndpoint,
        matches: endpointMatches,
      },
    });
  }
}

function scanObservation(result: ScanDetailResult, now: () => Date) {
  if (result.status === "inconclusive") return undefined;
  const observedAt = result.observation.finishedAt ?? now().toISOString();
  const base = {
    indexed: result.status === "ok",
    observedAt,
    ...(result.observation.responseSha256 === null ? {} : { responseHash: result.observation.responseSha256 }),
  };
  if (result.status === "not_indexed") return base;
  const detail = result.detail;
  return {
    ...base,
    apiVersion: result.detail.sourceVersion ?? undefined,
    ...(safeIso(detail.sourceTimestamp) ? { apiTimestamp: detail.sourceTimestamp! } : {}),
    ...(detail.ownerAddress === null ? {} : { claimedOwner: detail.ownerAddress }),
    ...(detail.agentCardEndpoint === null ? {} : { claimedEndpoint: detail.agentCardEndpoint }),
    claimedName: detail.name,
    description: detail.description,
    creatorAddress: detail.creatorAddress,
    agentWallet: detail.agentWallet,
    isVerifiedByScan: detail.isVerifiedByScan,
    isEndpointVerifiedByScan: detail.isEndpointVerifiedByScan,
    endpointVerificationDomain: detail.endpointVerificationDomain,
    endpointVerificationError: detail.endpointVerificationError,
    ...(safeIso(detail.endpointLastCheckedAt) ? { endpointLastCheckedAt: detail.endpointLastCheckedAt! } : {}),
    isActive: detail.isActive,
    x402Supported: detail.x402Supported,
    feedbackCount: detail.feedbackCount,
    averageScore: detail.averageScore,
    healthScore: detail.healthScore,
    ...(safeIso(detail.healthCheckedAt) ? { healthCheckedAt: detail.healthCheckedAt! } : {}),
    ...(safeIso(detail.updatedAt) ? { updatedAt: detail.updatedAt! } : {}),
    supportedProtocols: [...detail.supportedProtocols],
  };
}

function chainObservation(result: Erc8004Result, now: () => Date) {
  if (result.status !== "verified") return undefined;
  const snapshot = result.snapshot;
  const responseHash = aggregateHashes(snapshot.calls.map((call) => call.responseSha256));
  return {
    chainId: snapshot.chainId,
    registryAddress: snapshot.registryAddress,
    tokenId: snapshot.tokenId,
    owner: snapshot.ownerAddress,
    observedBlock: safeBlockNumber(snapshot.observedBlockNumber),
    observedBlockHash: snapshot.observedBlockHash,
    confirmationDepth: snapshot.confirmationDepth,
    registryCodeHash: snapshot.registryCodeSha256,
    observedAt: snapshot.calls.at(-1)?.finishedAt ?? now().toISOString(),
    ...(responseHash === undefined ? {} : { responseHash }),
  };
}

function cardObservation(result: AgentCardResult, now: () => Date) {
  if (result.status !== "detected") return undefined;
  const card = result.card;
  return {
    url: card.url,
    observedAt: result.observation.finishedAt ?? now().toISOString(),
    ...(result.observation.responseSha256 === null ? {} : { responseHash: result.observation.responseSha256 }),
    protocolVersion: card.protocolVersion,
    preferredTransport: card.preferredTransport,
    skills: card.skills.map((skill) => ({
      id: skill.id,
      name: skill.name,
      description: skill.description,
      tags: [...skill.tags],
      inputModes: [...skill.inputModes],
      outputModes: [...skill.outputModes],
    })),
    inputModes: [...card.defaultInputModes],
    outputModes: [...card.defaultOutputModes],
  };
}

function gate(
  gateName: GateResult["gate"],
  state: GateResult["state"],
  evidence: GateResult["evidence"],
  evidenceRefs: readonly string[],
  note?: string,
  reasonCode?: ReportErrorCode,
): GateResult {
  return {
    gate: gateName,
    state,
    evidence: [...evidence],
    evidenceRefs: [...evidenceRefs],
    ...(note === undefined ? {} : { note }),
    ...(reasonCode === undefined ? {} : { reasonCode }),
  };
}

type InconclusiveScanResult = Extract<ScanDetailResult, { status: "inconclusive" }>;
type NonVerifiedChainResult = Exclude<Erc8004Result, { status: "verified" }>;
type NonDetectedCardResult = Exclude<AgentCardResult, { status: "detected" }>;

function scanErrorCode(code: InconclusiveScanResult["code"]): ReportErrorCode {
  switch (code) {
    case "SCAN_RATE_LIMITED":
      return "SOURCE_RATE_LIMITED";
    case "SCAN_INVALID_RESPONSE":
      return "SOURCE_MALFORMED";
    case "SCAN_UNAVAILABLE":
    case "SCAN_TRANSPORT_ERROR":
      return "SOURCE_UNAVAILABLE";
  }
}

function ercErrorCode(result: NonVerifiedChainResult): ReportErrorCode {
  if (result.status === "unavailable") return "IDENTITY_NOT_FOUND";
  switch (result.code) {
    case "CHAIN_ID_MISMATCH":
      return "RPC_CHAIN_MISMATCH";
    case "SNAPSHOT_INCONSISTENT":
      return "RPC_CANONICALITY_FAILED";
    case "REGISTRY_CODE_MISSING":
      return "RPC_REGISTRY_CODE_MISSING";
    case "RPC_UNAVAILABLE":
      return "RPC_UNAVAILABLE";
    default:
      return "SOURCE_MALFORMED";
  }
}

function cardErrorCode(result: NonDetectedCardResult): ReportErrorCode {
  if (result.status === "inconclusive") {
    const code = result.code;
    switch (code) {
      case "CARD_RESOLVER_UNAVAILABLE":
        return "SOURCE_UNAVAILABLE";
      case "CARD_CONFIGURATION_ERROR":
        return "POLICY_REJECTED";
      default:
        return assertNever(code);
    }
  }
  const code = result.code;
  switch (code) {
    case "CARD_INCOMPATIBLE":
      return "CARD_INCOMPATIBLE";
    case "CARD_ORIGIN_MISMATCH":
      return "ENDPOINT_MALFORMED";
    case "CARD_HTTP_STATUS":
      return "ENDPOINT_HTTP_ERROR";
    case "CARD_INVALID_RESPONSE":
      return "ENDPOINT_MALFORMED";
    case "CARD_ENDPOINT_TIMEOUT":
      return "ENDPOINT_TIMEOUT";
    case "CARD_NETWORK_ERROR":
      return "SOURCE_UNAVAILABLE";
    case "CARD_REDIRECTED":
      return "ENDPOINT_REDIRECTED";
    case "CARD_DNS_REJECTED":
      return "ENDPOINT_DNS_REJECTED";
    case "CARD_RESPONSE_POLICY_REJECTED":
      return "ENDPOINT_MALFORMED";
    default:
      return assertNever(code);
  }
}

function cardObservedAt(result: AgentCardResult, now: () => Date): string {
  return result.observation.finishedAt ?? now().toISOString();
}

function aggregateHashes(hashes: readonly string[]): string | undefined {
  if (hashes.length === 0) return undefined;
  return createHash("sha256").update(hashes.join("|")).digest("hex");
}

function safeBlockNumber(value: string): number {
  const parsed = Number(BigInt(value));
  if (!Number.isSafeInteger(parsed)) throw new Error("observed block exceeds safe integer range");
  return parsed;
}

function safeIso(value: string | null): boolean {
  return value !== null && !Number.isNaN(Date.parse(value));
}

function assertNever(value: never): never {
  throw new Error(`unhandled verifier classification: ${String(value)}`);
}
