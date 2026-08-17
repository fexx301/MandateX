import {
  candidateReportSchema,
  gateResultSchema,
  reportErrorCodeSchema,
  runReportSchema,
  sourceObservationSchema,
  type CandidateReport,
  type CandidateStatus,
  type ChainProfileSummary,
  type EvidenceRecord,
  type GateName,
  type GateResult,
  type ReportError,
  type ReportErrorCode,
  type RunReport,
  type SourceBudgets,
  type SourceObservation,
} from "./schema.js";
import {
  computePolicyFingerprint,
  DEFAULT_CHAIN_PROFILE,
  DEFAULT_POLICY,
  DEFAULT_SOURCE_BUDGETS,
} from "./policy.js";

export { computePolicyFingerprint } from "./policy.js";

const GATE_ORDER: readonly GateName[] = [
  "manifest_identity",
  "scan_detail",
  "bsc_chain",
  "token_ownership",
  "endpoint_origin",
  "endpoint_health",
  "task_interface",
  "endpoint_operator_binding",
  "quote_signature",
  "category_evidence",
  "mandate_policy",
  "transaction_preview",
];

const GATE_RANK = new Map(GATE_ORDER.map((gate, index) => [gate, index]));

export interface CandidateClassificationInput {
  readonly sources?: readonly SourceObservation[];
  readonly gates?: readonly GateResult[];
  readonly sourceError?: boolean;
  readonly rpcError?: boolean;
  readonly verifierError?: boolean;
  readonly budgetExceeded?: boolean;
  readonly endpointFailure?: boolean;
  readonly definitiveEndpointFailure?: boolean;
  readonly identityFailure?: boolean;
  readonly definitiveIdentityFailure?: boolean;
}

/**
 * Applies the passive-v1 precedence rules. VERIFIED_HIREABLE is deliberately
 * absent: quote, policy, category, binding, and preview gates are not probed.
 */
export function classifyCandidate(input: CandidateClassificationInput): CandidateStatus {
  const infrastructureFailure =
    input.sourceError === true ||
    input.rpcError === true ||
    input.verifierError === true ||
    input.budgetExceeded === true ||
    input.sources?.some((source) => source.disposition === "inconclusive") === true ||
    input.gates?.some((gate) => gate.state === "error") === true;

  if (infrastructureFailure) return "INCONCLUSIVE";

  const definitiveFailure =
    input.endpointFailure === true ||
    input.definitiveEndpointFailure === true ||
    input.identityFailure === true ||
    input.definitiveIdentityFailure === true ||
    input.sources?.some((source) => source.disposition === "definitive_failure") === true ||
    input.gates?.some(
      (gate) =>
        gate.state === "fail" &&
        (gate.gate === "token_ownership" || gate.gate === "endpoint_origin" || gate.gate === "endpoint_health"),
    ) === true;

  if (definitiveFailure) return "UNAVAILABLE";
  return "REGISTERED_ONLY";
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "Verifier operation failed";
}

export function redactErrorMessage(error: unknown): string {
  let message = errorMessage(error)
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\bhttps?:\/\/[^\s"'<>]+/gi, "[redacted-url]")
    .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[redacted-authorization]")
    .replace(
      /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|password|passwd|secret|signature)\b\s*[:=]\s*[^\s,;]+/gi,
      "$1=[redacted]",
    )
    .replace(/\b(?:sk|pk)_[A-Za-z0-9_-]{12,}\b/g, "[redacted-secret]")
    .replace(/\b0x[a-fA-F0-9]{64}\b/g, "[redacted-secret]")
    .replace(/\s{2,}/g, " ")
    .trim();

  if (message.length === 0) message = "Verifier operation failed";
  if (message.length > 240) message = `${message.slice(0, 237)}...`;
  return message;
}

export function redactError(error: unknown, code?: ReportErrorCode): ReportError;
export function redactError(code: ReportErrorCode, error: unknown): ReportError;
export function redactError(
  errorOrCode: unknown | ReportErrorCode,
  codeOrError: ReportErrorCode | unknown = "INTERNAL_ERROR",
): ReportError {
  if (typeof errorOrCode === "string" && reportErrorCodeSchema.safeParse(errorOrCode).success) {
    return { code: errorOrCode as ReportErrorCode, message: redactErrorMessage(codeOrError) };
  }
  const parsedCode = reportErrorCodeSchema.safeParse(codeOrError);
  return {
    code: parsedCode.success ? parsedCode.data : "INTERNAL_ERROR",
    message: redactErrorMessage(errorOrCode),
  };
}

export interface CandidateReportInput {
  readonly chainId: number;
  readonly tokenId: string;
  readonly expectedName: string;
  readonly expectedEndpoint: string;
  readonly expectedOrigin: string;
  readonly categories: readonly string[];
  readonly provider?: string;
  readonly teamOperatedReference?: boolean;
  readonly status?: Exclude<CandidateStatus, "VERIFIED_HIREABLE">;
  readonly sources?: readonly SourceObservation[];
  readonly evidence?: readonly EvidenceRecord[];
  readonly gates?: readonly GateResult[];
  readonly errors?: readonly ReportError[];
  readonly scan?: CandidateReport["scan"];
  readonly chain?: CandidateReport["chain"];
  readonly card?: CandidateReport["card"];
  readonly owner?: string;
  readonly addresses?: readonly string[];
}

export interface BuildReportInput {
  readonly generatedAt: string | Date;
  readonly chainProfile?: ChainProfileSummary;
  readonly policy?: unknown;
  readonly policyFingerprint?: string;
  readonly budgets?: SourceBudgets;
  readonly sources?: readonly SourceObservation[];
  readonly candidates: readonly (CandidateReportInput | CandidateReport)[];
  readonly runStatus?: "complete" | "inconclusive";
}

function compareTokenIds(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareSources(left: SourceObservation, right: SourceObservation): number {
  return (
    compareStrings(left.source, right.source) ||
    compareStrings(left.startedAt, right.startedAt) ||
    compareStrings(left.status, right.status) ||
    compareStrings(left.endedAt, right.endedAt)
  );
}

function normalizeReportError(error: ReportError): ReportError {
  return redactError(error.code, error.message);
}

function normalizeSource(source: SourceObservation): SourceObservation {
  const parsed = sourceObservationSchema.parse(source);
  const normalized: SourceObservation = { ...parsed };
  if (parsed.error !== undefined) normalized.error = normalizeReportError(parsed.error);
  return normalized;
}

function normalizeGate(gate: GateResult): GateResult {
  return gateResultSchema.parse(gate);
}

function normalizeCandidate(candidate: CandidateReportInput | CandidateReport): CandidateReport {
  if (candidate.status === "VERIFIED_HIREABLE") {
    throw new Error("VERIFIED_HIREABLE is unreachable in the passive report schema");
  }

  const sources = [...(candidate.sources ?? [])].map(normalizeSource).sort(compareSources);
  const gates = [...(candidate.gates ?? [])]
    .map(normalizeGate)
    .sort((left, right) => (GATE_RANK.get(left.gate) ?? 999) - (GATE_RANK.get(right.gate) ?? 999));
  const evidence = [...(candidate.evidence ?? [])].sort((left, right) => compareStrings(left.id, right.id));
  const errors = [...(candidate.errors ?? [])]
    .map(normalizeReportError)
    .sort((left, right) => compareStrings(left.code, right.code) || compareStrings(left.message, right.message));

  const normalized: Record<string, unknown> = {
    chainId: candidate.chainId,
    tokenId: candidate.tokenId,
    expectedName: candidate.expectedName,
    expectedEndpoint: candidate.expectedEndpoint,
    expectedOrigin: candidate.expectedOrigin,
    categories: [...new Set(candidate.categories)].sort(),
    status: candidate.status ?? classifyCandidate({ sources, gates }),
    sources,
    evidence,
    gates,
    errors,
  };

  if (candidate.provider !== undefined) normalized.provider = candidate.provider;
  if (candidate.teamOperatedReference !== undefined) {
    normalized.teamOperatedReference = candidate.teamOperatedReference;
  }

  if (candidate.scan !== undefined) {
    normalized.scan = {
      ...candidate.scan,
      ...(candidate.scan.endpointVerificationError === undefined || candidate.scan.endpointVerificationError === null
        ? {}
        : { endpointVerificationError: redactErrorMessage(candidate.scan.endpointVerificationError) }),
      ...(candidate.scan.supportedProtocols === undefined
        ? {}
        : { supportedProtocols: [...new Set(candidate.scan.supportedProtocols)].sort() }),
    };
  }
  if (candidate.chain !== undefined) normalized.chain = candidate.chain;
  if (candidate.card !== undefined) normalized.card = candidate.card;
  if (candidate.owner !== undefined) normalized.owner = candidate.owner;
  if (candidate.addresses !== undefined) {
    normalized.addresses = [...new Set(candidate.addresses.map((address) => address.toLowerCase()))].sort();
  }

  return candidateReportSchema.parse(normalized);
}

function toGeneratedAt(value: string | Date): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.valueOf())) throw new Error("generatedAt must be a valid timestamp");
  return date.toISOString();
}

export function buildReport(input: BuildReportInput): RunReport {
  const sources = [...(input.sources ?? [])].map(normalizeSource).sort(compareSources);
  const candidates = [...input.candidates]
    .map(normalizeCandidate)
    .sort((left, right) => left.chainId - right.chainId || compareTokenIds(left.tokenId, right.tokenId));

  const derivedRunStatus =
    sources.some((source) => source.disposition === "inconclusive") ||
    candidates.some((candidate) => candidate.status === "INCONCLUSIVE")
      ? "inconclusive"
      : "complete";

  if (input.runStatus === "complete" && derivedRunStatus === "inconclusive") {
    throw new Error("a run containing inconclusive source or candidate results cannot be marked complete");
  }

  return runReportSchema.parse({
    schema: "mandatex.agent-supply.report.v1",
    runStatus: input.runStatus ?? derivedRunStatus,
    generatedAt: toGeneratedAt(input.generatedAt),
    chainProfile: input.chainProfile ?? DEFAULT_CHAIN_PROFILE,
    policyFingerprint: input.policyFingerprint ?? computePolicyFingerprint(input.policy ?? DEFAULT_POLICY),
    budgets: input.budgets ?? DEFAULT_SOURCE_BUDGETS,
    sources,
    candidates,
  });
}

function sortedJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortedJsonValue);
  if (value !== null && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(object)
        .sort()
        .filter((key) => object[key] !== undefined)
        .map((key) => [key, sortedJsonValue(object[key])]),
    );
  }
  return value;
}

export function serializeReport(report: RunReport): string {
  if (report.candidates.some((candidate) => candidate.status === "VERIFIED_HIREABLE")) {
    throw new Error("VERIFIED_HIREABLE is unreachable in passive v1");
  }
  const normalized = buildReport({
    generatedAt: report.generatedAt,
    chainProfile: report.chainProfile,
    policyFingerprint: report.policyFingerprint,
    budgets: report.budgets,
    sources: report.sources,
    candidates: report.candidates,
    runStatus: report.runStatus,
  });
  return `${JSON.stringify(sortedJsonValue(normalized), null, 2)}\n`;
}
