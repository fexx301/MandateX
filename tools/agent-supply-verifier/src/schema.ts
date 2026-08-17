import { isIP } from "node:net";
import { z } from "zod";

export const REPORT_SCHEMA = "mandatex.agent-supply.report.v1" as const;

export const evidenceLevelSchema = z.enum(["claimed", "detected", "verified"]);
export type EvidenceLevel = z.infer<typeof evidenceLevelSchema>;

export const gateStateSchema = z.enum(["pass", "fail", "unknown", "error"]);
export type GateState = z.infer<typeof gateStateSchema>;

export const candidateStatusSchema = z.enum([
  "REGISTERED_ONLY",
  "INCONCLUSIVE",
  "UNAVAILABLE",
  "VERIFIED_HIREABLE",
]);
export type CandidateStatus = z.infer<typeof candidateStatusSchema>;

export const sourceKindSchema = z.enum([
  "manifest",
  "8004scan",
  "bsc_rpc",
  "agent_card",
  "verifier",
]);
export type SourceKind = z.infer<typeof sourceKindSchema>;

export const sourceDispositionSchema = z.enum([
  "success",
  "definitive_failure",
  "inconclusive",
  "mismatch",
  "not_observed",
]);
export type SourceDisposition = z.infer<typeof sourceDispositionSchema>;

export const reportErrorCodeSchema = z.enum([
  "BUDGET_EXCEEDED",
  "SOURCE_RATE_LIMITED",
  "SOURCE_UNAVAILABLE",
  "SOURCE_MALFORMED",
  "RPC_UNAVAILABLE",
  "RPC_CHAIN_MISMATCH",
  "RPC_CANONICALITY_FAILED",
  "RPC_REGISTRY_CODE_MISSING",
  "IDENTITY_NOT_FOUND",
  "ENDPOINT_DNS_REJECTED",
  "ENDPOINT_TLS_FAILED",
  "ENDPOINT_TIMEOUT",
  "ENDPOINT_HTTP_ERROR",
  "ENDPOINT_REDIRECTED",
  "ENDPOINT_MALFORMED",
  "CARD_INCOMPATIBLE",
  "POLICY_REJECTED",
  "INTERNAL_ERROR",
]);
export type ReportErrorCode = z.infer<typeof reportErrorCodeSchema>;

const isoUtcPattern =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

export const isoUtcSchema = z
  .string()
  .refine((value) => isoUtcPattern.test(value) && !Number.isNaN(Date.parse(value)), {
    message: "timestamp must be an ISO-8601 UTC string",
  })
  .transform((value) => new Date(value).toISOString());
export type IsoUtc = z.infer<typeof isoUtcSchema>;

export const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/, "expected a lowercase SHA-256 digest");
export type Sha256 = z.infer<typeof sha256Schema>;

export const addressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/, "expected an EVM address")
  .transform((value) => value.toLowerCase());
export type Address = z.infer<typeof addressSchema>;

export const blockHashSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{64}$/, "expected a block hash")
  .transform((value) => value.toLowerCase());

const uint256DecimalSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/, "expected a canonical unsigned decimal integer")
  .refine((value) => {
    try {
      return BigInt(value) <= (1n << 256n) - 1n;
    } catch {
      return false;
    }
  }, "integer is outside uint256 range");

export const tokenIdSchema = uint256DecimalSchema;
export type TokenId = z.infer<typeof tokenIdSchema>;

const boundedText = (max: number) => z.string().trim().min(1).max(max);
const boundedOptionalText = (max: number) => z.string().trim().min(1).max(max).optional();

function canonicalHttpsUrl(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }

  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  if (parsed.protocol !== "https:") throw new Error(`${label} must use HTTPS`);
  if (parsed.username || parsed.password) throw new Error(`${label} must not contain credentials`);
  if (parsed.port !== "" && parsed.port !== "443") throw new Error(`${label} must use port 443`);
  if (isIP(host) !== 0) throw new Error(`${label} must use a DNS hostname, not an IP literal`);
  if (parsed.hash) throw new Error(`${label} must not contain a fragment`);
  if (parsed.search) throw new Error(`${label} must not contain a query string`);
  if (parsed.hostname.length === 0 || parsed.hostname.length > 253) {
    throw new Error(`${label} has an invalid hostname`);
  }

  const canonical = parsed.href;
  if (canonical !== value) throw new Error(`${label} must be canonical`);
  return canonical;
}

function canonicalHttpsOrigin(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  if (parsed.protocol !== "https:") throw new Error(`${label} must use HTTPS`);
  if (parsed.username || parsed.password) throw new Error(`${label} must not contain credentials`);
  if (parsed.port !== "" && parsed.port !== "443") throw new Error(`${label} must use port 443`);
  if (isIP(host) !== 0) throw new Error(`${label} must use a DNS hostname, not an IP literal`);
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) throw new Error(`${label} must be an origin`);
  if (value !== parsed.origin) throw new Error(`${label} must be canonical`);
  return parsed.origin;
}

const categorySchema = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9._-]*$/, "category must be lowercase and identifier-like");

export const manifestCandidateSchema = z
  .object({
    chainId: z.number().int().positive(),
    tokenId: tokenIdSchema,
    expectedName: boundedText(200),
    expectedEndpoint: boundedText(2048),
    expectedOrigin: boundedText(512),
    categories: z.array(categorySchema).max(32),
    source: z.literal("8004scan"),
    provider: boundedOptionalText(200),
    teamOperatedReference: z.boolean().optional(),
  })
  .strict()
  .superRefine((candidate, context) => {
    let endpoint: string;
    let origin: string;
    try {
      endpoint = canonicalHttpsUrl(candidate.expectedEndpoint, "expectedEndpoint");
    } catch (error) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expectedEndpoint"],
        message: error instanceof Error ? error.message : "invalid endpoint",
      });
      return;
    }
    try {
      origin = canonicalHttpsOrigin(candidate.expectedOrigin, "expectedOrigin");
    } catch (error) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expectedOrigin"],
        message: error instanceof Error ? error.message : "invalid origin",
      });
      return;
    }
    if (new URL(endpoint).origin !== origin) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expectedOrigin"],
        message: "expectedOrigin must match expectedEndpoint origin",
      });
    }
    if (new Set(candidate.categories).size !== candidate.categories.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categories"],
        message: "categories must be unique",
      });
    }
  })
  .transform((candidate) => ({
    ...candidate,
    expectedEndpoint: canonicalHttpsUrl(candidate.expectedEndpoint, "expectedEndpoint"),
    expectedOrigin: canonicalHttpsOrigin(candidate.expectedOrigin, "expectedOrigin"),
    categories: [...candidate.categories].sort(),
  }));

export type ManifestCandidate = z.infer<typeof manifestCandidateSchema>;

export const manifestFileSchema = z
  .object({
    version: z.literal(1),
    candidates: z.array(manifestCandidateSchema).min(1).max(8),
  })
  .strict()
  .superRefine((manifest, context) => {
    const keys = manifest.candidates.map((candidate) => `${candidate.chainId}:${candidate.tokenId}`);
    if (new Set(keys).size !== keys.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["candidates"],
        message: "candidate chainId/tokenId pairs must be unique",
      });
    }
  })
  .transform((manifest) => ({
    ...manifest,
    candidates: [...manifest.candidates].sort((left, right) =>
      left.chainId - right.chainId || compareTokenIds(left.tokenId, right.tokenId),
    ),
  }));
export type ManifestFile = z.infer<typeof manifestFileSchema>;

function compareTokenIds(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

const mediaTypeSchema = z.string().regex(/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i).max(128);
const skillIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/).max(128);

export const agentCardSkillSchema = z
  .object({
    id: skillIdSchema,
    name: boundedText(200),
    description: boundedText(1000),
    tags: z.array(z.string().trim().min(1).max(64)).max(32),
    inputModes: z.array(mediaTypeSchema).min(1).max(16),
    outputModes: z.array(mediaTypeSchema).min(1).max(16),
    url: boundedOptionalText(2048),
  })
  .strict()
  .superRefine((skill, context) => {
    if (skill.url === undefined) return;
    try {
      const url = new URL(skill.url);
      if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search) {
        throw new Error("skill URL must be a credential-free HTTPS URL without query or fragment");
      }
      if (url.port !== "" && url.port !== "443") throw new Error("skill URL must use port 443");
      if (isIP(url.hostname.replace(/^\[|\]$/g, "")) !== 0) throw new Error("skill URL must use a hostname");
    } catch (error) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["url"],
        message: error instanceof Error ? error.message : "invalid skill URL",
      });
    }
  })
  .transform((skill) => ({
    ...skill,
    tags: [...new Set(skill.tags)].sort(),
    inputModes: [...new Set(skill.inputModes)].sort(),
    outputModes: [...new Set(skill.outputModes)].sort(),
  }));
export type AgentCardSkill = z.infer<typeof agentCardSkillSchema>;

export const agentCardSchema = z
  .object({
    name: boundedText(200),
    description: boundedText(2000),
    url: boundedText(2048),
    version: boundedText(64),
    protocolVersion: z
      .string()
      .regex(/^0\.3\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/, "protocolVersion must be 0.3.x"),
    preferredTransport: z.literal("JSONRPC"),
    capabilities: z.object({ streaming: z.boolean().optional() }).passthrough().optional(),
    defaultInputModes: z.array(mediaTypeSchema).min(1).max(16),
    defaultOutputModes: z.array(mediaTypeSchema).min(1).max(16),
    skills: z.array(agentCardSkillSchema).min(1).max(64),
  })
  .passthrough()
  .superRefine((card, context) => {
    if (!card.defaultInputModes.includes("application/json")) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["defaultInputModes"], message: "application/json is required" });
    }
    if (!card.defaultOutputModes.includes("application/json")) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["defaultOutputModes"], message: "application/json is required" });
    }
    const ids = card.skills.map((skill) => skill.id);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["skills"], message: "skill IDs must be unique" });
    }
    try {
      const cardUrl = new URL(card.url);
      if (cardUrl.protocol !== "https:" || cardUrl.username || cardUrl.password || cardUrl.hash || cardUrl.search) {
        throw new Error("card URL must be a credential-free HTTPS URL without query or fragment");
      }
      if (cardUrl.port !== "" && cardUrl.port !== "443") throw new Error("card URL must use port 443");
      if (isIP(cardUrl.hostname.replace(/^\[|\]$/g, "")) !== 0) throw new Error("card URL must use a hostname");
    } catch (error) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["url"], message: error instanceof Error ? error.message : "invalid card URL" });
    }
  })
  .transform((card) => ({
    ...card,
    defaultInputModes: [...new Set(card.defaultInputModes)].sort(),
    defaultOutputModes: [...new Set(card.defaultOutputModes)].sort(),
    skills: [...card.skills].sort((left, right) => compareStrings(left.id, right.id)),
  }));
export type AgentCard = z.infer<typeof agentCardSchema>;

export function parseAgentCard(value: unknown, expectedOrigin?: string): AgentCard {
  const card = agentCardSchema.parse(value);
  if (expectedOrigin !== undefined) {
    const origin = canonicalHttpsOrigin(expectedOrigin, "expectedOrigin");
    if (new URL(card.url).origin !== origin) throw new Error("card URL origin does not match manifest origin");
    for (const skill of card.skills) {
      if (skill.url !== undefined && new URL(skill.url).origin !== origin) {
        throw new Error("skill URL origin does not match manifest origin");
      }
    }
  }
  return card;
}

export const sourceObservationSchema = z
  .object({
    source: sourceKindSchema,
    disposition: sourceDispositionSchema,
    startedAt: isoUtcSchema,
    endedAt: isoUtcSchema,
    latencyMs: z.number().finite().nonnegative().max(86_400_000),
    status: z.string().trim().min(1).max(64),
    responseHash: sha256Schema.optional(),
    httpStatus: z.number().int().min(100).max(599).optional(),
    origin: boundedOptionalText(512),
    observedBlock: z.number().int().nonnegative().optional(),
    observedBlockHash: blockHashSchema.optional(),
    confirmationDepth: z.number().int().nonnegative().optional(),
    registryAddress: addressSchema.optional(),
    error: z.object({ code: reportErrorCodeSchema, message: boundedText(240) }).strict().optional(),
  })
  .strict();
export type SourceObservation = z.infer<typeof sourceObservationSchema>;

export const gateNameSchema = z.enum([
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
]);
export type GateName = z.infer<typeof gateNameSchema>;

export const gateResultSchema = z
  .object({
    gate: gateNameSchema,
    state: gateStateSchema,
    evidence: z.array(evidenceLevelSchema).max(3),
    evidenceRefs: z.array(z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/)).max(64),
    reasonCode: reportErrorCodeSchema.optional(),
    note: boundedOptionalText(240),
  })
  .strict()
  .transform((gate) => ({
    ...gate,
    evidence: [...new Set(gate.evidence)].sort(),
    evidenceRefs: [...new Set(gate.evidenceRefs)].sort(),
  }));
export type GateResult = z.infer<typeof gateResultSchema>;

const jsonPrimitiveSchema = z.union([z.string().max(2000), z.number().finite(), z.boolean(), z.null()]);
type JsonValue = z.infer<typeof jsonPrimitiveSchema> | JsonValue[] | { [key: string]: JsonValue };
const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([jsonPrimitiveSchema, z.array(jsonValueSchema).max(64), z.record(jsonValueSchema).refine((value) => Object.keys(value).length <= 64)]),
);

export const evidenceRecordSchema = z
  .object({
    id: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/),
    level: evidenceLevelSchema,
    source: sourceKindSchema,
    claim: boundedText(160),
    observedAt: isoUtcSchema,
    responseHash: sha256Schema.optional(),
    observedBlock: z.number().int().nonnegative().optional(),
    observedBlockHash: blockHashSchema.optional(),
    details: z.record(jsonValueSchema).optional(),
  })
  .strict();
export type EvidenceRecord = z.infer<typeof evidenceRecordSchema>;

export const reportErrorSchema = z.object({ code: reportErrorCodeSchema, message: boundedText(240) }).strict();
export type ReportError = z.infer<typeof reportErrorSchema>;

export const scanObservationSchema = z
  .object({
    indexed: z.boolean(),
    observedAt: isoUtcSchema,
    responseHash: sha256Schema.optional(),
    apiVersion: boundedOptionalText(64),
    apiTimestamp: isoUtcSchema.optional(),
    claimedOwner: addressSchema.optional(),
    claimedEndpoint: boundedOptionalText(2048),
    claimedName: boundedOptionalText(200),
    description: z.string().trim().max(4000).nullable().optional(),
    creatorAddress: addressSchema.nullable().optional(),
    agentWallet: addressSchema.nullable().optional(),
    isVerifiedByScan: z.boolean().optional(),
    isEndpointVerifiedByScan: z.boolean().optional(),
    endpointVerificationDomain: z.string().trim().max(253).nullable().optional(),
    endpointVerificationError: z.string().trim().max(240).nullable().optional(),
    endpointLastCheckedAt: isoUtcSchema.nullable().optional(),
    isActive: z.boolean().nullable().optional(),
    x402Supported: z.boolean().nullable().optional(),
    feedbackCount: z.number().int().nonnegative().nullable().optional(),
    averageScore: z.number().finite().nullable().optional(),
    healthScore: z.number().finite().nullable().optional(),
    healthCheckedAt: isoUtcSchema.nullable().optional(),
    updatedAt: isoUtcSchema.nullable().optional(),
    supportedProtocols: z.array(boundedText(64)).max(32).optional(),
  })
  .strict();
export type ScanObservation = z.infer<typeof scanObservationSchema>;

export const chainObservationSchema = z
  .object({
    chainId: z.number().int().positive(),
    registryAddress: addressSchema,
    tokenId: tokenIdSchema,
    owner: addressSchema.optional(),
    observedBlock: z.number().int().nonnegative(),
    observedBlockHash: blockHashSchema,
    confirmationDepth: z.number().int().nonnegative(),
    registryCodeHash: sha256Schema,
    observedAt: isoUtcSchema,
    responseHash: sha256Schema.optional(),
  })
  .strict();
export type ChainObservation = z.infer<typeof chainObservationSchema>;

export const cardObservationSchema = z
  .object({
    url: boundedText(2048),
    observedAt: isoUtcSchema,
    responseHash: sha256Schema.optional(),
    protocolVersion: boundedText(64),
    preferredTransport: z.literal("JSONRPC"),
    skills: z.array(agentCardSkillSchema).max(64),
    inputModes: z.array(mediaTypeSchema).max(16),
    outputModes: z.array(mediaTypeSchema).max(16),
  })
  .strict()
  .transform((card) => ({
    ...card,
    skills: [...card.skills].sort((left, right) => compareStrings(left.id, right.id)),
    inputModes: [...new Set(card.inputModes)].sort(),
    outputModes: [...new Set(card.outputModes)].sort(),
  }));
export type CardObservation = z.infer<typeof cardObservationSchema>;

export const sourceBudgetsSchema = z
  .object({
    maxCandidates: z.number().int().positive(),
    maxScanDetailRequests: z.number().int().nonnegative(),
    scanConcurrency: z.number().int().positive(),
    requestDeadlineMs: z.number().int().positive(),
    maxDecodedBodyBytes: z.number().int().positive(),
    maxSnapshotRetries: z.number().int().nonnegative(),
  })
  .strict();
export type SourceBudgets = z.infer<typeof sourceBudgetsSchema>;

export const chainProfileSummarySchema = z
  .object({
    name: z.string().regex(/^[a-z0-9._-]+$/).max(64),
    chainId: z.number().int().positive(),
    registryAddress: addressSchema,
    rpcOrigin: boundedText(512),
  })
  .strict();
export type ChainProfileSummary = z.infer<typeof chainProfileSummarySchema>;

export const candidateReportSchema = z
  .object({
    chainId: z.number().int().positive(),
    tokenId: tokenIdSchema,
    expectedName: boundedText(200),
    expectedEndpoint: boundedText(2048),
    expectedOrigin: boundedText(512),
    categories: z.array(categorySchema).max(32),
    provider: boundedOptionalText(200),
    teamOperatedReference: z.boolean().optional(),
    status: candidateStatusSchema,
    sources: z.array(sourceObservationSchema).max(32),
    evidence: z.array(evidenceRecordSchema).max(256),
    gates: z.array(gateResultSchema).max(32),
    errors: z.array(reportErrorSchema).max(32),
    scan: scanObservationSchema.optional(),
    chain: chainObservationSchema.optional(),
    card: cardObservationSchema.optional(),
    owner: addressSchema.optional(),
    addresses: z.array(addressSchema).max(128).optional(),
  })
  .strict();
export type CandidateReport = z.infer<typeof candidateReportSchema>;

export const runReportSchema = z
  .object({
    schema: z.literal(REPORT_SCHEMA),
    runStatus: z.enum(["complete", "inconclusive"]),
    generatedAt: isoUtcSchema,
    chainProfile: chainProfileSummarySchema,
    policyFingerprint: sha256Schema,
    budgets: sourceBudgetsSchema,
    sources: z.array(sourceObservationSchema).max(64),
    candidates: z.array(candidateReportSchema).max(8),
  })
  .strict();
export type RunReport = z.infer<typeof runReportSchema>;

export type Report = RunReport;
