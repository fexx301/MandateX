import { createHash } from "node:crypto";

import type { ChainProfileSummary, SourceBudgets } from "./schema.js";

export const BSC_CHAIN_PROFILES = {
  mainnet: {
    name: "bsc-mainnet",
    chainId: 56,
    registryAddress: "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432",
    rpcOrigin: "https://bsc-dataseed.binance.org",
    liveEnabled: true,
  },
  testnet: {
    name: "bsc-testnet",
    chainId: 97,
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    rpcOrigin: "https://data-seed-prebsc-2-s2.binance.org:8545",
    liveEnabled: false,
  },
} as const;

export type ChainProfileName = keyof typeof BSC_CHAIN_PROFILES;
export type ChainProfile = (typeof BSC_CHAIN_PROFILES)[ChainProfileName];

export const DEFAULT_CHAIN_PROFILE: ChainProfileSummary = {
  name: BSC_CHAIN_PROFILES.mainnet.name,
  chainId: BSC_CHAIN_PROFILES.mainnet.chainId,
  registryAddress: BSC_CHAIN_PROFILES.mainnet.registryAddress,
  rpcOrigin: BSC_CHAIN_PROFILES.mainnet.rpcOrigin,
};

export const DEFAULT_SOURCE_BUDGETS: SourceBudgets = {
  maxCandidates: 8,
  maxScanDetailRequests: 8,
  scanConcurrency: 2,
  requestDeadlineMs: 8_000,
  maxDecodedBodyBytes: 256 * 1024,
  maxSnapshotRetries: 1,
};

export const RPC_METHOD_ALLOWLIST = [
  "eth_blockNumber",
  "eth_call",
  "eth_chainId",
  "eth_getBlockByHash",
  "eth_getBlockByNumber",
  "eth_getCode",
] as const;

export const PASSIVE_GATE_POLICY = {
  manifest_identity: { evidence: ["claimed"], passiveRule: "required" },
  scan_detail: { evidence: ["claimed", "detected"], passiveRule: "observe" },
  bsc_chain: { evidence: ["verified"], passiveRule: "required" },
  token_ownership: { evidence: ["verified"], passiveRule: "required" },
  endpoint_origin: { evidence: ["claimed", "detected"], passiveRule: "required" },
  endpoint_health: { evidence: ["detected"], passiveRule: "required" },
  task_interface: { evidence: ["detected"], passiveRule: "observe" },
  endpoint_operator_binding: { evidence: [], passiveRule: "unknown" },
  quote_signature: { evidence: [], passiveRule: "unknown" },
  category_evidence: { evidence: [], passiveRule: "unknown" },
  mandate_policy: { evidence: [], passiveRule: "unknown" },
  transaction_preview: { evidence: [], passiveRule: "unknown" },
} as const;

export const PASSIVE_V1_POLICY = {
  version: "mandatex.agent-supply.policy.v1",
  mode: "passive",
  chain: {
    profile: DEFAULT_CHAIN_PROFILE,
    targetBlockLag: 2,
    requireCanonical: true,
    finalHashRecheck: true,
    retryWholeSnapshot: true,
  },
  transport: {
    schemes: ["https"],
    livePorts: [443],
    allowCredentials: false,
    allowRedirects: false,
    allowCompression: false,
    allowAmbientProxy: false,
    allowCookies: false,
    resolveAllAddresses: true,
    rejectReservedAddresses: true,
    pinValidatedSocketAddress: true,
    preserveTlsHostname: true,
    connectTimeoutMs: 3_000,
    headerTimeoutMs: 5_000,
    totalTimeoutMs: DEFAULT_SOURCE_BUDGETS.requestDeadlineMs,
    maxDecodedBodyBytes: DEFAULT_SOURCE_BUDGETS.maxDecodedBodyBytes,
    methodMatrix: {
      scan: { method: "GET", host: "8004scan.io", pathTemplate: "/api/v1/public/agents/{chainId}/{tokenId}" },
      agentCard: { method: "GET", path: "manifest-exact" },
      rpc: { method: "POST", origin: DEFAULT_CHAIN_PROFILE.rpcOrigin, methods: RPC_METHOD_ALLOWLIST },
    },
  },
  sources: {
    budgets: DEFAULT_SOURCE_BUDGETS,
    scan: {
      anonymous: true,
      stopOnHttp429: true,
      stopOnRetryAfter: true,
      retries: 0,
    },
    rpc: {
      snapshotAttempts: DEFAULT_SOURCE_BUDGETS.maxSnapshotRetries + 1,
      retryableCanonicalityErrors: ["header not found", "missing trie node", "canonicality failure"],
    },
    agentCard: {
      requiredHttpStatus: 200,
      requiredContentType: "application/json",
      protocolRange: "0.3.x",
      preferredTransport: "JSONRPC",
      requiredMode: "application/json",
      probeNestedUrls: false,
    },
  },
  gates: PASSIVE_GATE_POLICY,
  classifications: {
    verifiedHireableEnabled: false,
    infrastructureFailure: "INCONCLUSIVE",
    definitiveCandidateFailure: "UNAVAILABLE",
    passiveSuccess: "REGISTERED_ONLY",
  },
  activeMethods: {
    negotiate: false,
    notify_funded: false,
    create: false,
    fund: false,
  },
} as const;

export type EffectivePolicy = typeof PASSIVE_V1_POLICY;
export const DEFAULT_POLICY = PASSIVE_V1_POLICY;

function canonicalPolicyJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("policy contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalPolicyJson).join(",")}]`;
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    const entries = Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalPolicyJson(object[key])}`);
    return `{${entries.join(",")}}`;
  }
  throw new TypeError(`policy contains unsupported value type: ${typeof value}`);
}

export function computePolicyFingerprint(policy: unknown = PASSIVE_V1_POLICY): string {
  return createHash("sha256").update(canonicalPolicyJson(policy), "utf8").digest("hex");
}

export const POLICY_FINGERPRINT = computePolicyFingerprint();

