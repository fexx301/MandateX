import { createHash } from "node:crypto";
import { promises as dns } from "node:dns";
import { request as httpsRequest, type RequestOptions } from "node:https";
import {
  BlockList,
  isIP,
  type LookupFunction,
} from "node:net";
import type { TLSSocket } from "node:tls";

export const SCAN_ORIGIN = "https://8004scan.io";
export const BSC_MAINNET_RPC_ORIGIN = "https://bsc-dataseed.binance.org";

export const ALLOWED_RPC_METHODS = [
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getBlockByHash",
  "eth_getCode",
  "eth_call",
] as const;

export type AllowedRpcMethod = (typeof ALLOWED_RPC_METHODS)[number];

export const DEFAULT_HTTP_LIMITS = Object.freeze({
  connectTimeoutMs: 3_000,
  headersTimeoutMs: 5_000,
  totalTimeoutMs: 8_000,
  maxResponseBytes: 256 * 1024,
  maxRequestBytes: 32 * 1024,
});

export const ACTIVE_QUOTE_LIMITS = Object.freeze({
  maxRequestBytes: 16 * 1024,
  maxResponseBytes: 64 * 1024,
});

export const ACTIVE_QUOTE_RPC_LIMITS = Object.freeze({
  maxRequestBytes: 8 * 1024,
  maxResponseBytes: 16 * 1024,
});

export const ACTIVE_QUOTE_RPC_METHODS = ["eth_getCode", "eth_call"] as const;

export const BSC_PREVIEW_RPC_LIMITS = Object.freeze({
  maxRequestBytes: 24 * 1024,
  maxResponseBytes: 64 * 1024,
});

/** Limits for the isolated category-evidence reader. */
export const BSC_CATEGORY_RPC_LIMITS = Object.freeze({
  maxRequestBytes: 16 * 1024,
  maxResponseBytes: 64 * 1024,
});

export const BSC_CATEGORY_RPC_METHODS = [
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_call",
] as const;

export const BSC_ACTIVATION_RPC_LIMITS = Object.freeze({
  maxRequestBytes: 24 * 1024,
  maxResponseBytes: 128 * 1024,
});

export const BSC_ACTIVATION_RPC_METHODS = [
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getTransactionByHash",
  "eth_getTransactionReceipt",
  "eth_getCode",
  "eth_getStorageAt",
  "eth_call",
] as const;

export const BSC_ACTIVATION_TARGETS = Object.freeze([
  "0xea4daa3100a767e86fded867729ae7446476eba6",
  "0xd5f9b570c96b5d67702d508c0bfb8b3b09209787",
  "0x51895229e12f9876011789b04f8698af06ccd6da",
  "0xf0cf8f47e5c035f16247ff16e9f367e477ee5007",
  "0x9c01845705b3078aa2e8cff7520a6376fd766de5",
  "0xce24439f2d9c6a2289f741120fe202248b666666",
] as const);

export const BSC_ACTIVATION_STATE_READ_SELECTORS = Object.freeze([
  "0x3013ce29", // paymentToken()
  "0xbf22c457", // getJob(uint256)
  "0xfabc3329", // jobHasBudget(uint256)
  "0x912955fd", // commerce()
  "0xa35634b9", // jobPolicy(uint256)
  "0x70be56b9", // policyWhitelist(address)
  "0x5c975abb", // paused()
  "0x4f4a1777", // inflightJobCount()
  "0xf887ea40", // router()
  "0x117f5f92", // disputeWindow()
] as const);

export const BSC_ACTIVATION_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as const;

const BSC_ACTIVATION_TARGET_SET = new Set<string>(BSC_ACTIVATION_TARGETS);
const BSC_ACTIVATION_STATE_READ_SELECTOR_SET = new Set<string>(
  BSC_ACTIVATION_STATE_READ_SELECTORS,
);

export const BSC_PREVIEW_RPC_METHODS = [
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_call",
] as const;

export const BSC_PREVIEW_POSITION_MANAGER =
  "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364" as const;
export const BSC_PREVIEW_MULTICALL_SELECTOR = "0xac9650d8" as const;
export const BSC_PREVIEW_SIMULATION_GAS = "0x7a1200" as const;

export const BSC_PREVIEW_STATE_READ_SELECTORS = Object.freeze([
  "0x6352211e", // ownerOf(uint256)
  "0xc45a0155", // factory()
  "0xd5f39488", // deployer()
  "0x99fbab88", // positions(uint256)
  "0x081812fc", // getApproved(uint256)
  "0xe985e9c5", // isApprovedForAll(address,address)
  "0x3850c7bd", // slot0()
  "0x1a686502", // liquidity()
  "0x0dfe1681", // token0()
  "0xd21220a7", // token1()
  "0xddca3f43", // fee()
  "0xd0c93a7c", // tickSpacing()
  "0x1698ee82", // getPool(address,address,uint24)
  "0x22afcccb", // feeAmountTickSpacing(uint24)
  "0x313ce567", // decimals()
  "0x70a08231", // balanceOf(address)
  "0xdd62ed3e", // allowance(address,address)
] as const);

/** Static selectors category adapters are allowed to call on BSC. */
export const BSC_CATEGORY_STATE_READ_SELECTORS = Object.freeze([
  "0x3850c7bd", // slot0()
  "0x01e1d114", // totalAssets()
  "0x18160ddd", // totalSupply()
  "0xbf92857c", // getUserAccountData(address)
  "0x5ec88c79", // getAccountLiquidity(address)
  "0xabfceffc", // getAssetsIn(address)
  "0x95dd9193", // borrowBalanceStored(address)
] as const);

const BSC_CATEGORY_STATE_READ_SELECTOR_SET = new Set<string>(
  BSC_CATEGORY_STATE_READ_SELECTORS,
);
const BSC_CATEGORY_NO_ARGUMENT_SELECTOR_SET = new Set<string>([
  "0x3850c7bd",
  "0x01e1d114",
  "0x18160ddd",
]);
const BSC_CATEGORY_ADDRESS_ARGUMENT_SELECTOR_SET = new Set<string>([
  "0xbf92857c",
  "0x5ec88c79",
  "0xabfceffc",
  "0x95dd9193",
]);

const BSC_PREVIEW_STATE_READ_SELECTOR_SET = new Set<string>(
  BSC_PREVIEW_STATE_READ_SELECTORS,
);

type BscPreviewRpcCommon = Readonly<{
  kind: "bsc-preview-rpc";
  method: "POST";
  url: string;
  body: string;
}>;

export type BscPreviewRpcRoute =
  | (BscPreviewRpcCommon &
      Readonly<{
        purpose: "chain-id";
        rpcMethod: "eth_chainId";
      }>)
  | (BscPreviewRpcCommon &
      Readonly<{
        purpose: "head-block-number";
        rpcMethod: "eth_blockNumber";
      }>)
  | (BscPreviewRpcCommon &
      Readonly<{
        purpose: "block-header";
        rpcMethod: "eth_getBlockByNumber";
        approvedBlockNumber: string;
      }>)
  | (BscPreviewRpcCommon &
      Readonly<{
        purpose: "contract-code";
        rpcMethod: "eth_getCode";
        approvedTargets: readonly [string];
        approvedBlockHash: string;
      }>)
  | (BscPreviewRpcCommon &
      Readonly<{
        purpose: "state-read";
        rpcMethod: "eth_call";
        approvedTargets: readonly [string];
        approvedBlockHash: string;
      }>)
  | (BscPreviewRpcCommon &
      Readonly<{
        purpose: "simulation";
        rpcMethod: "eth_call";
        approvedCaller: string;
        approvedCalldataSha256: string;
        approvedBlockHash: string;
      }>);

type BscCategoryRpcCommon = Readonly<{
  kind: "bsc-category-rpc";
  method: "POST";
  url: string;
  body: string;
}>;

export type BscCategoryRpcRoute =
  | (BscCategoryRpcCommon &
      Readonly<{ purpose: "chain-id"; rpcMethod: "eth_chainId" }>)
  | (BscCategoryRpcCommon &
      Readonly<{ purpose: "head-block-number"; rpcMethod: "eth_blockNumber" }>)
  | (BscCategoryRpcCommon &
      Readonly<{
        purpose: "block-header";
        rpcMethod: "eth_getBlockByNumber";
        approvedBlockNumber: string;
      }>)
  | (BscCategoryRpcCommon &
      Readonly<{
        purpose: "state-read";
        rpcMethod: "eth_call";
        approvedTargets: readonly [string];
        approvedCalldata: string;
        approvedBlockHash: string;
      }>);

type BscActivationRpcCommon = Readonly<{
  kind: "bsc-activation-rpc";
  method: "POST";
  url: string;
  body: string;
}>;

export type BscActivationRpcRoute =
  | (BscActivationRpcCommon &
      Readonly<{ purpose: "chain-id"; rpcMethod: "eth_chainId" }>)
  | (BscActivationRpcCommon &
      Readonly<{ purpose: "head-block-number"; rpcMethod: "eth_blockNumber" }>)
  | (BscActivationRpcCommon &
      Readonly<{
        purpose: "block-header";
        rpcMethod: "eth_getBlockByNumber";
        approvedBlockNumber: string;
      }>)
  | (BscActivationRpcCommon &
      Readonly<{
        purpose: "transaction";
        rpcMethod: "eth_getTransactionByHash";
        approvedTransactionHash: string;
      }>)
  | (BscActivationRpcCommon &
      Readonly<{
        purpose: "receipt";
        rpcMethod: "eth_getTransactionReceipt";
        approvedTransactionHash: string;
      }>)
  | (BscActivationRpcCommon &
      Readonly<{
        purpose: "contract-code";
        rpcMethod: "eth_getCode";
        approvedTargets: readonly [string];
        approvedBlockHash: string;
      }>)
  | (BscActivationRpcCommon &
      Readonly<{
        purpose: "proxy-implementation";
        rpcMethod: "eth_getStorageAt";
        approvedTargets: readonly [string];
        approvedBlockHash: string;
      }>)
  | (BscActivationRpcCommon &
      Readonly<{
        purpose: "state-read";
        rpcMethod: "eth_call";
        approvedTargets: readonly [string];
        approvedBlockHash: string;
      }>);

export type DnsAddress = Readonly<{
  address: string;
  family: 4 | 6;
}>;

export type Resolver = (hostname: string) => Promise<readonly DnsAddress[]>;

export type TransportRoute =
  | Readonly<{
      kind: "scan-detail";
      method: "GET";
      url: string;
      chainId: number;
      tokenId: string;
    }>
  | Readonly<{
      kind: "agent-card";
      method: "GET";
      url: string;
      expectedOrigin: string;
      expectedPath: string;
    }>
  | Readonly<{
      kind: "bsc-rpc";
      method: "POST";
      url: string;
      rpcMethod: AllowedRpcMethod;
      body: string;
    }>
  | Readonly<{
      kind: "bsc-quote-rpc";
      method: "POST";
      url: string;
      rpcMethod: "eth_getCode" | "eth_call";
      approvedProvider: string;
      approvedBlockHash: string;
      body: string;
    }>
  | BscPreviewRpcRoute
  | BscCategoryRpcRoute
  | BscActivationRpcRoute
  | Readonly<{
      kind: "a2a-quote";
      method: "POST";
      url: string;
      approvedUrl: string;
      rpcMethod: "message/send";
      body: string;
    }>;

export type HttpLimits = Readonly<{
  connectTimeoutMs: number;
  headersTimeoutMs: number;
  totalTimeoutMs: number;
  maxResponseBytes: number;
  maxRequestBytes: number;
}>;

export type BoundedHttpResponse = Readonly<{
  status: number;
  contentType: string | null;
  retryAfter: string | null;
  rateLimitRemaining: string | null;
  body: Uint8Array;
  responseSha256: string;
  resolvedAddress: string;
  startedAt: string;
  finishedAt: string;
  latencyMs: number;
}>;

export type TransportErrorCode =
  | "INVALID_URL"
  | "METHOD_NOT_ALLOWED"
  | "ORIGIN_NOT_ALLOWED"
  | "PATH_NOT_ALLOWED"
  | "RPC_METHOD_NOT_ALLOWED"
  | "REQUEST_TOO_LARGE"
  | "DNS_EMPTY"
  | "DNS_UNSAFE_ADDRESS"
  | "DNS_ERROR"
  | "CONNECT_TIMEOUT"
  | "HEADERS_TIMEOUT"
  | "TOTAL_TIMEOUT"
  | "REMOTE_ADDRESS_MISMATCH"
  | "REDIRECT_REJECTED"
  | "COMPRESSED_RESPONSE_REJECTED"
  | "RESPONSE_TOO_LARGE"
  | "RESPONSE_ABORTED"
  | "NETWORK_ERROR"
  | "INVALID_CONTENT_TYPE"
  | "INVALID_JSON";

const PUBLIC_ERROR_MESSAGES: Readonly<Record<TransportErrorCode, string>> = {
  INVALID_URL: "request URL violates verifier policy",
  METHOD_NOT_ALLOWED: "HTTP method violates verifier policy",
  ORIGIN_NOT_ALLOWED: "request origin is not approved",
  PATH_NOT_ALLOWED: "request path is not approved",
  RPC_METHOD_NOT_ALLOWED: "JSON-RPC method is not approved",
  REQUEST_TOO_LARGE: "request body exceeds verifier limit",
  DNS_EMPTY: "hostname returned no usable addresses",
  DNS_UNSAFE_ADDRESS: "hostname resolved to a non-public address",
  DNS_ERROR: "hostname resolution failed",
  CONNECT_TIMEOUT: "connection deadline exceeded",
  HEADERS_TIMEOUT: "response header deadline exceeded",
  TOTAL_TIMEOUT: "request deadline exceeded",
  REMOTE_ADDRESS_MISMATCH: "socket destination did not match the pinned address",
  REDIRECT_REJECTED: "redirect responses are not allowed",
  COMPRESSED_RESPONSE_REJECTED: "compressed responses are not allowed",
  RESPONSE_TOO_LARGE: "response body exceeds verifier limit",
  RESPONSE_ABORTED: "response ended before completion",
  NETWORK_ERROR: "network request failed",
  INVALID_CONTENT_TYPE: "response is not JSON",
  INVALID_JSON: "response contains malformed JSON",
};

export class TransportError extends Error {
  readonly code: TransportErrorCode;

  constructor(code: TransportErrorCode) {
    super(PUBLIC_ERROR_MESSAGES[code]);
    this.name = "TransportError";
    this.code = code;
  }
}

export async function systemResolver(hostname: string): Promise<DnsAddress[]> {
  try {
    const answers = await dns.lookup(hostname, { all: true, verbatim: true });
    return answers.map((answer) => {
      if (answer.family !== 4 && answer.family !== 6) {
        throw new TransportError("DNS_ERROR");
      }
      return {
        address: answer.address,
        family: answer.family,
      };
    });
  } catch {
    throw new TransportError("DNS_ERROR");
  }
}

const RESERVED_DESTINATIONS = buildReservedDestinationLists();

function buildReservedDestinationLists(): Readonly<{
  ipv4: BlockList;
  ipv6: BlockList;
}> {
  const ipv4 = new BlockList();
  const ipv6 = new BlockList();

  const ipv4Subnets: ReadonlyArray<readonly [string, number]> = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ];

  const ipv6Subnets: ReadonlyArray<readonly [string, number]> = [
    ["::", 128],
    ["::1", 128],
    ["::ffff:0:0", 96],
    ["64:ff9b::", 96],
    ["100::", 64],
    ["2001::", 32],
    ["2001:10::", 28],
    ["2001:20::", 28],
    ["2001:db8::", 32],
    ["2002::", 16],
    ["3fff::", 20],
    ["fc00::", 7],
    ["fe80::", 10],
    ["fec0::", 10],
    ["ff00::", 8],
  ];

  for (const [network, prefix] of ipv4Subnets) {
    ipv4.addSubnet(network, prefix, "ipv4");
  }
  for (const [network, prefix] of ipv6Subnets) {
    ipv6.addSubnet(network, prefix, "ipv6");
  }

  return { ipv4, ipv6 };
}

export function isPublicDestination(address: string, family?: 4 | 6): boolean {
  const detectedFamily = isIP(stripIpv6Brackets(address));
  if (detectedFamily === 0) return false;
  if (family !== undefined && detectedFamily !== family) return false;

  return detectedFamily === 4
    ? !RESERVED_DESTINATIONS.ipv4.check(stripIpv6Brackets(address), "ipv4")
    : !RESERVED_DESTINATIONS.ipv6.check(stripIpv6Brackets(address), "ipv6");
}

export function selectPinnedAddress(
  answers: readonly DnsAddress[],
): DnsAddress {
  if (answers.length === 0) throw new TransportError("DNS_EMPTY");

  const unique = new Map<string, DnsAddress>();
  for (const answer of answers) {
    if (!isPublicDestination(answer.address, answer.family)) {
      throw new TransportError("DNS_UNSAFE_ADDRESS");
    }
    unique.set(`${answer.family}:${answer.address}`, answer);
  }

  const sorted = [...unique.values()].sort(
    (left, right) =>
      left.family - right.family || left.address.localeCompare(right.address),
  );
  const selected = sorted[0];
  if (selected === undefined) throw new TransportError("DNS_EMPTY");
  return selected;
}

function stripIpv6Brackets(value: string): string {
  return value.startsWith("[") && value.endsWith("]")
    ? value.slice(1, -1)
    : value;
}

export function validateTransportRoute(route: TransportRoute): URL {
  return validateTransportRouteSnapshot(snapshotTransportRoute(route));
}

function validateTransportRouteSnapshot(route: TransportRoute): URL {
  let url: URL;
  try {
    url = new URL(route.url);
  } catch {
    throw new TransportError("INVALID_URL");
  }

  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    url.search !== "" ||
    (url.port !== "" && url.port !== "443") ||
    url.hostname.endsWith(".") ||
    isIP(stripIpv6Brackets(url.hostname)) !== 0
  ) {
    throw new TransportError("INVALID_URL");
  }

  if (route.kind === "scan-detail") {
    if (route.method !== "GET") throw new TransportError("METHOD_NOT_ALLOWED");
    if (url.origin !== SCAN_ORIGIN) {
      throw new TransportError("ORIGIN_NOT_ALLOWED");
    }
    const expectedPath = `/api/v1/public/agents/${route.chainId}/${route.tokenId}`;
    if (url.pathname !== expectedPath) {
      throw new TransportError("PATH_NOT_ALLOWED");
    }
  } else if (route.kind === "agent-card") {
    if (route.method !== "GET") throw new TransportError("METHOD_NOT_ALLOWED");
    if (url.origin !== normalizeOrigin(route.expectedOrigin)) {
      throw new TransportError("ORIGIN_NOT_ALLOWED");
    }
    if (url.pathname !== route.expectedPath) {
      throw new TransportError("PATH_NOT_ALLOWED");
    }
  } else if (route.kind === "bsc-rpc" || route.kind === "bsc-quote-rpc") {
    if (route.method !== "POST") throw new TransportError("METHOD_NOT_ALLOWED");
    if (url.origin !== BSC_MAINNET_RPC_ORIGIN || url.pathname !== "/") {
      throw new TransportError("ORIGIN_NOT_ALLOWED");
    }
    if (
      route.kind === "bsc-quote-rpc" &&
      !ACTIVE_QUOTE_RPC_METHODS.includes(route.rpcMethod)
    ) {
      throw new TransportError("RPC_METHOD_NOT_ALLOWED");
    }
    if (!ALLOWED_RPC_METHODS.includes(route.rpcMethod)) {
      throw new TransportError("RPC_METHOD_NOT_ALLOWED");
    }
    if (route.kind === "bsc-quote-rpc") {
      assertQuoteRpcBody(
        route.body,
        route.rpcMethod,
        route.approvedProvider,
        route.approvedBlockHash,
      );
    } else {
      assertRpcBodyMethod(route.body, route.rpcMethod);
    }
  } else if (route.kind === "bsc-preview-rpc") {
    if (route.method !== "POST") throw new TransportError("METHOD_NOT_ALLOWED");
    if (url.origin !== BSC_MAINNET_RPC_ORIGIN || url.pathname !== "/") {
      throw new TransportError("ORIGIN_NOT_ALLOWED");
    }
    if (!BSC_PREVIEW_RPC_METHODS.includes(route.rpcMethod)) {
      throw new TransportError("RPC_METHOD_NOT_ALLOWED");
    }
    assertPreviewRpcRoute(route);
  } else if (route.kind === "bsc-category-rpc") {
    if (route.method !== "POST") throw new TransportError("METHOD_NOT_ALLOWED");
    if (url.origin !== BSC_MAINNET_RPC_ORIGIN || url.pathname !== "/") {
      throw new TransportError("ORIGIN_NOT_ALLOWED");
    }
    if (!BSC_CATEGORY_RPC_METHODS.includes(route.rpcMethod)) {
      throw new TransportError("RPC_METHOD_NOT_ALLOWED");
    }
    assertCategoryRpcRoute(route);
  } else if (route.kind === "bsc-activation-rpc") {
    if (route.method !== "POST") throw new TransportError("METHOD_NOT_ALLOWED");
    if (url.origin !== BSC_MAINNET_RPC_ORIGIN || url.pathname !== "/") {
      throw new TransportError("ORIGIN_NOT_ALLOWED");
    }
    if (!BSC_ACTIVATION_RPC_METHODS.includes(route.rpcMethod)) {
      throw new TransportError("RPC_METHOD_NOT_ALLOWED");
    }
    assertActivationRpcRoute(route);
  } else if (route.kind === "a2a-quote") {
    if (route.method !== "POST") throw new TransportError("METHOD_NOT_ALLOWED");
    if (url.href !== canonicalApprovedQuoteUrl(route.approvedUrl)) {
      throw new TransportError("ORIGIN_NOT_ALLOWED");
    }
    if (route.rpcMethod !== "message/send") {
      throw new TransportError("RPC_METHOD_NOT_ALLOWED");
    }
    assertQuoteBody(route.body);
  } else {
    assertNever(route);
  }

  return url;
}

function normalizeOrigin(value: string): string {
  let origin: URL;
  try {
    origin = new URL(value);
  } catch {
    throw new TransportError("INVALID_URL");
  }
  if (
    origin.protocol !== "https:" ||
    origin.username !== "" ||
    origin.password !== "" ||
    origin.hash !== "" ||
    origin.search !== "" ||
    origin.pathname !== "/" ||
    (origin.port !== "" && origin.port !== "443") ||
    isIP(stripIpv6Brackets(origin.hostname)) !== 0
  ) {
    throw new TransportError("INVALID_URL");
  }
  return origin.origin;
}

function assertRpcBodyMethod(body: string, expected: AllowedRpcMethod): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  if (!isRecord(parsed) || parsed.method !== expected) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
}

function assertQuoteRpcBody(
  body: string,
  expectedMethod: "eth_getCode" | "eth_call",
  approvedProvider: string,
  approvedBlockHash: string,
): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  if (
    !isRecord(parsed) ||
    !hasExactKeys(parsed, ["id", "jsonrpc", "method", "params"]) ||
    parsed.jsonrpc !== "2.0" ||
    parsed.method !== expectedMethod ||
    typeof parsed.id !== "string" ||
    parsed.id.length < 1 ||
    parsed.id.length > 128 ||
    !Array.isArray(parsed.params) ||
    parsed.params.length !== 2 ||
    !/^0x[a-fA-F0-9]{40}$/.test(approvedProvider) ||
    !/^0x[a-fA-F0-9]{64}$/.test(approvedBlockHash)
  ) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  const block = parsed.params[1];
  if (
    !isRecord(block) ||
    !hasExactKeys(block, ["blockHash", "requireCanonical"]) ||
    block.blockHash !== approvedBlockHash ||
    block.requireCanonical !== true
  ) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  const normalizedProvider = approvedProvider.toLowerCase();
  if (expectedMethod === "eth_getCode") {
    if (
      typeof parsed.params[0] !== "string" ||
      parsed.params[0].toLowerCase() !== normalizedProvider
    ) {
      throw new TransportError("RPC_METHOD_NOT_ALLOWED");
    }
    return;
  }
  const call = parsed.params[0];
  if (
    !isRecord(call) ||
    !hasExactKeys(call, ["data", "to"]) ||
    typeof call.to !== "string" ||
    call.to.toLowerCase() !== normalizedProvider ||
    typeof call.data !== "string" ||
    !/^0x[a-fA-F0-9]+$/.test(call.data) ||
    !call.data.toLowerCase().startsWith("0x1626ba7e")
  ) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
}

function assertPreviewRpcRoute(route: BscPreviewRpcRoute): void {
  assertPreviewRouteKeys(route);
  const parsed = parseStrictRpcBody(route.body, route.rpcMethod);

  switch (route.purpose) {
    case "chain-id":
      if (route.rpcMethod !== "eth_chainId" || parsed.params.length !== 0) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    case "head-block-number":
      if (route.rpcMethod !== "eth_blockNumber" || parsed.params.length !== 0) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    case "block-header":
      if (
        route.rpcMethod !== "eth_getBlockByNumber" ||
        !isCanonicalHexQuantity(route.approvedBlockNumber) ||
        parsed.params.length !== 2 ||
        parsed.params[0] !== route.approvedBlockNumber ||
        parsed.params[1] !== false
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    case "contract-code": {
      const target = assertSingletonApprovedTarget(route.approvedTargets);
      if (
        route.rpcMethod !== "eth_getCode" ||
        parsed.params.length !== 2 ||
        parsed.params[0] !== target
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      assertCanonicalBlockSelector(parsed.params[1], route.approvedBlockHash);
      return;
    }
    case "state-read": {
      const target = assertSingletonApprovedTarget(route.approvedTargets);
      if (route.rpcMethod !== "eth_call" || parsed.params.length !== 2) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      const call = parsed.params[0];
      if (
        !isRecord(call) ||
        !hasExactKeys(call, ["data", "to"]) ||
        call.to !== target ||
        !isCanonicalHexData(call.data)
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      const selector = call.data.slice(0, 10);
      if (!BSC_PREVIEW_STATE_READ_SELECTOR_SET.has(selector)) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      assertCanonicalBlockSelector(parsed.params[1], route.approvedBlockHash);
      return;
    }
    case "simulation": {
      if (
        route.rpcMethod !== "eth_call" ||
        !isCanonicalAddress(route.approvedCaller) ||
        !isLowercaseSha256(route.approvedCalldataSha256) ||
        parsed.params.length !== 2
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      const call = parsed.params[0];
      if (
        !isRecord(call) ||
        !hasExactKeys(call, ["data", "from", "gas", "to", "value"]) ||
        call.from !== route.approvedCaller ||
        call.to !== BSC_PREVIEW_POSITION_MANAGER ||
        call.value !== "0x0" ||
        call.gas !== BSC_PREVIEW_SIMULATION_GAS ||
        !isCanonicalHexData(call.data) ||
        !call.data.startsWith(BSC_PREVIEW_MULTICALL_SELECTOR) ||
        computeBscPreviewCalldataSha256(call.data) !==
          route.approvedCalldataSha256
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      assertCanonicalBlockSelector(parsed.params[1], route.approvedBlockHash);
      return;
    }
    default:
      return assertNever(route);
  }
}

function assertCategoryRpcRoute(route: BscCategoryRpcRoute): void {
  assertCategoryRouteKeys(route);
  const parsed = parseStrictRpcBody(route.body, route.rpcMethod);

  switch (route.purpose) {
    case "chain-id":
      if (
        route.rpcMethod !== "eth_chainId" ||
        parsed.params.length !== 0
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    case "head-block-number":
      if (
        route.rpcMethod !== "eth_blockNumber" ||
        parsed.params.length !== 0
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    case "block-header":
      if (
        route.rpcMethod !== "eth_getBlockByNumber" ||
        !isCanonicalHexQuantity(route.approvedBlockNumber) ||
        parsed.params.length !== 2 ||
        parsed.params[0] !== route.approvedBlockNumber ||
        parsed.params[1] !== false
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    case "state-read": {
      const target = assertSingletonApprovedTarget(route.approvedTargets);
      if (
        route.rpcMethod !== "eth_call" ||
        parsed.params.length !== 2 ||
        !isCategoryCalldataAllowed(route.approvedCalldata)
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      const call = parsed.params[0];
      if (
        !isRecord(call) ||
        !hasExactKeys(call, ["data", "to"]) ||
        call.to !== target ||
        call.data !== route.approvedCalldata
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      assertCanonicalBlockSelector(parsed.params[1], route.approvedBlockHash);
      return;
    }
    default:
      return assertNever(route);
  }
}

function assertCategoryRouteKeys(route: BscCategoryRpcRoute): void {
  const common = ["body", "kind", "method", "purpose", "rpcMethod", "url"];
  let expected: readonly string[];
  switch (route.purpose) {
    case "chain-id":
    case "head-block-number":
      expected = common;
      break;
    case "block-header":
      expected = [...common, "approvedBlockNumber"];
      break;
    case "state-read":
      expected = [
        ...common,
        "approvedBlockHash",
        "approvedCalldata",
        "approvedTargets",
      ];
      break;
    default:
      return assertNever(route);
  }
  if (!hasExactKeys(route as unknown as Record<string, unknown>, expected)) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
}

function isCategoryCalldataAllowed(value: unknown): value is string {
  if (typeof value !== "string" || !isCanonicalHexData(value)) return false;
  const selector = value.slice(0, 10);
  if (!BSC_CATEGORY_STATE_READ_SELECTOR_SET.has(selector)) return false;
  if (BSC_CATEGORY_NO_ARGUMENT_SELECTOR_SET.has(selector)) {
    return value.length === 10;
  }
  return (
    BSC_CATEGORY_ADDRESS_ARGUMENT_SELECTOR_SET.has(selector) &&
    /^0{24}[0-9a-f]{40}$/.test(value.slice(10))
  );
}

function assertActivationRpcRoute(route: BscActivationRpcRoute): void {
  assertActivationRouteKeys(route);
  const parsed = parseStrictRpcBody(route.body, route.rpcMethod);
  switch (route.purpose) {
    case "chain-id":
      if (route.rpcMethod !== "eth_chainId" || parsed.params.length !== 0) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    case "head-block-number":
      if (route.rpcMethod !== "eth_blockNumber" || parsed.params.length !== 0) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    case "block-header":
      if (
        route.rpcMethod !== "eth_getBlockByNumber" ||
        !isCanonicalHexQuantity(route.approvedBlockNumber) ||
        parsed.params.length !== 2 ||
        parsed.params[0] !== route.approvedBlockNumber ||
        parsed.params[1] !== false
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    case "transaction":
    case "receipt": {
      const expectedMethod =
        route.purpose === "transaction"
          ? "eth_getTransactionByHash"
          : "eth_getTransactionReceipt";
      if (
        route.rpcMethod !== expectedMethod ||
        !isCanonicalBlockHash(route.approvedTransactionHash) ||
        parsed.params.length !== 1 ||
        parsed.params[0] !== route.approvedTransactionHash
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      return;
    }
    case "contract-code": {
      const target = activationTarget(route.approvedTargets);
      if (
        route.rpcMethod !== "eth_getCode" ||
        parsed.params.length !== 2 ||
        parsed.params[0] !== target
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      assertCanonicalBlockSelector(parsed.params[1], route.approvedBlockHash);
      return;
    }
    case "proxy-implementation": {
      const target = activationTarget(route.approvedTargets);
      if (
        route.rpcMethod !== "eth_getStorageAt" ||
        (target !== BSC_ACTIVATION_TARGETS[0] &&
          target !== BSC_ACTIVATION_TARGETS[2]) ||
        parsed.params.length !== 3 ||
        parsed.params[0] !== target ||
        parsed.params[1] !== BSC_ACTIVATION_IMPLEMENTATION_SLOT
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      assertCanonicalBlockSelector(parsed.params[2], route.approvedBlockHash);
      return;
    }
    case "state-read": {
      const target = activationTarget(route.approvedTargets);
      if (route.rpcMethod !== "eth_call" || parsed.params.length !== 2) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      const call = parsed.params[0];
      if (
        !isRecord(call) ||
        !hasExactKeys(call, ["data", "to"]) ||
        call.to !== target ||
        !isCanonicalHexData(call.data) ||
        !BSC_ACTIVATION_STATE_READ_SELECTOR_SET.has(call.data.slice(0, 10))
      ) {
        throw new TransportError("RPC_METHOD_NOT_ALLOWED");
      }
      assertCanonicalBlockSelector(parsed.params[1], route.approvedBlockHash);
      return;
    }
    default:
      return assertNever(route);
  }
}

function activationTarget(targets: readonly [string]): string {
  const target = assertSingletonApprovedTarget(targets);
  if (!BSC_ACTIVATION_TARGET_SET.has(target)) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  return target;
}

function assertActivationRouteKeys(route: BscActivationRpcRoute): void {
  const common = ["body", "kind", "method", "purpose", "rpcMethod", "url"];
  let expected: readonly string[];
  switch (route.purpose) {
    case "chain-id":
    case "head-block-number":
      expected = common;
      break;
    case "block-header":
      expected = [...common, "approvedBlockNumber"];
      break;
    case "transaction":
    case "receipt":
      expected = [...common, "approvedTransactionHash"];
      break;
    case "contract-code":
    case "proxy-implementation":
    case "state-read":
      expected = [...common, "approvedBlockHash", "approvedTargets"];
      break;
    default:
      return assertNever(route);
  }
  if (!hasExactKeys(route as unknown as Record<string, unknown>, expected)) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
}

function assertPreviewRouteKeys(route: BscPreviewRpcRoute): void {
  const common = ["body", "kind", "method", "purpose", "rpcMethod", "url"];
  let expected: readonly string[];
  switch (route.purpose) {
    case "chain-id":
    case "head-block-number":
      expected = common;
      break;
    case "block-header":
      expected = [...common, "approvedBlockNumber"];
      break;
    case "contract-code":
    case "state-read":
      expected = [...common, "approvedBlockHash", "approvedTargets"];
      break;
    case "simulation":
      expected = [
        ...common,
        "approvedBlockHash",
        "approvedCaller",
        "approvedCalldataSha256",
      ];
      break;
    default:
      return assertNever(route);
  }
  if (!hasExactKeys(route as unknown as Record<string, unknown>, expected)) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
}

function parseStrictRpcBody(
  body: string,
  expectedMethod:
    | (typeof BSC_PREVIEW_RPC_METHODS)[number]
    | (typeof BSC_CATEGORY_RPC_METHODS)[number]
    | (typeof BSC_ACTIVATION_RPC_METHODS)[number],
): Readonly<{ params: readonly unknown[] }> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  if (
    !isRecord(parsed) ||
    !hasExactKeys(parsed, ["id", "jsonrpc", "method", "params"]) ||
    parsed.jsonrpc !== "2.0" ||
    parsed.method !== expectedMethod ||
    typeof parsed.id !== "string" ||
    parsed.id.length < 1 ||
    parsed.id.length > 128 ||
    !Array.isArray(parsed.params)
  ) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  return { params: parsed.params };
}

function assertSingletonApprovedTarget(targets: unknown): string {
  if (
    !Array.isArray(targets) ||
    targets.length !== 1 ||
    !isCanonicalAddress(targets[0]) ||
    targets[0] === "0x0000000000000000000000000000000000000000"
  ) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  return targets[0];
}

function assertCanonicalBlockSelector(
  value: unknown,
  approvedBlockHash: string,
): void {
  if (
    !isCanonicalBlockHash(approvedBlockHash) ||
    !isRecord(value) ||
    !hasExactKeys(value, ["blockHash", "requireCanonical"]) ||
    value.blockHash !== approvedBlockHash ||
    value.requireCanonical !== true
  ) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
}

function isCanonicalAddress(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-f]{40}$/.test(value);
}

function isCanonicalBlockHash(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-f]{64}$/.test(value);
}

function isCanonicalHexQuantity(value: unknown): value is string {
  return typeof value === "string" && /^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value);
}

function isCanonicalHexData(value: unknown): value is string {
  return typeof value === "string" && /^0x(?:[0-9a-f]{2})+$/.test(value);
}

function isLowercaseSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

export function computeBscPreviewCalldataSha256(value: string): string {
  if (!isCanonicalHexData(value)) {
    throw new TypeError("preview calldata must be lowercase byte-aligned hex data");
  }
  return createHash("sha256")
    .update(Buffer.from(value.slice(2), "hex"))
    .digest("hex");
}

function canonicalApprovedQuoteUrl(value: string): string {
  let approved: URL;
  try {
    approved = new URL(value);
  } catch {
    throw new TransportError("INVALID_URL");
  }
  if (
    approved.protocol !== "https:" ||
    approved.username !== "" ||
    approved.password !== "" ||
    approved.hash !== "" ||
    approved.search !== "" ||
    (approved.port !== "" && approved.port !== "443") ||
    approved.hostname.endsWith(".") ||
    isIP(stripIpv6Brackets(approved.hostname)) !== 0 ||
    approved.href !== value
  ) {
    throw new TransportError("INVALID_URL");
  }
  return approved.href;
}

function assertQuoteBody(body: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  if (!isRecord(parsed) || !hasExactKeys(parsed, ["id", "jsonrpc", "method", "params"])) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
  if (
    parsed.jsonrpc !== "2.0" ||
    parsed.method !== "message/send" ||
    typeof parsed.id !== "string" ||
    parsed.id.length < 1 ||
    parsed.id.length > 128 ||
    !isRecord(parsed.params) ||
    !hasExactKeys(parsed.params, ["message"])
  ) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }

  const message = parsed.params.message;
  if (
    !isRecord(message) ||
    !hasExactKeys(message, ["kind", "messageId", "parts", "role"]) ||
    message.kind !== "message" ||
    message.role !== "user" ||
    typeof message.messageId !== "string" ||
    message.messageId.length < 1 ||
    message.messageId.length > 128 ||
    !Array.isArray(message.parts) ||
    message.parts.length !== 1
  ) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }

  const part = message.parts[0];
  if (
    !isRecord(part) ||
    !hasExactKeys(part, ["data", "kind"]) ||
    part.kind !== "data" ||
    !isRecord(part.data) ||
    !hasExactKeys(part.data, ["request", "skill"]) ||
    part.data.skill !== "negotiate" ||
    !isRecord(part.data.request) ||
    !hasExactKeys(part.data.request, ["mandate"]) ||
    !isRecord(part.data.request.mandate)
  ) {
    throw new TransportError("RPC_METHOD_NOT_ALLOWED");
  }
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index])
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertNever(value: never): never {
  throw new TransportError("METHOD_NOT_ALLOWED");
}

type RequestFactory = typeof httpsRequest;

export class PinnedHttpsTransport {
  readonly #resolver: Resolver;
  readonly #limits: HttpLimits;
  readonly #requestFactory: RequestFactory;
  readonly #now: () => Date;
  readonly #monotonicNow: () => number;

  constructor(options: {
    resolver?: Resolver;
    limits?: Partial<HttpLimits>;
    requestFactory?: RequestFactory;
    now?: () => Date;
    monotonicNow?: () => number;
  } = {}) {
    this.#resolver = options.resolver ?? systemResolver;
    this.#limits = Object.freeze({
      ...DEFAULT_HTTP_LIMITS,
      ...options.limits,
    });
    this.#requestFactory = options.requestFactory ?? httpsRequest;
    this.#now = options.now ?? (() => new Date());
    this.#monotonicNow = options.monotonicNow ?? (() => performance.now());
  }

  async request(route: TransportRoute): Promise<BoundedHttpResponse> {
    const routeSnapshot = snapshotTransportRoute(route);
    const url = validateTransportRouteSnapshot(routeSnapshot);
    const requestBody = requestBodyForRoute(routeSnapshot);
    const requestBytes =
      requestBody === undefined ? 0 : Buffer.byteLength(requestBody, "utf8");
    const maxRequestBytes =
      routeSnapshot.kind === "a2a-quote"
        ? Math.min(this.#limits.maxRequestBytes, ACTIVE_QUOTE_LIMITS.maxRequestBytes)
        : routeSnapshot.kind === "bsc-quote-rpc"
          ? Math.min(
              this.#limits.maxRequestBytes,
              ACTIVE_QUOTE_RPC_LIMITS.maxRequestBytes,
            )
          : routeSnapshot.kind === "bsc-preview-rpc"
            ? Math.min(
                this.#limits.maxRequestBytes,
                BSC_PREVIEW_RPC_LIMITS.maxRequestBytes,
              )
            : routeSnapshot.kind === "bsc-category-rpc"
              ? Math.min(
                  this.#limits.maxRequestBytes,
                  BSC_CATEGORY_RPC_LIMITS.maxRequestBytes,
                )
            : routeSnapshot.kind === "bsc-activation-rpc"
              ? Math.min(
                  this.#limits.maxRequestBytes,
                  BSC_ACTIVATION_RPC_LIMITS.maxRequestBytes,
                )
        : this.#limits.maxRequestBytes;
    if (requestBytes > maxRequestBytes) {
      throw new TransportError("REQUEST_TOO_LARGE");
    }

    let answers: readonly DnsAddress[];
    try {
      answers = await this.#resolver(url.hostname);
    } catch (error) {
      if (error instanceof TransportError) throw error;
      throw new TransportError("DNS_ERROR");
    }
    const pinned = selectPinnedAddress(answers);

    const maxResponseBytes =
      routeSnapshot.kind === "a2a-quote"
        ? Math.min(this.#limits.maxResponseBytes, ACTIVE_QUOTE_LIMITS.maxResponseBytes)
        : routeSnapshot.kind === "bsc-quote-rpc"
          ? Math.min(
              this.#limits.maxResponseBytes,
              ACTIVE_QUOTE_RPC_LIMITS.maxResponseBytes,
            )
          : routeSnapshot.kind === "bsc-preview-rpc"
            ? Math.min(
                this.#limits.maxResponseBytes,
                BSC_PREVIEW_RPC_LIMITS.maxResponseBytes,
              )
            : routeSnapshot.kind === "bsc-category-rpc"
              ? Math.min(
                  this.#limits.maxResponseBytes,
                  BSC_CATEGORY_RPC_LIMITS.maxResponseBytes,
                )
            : routeSnapshot.kind === "bsc-activation-rpc"
              ? Math.min(
                  this.#limits.maxResponseBytes,
                  BSC_ACTIVATION_RPC_LIMITS.maxResponseBytes,
                )
        : this.#limits.maxResponseBytes;
    return this.#requestPinned(
      url,
      routeSnapshot,
      pinned,
      requestBody,
      maxResponseBytes,
    );
  }

  async #requestPinned(
    url: URL,
    route: TransportRoute,
    pinned: DnsAddress,
    requestBody: string | undefined,
    maxResponseBytes: number,
  ): Promise<BoundedHttpResponse> {
    const startedAt = this.#now().toISOString();
    const startedMonotonic = this.#monotonicNow();

    return new Promise<BoundedHttpResponse>((resolve, reject) => {
      let settled = false;
      let connectTimer: NodeJS.Timeout | undefined;
      let headersTimer: NodeJS.Timeout | undefined;
      let totalTimer: NodeJS.Timeout | undefined;

      const finishReject = (error: TransportError): void => {
        if (settled) return;
        settled = true;
        clearTimers();
        reject(error);
      };

      const clearTimers = (): void => {
        if (connectTimer !== undefined) clearTimeout(connectTimer);
        if (headersTimer !== undefined) clearTimeout(headersTimer);
        if (totalTimer !== undefined) clearTimeout(totalTimer);
      };

      const lookup: LookupFunction = (_hostname, options, callback) => {
        if (options.all) {
          callback(null, [{ address: pinned.address, family: pinned.family }]);
          return;
        }
        callback(null, pinned.address, pinned.family);
      };

      const headers: Record<string, string> = {
        Accept: "application/json",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
        "User-Agent": "MandateX-Agent-Supply-Verifier/0.1",
      };
      if (requestBody !== undefined) {
        headers["Content-Type"] = "application/json";
        headers["Content-Length"] = String(Buffer.byteLength(requestBody, "utf8"));
      }

      const options: RequestOptions = {
        protocol: "https:",
        hostname: url.hostname,
        port: 443,
        method: route.method,
        path: url.pathname,
        headers,
        agent: false,
        servername: url.hostname,
        lookup,
      };

      const request = this.#requestFactory(options, (response) => {
        if (headersTimer !== undefined) clearTimeout(headersTimer);

        const status = response.statusCode ?? 0;
        if (status >= 300 && status < 400) {
          response.destroy();
          finishReject(new TransportError("REDIRECT_REJECTED"));
          return;
        }

        const contentEncoding = headerValue(response.headers["content-encoding"]);
        if (
          contentEncoding !== null &&
          contentEncoding.toLowerCase() !== "identity"
        ) {
          response.destroy();
          finishReject(new TransportError("COMPRESSED_RESPONSE_REJECTED"));
          return;
        }

        const contentLength = headerValue(response.headers["content-length"]);
        if (
          contentLength !== null &&
          Number.isFinite(Number(contentLength)) &&
          Number(contentLength) > maxResponseBytes
        ) {
          response.destroy();
          finishReject(new TransportError("RESPONSE_TOO_LARGE"));
          return;
        }

        const chunks: Buffer[] = [];
        let bytes = 0;
        response.on("data", (chunk: Buffer | string) => {
          const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          bytes += buffer.byteLength;
          if (bytes > maxResponseBytes) {
            response.destroy();
            finishReject(new TransportError("RESPONSE_TOO_LARGE"));
            return;
          }
          chunks.push(buffer);
        });
        response.once("aborted", () => {
          finishReject(new TransportError("RESPONSE_ABORTED"));
        });
        response.once("error", () => {
          finishReject(new TransportError("NETWORK_ERROR"));
        });
        response.once("end", () => {
          if (settled) return;
          settled = true;
          clearTimers();
          const body = Buffer.concat(chunks, bytes);
          const finishedAt = this.#now().toISOString();
          const latencyMs = Math.max(
            0,
            Math.round(this.#monotonicNow() - startedMonotonic),
          );
          resolve({
            status,
            contentType: headerValue(response.headers["content-type"]),
            retryAfter: headerValue(response.headers["retry-after"]),
            rateLimitRemaining:
              headerValue(response.headers["ratelimit-remaining"]) ??
              headerValue(response.headers["x-ratelimit-remaining"]),
            body,
            responseSha256: createHash("sha256").update(body).digest("hex"),
            resolvedAddress: pinned.address,
            startedAt,
            finishedAt,
            latencyMs,
          });
        });
      });

      request.once("socket", (socket) => {
        const tlsSocket = socket as TLSSocket;
        tlsSocket.once("secureConnect", () => {
          if (connectTimer !== undefined) clearTimeout(connectTimer);
          if (tlsSocket.remoteAddress !== pinned.address) {
            request.destroy(new TransportError("REMOTE_ADDRESS_MISMATCH"));
          }
        });
      });
      request.once("error", (error) => {
        finishReject(
          error instanceof TransportError
            ? error
            : new TransportError("NETWORK_ERROR"),
        );
      });

      connectTimer = setTimeout(() => {
        request.destroy(new TransportError("CONNECT_TIMEOUT"));
      }, this.#limits.connectTimeoutMs);
      headersTimer = setTimeout(() => {
        request.destroy(new TransportError("HEADERS_TIMEOUT"));
      }, this.#limits.headersTimeoutMs);
      totalTimer = setTimeout(() => {
        request.destroy(new TransportError("TOTAL_TIMEOUT"));
      }, this.#limits.totalTimeoutMs);

      if (requestBody !== undefined) request.write(requestBody);
      request.end();
    });
  }
}

function snapshotTransportRoute(route: unknown): TransportRoute {
  try {
    if (!isRecord(route)) throw new TransportError("METHOD_NOT_ALLOWED");
    const snapshot = Object.create(null) as Record<string, unknown>;
    for (const key of Reflect.ownKeys(route)) {
      if (typeof key !== "string") {
        throw new TransportError("METHOD_NOT_ALLOWED");
      }
      const descriptor = Object.getOwnPropertyDescriptor(route, key);
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true
      ) {
        throw new TransportError("METHOD_NOT_ALLOWED");
      }
      Object.defineProperty(snapshot, key, {
        value: descriptor.value,
        enumerable: true,
        writable: false,
        configurable: false,
      });
    }
    return Object.freeze(snapshot) as unknown as TransportRoute;
  } catch (cause) {
    if (cause instanceof TransportError) throw cause;
    throw new TransportError("METHOD_NOT_ALLOWED");
  }
}

function requestBodyForRoute(route: TransportRoute): string | undefined {
  switch (route.kind) {
    case "scan-detail":
    case "agent-card":
      return undefined;
    case "bsc-rpc":
    case "bsc-quote-rpc":
    case "bsc-preview-rpc":
    case "bsc-category-rpc":
    case "bsc-activation-rpc":
    case "a2a-quote":
      return route.body;
    default:
      return assertNever(route);
  }
}

function headerValue(value: string | string[] | undefined): string | null {
  if (value === undefined) return null;
  return Array.isArray(value) ? value.join(",") : value;
}

export function parseJsonResponse(response: BoundedHttpResponse): unknown {
  if (
    response.contentType === null ||
    !/^application\/json(?:\s*;|$)/i.test(response.contentType)
  ) {
    throw new TransportError("INVALID_CONTENT_TYPE");
  }
  try {
    return JSON.parse(Buffer.from(response.body).toString("utf8"));
  } catch {
    throw new TransportError("INVALID_JSON");
  }
}

export function redactDiagnostic(error: unknown): string {
  if (error instanceof TransportError) return error.message;
  return "verification dependency failed";
}
