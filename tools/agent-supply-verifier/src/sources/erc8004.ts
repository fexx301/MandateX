import { createHash } from "node:crypto";

import {
  decodeFunctionResult,
  encodeFunctionData,
  isAddress,
  type Hex,
} from "viem";
import { z } from "zod";

import {
  BSC_MAINNET_RPC_ORIGIN,
  parseJsonResponse,
  redactDiagnostic,
  type AllowedRpcMethod,
  type BoundedHttpResponse,
  type PinnedHttpsTransport,
} from "../transport/http.js";

export const BSC_MAINNET = Object.freeze({
  name: "bsc-mainnet",
  chainId: 56,
  registryAddress: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
  rpcOrigin: BSC_MAINNET_RPC_ORIGIN,
  confirmationDepth: 2,
  registryDeploymentSource: "@bnbagent/sdk@0.5.0 ERC-8004 chain configuration",
});

export const BSC_TESTNET_REFERENCE = Object.freeze({
  name: "bsc-testnet-reference",
  chainId: 97,
  registryAddress: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
  rpcOrigin: "https://data-seed-prebsc-2-s2.binance.org:8545",
  liveEnabled: false,
});

const ownerOfAbi = [
  {
    type: "function",
    name: "ownerOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "owner", type: "address" }],
  },
] as const;

const hexQuantitySchema = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/);
const blockHashSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const blockSchema = z.object({
  number: hexQuantitySchema,
  hash: blockHashSchema,
  timestamp: hexQuantitySchema.optional(),
});
const sharedAnchorSchema = z
  .object({
    number: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    hash: blockHashSchema.transform((value) => value.toLowerCase()),
    timestamp: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  })
  .strict();

export type RpcCallObservation = Readonly<{
  method: AllowedRpcMethod;
  httpStatus: number;
  startedAt: string;
  finishedAt: string;
  latencyMs: number;
  responseSha256: string;
}>;

export type Erc8004Snapshot = Readonly<{
  chainId: 56;
  rpcOrigin: string;
  registryAddress: string;
  registryDeploymentSource: string;
  registryCodeSha256: string;
  registryCodeBytes: number;
  tokenId: string;
  ownerAddress: string;
  headBlockNumber: string;
  observedBlockNumber: string;
  observedBlockHash: string;
  confirmationDepth: 2;
  requireCanonical: true;
  attempts: number;
  calls: readonly RpcCallObservation[];
}>;

/** A verifier-owned canonical block anchor shared with another evidence path. */
export type Erc8004SharedAnchor = Readonly<{
  readonly number: number;
  readonly hash: string;
  readonly timestamp: number;
}>;

export type Erc8004Result =
  | Readonly<{
      status: "verified";
      snapshot: Erc8004Snapshot;
    }>
  | Readonly<{
      status: "unavailable";
      code: "TOKEN_NOT_FOUND";
      message: string;
      calls: readonly RpcCallObservation[];
    }>
  | Readonly<{
      status: "inconclusive";
      code:
        | "CHAIN_UNSUPPORTED"
        | "RPC_UNAVAILABLE"
        | "RPC_INVALID_RESPONSE"
        | "CHAIN_ID_MISMATCH"
        | "HEAD_TOO_LOW"
        | "REGISTRY_CODE_MISSING"
        | "SNAPSHOT_INCONSISTENT"
        | "OWNER_INVALID";
      message: string;
      attempts: number;
      calls: readonly RpcCallObservation[];
    }>;

type InconclusiveCode = Extract<Erc8004Result, { status: "inconclusive" }>['code'];

class RpcFault extends Error {
  readonly kind: "propagation" | "token-not-found" | "invalid" | "unavailable";
  readonly code: InconclusiveCode | null;

  constructor(kind: RpcFault["kind"], code: InconclusiveCode | null = null) {
    super(kind);
    this.kind = kind;
    this.code = code;
  }
}

export async function verifyErc8004Ownership(options: {
  transport: Pick<PinnedHttpsTransport, "request">;
  chainId: number;
  tokenId: string;
  registryAddress: string;
  sharedAnchor?: Erc8004SharedAnchor;
}): Promise<Erc8004Result> {
  if (options.chainId !== BSC_MAINNET.chainId) {
    return {
      status: "inconclusive",
      code: "CHAIN_UNSUPPORTED",
      message: "live passive verification supports BSC mainnet only",
      attempts: 0,
      calls: [],
    };
  }
  if (!/^\d+$/.test(options.tokenId)) {
    throw new TypeError("tokenId must be an unsigned decimal string");
  }
  const registryAddressInput = options.registryAddress;
  if (!isAddress(registryAddressInput)) {
    throw new TypeError("registryAddress must be an EVM address");
  }
  const registryAddress = registryAddressInput.toLowerCase();
  const sharedAnchor =
    options.sharedAnchor === undefined
      ? undefined
      : sharedAnchorSchema.parse(options.sharedAnchor);

  let tokenId: bigint;
  try {
    tokenId = BigInt(options.tokenId);
  } catch {
    throw new TypeError("tokenId is outside the supported integer range");
  }
  if (tokenId < 0n || tokenId >= 1n << 256n) {
    throw new TypeError("tokenId is outside uint256");
  }

  const allCalls: RpcCallObservation[] = [];
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const attemptCalls: RpcCallObservation[] = [];
    try {
      const snapshot = await readSnapshot(
        options.transport,
        options.tokenId,
        tokenId,
        attempt,
        attemptCalls,
        registryAddress,
        sharedAnchor,
      );
      allCalls.push(...attemptCalls);
      return {
        status: "verified",
        snapshot: { ...snapshot, calls: allCalls },
      };
    } catch (error) {
      allCalls.push(...attemptCalls);
      if (error instanceof RpcFault && error.kind === "token-not-found") {
        return {
          status: "unavailable",
          code: "TOKEN_NOT_FOUND",
          message: "ERC-8004 token does not exist at the canonical snapshot",
          calls: allCalls,
        };
      }
      if (
        error instanceof RpcFault &&
        error.kind === "propagation" &&
        attempt === 1
      ) {
        continue;
      }

      return inconclusiveFromError(error, attempt, allCalls);
    }
  }

  return {
    status: "inconclusive",
    code: "SNAPSHOT_INCONSISTENT",
    message: "canonical chain snapshot could not be established",
    attempts: 2,
    calls: allCalls,
  };
}

async function readSnapshot(
  transport: Pick<PinnedHttpsTransport, "request">,
  tokenIdText: string,
  tokenId: bigint,
  attempt: number,
  calls: RpcCallObservation[],
  registryAddress: string,
  sharedAnchor?: Erc8004SharedAnchor,
): Promise<Omit<Erc8004Snapshot, "calls">> {
  let nextId = attempt * 100;
  const rpc = async <T>(
    method: AllowedRpcMethod,
    params: readonly unknown[],
  ): Promise<T> => {
    nextId += 1;
    return rpcCall<T>(transport, method, params, nextId, calls);
  };

  const chainIdHex = await rpc<string>("eth_chainId", []);
  if (parseQuantity(chainIdHex) !== BigInt(BSC_MAINNET.chainId)) {
    throw new RpcFault("invalid", "CHAIN_ID_MISMATCH");
  }

  const head = await readCanonicalHead(rpc);
  const target = sharedAnchor
    ? BigInt(sharedAnchor.number)
    : head - BigInt(BSC_MAINNET.confirmationDepth);
  if (
    sharedAnchor !== undefined &&
    (target < 0n ||
      head < target + BigInt(BSC_MAINNET.confirmationDepth))
  ) {
    throw new RpcFault("invalid", "SNAPSHOT_INCONSISTENT");
  }
  const targetHex = toQuantity(target);

  const initialBlockRaw = await rpc<unknown>("eth_getBlockByNumber", [
    targetHex,
    false,
  ]);
  const initialBlock = parseBlock(initialBlockRaw, target);
  if (
    sharedAnchor !== undefined &&
    (initialBlock.hash.toLowerCase() !== sharedAnchor.hash.toLowerCase() ||
      initialBlock.timestamp === undefined ||
      parseQuantity(initialBlock.timestamp) !== BigInt(sharedAnchor.timestamp) ||
      false)
  ) {
    throw new RpcFault("propagation");
  }
  const blockSelector = {
    blockHash: initialBlock.hash,
    requireCanonical: true,
  } as const;

  const registryCode = await rpc<string>("eth_getCode", [
    registryAddress,
    blockSelector,
  ]);
  if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(registryCode) || registryCode === "0x") {
    throw new RpcFault("invalid", "REGISTRY_CODE_MISSING");
  }

  const ownerData = encodeFunctionData({
    abi: ownerOfAbi,
    functionName: "ownerOf",
    args: [tokenId],
  });
  const ownerResult = await rpc<Hex>("eth_call", [
    { to: registryAddress, data: ownerData },
    blockSelector,
  ]);

  let owner: string;
  try {
    owner = decodeFunctionResult({
      abi: ownerOfAbi,
      functionName: "ownerOf",
      data: ownerResult,
    });
  } catch {
    throw new RpcFault("invalid", "OWNER_INVALID");
  }
  if (!isAddress(owner) || /^0x0{40}$/i.test(owner)) {
    throw new RpcFault("invalid", "OWNER_INVALID");
  }

  const finalBlockRaw = await rpc<unknown>("eth_getBlockByNumber", [
    targetHex,
    false,
  ]);
  const finalBlock = parseBlock(finalBlockRaw, target);
  if (
    finalBlock.hash.toLowerCase() !== initialBlock.hash.toLowerCase() ||
    (sharedAnchor !== undefined &&
      (finalBlock.timestamp === undefined ||
        parseQuantity(finalBlock.timestamp) !== BigInt(sharedAnchor.timestamp)))
  ) {
    throw new RpcFault("propagation");
  }

  const codeBytes = Buffer.from(registryCode.slice(2), "hex");
  return {
    chainId: 56,
    rpcOrigin: BSC_MAINNET.rpcOrigin,
    registryAddress,
    registryDeploymentSource: "explicit verifier configuration",
    registryCodeSha256: createHash("sha256").update(codeBytes).digest("hex"),
    registryCodeBytes: codeBytes.byteLength,
    tokenId: tokenIdText,
    ownerAddress: owner.toLowerCase(),
    headBlockNumber: head.toString(10),
    observedBlockNumber: target.toString(10),
    observedBlockHash: initialBlock.hash.toLowerCase(),
    confirmationDepth: 2,
    requireCanonical: true,
    attempts: attempt,
  };
}

async function readCanonicalHead(
  rpc: <T>(method: AllowedRpcMethod, params: readonly unknown[]) => Promise<T>,
): Promise<bigint> {
  const headHex = await rpc<string>("eth_blockNumber", []);
  const head = parseQuantity(headHex);
  if (head < BigInt(BSC_MAINNET.confirmationDepth)) {
    throw new RpcFault("invalid", "HEAD_TOO_LOW");
  }
  return head;
}

async function rpcCall<T>(
  transport: Pick<PinnedHttpsTransport, "request">,
  method: AllowedRpcMethod,
  params: readonly unknown[],
  id: number,
  calls: RpcCallObservation[],
): Promise<T> {
  const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });
  let response: BoundedHttpResponse;
  try {
    response = await transport.request({
      kind: "bsc-rpc",
      method: "POST",
      url: BSC_MAINNET.rpcOrigin,
      rpcMethod: method,
      body,
    });
  } catch {
    throw new RpcFault("unavailable");
  }
  calls.push({
    method,
    httpStatus: response.status,
    startedAt: response.startedAt,
    finishedAt: response.finishedAt,
    latencyMs: response.latencyMs,
    responseSha256: response.responseSha256,
  });
  if (response.status !== 200) throw new RpcFault("unavailable");

  let parsed: unknown;
  try {
    parsed = parseJsonResponse(response);
  } catch {
    throw new RpcFault("invalid");
  }
  if (!isRecord(parsed) || parsed.jsonrpc !== "2.0" || parsed.id !== id) {
    throw new RpcFault("invalid");
  }
  if (isRecord(parsed.error)) {
    const message =
      typeof parsed.error.message === "string"
        ? parsed.error.message.toLowerCase()
        : "";
    if (isPropagationError(message)) throw new RpcFault("propagation");
    if (isNonexistentTokenError(message)) throw new RpcFault("token-not-found");
    throw new RpcFault("invalid");
  }
  if (!("result" in parsed)) throw new RpcFault("invalid");
  if (parsed.result === null && method.startsWith("eth_getBlock")) {
    throw new RpcFault("propagation");
  }
  return parsed.result as T;
}

function parseBlock(value: unknown, expectedNumber: bigint): {
  number: string;
  hash: string;
  timestamp: string | undefined;
} {
  const parsed = blockSchema.safeParse(value);
  if (!parsed.success) throw new RpcFault("propagation");
  if (parseQuantity(parsed.data.number) !== expectedNumber) {
    throw new RpcFault("propagation");
  }
  return {
    number: parsed.data.number,
    hash: parsed.data.hash,
    timestamp: parsed.data.timestamp,
  };
}

function parseQuantity(value: unknown): bigint {
  const parsed = hexQuantitySchema.safeParse(value);
  if (!parsed.success) throw new RpcFault("invalid");
  try {
    return BigInt(parsed.data);
  } catch {
    throw new RpcFault("invalid");
  }
}

function toQuantity(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

function isPropagationError(message: string): boolean {
  return [
    "header not found",
    "missing trie node",
    "unknown block",
    "not canonical",
    "canonical hash",
  ].some((fragment) => message.includes(fragment));
}

function isNonexistentTokenError(message: string): boolean {
  return [
    "nonexistent token",
    "non-existent token",
    "invalid token id",
    "owner query for nonexistent token",
  ].some((fragment) => message.includes(fragment));
}

function inconclusiveFromError(
  error: unknown,
  attempts: number,
  calls: readonly RpcCallObservation[],
): Erc8004Result {
  if (error instanceof RpcFault && error.kind === "propagation") {
    return {
      status: "inconclusive",
      code: "SNAPSHOT_INCONSISTENT",
      message: "canonical chain snapshot could not be established",
      attempts,
      calls,
    };
  }
  if (error instanceof RpcFault && error.kind === "unavailable") {
    return {
      status: "inconclusive",
      code: "RPC_UNAVAILABLE",
      message: "BSC RPC was unavailable within the verifier budget",
      attempts,
      calls,
    };
  }
  if (error instanceof RpcFault && error.kind === "invalid") {
    return {
      status: "inconclusive",
      code: error.code ?? "RPC_INVALID_RESPONSE",
      message: inconclusiveMessage(error.code),
      attempts,
      calls,
    };
  }
  return {
    status: "inconclusive",
    code: "RPC_UNAVAILABLE",
    message: redactDiagnostic(error),
    attempts,
    calls,
  };
}

function inconclusiveMessage(code: InconclusiveCode | null): string {
  switch (code) {
    case "CHAIN_ID_MISMATCH":
      return "BSC RPC chain ID did not match the approved profile";
    case "HEAD_TOO_LOW":
      return "BSC RPC head could not satisfy the snapshot confirmation buffer";
    case "REGISTRY_CODE_MISSING":
      return "canonical ERC-8004 registry code was missing at the snapshot";
    case "OWNER_INVALID":
      return "ERC-8004 owner response could not be validated";
    default:
      return "BSC RPC returned an invalid or unsupported response";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
