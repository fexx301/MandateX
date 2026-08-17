import type { Hex } from "viem";

import { computeQuoteSha256 } from "../quotes/protocol.js";
import {
  BSC_MAINNET_RPC_ORIGIN,
  BSC_PREVIEW_SIMULATION_GAS,
  computeBscPreviewCalldataSha256,
  parseJsonResponse,
  type PinnedHttpsTransport,
} from "../transport/http.js";
import {
  PancakeStateRpcError,
  type PancakeStateRpc,
  type PancakeStateRpcRequest,
} from "./pancake.js";

export type PreviewSimulationObservation = Readonly<{
  rawResult: Hex;
  requestSha256: string;
  responseSha256: string;
}>;

export class PreviewSimulationError extends Error {
  constructor(
    readonly kind: "reverted" | "unavailable" | "invalid-response",
    readonly evidence: Readonly<{
      requestSha256?: string;
      responseSha256?: string;
    }> = {},
  ) {
    super("the pinned transaction simulation did not complete successfully");
    this.name = "PreviewSimulationError";
  }
}

export class TransportPancakeStateRpc implements PancakeStateRpc {
  constructor(
    private readonly transport: Pick<PinnedHttpsTransport, "request">,
    private readonly randomUUID: () => string,
  ) {}

  async request<T = unknown>(request: PancakeStateRpcRequest): Promise<T> {
    const id = `preview-state-${this.randomUUID()}`;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: request.method,
      params: request.params,
    });

    try {
      const response = await this.transport.request(
        previewStateRoute(request, body),
      );
      if (response.status !== 200) {
        throw new PancakeStateRpcError("unavailable");
      }
      const parsed = parseJsonResponse(response);
      if (
        !isRecord(parsed) ||
        parsed.jsonrpc !== "2.0" ||
        parsed.id !== id
      ) {
        throw new PancakeStateRpcError("invalid-response");
      }
      if (isRecord(parsed.error)) {
        const message =
          typeof parsed.error.message === "string"
            ? parsed.error.message.toLowerCase()
            : "";
        throw new PancakeStateRpcError(
          isPropagationMessage(message) ? "propagation" : "invalid-response",
        );
      }
      if (!("result" in parsed)) {
        throw new PancakeStateRpcError("invalid-response");
      }
      return parsed.result as T;
    } catch (error) {
      if (error instanceof PancakeStateRpcError) throw error;
      throw new PancakeStateRpcError("unavailable");
    }
  }
}

export async function simulatePinnedRebalancePlan(input: {
  transport: Pick<PinnedHttpsTransport, "request">;
  randomUUID: () => string;
  caller: string;
  data: Hex;
  blockHash: string;
}): Promise<PreviewSimulationObservation> {
  const id = `preview-simulation-${input.randomUUID()}`;
  const params = [
    {
      from: input.caller,
      to: "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364",
      value: "0x0",
      gas: BSC_PREVIEW_SIMULATION_GAS,
      data: input.data,
    },
    { blockHash: input.blockHash, requireCanonical: true },
  ] as const;
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id,
    method: "eth_call",
    params,
  });
  const requestSha256 = computeQuoteSha256(body);

  let response;
  try {
    response = await input.transport.request({
      kind: "bsc-preview-rpc",
      purpose: "simulation",
      method: "POST",
      url: BSC_MAINNET_RPC_ORIGIN,
      rpcMethod: "eth_call",
      approvedCaller: input.caller,
      approvedCalldataSha256: computeBscPreviewCalldataSha256(input.data),
      approvedBlockHash: input.blockHash,
      body,
    });
  } catch {
    throw new PreviewSimulationError("unavailable", { requestSha256 });
  }
  if (response.status !== 200) {
    throw new PreviewSimulationError("unavailable", {
      requestSha256,
      responseSha256: response.responseSha256,
    });
  }

  let parsed: unknown;
  try {
    parsed = parseJsonResponse(response);
  } catch {
    throw new PreviewSimulationError("invalid-response", {
      requestSha256,
      responseSha256: response.responseSha256,
    });
  }
  if (
    !isRecord(parsed) ||
    parsed.jsonrpc !== "2.0" ||
    parsed.id !== id
  ) {
    throw new PreviewSimulationError("invalid-response", {
      requestSha256,
      responseSha256: response.responseSha256,
    });
  }
  if ("error" in parsed) {
    if (!isRecord(parsed.error)) {
      throw new PreviewSimulationError("invalid-response", {
        requestSha256,
        responseSha256: response.responseSha256,
      });
    }
    if (
      typeof parsed.error.message !== "string" ||
      parsed.error.message.length === 0 ||
      typeof parsed.error.code !== "number" ||
      !Number.isSafeInteger(parsed.error.code)
    ) {
      throw new PreviewSimulationError("invalid-response", {
        requestSha256,
        responseSha256: response.responseSha256,
      });
    }
    const message = parsed.error.message.toLowerCase();
    throw new PreviewSimulationError(
      message.includes("execution reverted")
        ? "reverted"
        : "unavailable",
      {
        requestSha256,
        responseSha256: response.responseSha256,
      },
    );
  }
  if (
    !("result" in parsed) ||
    typeof parsed.result !== "string" ||
    !/^0x(?:[0-9a-f]{2})+$/.test(parsed.result)
  ) {
    throw new PreviewSimulationError("invalid-response", {
      requestSha256,
      responseSha256: response.responseSha256,
    });
  }

  return {
    rawResult: parsed.result as Hex,
    requestSha256,
    responseSha256: response.responseSha256,
  };
}

export async function assertPreviewBlockCanonical(input: {
  rpc: PancakeStateRpc;
  blockNumber: string;
  blockHash: string;
}): Promise<void> {
  const raw = await input.rpc.request<unknown>({
    method: "eth_getBlockByNumber",
    params: [`0x${BigInt(input.blockNumber).toString(16)}`, false],
  });
  if (
    !isRecord(raw) ||
    raw.number !== `0x${BigInt(input.blockNumber).toString(16)}` ||
    typeof raw.hash !== "string" ||
    raw.hash !== input.blockHash
  ) {
    throw new PancakeStateRpcError("propagation");
  }
}

function previewStateRoute(request: PancakeStateRpcRequest, body: string) {
  switch (request.method) {
    case "eth_chainId":
      return {
        kind: "bsc-preview-rpc" as const,
        purpose: "chain-id" as const,
        method: "POST" as const,
        url: BSC_MAINNET_RPC_ORIGIN,
        rpcMethod: request.method,
        body,
      };
    case "eth_blockNumber":
      return {
        kind: "bsc-preview-rpc" as const,
        purpose: "head-block-number" as const,
        method: "POST" as const,
        url: BSC_MAINNET_RPC_ORIGIN,
        rpcMethod: request.method,
        body,
      };
    case "eth_getBlockByNumber": {
      const blockNumber = request.params[0];
      if (typeof blockNumber !== "string") {
        throw new PancakeStateRpcError("invalid-response");
      }
      return {
        kind: "bsc-preview-rpc" as const,
        purpose: "block-header" as const,
        method: "POST" as const,
        url: BSC_MAINNET_RPC_ORIGIN,
        rpcMethod: request.method,
        approvedBlockNumber: blockNumber,
        body,
      };
    }
    case "eth_getCode": {
      const [target, selector] = request.params;
      const blockHash = canonicalBlockHash(selector);
      if (typeof target !== "string") {
        throw new PancakeStateRpcError("invalid-response");
      }
      return {
        kind: "bsc-preview-rpc" as const,
        purpose: "contract-code" as const,
        method: "POST" as const,
        url: BSC_MAINNET_RPC_ORIGIN,
        rpcMethod: request.method,
        approvedTargets: [target] as readonly [string],
        approvedBlockHash: blockHash,
        body,
      };
    }
    case "eth_call": {
      const [call, selector] = request.params;
      const blockHash = canonicalBlockHash(selector);
      if (!isRecord(call) || typeof call.to !== "string") {
        throw new PancakeStateRpcError("invalid-response");
      }
      return {
        kind: "bsc-preview-rpc" as const,
        purpose: "state-read" as const,
        method: "POST" as const,
        url: BSC_MAINNET_RPC_ORIGIN,
        rpcMethod: request.method,
        approvedTargets: [call.to] as readonly [string],
        approvedBlockHash: blockHash,
        body,
      };
    }
  }
}

function canonicalBlockHash(value: unknown): string {
  if (
    !isRecord(value) ||
    value.requireCanonical !== true ||
    typeof value.blockHash !== "string"
  ) {
    throw new PancakeStateRpcError("invalid-response");
  }
  return value.blockHash;
}

function isPropagationMessage(message: string): boolean {
  return ["header not found", "missing trie node", "unknown block"].some(
    (part) => message.includes(part),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
