import { z } from "zod";

import {
  SCAN_ORIGIN,
  TransportError,
  parseJsonResponse,
  redactDiagnostic,
  type BoundedHttpResponse,
  type PinnedHttpsTransport,
} from "../transport/http.js";

const addressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/);

const scanResponseSchema = z.object({
  success: z.literal(true),
  data: z.object({
    chain_id: z.number().int().positive(),
    token_id: z.string().regex(/^\d+$/),
    contract_address: addressSchema,
    name: z.string().min(1).max(300),
    description: z.string().max(20_000).nullable().optional(),
    owner_address: addressSchema.nullable().optional(),
    creator_address: addressSchema.nullable().optional(),
    agent_wallet: addressSchema.nullable().optional(),
    is_verified: z.boolean().optional(),
    is_endpoint_verified: z.boolean().optional(),
    endpoint_verified_at: z.string().nullable().optional(),
    endpoint_verified_domain: z.string().nullable().optional(),
    endpoint_verification_error: z.string().nullable().optional(),
    endpoint_last_checked_at: z.string().nullable().optional(),
    is_active: z.boolean().optional(),
    supported_protocols: z.array(z.string().max(100)).max(32).optional(),
    x402_supported: z.boolean().optional(),
    total_feedbacks: z.number().int().nonnegative().optional(),
    average_score: z.number().finite().optional(),
    health_score: z.number().finite().nullable().optional(),
    health_checked_at: z.string().nullable().optional(),
    updated_at: z.string().nullable().optional(),
    services: z
      .object({
        a2a: z
          .object({
            endpoint: z.string().url(),
            version: z.string().max(100).nullable().optional(),
          })
          .passthrough()
          .optional(),
      })
      .passthrough()
      .optional(),
  }),
  meta: z
    .object({
      version: z.string().max(100).optional(),
      timestamp: z.string().optional(),
    })
    .passthrough()
    .optional(),
});

export type ScanAgentDetail = Readonly<{
  chainId: number;
  tokenId: string;
  registryAddress: string;
  name: string;
  description: string | null;
  ownerAddress: string | null;
  creatorAddress: string | null;
  agentWallet: string | null;
  agentCardEndpoint: string | null;
  agentCardVersion: string | null;
  supportedProtocols: readonly string[];
  isVerifiedByScan: boolean;
  isEndpointVerifiedByScan: boolean;
  endpointVerificationDomain: string | null;
  endpointVerificationError: string | null;
  endpointLastCheckedAt: string | null;
  isActive: boolean | null;
  x402Supported: boolean | null;
  feedbackCount: number | null;
  averageScore: number | null;
  healthScore: number | null;
  healthCheckedAt: string | null;
  updatedAt: string | null;
  sourceVersion: string | null;
  sourceTimestamp: string | null;
}>;

export type ScanSourceObservation = Readonly<{
  source: "8004scan";
  url: string;
  httpStatus: number | null;
  startedAt: string | null;
  finishedAt: string | null;
  latencyMs: number | null;
  responseSha256: string | null;
}>;

export type ScanDetailResult =
  | Readonly<{
      status: "ok";
      detail: ScanAgentDetail;
      observation: ScanSourceObservation;
    }>
  | Readonly<{
      status: "not_indexed";
      code: "SCAN_NOT_INDEXED";
      observation: ScanSourceObservation;
    }>
  | Readonly<{
      status: "inconclusive";
      code:
        | "SCAN_RATE_LIMITED"
        | "SCAN_UNAVAILABLE"
        | "SCAN_INVALID_RESPONSE"
        | "SCAN_TRANSPORT_ERROR";
      message: string;
      observation: ScanSourceObservation;
    }>;

export async function fetchScanAgentDetail(options: {
  transport: Pick<PinnedHttpsTransport, "request">;
  chainId: number;
  tokenId: string;
}): Promise<ScanDetailResult> {
  if (!Number.isSafeInteger(options.chainId) || options.chainId <= 0) {
    throw new TypeError("chainId must be a positive integer");
  }
  if (!/^\d+$/.test(options.tokenId)) {
    throw new TypeError("tokenId must be an unsigned decimal string");
  }

  const url = `${SCAN_ORIGIN}/api/v1/public/agents/${options.chainId}/${options.tokenId}`;
  let response: BoundedHttpResponse;
  try {
    response = await options.transport.request({
      kind: "scan-detail",
      method: "GET",
      url,
      chainId: options.chainId,
      tokenId: options.tokenId,
    });
  } catch (error) {
    return {
      status: "inconclusive",
      code: "SCAN_TRANSPORT_ERROR",
      message: redactDiagnostic(error),
      observation: emptyObservation(url),
    };
  }

  const observation = observationFromResponse(url, response);
  if (response.status === 404) {
    return { status: "not_indexed", code: "SCAN_NOT_INDEXED", observation };
  }
  if (response.status === 429 || response.retryAfter !== null) {
    return {
      status: "inconclusive",
      code: "SCAN_RATE_LIMITED",
      message: "8004scan rate budget is unavailable",
      observation,
    };
  }
  if (response.status < 200 || response.status >= 300) {
    return {
      status: "inconclusive",
      code: "SCAN_UNAVAILABLE",
      message: "8004scan detail source returned an unusable response",
      observation,
    };
  }

  let parsed: unknown;
  try {
    parsed = parseJsonResponse(response);
  } catch (error) {
    return {
      status: "inconclusive",
      code: "SCAN_INVALID_RESPONSE",
      message: redactDiagnostic(error),
      observation,
    };
  }
  const result = scanResponseSchema.safeParse(parsed);
  if (!result.success) {
    return {
      status: "inconclusive",
      code: "SCAN_INVALID_RESPONSE",
      message: "8004scan detail response failed schema validation",
      observation,
    };
  }

  const data = result.data.data;
  if (data.chain_id !== options.chainId || data.token_id !== options.tokenId) {
    return {
      status: "inconclusive",
      code: "SCAN_INVALID_RESPONSE",
      message: "8004scan detail identity did not match the request",
      observation,
    };
  }

  return {
    status: "ok",
    detail: {
      chainId: data.chain_id,
      tokenId: data.token_id,
      registryAddress: data.contract_address.toLowerCase(),
      name: data.name,
      description: data.description ?? null,
      ownerAddress: data.owner_address?.toLowerCase() ?? null,
      creatorAddress: data.creator_address?.toLowerCase() ?? null,
      agentWallet: data.agent_wallet?.toLowerCase() ?? null,
      agentCardEndpoint: data.services?.a2a?.endpoint ?? null,
      agentCardVersion: data.services?.a2a?.version ?? null,
      supportedProtocols: [...(data.supported_protocols ?? [])].sort(),
      isVerifiedByScan: data.is_verified ?? false,
      isEndpointVerifiedByScan: data.is_endpoint_verified ?? false,
      endpointVerificationDomain: data.endpoint_verified_domain ?? null,
      endpointVerificationError: data.endpoint_verification_error ?? null,
      endpointLastCheckedAt: data.endpoint_last_checked_at ?? null,
      isActive: data.is_active ?? null,
      x402Supported: data.x402_supported ?? null,
      feedbackCount: data.total_feedbacks ?? null,
      averageScore: data.average_score ?? null,
      healthScore: data.health_score ?? null,
      healthCheckedAt: data.health_checked_at ?? null,
      updatedAt: data.updated_at ?? null,
      sourceVersion: result.data.meta?.version ?? null,
      sourceTimestamp: result.data.meta?.timestamp ?? null,
    },
    observation,
  };
}

function observationFromResponse(
  url: string,
  response: BoundedHttpResponse,
): ScanSourceObservation {
  return {
    source: "8004scan",
    url,
    httpStatus: response.status,
    startedAt: response.startedAt,
    finishedAt: response.finishedAt,
    latencyMs: response.latencyMs,
    responseSha256: response.responseSha256,
  };
}

function emptyObservation(url: string): ScanSourceObservation {
  return {
    source: "8004scan",
    url,
    httpStatus: null,
    startedAt: null,
    finishedAt: null,
    latencyMs: null,
    responseSha256: null,
  };
}

export function isTransportFailure(error: unknown): error is TransportError {
  return error instanceof TransportError;
}
