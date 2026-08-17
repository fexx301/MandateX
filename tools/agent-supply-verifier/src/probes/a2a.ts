import { z } from "zod";

import {
  TransportError,
  parseJsonResponse,
  redactDiagnostic,
  type BoundedHttpResponse,
  type PinnedHttpsTransport,
} from "../transport/http.js";

const modeSchema = z.string().min(1).max(100);
const skillSchema = z.object({
  id: z.string().regex(/^[A-Za-z0-9._-]{1,100}$/),
  name: z.string().min(1).max(200),
  description: z.string().min(1).max(8_000),
  tags: z.array(z.string().min(1).max(100)).max(32).default([]),
  inputModes: z.array(modeSchema).max(16).optional(),
  outputModes: z.array(modeSchema).max(16).optional(),
});

const agentCardSchema = z.object({
  name: z.string().min(1).max(300),
  description: z.string().min(1).max(20_000),
  url: z.string().url(),
  version: z.string().min(1).max(100),
  protocolVersion: z.string().regex(/^0\.3\.\d+(?:[-+][0-9A-Za-z.-]+)?$/),
  preferredTransport: z.literal("JSONRPC"),
  capabilities: z
    .object({
      streaming: z.boolean().optional(),
    })
    .passthrough(),
  defaultInputModes: z.array(modeSchema).min(1).max(16),
  defaultOutputModes: z.array(modeSchema).min(1).max(16),
  skills: z.array(skillSchema).min(1).max(32),
  securitySchemes: z.unknown().optional(),
  security: z.unknown().optional(),
});

export type DetectedAgentSkill = Readonly<{
  id: string;
  name: string;
  description: string;
  tags: readonly string[];
  inputModes: readonly string[];
  outputModes: readonly string[];
}>;

export type DetectedAgentCard = Readonly<{
  name: string;
  description: string;
  url: string;
  version: string;
  protocolVersion: string;
  preferredTransport: "JSONRPC";
  streaming: boolean | null;
  defaultInputModes: readonly string[];
  defaultOutputModes: readonly string[];
  skills: readonly DetectedAgentSkill[];
}>;

export type AgentCardObservation = Readonly<{
  url: string;
  httpStatus: number | null;
  resolvedAddress: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  latencyMs: number | null;
  responseSha256: string | null;
}>;

export type AgentCardResult =
  | Readonly<{
      status: "detected";
      card: DetectedAgentCard;
      observation: AgentCardObservation;
    }>
  | Readonly<{
      status: "unavailable";
      code:
        | "CARD_ENDPOINT_TIMEOUT"
        | "CARD_NETWORK_ERROR"
        | "CARD_REDIRECTED"
        | "CARD_DNS_REJECTED"
        | "CARD_RESPONSE_POLICY_REJECTED"
        | "CARD_HTTP_STATUS"
        | "CARD_INVALID_RESPONSE"
        | "CARD_INCOMPATIBLE"
        | "CARD_ORIGIN_MISMATCH";
      message: string;
      observation: AgentCardObservation;
    }>
  | Readonly<{
      status: "inconclusive";
      code: "CARD_RESOLVER_UNAVAILABLE" | "CARD_CONFIGURATION_ERROR";
      message: string;
      observation: AgentCardObservation;
    }>;

export async function probeAgentCard(options: {
  transport: Pick<PinnedHttpsTransport, "request">;
  endpoint: string;
  expectedOrigin: string;
}): Promise<AgentCardResult> {
  let endpointUrl: URL;
  try {
    endpointUrl = new URL(options.endpoint);
  } catch {
    return inconclusive(
      "CARD_CONFIGURATION_ERROR",
      "manifest Agent Card URL is invalid",
      options.endpoint,
    );
  }

  let response: BoundedHttpResponse;
  try {
    response = await options.transport.request({
      kind: "agent-card",
      method: "GET",
      url: options.endpoint,
      expectedOrigin: options.expectedOrigin,
      expectedPath: endpointUrl.pathname,
    });
  } catch (error) {
    return transportFailure(error, options.endpoint);
  }

  const observation = observationFromResponse(options.endpoint, response);
  if (response.status !== 200) {
    return {
      status: "unavailable",
      code: "CARD_HTTP_STATUS",
      message: "Agent Card endpoint did not return HTTP 200",
      observation,
    };
  }

  let parsed: unknown;
  try {
    parsed = parseJsonResponse(response);
  } catch (error) {
    return {
      status: "unavailable",
      code: "CARD_INVALID_RESPONSE",
      message: redactDiagnostic(error),
      observation,
    };
  }
  const cardResult = agentCardSchema.safeParse(parsed);
  if (!cardResult.success) {
    return {
      status: "unavailable",
      code: "CARD_INCOMPATIBLE",
      message: "Agent Card is not compatible with passive v1 requirements",
      observation,
    };
  }

  const card = cardResult.data;
  if (
    !card.defaultInputModes.includes("application/json") ||
    !card.defaultOutputModes.includes("application/json")
  ) {
    return {
      status: "unavailable",
      code: "CARD_INCOMPATIBLE",
      message: "Agent Card does not declare JSON input and output modes",
      observation,
    };
  }

  const skillIds = new Set<string>();
  for (const skill of card.skills) {
    if (skillIds.has(skill.id)) {
      return {
        status: "unavailable",
        code: "CARD_INCOMPATIBLE",
        message: "Agent Card contains duplicate skill identifiers",
        observation,
      };
    }
    skillIds.add(skill.id);
  }

  let declaredUrl: URL;
  try {
    declaredUrl = new URL(card.url);
  } catch {
    return {
      status: "unavailable",
      code: "CARD_ORIGIN_MISMATCH",
      message: "Agent Card URL is invalid",
      observation,
    };
  }
  if (
    declaredUrl.origin !== new URL(options.expectedOrigin).origin ||
    declaredUrl.username !== "" ||
    declaredUrl.password !== ""
  ) {
    return {
      status: "unavailable",
      code: "CARD_ORIGIN_MISMATCH",
      message: "Agent Card URL does not match the approved manifest origin",
      observation,
    };
  }

  return {
    status: "detected",
    card: {
      name: card.name,
      description: card.description,
      url: card.url,
      version: card.version,
      protocolVersion: card.protocolVersion,
      preferredTransport: card.preferredTransport,
      streaming: card.capabilities.streaming ?? null,
      defaultInputModes: [...card.defaultInputModes].sort(),
      defaultOutputModes: [...card.defaultOutputModes].sort(),
      skills: card.skills
        .map((skill) => ({
          id: skill.id,
          name: skill.name,
          description: skill.description,
          tags: [...skill.tags].sort(),
          inputModes: [...(skill.inputModes ?? card.defaultInputModes)].sort(),
          outputModes: [...(skill.outputModes ?? card.defaultOutputModes)].sort(),
        }))
        .sort((left, right) => left.id.localeCompare(right.id)),
    },
    observation,
  };
}

function transportFailure(error: unknown, url: string): AgentCardResult {
  if (!(error instanceof TransportError)) {
    return unavailable("CARD_NETWORK_ERROR", redactDiagnostic(error), url);
  }

  switch (error.code) {
    case "CONNECT_TIMEOUT":
    case "HEADERS_TIMEOUT":
    case "TOTAL_TIMEOUT":
      return unavailable("CARD_ENDPOINT_TIMEOUT", redactDiagnostic(error), url);
    case "NETWORK_ERROR":
    case "RESPONSE_ABORTED":
      return unavailable("CARD_NETWORK_ERROR", redactDiagnostic(error), url);
    case "REDIRECT_REJECTED":
      return unavailable("CARD_REDIRECTED", redactDiagnostic(error), url);
    case "DNS_UNSAFE_ADDRESS":
    case "REMOTE_ADDRESS_MISMATCH":
      return unavailable("CARD_DNS_REJECTED", redactDiagnostic(error), url);
    case "DNS_EMPTY":
    case "DNS_ERROR":
      return inconclusive(
        "CARD_RESOLVER_UNAVAILABLE",
        redactDiagnostic(error),
        url,
      );
    case "INVALID_URL":
    case "METHOD_NOT_ALLOWED":
    case "ORIGIN_NOT_ALLOWED":
    case "PATH_NOT_ALLOWED":
    case "RPC_METHOD_NOT_ALLOWED":
    case "REQUEST_TOO_LARGE":
      return inconclusive(
        "CARD_CONFIGURATION_ERROR",
        redactDiagnostic(error),
        url,
      );
    case "COMPRESSED_RESPONSE_REJECTED":
    case "RESPONSE_TOO_LARGE":
    case "INVALID_CONTENT_TYPE":
    case "INVALID_JSON":
      return unavailable(
        "CARD_RESPONSE_POLICY_REJECTED",
        redactDiagnostic(error),
        url,
      );
    default:
      return assertNever(error.code);
  }
}

function observationFromResponse(
  url: string,
  response: BoundedHttpResponse,
): AgentCardObservation {
  return {
    url,
    httpStatus: response.status,
    resolvedAddress: response.resolvedAddress,
    startedAt: response.startedAt,
    finishedAt: response.finishedAt,
    latencyMs: response.latencyMs,
    responseSha256: response.responseSha256,
  };
}

function emptyObservation(url: string): AgentCardObservation {
  return {
    url,
    httpStatus: null,
    resolvedAddress: null,
    startedAt: null,
    finishedAt: null,
    latencyMs: null,
    responseSha256: null,
  };
}

function unavailable(
  code: Extract<AgentCardResult, { status: "unavailable" }>['code'],
  message: string,
  url: string,
): AgentCardResult {
  return { status: "unavailable", code, message, observation: emptyObservation(url) };
}

function inconclusive(
  code: Extract<AgentCardResult, { status: "inconclusive" }>['code'],
  message: string,
  url: string,
): AgentCardResult {
  return {
    status: "inconclusive",
    code,
    message,
    observation: emptyObservation(url),
  };
}

function assertNever(value: never): never {
  throw new Error(`unhandled Agent Card transport code: ${String(value)}`);
}
