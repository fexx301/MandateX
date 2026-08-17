import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";

import {
  getAddress,
  hashMessage,
  keccak256,
  recoverMessageAddress,
  toBytes,
  type Address,
  type Hex,
} from "viem";

import {
  QUOTE_SIDECAR_SCHEMA,
  quoteA2aRequestSchema,
  quoteA2aResponseSchema,
  quoteAcceptedEnvelopeSchema,
  quoteAcceptedResponseSchema,
  quoteBytes32Schema,
  quoteMandateSchema,
  quoteMandatexRebalanceMandateSchema,
  quoteMandatexSignedRebalanceTaskSchema,
  quoteNegotiationRequestSchema,
  quoteRejectedEnvelopeSchema,
  quoteRejectedResponseSchema,
  quoteSidecarSchema,
  quoteTrustFileSchema,
  type QuoteA2aRequest,
  type QuoteAcceptedEnvelope,
  type QuoteAcceptedResponse,
  type QuoteEnvelope,
  type QuoteMandate,
  type QuoteMandatexSignedRebalanceTask,
  type QuoteProtocolErrorCode,
  type QuoteProviderKind,
  type QuoteRejectedResponse,
  type QuoteReplayStatus,
  type QuoteSidecar,
  type QuoteSidecarCandidate,
  type QuoteSignatureMethod,
  type QuoteTrustFile,
  type QuoteValidationGates,
} from "./schema.js";
import { deriveNearestCenteredExactRange } from "./range.js";

export class QuoteProtocolError extends Error {
  readonly code: QuoteProtocolErrorCode;

  constructor(
    code: QuoteProtocolErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "QuoteProtocolError";
    this.code = code;
  }
}

export interface BuildQuoteA2aRequestInput {
  readonly rpcId: string;
  readonly messageId: string;
  readonly mandate: QuoteMandate;
}

export function buildQuoteA2aRequest(
  input: BuildQuoteA2aRequestInput,
): QuoteA2aRequest {
  return quoteA2aRequestSchema.parse({
    jsonrpc: "2.0",
    id: input.rpcId,
    method: "message/send",
    params: {
      message: {
        kind: "message",
        messageId: input.messageId,
        role: "user",
        parts: [
          {
            kind: "data",
            data: {
              skill: "negotiate",
              request: { mandate: quoteMandateSchema.parse(input.mandate) },
            },
          },
        ],
      },
    },
  });
}

export const buildQuoteJsonRpcRequest = buildQuoteA2aRequest;

export function serializeQuoteA2aRequest(request: QuoteA2aRequest): string {
  return canonicalQuoteJson(quoteA2aRequestSchema.parse(request));
}

export const serializeQuoteJsonRpcRequest = serializeQuoteA2aRequest;

export interface ParseQuoteA2aResponseOptions {
  readonly expectedRpcId?: string;
}

export function parseQuoteA2aResponse(
  value: unknown,
  options: ParseQuoteA2aResponseOptions = {},
): QuoteEnvelope {
  let parsedJson = value;
  if (typeof value === "string") {
    try {
      parsedJson = JSON.parse(value) as unknown;
    } catch (error) {
      throw new QuoteProtocolError(
        "RESPONSE_JSON_INVALID",
        "quote endpoint response is not valid JSON",
        { cause: error },
      );
    }
  }

  const parsed = quoteA2aResponseSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new QuoteProtocolError(
      "RESPONSE_SCHEMA_INVALID",
      "quote endpoint response does not match the A2A quote schema",
    );
  }

  if (
    options.expectedRpcId !== undefined &&
    parsed.data.id !== options.expectedRpcId
  ) {
    throw new QuoteProtocolError(
      "RPC_ID_MISMATCH",
      "quote endpoint response JSON-RPC id does not match the request",
    );
  }

  if ("error" in parsed.data) {
    throw new QuoteProtocolError(
      "JSON_RPC_ERROR",
      "quote endpoint returned a JSON-RPC error",
    );
  }

  return parsed.data.result.parts[0]!.data;
}

export const parseQuoteJsonRpcResponse = parseQuoteA2aResponse;

function sortCanonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortCanonicalValue);
  if (value !== null && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(object)
        .sort()
        .map((key) => [key, sortCanonicalValue(object[key])]),
    );
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError(
      `canonicalQuoteJson: non-finite numbers are not allowed (got ${value})`,
    );
  }
  return value;
}

export function canonicalQuoteJson(value: unknown): string {
  const serialized = JSON.stringify(sortCanonicalValue(value));
  if (serialized === undefined) {
    throw new TypeError("canonicalQuoteJson: value is not JSON-serializable");
  }
  return serialized.replace(
    /[\u007f-\uffff]/g,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

export function sanitizeQuoteClaim(value: unknown): string {
  if (typeof value !== "string") return String(value);

  let sanitized = value.replaceAll("[", "(").replaceAll("]", ")");
  let result = "";
  for (const character of sanitized) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint >= 32 || character === "\t" || character === "\n") {
      result += character;
    }
  }
  sanitized = result;
  return sanitized;
}

const MANDATEX_REBALANCE_TASK_CODEC = "mandatex-rebalance:v1" as const;
const MANDATEX_REBALANCE_TASK_PREFIX =
  `${MANDATEX_REBALANCE_TASK_CODEC}:` as const;
const MAX_ENCODED_REBALANCE_TASK_BYTES = 2_600;
const MAX_DECODED_REBALANCE_TASK_BYTES = 16_000;
const MANDATEX_BSC_MAINNET = "bsc-mainnet" as const;
const BSC_MAINNET_CHAIN_ID = 56;
const BSC_MAINNET_PANCAKE_V3_POSITION_MANAGER =
  "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364" as const;
export const REBALANCE_FUTURE_TOLERANCE_SECONDS = 15 as const;
const REQUIRED_REBALANCE_CALLS = [
  "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
  "collect((uint256,address,uint128,uint128))",
  "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
] as const;

export function decodeQuoteSignedTask(
  encoded: string,
  codec: typeof MANDATEX_REBALANCE_TASK_CODEC,
): QuoteMandatexSignedRebalanceTask {
  if (codec !== MANDATEX_REBALANCE_TASK_CODEC) {
    throw new QuoteProtocolError(
      "SIGNED_TASK_INVALID",
      "unsupported signed task codec",
    );
  }
  if (!encoded.startsWith(MANDATEX_REBALANCE_TASK_PREFIX)) {
    throw new QuoteProtocolError(
      "SIGNED_TASK_INVALID",
      "signed task does not use the trusted codec",
    );
  }
  if (Buffer.byteLength(encoded, "utf8") > MAX_ENCODED_REBALANCE_TASK_BYTES) {
    throw new QuoteProtocolError(
      "SIGNED_TASK_INVALID",
      "signed task exceeds the encoded safety bound",
    );
  }

  const payload = encoded.slice(MANDATEX_REBALANCE_TASK_PREFIX.length);
  if (payload.length === 0 || !/^[A-Za-z0-9_-]+$/.test(payload)) {
    throw new QuoteProtocolError(
      "SIGNED_TASK_INVALID",
      "signed task payload is not canonical base64url",
    );
  }

  let decoded: string;
  try {
    const compressed = Buffer.from(payload, "base64url");
    if (compressed.toString("base64url") !== payload) {
      throw new Error("non-canonical base64url");
    }
    decoded = inflateRawSync(compressed, {
      maxOutputLength: MAX_DECODED_REBALANCE_TASK_BYTES,
    }).toString("utf8");
  } catch (error) {
    throw new QuoteProtocolError(
      "SIGNED_TASK_INVALID",
      "signed task payload could not be decoded",
      { cause: error },
    );
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(decoded) as unknown;
  } catch (error) {
    throw new QuoteProtocolError(
      "SIGNED_TASK_INVALID",
      "signed task payload is not valid JSON",
      { cause: error },
    );
  }
  if (canonicalQuoteJson(parsedJson) !== decoded) {
    throw new QuoteProtocolError(
      "SIGNED_TASK_INVALID",
      "signed task JSON is not canonical",
    );
  }

  const parsed = quoteMandatexSignedRebalanceTaskSchema.safeParse(parsedJson);
  if (!parsed.success) {
    throw new QuoteProtocolError(
      "SIGNED_TASK_INVALID",
      "signed task does not match the MandateX rebalance schema",
    );
  }
  return parsed.data;
}

export interface VerifyQuoteMandateBindingInput {
  readonly envelope: QuoteEnvelope;
  readonly mandate: QuoteMandate;
  readonly codec: typeof MANDATEX_REBALANCE_TASK_CODEC;
  readonly now: number | Date;
}

export interface VerifiedQuoteMandateBinding {
  readonly codec: typeof MANDATEX_REBALANCE_TASK_CODEC;
  readonly mandateSha256: string;
  readonly signedTask: QuoteMandatexSignedRebalanceTask;
}

function throwMandateBindingMismatch(message: string): never {
  throw new QuoteProtocolError("MANDATE_BINDING_MISMATCH", message);
}

function assertRebalanceTimestampFresh(
  subject: string,
  observedAt: number,
  checkedAt: number,
  verifiedAt: number,
  maxAgeSeconds: number,
): void {
  const ages = [checkedAt - observedAt, verifiedAt - observedAt];
  if (ages.some((age) => age > maxAgeSeconds)) {
    throwMandateBindingMismatch(`${subject} exceeds the mandate freshness window`);
  }
  if (ages.some((age) => age < -REBALANCE_FUTURE_TOLERANCE_SECONDS)) {
    throwMandateBindingMismatch(`${subject} is unreasonably far in the future`);
  }
}

function assertSignedRebalancePolicy(
  task: QuoteMandatexSignedRebalanceTask,
  envelope: QuoteAcceptedEnvelope,
  verifiedAt: number,
): void {
  const { mandate, evidence, proposal, eligibility } = task;
  const checkedAt = eligibility.checked_at;

  if (
    evidence.network !== MANDATEX_BSC_MAINNET ||
    mandate.chain_id !== BSC_MAINNET_CHAIN_ID ||
    evidence.chain_id !== mandate.chain_id ||
    envelope.chain_id !== mandate.chain_id
  ) {
    throwMandateBindingMismatch(
      "signed task evidence does not match the BSC mainnet mandate domain",
    );
  }
  if (
    evidence.pool_address !== mandate.position.pool_address ||
    evidence.position_manager_address !==
      mandate.position.position_manager_address ||
    evidence.position_token_id !== mandate.position.token_id
  ) {
    throwMandateBindingMismatch(
      "signed task evidence does not match the mandated position",
    );
  }
  if (
    mandate.position.position_manager_address !==
    BSC_MAINNET_PANCAKE_V3_POSITION_MANAGER
  ) {
    throwMandateBindingMismatch(
      "signed task does not use the canonical BSC PancakeSwap V3 position manager",
    );
  }
  if (
    evidence.sources.length === 0 ||
    evidence.sources.some(
      (source) => source.observed_block !== evidence.observed_block,
    )
  ) {
    throwMandateBindingMismatch(
      "signed task evidence sources do not match the observed block",
    );
  }
  if (checkedAt > verifiedAt + REBALANCE_FUTURE_TOLERANCE_SECONDS) {
    throwMandateBindingMismatch(
      "signed task eligibility time is unreasonably far in the future",
    );
  }
  if (
    checkedAt >
    envelope.response.negotiated_at + REBALANCE_FUTURE_TOLERANCE_SECONDS
  ) {
    throwMandateBindingMismatch(
      "signed task eligibility time is later than quote negotiation",
    );
  }
  assertRebalanceTimestampFresh(
    "signed task evidence",
    evidence.observed_at,
    checkedAt,
    verifiedAt,
    mandate.max_evidence_age_seconds,
  );
  assertRebalanceTimestampFresh(
    "signed task execution estimate",
    mandate.execution_estimate.observed_at,
    checkedAt,
    verifiedAt,
    mandate.max_evidence_age_seconds,
  );
  if (
    mandate.expires_at <= checkedAt ||
    mandate.permissions.expires_at <= checkedAt ||
    mandate.expires_at <= verifiedAt ||
    mandate.permissions.expires_at <= verifiedAt
  ) {
    throwMandateBindingMismatch(
      "signed task mandate or permissions are expired at validation time",
    );
  }

  const isOutsideCurrentRange =
    evidence.current_tick < evidence.position_tick_lower ||
    evidence.current_tick >= evidence.position_tick_upper;
  const boundaryDistance = isOutsideCurrentRange
    ? 0
    : Math.min(
        evidence.current_tick - evidence.position_tick_lower,
        evidence.position_tick_upper - evidence.current_tick,
      );
  const triggerFired =
    isOutsideCurrentRange ||
    (mandate.range_policy.trigger_mode === "boundary_proximity" &&
      boundaryDistance <= mandate.range_policy.trigger_distance_ticks);
  const expectedTriggerReason = isOutsideCurrentRange
    ? "outside_current_range"
    : "near_range_boundary";
  if (
    !triggerFired ||
    proposal.trigger.reason !== expectedTriggerReason ||
    proposal.trigger.distance_to_boundary_ticks !== boundaryDistance
  ) {
    throwMandateBindingMismatch(
      "signed task trigger does not follow the mandated rebalance policy",
    );
  }

  const proposedLower = proposal.proposed_lower_tick;
  const proposedUpper = proposal.proposed_upper_tick;
  const targetWidth = mandate.range_policy.target_width_ticks;
  const tickSpacing = evidence.tick_spacing;
  if (
    proposedLower >= proposedUpper ||
    proposedLower < mandate.range_policy.approved_lower_tick ||
    proposedUpper > mandate.range_policy.approved_upper_tick ||
    evidence.current_tick < proposedLower ||
    evidence.current_tick >= proposedUpper
  ) {
    throwMandateBindingMismatch(
      "signed task proposal range is outside the mandate or current tick",
    );
  }
  if (
    targetWidth % tickSpacing !== 0 ||
    evidence.position_tick_lower % tickSpacing !== 0 ||
    evidence.position_tick_upper % tickSpacing !== 0 ||
    proposedLower % tickSpacing !== 0 ||
    proposedUpper % tickSpacing !== 0 ||
    proposedUpper - proposedLower !== targetWidth
  ) {
    throwMandateBindingMismatch(
      "signed task range widths or executable endpoints do not align to tick spacing",
    );
  }
  const expected = deriveNearestCenteredExactRange(
    evidence.current_tick,
    targetWidth,
    tickSpacing,
  );
  if (proposedLower !== expected.lower || proposedUpper !== expected.upper) {
    throwMandateBindingMismatch(
      "signed task proposal range is not the deterministic mandated range",
    );
  }

  const estimate = mandate.execution_estimate;
  if (
    proposal.estimated_gas_usd !== estimate.gas_usd ||
    proposal.estimated_slippage_bps !== estimate.slippage_bps ||
    proposal.estimated_exposure_usd !== estimate.exposure_usd ||
    proposal.estimate_source_url !== estimate.source_url
  ) {
    throwMandateBindingMismatch(
      "signed task proposal estimates do not match the mandate estimate",
    );
  }
  if (
    estimate.gas_usd > mandate.limits.max_gas_usd ||
    estimate.slippage_bps > mandate.limits.max_slippage_bps ||
    estimate.exposure_usd > mandate.limits.max_exposure_usd ||
    estimate.exposure_usd > mandate.permissions.spend_cap_usd
  ) {
    throwMandateBindingMismatch(
      "signed task proposal estimates exceed the mandate limits",
    );
  }

  const allowedContracts = new Set(mandate.permissions.allowed_contracts);
  const allowedCalls = new Set(mandate.permissions.allowed_calls);
  if (
    proposal.permissions.contracts.length !== 1 ||
    proposal.permissions.contracts[0] !==
      mandate.position.position_manager_address ||
    proposal.permissions.contracts.some(
      (contract) => !allowedContracts.has(contract),
    )
  ) {
    throwMandateBindingMismatch(
      "signed task proposal contracts exceed the mandate permissions",
    );
  }
  if (
    proposal.permissions.calls.length !== REQUIRED_REBALANCE_CALLS.length ||
    proposal.permissions.calls.some(
      (call, index) => call !== REQUIRED_REBALANCE_CALLS[index],
    ) ||
    proposal.permissions.calls.some((call) => !allowedCalls.has(call)) ||
    REQUIRED_REBALANCE_CALLS.some(
      (requiredCall) => !proposal.permissions.calls.includes(requiredCall),
    )
  ) {
    throwMandateBindingMismatch(
      "signed task proposal calls do not match the mandated rebalance permissions",
    );
  }
  if (
    proposal.permissions.spend_cap_usd !== mandate.permissions.spend_cap_usd ||
    proposal.estimated_exposure_usd > proposal.permissions.spend_cap_usd
  ) {
    throwMandateBindingMismatch(
      "signed task proposal spend exceeds the mandate permissions",
    );
  }
  if (
    proposal.permissions.expires_at !== mandate.permissions.expires_at ||
    proposal.permissions.expires_at > mandate.expires_at ||
    proposal.permissions.expires_at <= checkedAt ||
    proposal.permissions.expires_at <= verifiedAt ||
    envelope.response.quote_expires_at > proposal.permissions.expires_at
  ) {
    throwMandateBindingMismatch(
      "signed task proposal permissions do not cover the quote lifetime",
    );
  }
}

export function verifyQuoteMandateBinding(
  input: VerifyQuoteMandateBindingInput,
): VerifiedQuoteMandateBinding {
  const accepted = quoteAcceptedEnvelopeSchema.safeParse(input.envelope);
  if (!accepted.success) {
    throw new QuoteProtocolError(
      input.envelope.response.accepted
        ? "RESPONSE_SCHEMA_INVALID"
        : "QUOTE_REJECTED",
      "only accepted quote envelopes contain a signed task",
    );
  }

  const signedTask = decodeQuoteSignedTask(
    accepted.data.request.task_description,
    input.codec,
  );
  const outboundMandate = quoteMandatexRebalanceMandateSchema.safeParse(
    input.mandate,
  );
  if (!outboundMandate.success) {
    throw new QuoteProtocolError(
      "MANDATE_BINDING_MISMATCH",
      "outbound mandate does not match the trusted rebalance schema",
    );
  }

  const outboundCanonical = canonicalQuoteJson(outboundMandate.data);
  if (canonicalQuoteJson(signedTask.mandate) !== outboundCanonical) {
    throwMandateBindingMismatch(
      "signed task mandate does not match the outbound mandate",
    );
  }

  assertSignedRebalancePolicy(
    signedTask,
    accepted.data,
    unixSeconds(input.now),
  );

  const display = accepted.data.mandatex;
  if (display !== undefined) {
    const observedBlock = signedTask.evidence.observed_block;
    const lowerTick = signedTask.proposal.proposed_lower_tick;
    const upperTick = signedTask.proposal.proposed_upper_tick;
    if (
      display.mandate_id !== signedTask.mandate.mandate_id ||
      display.observed_block !== observedBlock ||
      display.proposed_lower_tick !== lowerTick ||
      display.proposed_upper_tick !== upperTick
    ) {
      throwMandateBindingMismatch(
        "quote display extension does not match the signed task",
      );
    }
  }

  return {
    codec: MANDATEX_REBALANCE_TASK_CODEC,
    mandateSha256: computeQuoteSha256(outboundCanonical),
    signedTask,
  };
}

function keccakCanonical(value: unknown): Hex {
  return keccak256(toBytes(canonicalQuoteJson(value)));
}

export function computeQuoteRequestHash(request: unknown): Hex {
  return keccakCanonical(quoteNegotiationRequestSchema.parse(request));
}

export function computeQuoteResponseHash(
  response: QuoteAcceptedResponse | QuoteRejectedResponse,
): Hex {
  const accepted = response.accepted;
  if (accepted) {
    const parsed = quoteAcceptedResponseSchema.parse(response);
    return keccakCanonical({
      accepted: true,
      terms: parsed.terms,
      estimated_completion_seconds: parsed.estimated_completion_seconds,
      quote_expires_at: parsed.quote_expires_at,
    });
  }

  quoteRejectedResponseSchema.parse(response);
  return keccakCanonical({ accepted: false });
}

export interface QuoteSignedContent {
  readonly version: 1;
  readonly negotiated_at: number;
  readonly task: string;
  readonly terms: Readonly<{
    deliverables: string;
    quality_standards: string;
    success_criteria?: readonly string[];
  }>;
  readonly price: string;
  readonly currency: string;
  readonly quote_expires_at: number;
  readonly chain_id: number;
  readonly verifying_contract: Address;
}

export function buildQuoteSignedContent(
  envelope: QuoteAcceptedEnvelope,
): QuoteSignedContent {
  const parsed = quoteAcceptedEnvelopeSchema.parse(envelope);
  const terms: {
    deliverables: string;
    quality_standards: string;
    success_criteria?: string[];
  } = {
    deliverables: sanitizeQuoteClaim(parsed.response.terms.deliverables),
    quality_standards: sanitizeQuoteClaim(
      parsed.response.terms.quality_standards,
    ),
  };
  const successCriteria = parsed.response.terms.success_criteria;
  if (successCriteria !== undefined && successCriteria.length > 0) {
    terms.success_criteria = successCriteria.map(sanitizeQuoteClaim);
  }

  return {
    version: 1,
    negotiated_at: parsed.response.negotiated_at,
    task: sanitizeQuoteClaim(parsed.request.task_description),
    terms,
    price: parsed.response.terms.price,
    currency: parsed.response.terms.currency,
    quote_expires_at: parsed.response.quote_expires_at,
    chain_id: parsed.chain_id,
    verifying_contract: getAddress(parsed.verifying_contract),
  };
}

export function computeQuoteNegotiationHash(
  envelope: QuoteAcceptedEnvelope,
): Hex {
  return keccakCanonical(buildQuoteSignedContent(envelope));
}

export interface ComputeQuoteReplayKeyInput {
  readonly chainId: number;
  readonly tokenId: string;
  readonly endpointHash: string;
  readonly provider: string;
  readonly commerceContract: string;
  readonly negotiationHash: string;
}

export function computeQuoteReplayKey(
  input: ComputeQuoteReplayKeyInput,
): string {
  if (!Number.isSafeInteger(input.chainId) || input.chainId <= 0) {
    throw new TypeError("chainId must be a positive safe integer");
  }
  if (!/^(?:0|[1-9][0-9]*)$/.test(input.tokenId)) {
    throw new TypeError("tokenId must be a canonical unsigned decimal integer");
  }
  if (!/^[a-f0-9]{64}$/.test(input.endpointHash)) {
    throw new TypeError("endpointHash must be a lowercase SHA-256 digest");
  }
  const negotiationHash = quoteBytes32Schema.parse(
    input.negotiationHash,
  ).toLowerCase();
  const content = canonicalQuoteJson({
    schema: "mandatex.agent-supply.quote-replay-key.v1",
    chainId: input.chainId,
    tokenId: input.tokenId,
    endpointHash: input.endpointHash,
    provider: getAddress(input.provider).toLowerCase(),
    commerceContract: getAddress(input.commerceContract).toLowerCase(),
    negotiationHash,
  });
  return createHash("sha256").update(content, "utf8").digest("hex");
}

export interface QuoteErc1271CallInput {
  readonly provider: Address;
  readonly hash: Hex;
  readonly signature: Hex;
  readonly checker: Address;
}

export type QuoteErc1271Call = (
  input: QuoteErc1271CallInput,
) => Promise<boolean>;

export interface VerifyQuoteEnvelopeInput {
  readonly envelope: QuoteEnvelope;
  readonly expectedProvider: string;
  readonly expectedProviderKind: QuoteProviderKind;
  readonly expectedChainId: number;
  readonly expectedVerifyingContract: string;
  readonly now: number | Date;
  readonly erc1271Call?: QuoteErc1271Call;
}

export interface VerifiedQuoteEnvelope {
  readonly signatureMethod: QuoteSignatureMethod;
  readonly signer: string;
  readonly validatedProvider: string;
  readonly requestHash: Hex;
  readonly responseHash: Hex;
  readonly negotiationHash: Hex;
  readonly chainId: number;
  readonly verifyingContract: string;
  readonly negotiatedAt: number;
  readonly quoteExpiresAt: number;
  readonly price: string;
  readonly currency: string;
  readonly estimatedCompletionSeconds: number;
}

function throwProtocol(
  code: QuoteProtocolErrorCode,
  message: string,
): never {
  throw new QuoteProtocolError(code, message);
}

function assertHashEquals(
  actual: string,
  expected: string,
  code: QuoteProtocolErrorCode,
): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throwProtocol(code, "quote integrity hash does not match its content");
  }
}

function unixSeconds(value: number | Date): number {
  const seconds =
    value instanceof Date ? Math.floor(value.valueOf() / 1_000) : value;
  if (!Number.isSafeInteger(seconds) || seconds < 0) {
    throw new TypeError("now must be a non-negative integer unix timestamp");
  }
  return seconds;
}

export async function verifyQuoteEnvelope(
  input: VerifyQuoteEnvelopeInput,
): Promise<VerifiedQuoteEnvelope> {
  if (!input.envelope.response.accepted) {
    throwProtocol("QUOTE_REJECTED", "quote endpoint refused the mandate");
  }

  const parsedResult = quoteAcceptedEnvelopeSchema.safeParse(input.envelope);
  if (!parsedResult.success) {
    throwProtocol(
      "RESPONSE_SCHEMA_INVALID",
      "accepted quote does not match the signed envelope schema",
    );
  }
  const envelope = parsedResult.data;

  if (envelope.chain_id !== input.expectedChainId) {
    throwProtocol("CHAIN_ID_MISMATCH", "quote is bound to an unexpected chain");
  }

  let signedContract: Address;
  let expectedContract: Address;
  let expectedProvider: Address;
  try {
    signedContract = getAddress(envelope.verifying_contract);
    expectedContract = getAddress(input.expectedVerifyingContract);
    expectedProvider = getAddress(input.expectedProvider);
  } catch {
    throwProtocol(
      "VERIFYING_CONTRACT_MISMATCH",
      "quote trust domain contains an invalid address",
    );
  }
  if (signedContract !== expectedContract) {
    throwProtocol(
      "VERIFYING_CONTRACT_MISMATCH",
      "quote is bound to an unexpected Commerce contract",
    );
  }

  const requestHash = computeQuoteRequestHash(envelope.request);
  assertHashEquals(
    requestHash,
    envelope.request_hash,
    "REQUEST_HASH_MISMATCH",
  );
  const responseHash = computeQuoteResponseHash(envelope.response);
  assertHashEquals(
    responseHash,
    envelope.response_hash,
    "RESPONSE_HASH_MISMATCH",
  );
  const negotiationHash = computeQuoteNegotiationHash(envelope);
  assertHashEquals(
    negotiationHash,
    envelope.negotiation_hash,
    "NEGOTIATION_HASH_MISMATCH",
  );

  if (envelope.response.quote_expires_at <= unixSeconds(input.now)) {
    throwProtocol("QUOTE_EXPIRED", "quote has expired");
  }

  let signatureMethod: QuoteSignatureMethod;
  if (input.expectedProviderKind === "eoa") {
    let recovered: Address;
    try {
      recovered = await recoverMessageAddress({
        message: envelope.negotiation_hash,
        signature: envelope.provider_sig as Hex,
      });
    } catch {
      throwProtocol(
        "PROVIDER_SIGNATURE_INVALID",
        "provider signature could not be recovered",
      );
    }
    if (recovered !== expectedProvider) {
      throwProtocol(
        "PROVIDER_SIGNATURE_INVALID",
        "provider signature does not match the trusted provider",
      );
    }
    signatureMethod = "eip191";
  } else {
    if (input.erc1271Call === undefined) {
      throwProtocol(
        "ERC1271_UNAVAILABLE",
        "ERC-1271 verification callback is unavailable",
      );
    }
    let valid: boolean;
    try {
      valid = await input.erc1271Call({
        provider: expectedProvider,
        hash: hashMessage(envelope.negotiation_hash),
        signature: envelope.provider_sig as Hex,
        checker: expectedContract,
      });
    } catch (error) {
      throw new QuoteProtocolError(
        "ERC1271_UNAVAILABLE",
        "ERC-1271 verification could not be completed",
        { cause: error },
      );
    }
    if (!valid) {
      throwProtocol(
        "PROVIDER_SIGNATURE_INVALID",
        "ERC-1271 provider rejected the quote signature",
      );
    }
    signatureMethod = "erc1271";
  }

  const normalizedProvider = expectedProvider.toLowerCase();
  return {
    signatureMethod,
    signer: normalizedProvider,
    validatedProvider: normalizedProvider,
    requestHash: requestHash.toLowerCase() as Hex,
    responseHash: responseHash.toLowerCase() as Hex,
    negotiationHash: negotiationHash.toLowerCase() as Hex,
    chainId: envelope.chain_id,
    verifyingContract: signedContract.toLowerCase(),
    negotiatedAt: envelope.response.negotiated_at,
    quoteExpiresAt: envelope.response.quote_expires_at,
    price: envelope.response.terms.price,
    currency: getAddress(envelope.response.terms.currency).toLowerCase(),
    estimatedCompletionSeconds:
      envelope.response.estimated_completion_seconds,
  };
}

export const verifyAcceptedQuote = verifyQuoteEnvelope;

export interface BuildQuoteSidecarInput {
  readonly observedAt: string | Date;
  readonly outcome: "valid" | "refused" | "invalid" | "inconclusive";
  readonly candidate: QuoteSidecarCandidate;
  readonly passiveReportSha256: string;
  readonly passiveCandidateSha256: string;
  readonly passivePolicyFingerprint: string;
  readonly trustPolicySha256: string;
  readonly quoteEndpoint: string;
  readonly a2aRequestSha256: string;
  readonly a2aResponseSha256?: string;
  readonly responseSha256?: string;
  readonly expectedProvider: string;
  readonly validatedProvider?: string;
  readonly signer?: string;
  readonly providerKind: QuoteProviderKind;
  readonly signatureMethod?: QuoteSignatureMethod;
  readonly verifyingContract?: string;
  readonly requestHash?: string;
  readonly responseHash?: string;
  readonly negotiationHash?: string;
  readonly negotiatedAt?: number;
  readonly quoteExpiresAt?: number;
  readonly replayKey?: string;
  readonly replayStatus: QuoteReplayStatus;
  readonly gates: QuoteValidationGates;
  readonly errorCode?: QuoteProtocolErrorCode;
  readonly refusalCode?: string;
  readonly envelope?: QuoteEnvelope;
  readonly verification?: VerifiedQuoteEnvelope;
}

function sidecarTimestamp(value: string | Date): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.valueOf())) {
    throw new TypeError("observedAt must be a valid timestamp");
  }
  return date.toISOString();
}

function setIfDefined(
  target: Record<string, unknown>,
  key: string,
  value: unknown,
): void {
  if (value !== undefined) target[key] = value;
}

export function buildQuoteSidecar(input: BuildQuoteSidecarInput): QuoteSidecar {
  const sidecar: Record<string, unknown> = {
    schema: QUOTE_SIDECAR_SCHEMA,
    observedAt: sidecarTimestamp(input.observedAt),
    outcome: input.outcome,
    candidate: input.candidate,
    passiveReportSha256: input.passiveReportSha256,
    passiveCandidateSha256: input.passiveCandidateSha256,
    passivePolicyFingerprint: input.passivePolicyFingerprint,
    trustPolicySha256: input.trustPolicySha256,
    quoteEndpoint: input.quoteEndpoint,
    a2aRequestSha256: input.a2aRequestSha256,
    expectedProvider: input.expectedProvider,
    providerKind: input.providerKind,
    replayStatus: input.replayStatus,
    gates: input.gates,
  };

  setIfDefined(
    sidecar,
    "a2aResponseSha256",
    input.a2aResponseSha256 ?? input.responseSha256,
  );
  setIfDefined(
    sidecar,
    "validatedProvider",
    input.validatedProvider ?? input.signer ?? input.verification?.validatedProvider,
  );
  setIfDefined(
    sidecar,
    "signatureMethod",
    input.signatureMethod ?? input.verification?.signatureMethod,
  );
  setIfDefined(
    sidecar,
    "verifyingContract",
    input.verifyingContract ?? input.verification?.verifyingContract,
  );
  setIfDefined(
    sidecar,
    "requestHash",
    input.requestHash ?? input.verification?.requestHash,
  );
  setIfDefined(
    sidecar,
    "responseHash",
    input.responseHash ?? input.verification?.responseHash,
  );
  setIfDefined(
    sidecar,
    "negotiationHash",
    input.negotiationHash ?? input.verification?.negotiationHash,
  );
  setIfDefined(
    sidecar,
    "negotiatedAt",
    input.negotiatedAt ?? input.verification?.negotiatedAt,
  );
  setIfDefined(
    sidecar,
    "quoteExpiresAt",
    input.quoteExpiresAt ?? input.verification?.quoteExpiresAt,
  );
  setIfDefined(sidecar, "replayKey", input.replayKey);
  setIfDefined(sidecar, "errorCode", input.errorCode);
  setIfDefined(sidecar, "refusalCode", input.refusalCode);

  if (input.envelope !== undefined) {
    const envelope = input.envelope;
    if (envelope.request_hash !== "") {
      setIfDefined(sidecar, "requestHash", sidecar.requestHash ?? envelope.request_hash);
    }
    if (envelope.response_hash !== "") {
      setIfDefined(
        sidecar,
        "responseHash",
        sidecar.responseHash ?? envelope.response_hash,
      );
    }
    const acceptedEnvelope = quoteAcceptedEnvelopeSchema.safeParse(envelope);
    if (acceptedEnvelope.success) {
      const accepted = acceptedEnvelope.data;
      setIfDefined(
        sidecar,
        "negotiationHash",
        sidecar.negotiationHash ?? accepted.negotiation_hash,
      );
      setIfDefined(
        sidecar,
        "verifyingContract",
        sidecar.verifyingContract ?? accepted.verifying_contract,
      );
      setIfDefined(
        sidecar,
        "negotiatedAt",
        sidecar.negotiatedAt ?? accepted.response.negotiated_at,
      );
      setIfDefined(
        sidecar,
        "quoteExpiresAt",
        sidecar.quoteExpiresAt ?? accepted.response.quote_expires_at,
      );
    } else if (sidecar.refusalCode === undefined) {
      const rejected = quoteRejectedEnvelopeSchema.parse(envelope);
      const refusalCode =
        rejected.mandatex?.refusal.code ?? rejected.response.reason_code;
      setIfDefined(sidecar, "refusalCode", refusalCode);
    }
  }

  return quoteSidecarSchema.parse(sidecar);
}

function sortedPrettyJson(value: unknown): string {
  return `${JSON.stringify(sortCanonicalValue(value), null, 2)}\n`;
}

export function serializeQuoteSidecar(sidecar: QuoteSidecar): string {
  return sortedPrettyJson(quoteSidecarSchema.parse(sidecar));
}

export function serializeQuoteTrustFile(file: QuoteTrustFile): string {
  return sortedPrettyJson(quoteTrustFileSchema.parse(file));
}

export function computeQuoteSha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
