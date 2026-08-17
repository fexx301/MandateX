import { isIP } from "node:net";

import { z } from "zod";

import {
  addressSchema,
  isoUtcSchema,
  sha256Schema,
  tokenIdSchema,
} from "../schema.js";
import {
  deriveNearestCenteredExactRange,
  MAX_REBALANCE_TICK,
  MAX_REBALANCE_TICK_SPACING,
  MIN_REBALANCE_TICK,
} from "./range.js";

export const MAX_PASSIVE_AGE_SECONDS = 300 as const;
export const MAX_CLOCK_SKEW_SECONDS = 30 as const;
export const MAX_QUOTE_TTL_SECONDS = 900 as const;
export const MIN_QUOTE_REMAINING_SECONDS = 30 as const;
export const QUOTE_TRUST_SCHEMA =
  "mandatex.agent-supply.quote-trust.v1" as const;
export const QUOTE_SIDECAR_SCHEMA =
  "mandatex.agent-supply.quote-validation.v1" as const;
export const QUOTE_MARKETPLACE_EVALUATION_EVIDENCE_SCHEMA =
  "mandatex.agent-supply.quote-marketplace-evaluation-evidence.v1" as const;

export type QuoteJsonValue =
  | string
  | number
  | boolean
  | null
  | QuoteJsonValue[]
  | { [key: string]: QuoteJsonValue };

const quoteJsonPrimitiveSchema = z.union([
  z.string().max(16_384),
  z.number().finite(),
  z.boolean(),
  z.null(),
]);

function boundedQuoteJsonValueSchema(depth: number): z.ZodType<QuoteJsonValue> {
  if (depth === 0) return quoteJsonPrimitiveSchema;
  const child = boundedQuoteJsonValueSchema(depth - 1);
  return z.union([
    quoteJsonPrimitiveSchema,
    z.array(child).max(256),
    z.record(child).refine((value) => Object.keys(value).length <= 256, {
      message: "JSON object exceeds the quote field limit",
    }),
  ]);
}

export const quoteJsonValueSchema = boundedQuoteJsonValueSchema(16);

export const quoteMandateSchema = z
  .record(quoteJsonValueSchema)
  .refine((value) => Object.keys(value).length > 0, {
    message: "mandate must not be empty",
  })
  .refine((value) => Object.keys(value).length <= 128, {
    message: "mandate exceeds the field limit",
  });
export type QuoteMandate = z.infer<typeof quoteMandateSchema>;

const quoteIdSchema = z.string().min(1).max(128);
const quoteTextSchema = z.string().min(1).max(4_096);
const quoteShortTextSchema = z.string().min(1).max(256);
const quoteUnixSecondsSchema = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER);
const quoteAddressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/, "expected an EVM address");
export const quoteBytes32Schema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{64}$/, "expected a 32-byte hex value");
export const quoteSignatureSchema = z
  .string()
  .regex(/^0x(?:[a-fA-F0-9]{2})+$/, "expected a non-empty byte-aligned hex signature")
  .max(8_194);

export const quoteUint256DecimalSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/, "expected a canonical unsigned decimal integer")
  .refine((value) => {
    try {
      return BigInt(value) <= (1n << 256n) - 1n;
    } catch {
      return false;
    }
  }, "integer is outside uint256 range");

function isCanonicalQuoteHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      (url.port === "" || url.port === "443") &&
      url.search === "" &&
      url.hash === "" &&
      hostname.length > 0 &&
      hostname.length <= 253 &&
      isIP(hostname) === 0 &&
      url.href === value
    );
  } catch {
    return false;
  }
}

export const quoteCanonicalHttpsUrlSchema = z
  .string()
  .min(1)
  .max(2_048)
  .refine(isCanonicalQuoteHttpsUrl, {
    message: "expected a canonical credential-free HTTPS URL",
  });

export const quoteProviderKindSchema = z.enum(["eoa", "erc1271"]);
export type QuoteProviderKind = z.infer<typeof quoteProviderKindSchema>;

export const quoteTrustProtocolSchema = z
  .object({
    a2a: z.literal("0.3.x"),
    method: z.literal("message/send"),
    skill: z.literal("negotiate"),
    signature: z.literal("eip191-negotiation-hash-string"),
    signedTaskCodec: z.literal("mandatex-rebalance:v1"),
  })
  .strict();

export const quoteTrustEntrySchema = z
  .object({
    chainId: z.literal(56),
    registryAddress: addressSchema,
    tokenId: tokenIdSchema,
    category: z.literal("rebalancing"),
    cardUrl: quoteCanonicalHttpsUrlSchema,
    quoteEndpoint: quoteCanonicalHttpsUrlSchema,
    expectedProvider: addressSchema,
    providerKind: quoteProviderKindSchema,
    commerceContract: addressSchema,
    protocol: quoteTrustProtocolSchema,
    maxPassiveAgeSeconds: z
      .number()
      .int()
      .positive()
      .max(MAX_PASSIVE_AGE_SECONDS),
    maxQuoteTtlSeconds: z
      .number()
      .int()
      .positive()
      .max(MAX_QUOTE_TTL_SECONDS),
    maxClockSkewSeconds: z
      .number()
      .int()
      .nonnegative()
      .max(MAX_CLOCK_SKEW_SECONDS),
    allowedCurrencies: z.array(addressSchema).min(1).max(32),
    maxPrice: quoteUint256DecimalSchema,
  })
  .strict()
  .superRefine((entry, context) => {
    if (new Set(entry.allowedCurrencies).size !== entry.allowedCurrencies.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["allowedCurrencies"],
        message: "allowedCurrencies must contain unique addresses",
      });
    }
  })
  .transform((entry) => ({
    ...entry,
    allowedCurrencies: [...entry.allowedCurrencies].sort(),
  }));
export type QuoteTrustEntry = z.infer<typeof quoteTrustEntrySchema>;

export const quoteTrustFileSchema = z
  .object({
    schema: z.literal(QUOTE_TRUST_SCHEMA),
    candidates: z.array(quoteTrustEntrySchema).min(1).max(8),
  })
  .strict()
  .superRefine((file, context) => {
    const identities = file.candidates.map(
      (candidate) => `${candidate.chainId}:${candidate.tokenId}`,
    );
    if (new Set(identities).size !== identities.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["candidates"],
        message: "candidate chainId/tokenId pairs must be unique",
      });
    }
  })
  .transform((file) => ({
    ...file,
    candidates: [...file.candidates].sort((left, right) => {
      const leftToken = BigInt(left.tokenId);
      const rightToken = BigInt(right.tokenId);
      return leftToken < rightToken ? -1 : leftToken > rightToken ? 1 : 0;
    }),
  }));
export type QuoteTrustFile = z.infer<typeof quoteTrustFileSchema>;

const quoteTermsShape = {
  deliverables: quoteTextSchema,
  quality_standards: quoteTextSchema,
  evaluation_required: z.boolean(),
  evaluator_type: quoteShortTextSchema,
  success_criteria: z.array(quoteTextSchema).max(64).optional(),
};

export const quoteRequestTermsSchema = z
  .object({
    ...quoteTermsShape,
    price: quoteUint256DecimalSchema.optional(),
    currency: quoteAddressSchema.optional(),
  })
  .strict();
export type QuoteRequestTerms = z.infer<typeof quoteRequestTermsSchema>;

export const quoteAcceptedTermsSchema = z
  .object({
    ...quoteTermsShape,
    price: quoteUint256DecimalSchema,
    currency: quoteAddressSchema,
  })
  .strict();
export type QuoteAcceptedTerms = z.infer<typeof quoteAcceptedTermsSchema>;

export const quoteNegotiationRequestSchema = z
  .object({
    task_description: z.string().min(1).max(4_096),
    terms: quoteRequestTermsSchema,
    context_urls: z.array(z.string().url().max(2_048)).max(32).optional(),
    request_id: quoteIdSchema.optional(),
  })
  .strict();
export type QuoteNegotiationRequest = z.infer<
  typeof quoteNegotiationRequestSchema
>;

export const quoteAcceptedResponseSchema = z
  .object({
    accepted: z.literal(true),
    terms: quoteAcceptedTermsSchema,
    estimated_completion_seconds: z
      .number()
      .int()
      .nonnegative()
      .max(31_536_000),
    quote_expires_at: quoteUnixSecondsSchema,
    negotiated_at: quoteUnixSecondsSchema,
  })
  .strict()
  .superRefine((response, context) => {
    if (response.quote_expires_at <= response.negotiated_at) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["quote_expires_at"],
        message: "quote expiry must be after negotiation time",
      });
      return;
    }
    if (
      response.quote_expires_at - response.negotiated_at >
      MAX_QUOTE_TTL_SECONDS
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["quote_expires_at"],
        message: `quote lifetime must not exceed ${MAX_QUOTE_TTL_SECONDS} seconds`,
      });
    }
  });
export type QuoteAcceptedResponse = z.infer<
  typeof quoteAcceptedResponseSchema
>;

export const quoteRejectedResponseSchema = z
  .object({
    accepted: z.literal(false),
    reason_code: z.string().regex(/^0x[a-fA-F0-9]{2}$/).optional(),
    reason: z.string().min(1).max(1_000).optional(),
  })
  .strict();
export type QuoteRejectedResponse = z.infer<
  typeof quoteRejectedResponseSchema
>;

const quoteTickSchema = z
  .number()
  .int()
  .min(MIN_REBALANCE_TICK)
  .max(MAX_REBALANCE_TICK);
const quoteTickSpacingSchema = z
  .number()
  .int()
  .positive()
  .max(MAX_REBALANCE_TICK_SPACING);
const quoteUsdSchema = z.number().finite().nonnegative();
const quotePositiveUnixSecondsSchema = z.number().int().positive();

export const quoteMandatexRebalanceMandateSchema = z
  .object({
    version: z.literal("1"),
    mandate_id: z
      .string()
      .trim()
      .min(1)
      .max(80)
      .regex(/^[A-Za-z0-9._:-]+$/),
    category: z.literal("rebalancing"),
    chain_id: z.number().int().positive(),
    protocol: z.literal("pancakeswap-v3"),
    expires_at: quotePositiveUnixSecondsSchema,
    max_evidence_age_seconds: z.number().int().min(5).max(300).default(120),
    position: z
      .object({
        pool_address: addressSchema,
        position_manager_address: addressSchema,
        token_id: z
          .string()
          .trim()
          .regex(/^\d+$/)
          .transform((value) => BigInt(value).toString()),
      })
      .strict(),
    range_policy: z
      .object({
        approved_lower_tick: quoteTickSchema,
        approved_upper_tick: quoteTickSchema,
        target_width_ticks: z.number().int().positive().max(1_774_544),
        trigger_mode: z
          .enum(["out_of_range", "boundary_proximity"])
          .default("boundary_proximity"),
        trigger_distance_ticks: z.number().int().nonnegative().max(1_774_544),
        max_delivery_tick_drift: z.number().int().nonnegative().max(1_774_544),
      })
      .strict(),
    limits: z
      .object({
        max_gas_usd: quoteUsdSchema,
        max_slippage_bps: z.number().int().min(0).max(10_000),
        max_exposure_usd: quoteUsdSchema,
      })
      .strict(),
    execution_estimate: z
      .object({
        gas_usd: quoteUsdSchema,
        slippage_bps: z.number().int().min(0).max(10_000),
        exposure_usd: quoteUsdSchema,
        observed_at: quotePositiveUnixSecondsSchema,
        source_url: z.string().url().max(500),
      })
      .strict(),
    permissions: z
      .object({
        allowed_contracts: z.array(addressSchema).min(1).max(12),
        allowed_calls: z
          .array(z.string().trim().min(1).max(180))
          .min(1)
          .max(20),
        spend_cap_usd: quoteUsdSchema,
        expires_at: quotePositiveUnixSecondsSchema,
      })
      .strict(),
  })
  .strict()
  .superRefine((mandate, context) => {
    if (
      mandate.range_policy.approved_lower_tick >=
      mandate.range_policy.approved_upper_tick
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["range_policy", "approved_upper_tick"],
        message: "must be greater than approved_lower_tick",
      });
    }
    if (
      mandate.range_policy.target_width_ticks >
      mandate.range_policy.approved_upper_tick -
        mandate.range_policy.approved_lower_tick
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["range_policy", "target_width_ticks"],
        message: "must fit inside the approved tick envelope",
      });
    }
    if (mandate.permissions.expires_at > mandate.expires_at) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["permissions", "expires_at"],
        message: "must not outlive the mandate",
      });
    }
  })
  .transform((mandate) => ({
    ...mandate,
    permissions: {
      ...mandate.permissions,
      allowed_contracts: [
        ...new Set(mandate.permissions.allowed_contracts),
      ].sort(),
      allowed_calls: [...new Set(mandate.permissions.allowed_calls)].sort(),
    },
  }));
export type QuoteMandatexRebalanceMandate = z.infer<
  typeof quoteMandatexRebalanceMandateSchema
>;

export const quoteMandatexRebalanceEvidenceSchema = z
  .object({
    network: z.string(),
    chain_id: z.number().int().positive(),
    snapshot_head_block: z.number().int().nonnegative(),
    confirmation_depth_blocks: z.literal(2),
    observed_block: z.number().int().nonnegative(),
    observed_block_hash: quoteBytes32Schema.transform((value) =>
      value.toLowerCase(),
    ),
    observed_at: quotePositiveUnixSecondsSchema,
    pool_address: addressSchema,
    position_manager_address: addressSchema,
    position_token_id: z.string().regex(/^\d+$/),
    position_owner: addressSchema,
    token0: addressSchema,
    token1: addressSchema,
    token0_decimals: z.number().int().min(0).max(255),
    token1_decimals: z.number().int().min(0).max(255),
    fee: z.number().int().min(0).max(1_000_000),
    tick_spacing: quoteTickSpacingSchema,
    current_tick: quoteTickSchema,
    sqrt_price_x96: z.string().regex(/^\d+$/),
    approximate_token1_per_token0: z.string().nullable(),
    position_tick_lower: quoteTickSchema,
    position_tick_upper: quoteTickSchema,
    pool_liquidity: z.string().regex(/^\d+$/),
    position_liquidity: z.string().regex(/^\d+$/),
    sources: z.array(
      z
        .object({
          type: z.literal("onchain"),
          url: z.string().url(),
          observed_block: z.number().int().nonnegative(),
        })
        .strict(),
    ),
  })
  .strict()
  .superRefine((evidence, context) => {
    if (evidence.position_tick_lower >= evidence.position_tick_upper) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["position_tick_upper"],
        message: "must be greater than position_tick_lower",
      });
    }
    if (
      evidence.position_tick_lower % evidence.tick_spacing !== 0 ||
      evidence.position_tick_upper % evidence.tick_spacing !== 0
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["tick_spacing"],
        message: "position range endpoints must align to tick_spacing",
      });
    }
    if (
      evidence.snapshot_head_block - evidence.observed_block !==
      evidence.confirmation_depth_blocks
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["confirmation_depth_blocks"],
        message: "must equal snapshot_head_block minus observed_block",
      });
    }
  });

export const quoteMandatexRebalanceProposalSchema = z
  .object({
    execution_mode: z.literal("simulation"),
    proposed_lower_tick: quoteTickSchema,
    proposed_upper_tick: quoteTickSchema,
    trigger: z
      .object({
        fired: z.literal(true),
        reason: z.enum(["outside_current_range", "near_range_boundary"]),
        distance_to_boundary_ticks: z.number().int().nonnegative(),
      })
      .strict(),
    estimated_gas_usd: quoteUsdSchema,
    estimated_slippage_bps: z.number().int().min(0).max(10_000),
    estimated_exposure_usd: quoteUsdSchema,
    estimate_source_url: z.string().url(),
    permissions: z
      .object({
        contracts: z.array(addressSchema),
        calls: z.array(z.string()),
        spend_cap_usd: quoteUsdSchema,
        expires_at: quotePositiveUnixSecondsSchema,
      })
      .strict(),
    break_even: z
      .object({
        status: z.literal("not_calculated"),
        reason: z.string(),
      })
      .strict(),
  })
  .strict()
  .superRefine((proposal, context) => {
    if (proposal.proposed_lower_tick >= proposal.proposed_upper_tick) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["proposed_upper_tick"],
        message: "must be greater than proposed_lower_tick",
      });
    }
  });

export const quoteMandatexSignedRebalanceTaskSchema = z
  .object({
    schema: z.literal("mandatex.rebalance.quote.v1"),
    mandate: quoteMandatexRebalanceMandateSchema,
    evidence: quoteMandatexRebalanceEvidenceSchema,
    proposal: quoteMandatexRebalanceProposalSchema,
    eligibility: z
      .object({
        eligible: z.literal(true),
        checked_at: quotePositiveUnixSecondsSchema,
        checks: z.array(z.string().min(1).max(256)).min(1).max(64),
      })
      .strict(),
  })
  .strict()
  .superRefine((task, context) => {
    const width = task.mandate.range_policy.target_width_ticks;
    const spacing = task.evidence.tick_spacing;
    const lower = task.proposal.proposed_lower_tick;
    const upper = task.proposal.proposed_upper_tick;

    if (width % spacing !== 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["mandate", "range_policy", "target_width_ticks"],
        message: "must be divisible by evidence.tick_spacing",
      });
      return;
    }
    if (
      lower % spacing !== 0 ||
      upper % spacing !== 0 ||
      upper - lower !== width
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["proposal"],
        message: "proposal endpoints must be aligned and have exact target width",
      });
      return;
    }

    const expected = deriveNearestCenteredExactRange(
      task.evidence.current_tick,
      width,
      spacing,
    );
    if (lower !== expected.lower || upper !== expected.upper) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["proposal"],
        message: "proposal must use the deterministic exact target range",
      });
    }
  });
export type QuoteMandatexSignedRebalanceTask = z.infer<
  typeof quoteMandatexSignedRebalanceTaskSchema
>;

export const quoteMandatexDisplaySchema = z
  .object({
    schema: z.literal("mandatex.rebalance.quote.v1"),
    mandate_id: z
      .string()
      .min(1)
      .max(80)
      .regex(/^[A-Za-z0-9._:-]+$/),
    observed_block: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    proposed_lower_tick: z.number().int().min(-887_272).max(887_272),
    proposed_upper_tick: z.number().int().min(-887_272).max(887_272),
    display_only: z.literal(true),
  })
  .strict();

export const quoteMandatexRefusalSchema = z
  .object({
    eligible: z.literal(false),
    refusal: z
      .object({
        code: z.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/),
        message: z.string().min(1).max(1_000),
        details: z.record(quoteJsonValueSchema).optional(),
      })
      .strict(),
  })
  .strict();

export const quoteAcceptedEnvelopeSchema = z
  .object({
    request: quoteNegotiationRequestSchema,
    request_hash: quoteBytes32Schema,
    response: quoteAcceptedResponseSchema,
    response_hash: quoteBytes32Schema,
    negotiation_hash: quoteBytes32Schema,
    provider_sig: quoteSignatureSchema,
    chain_id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    verifying_contract: quoteAddressSchema,
    mandatex: quoteMandatexDisplaySchema.optional(),
  })
  .strict();
export type QuoteAcceptedEnvelope = z.infer<
  typeof quoteAcceptedEnvelopeSchema
>;

const quoteRejectedHashSchema = z.union([
  z.literal(""),
  quoteBytes32Schema,
]);

export const quoteRejectedEnvelopeSchema = z
  .object({
    request: z
      .record(quoteJsonValueSchema)
      .refine((value) => Object.keys(value).length <= 64),
    request_hash: quoteRejectedHashSchema,
    response: quoteRejectedResponseSchema,
    response_hash: quoteRejectedHashSchema,
    negotiation_hash: z.literal("").optional(),
    provider_sig: z.literal("").optional(),
    mandatex: quoteMandatexRefusalSchema.optional(),
  })
  .strict();
export type QuoteRejectedEnvelope = z.infer<
  typeof quoteRejectedEnvelopeSchema
>;

export const quoteEnvelopeSchema = z.union([
  quoteAcceptedEnvelopeSchema,
  quoteRejectedEnvelopeSchema,
]);
export type QuoteEnvelope = z.infer<typeof quoteEnvelopeSchema>;

export const quoteA2aRequestSchema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: quoteIdSchema,
    method: z.literal("message/send"),
    params: z
      .object({
        message: z
          .object({
            kind: z.literal("message"),
            messageId: quoteIdSchema,
            role: z.literal("user"),
            parts: z
              .array(
                z
                  .object({
                    kind: z.literal("data"),
                    data: z
                      .object({
                        skill: z.literal("negotiate"),
                        request: z
                          .object({ mandate: quoteMandateSchema })
                          .strict(),
                      })
                      .strict(),
                  })
                  .strict(),
              )
              .length(1),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();
export type QuoteA2aRequest = z.infer<typeof quoteA2aRequestSchema>;

const quoteA2aAgentMessageSchema = z
  .object({
    kind: z.literal("message"),
    role: z.literal("agent"),
    messageId: quoteIdSchema,
    contextId: quoteIdSchema.optional(),
    taskId: quoteIdSchema.optional(),
    parts: z
      .array(
        z
          .object({
            kind: z.literal("data"),
            data: quoteEnvelopeSchema,
          })
          .strict(),
      )
      .length(1),
  })
  .strict();

export const quoteA2aSuccessResponseSchema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: quoteIdSchema,
    result: quoteA2aAgentMessageSchema,
  })
  .strict();
export type QuoteA2aSuccessResponse = z.infer<
  typeof quoteA2aSuccessResponseSchema
>;

export const quoteA2aErrorResponseSchema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: quoteIdSchema.nullable(),
    error: z
      .object({
        code: z.number().int(),
        message: z.string().min(1).max(1_000),
        data: quoteJsonValueSchema.optional(),
      })
      .strict(),
  })
  .strict();
export type QuoteA2aErrorResponse = z.infer<
  typeof quoteA2aErrorResponseSchema
>;

export const quoteA2aResponseSchema = z.union([
  quoteA2aSuccessResponseSchema,
  quoteA2aErrorResponseSchema,
]);
export type QuoteA2aResponse = z.infer<typeof quoteA2aResponseSchema>;

export const quoteSignatureMethodSchema = z.enum(["eip191", "erc1271"]);
export type QuoteSignatureMethod = z.infer<
  typeof quoteSignatureMethodSchema
>;

export const verifiedQuoteEnvelopeSchema = z
  .object({
    signatureMethod: quoteSignatureMethodSchema,
    signer: addressSchema,
    validatedProvider: addressSchema,
    requestHash: quoteBytes32Schema.transform((value) => value.toLowerCase()),
    responseHash: quoteBytes32Schema.transform((value) => value.toLowerCase()),
    negotiationHash: quoteBytes32Schema.transform((value) => value.toLowerCase()),
    chainId: z.literal(56),
    verifyingContract: addressSchema,
    negotiatedAt: quoteUnixSecondsSchema,
    quoteExpiresAt: quoteUnixSecondsSchema,
    price: quoteUint256DecimalSchema,
    currency: addressSchema,
    estimatedCompletionSeconds: z
      .number()
      .int()
      .nonnegative()
      .max(31_536_000),
  })
  .strict()
  .superRefine((verification, context) => {
    if (verification.quoteExpiresAt <= verification.negotiatedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["quoteExpiresAt"],
        message: "quoteExpiresAt must be after negotiatedAt",
      });
    }
    if (verification.signer !== verification.validatedProvider) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["signer"],
        message: "signer must match validatedProvider",
      });
    }
  });
export type VerifiedQuoteEnvelopeArtifact = z.infer<
  typeof verifiedQuoteEnvelopeSchema
>;

export const quoteProtocolErrorCodeSchema = z.enum([
  "TRANSPORT_FAILED",
  "HTTP_STATUS_INVALID",
  "RESPONSE_JSON_INVALID",
  "RESPONSE_SCHEMA_INVALID",
  "RPC_ID_MISMATCH",
  "JSON_RPC_ERROR",
  "QUOTE_REJECTED",
  "REQUEST_HASH_MISMATCH",
  "RESPONSE_HASH_MISMATCH",
  "NEGOTIATION_HASH_MISMATCH",
  "SIGNED_TASK_INVALID",
  "MANDATE_BINDING_MISMATCH",
  "CHAIN_ID_MISMATCH",
  "VERIFYING_CONTRACT_MISMATCH",
  "QUOTE_EXPIRED",
  "PROVIDER_SIGNATURE_INVALID",
  "ERC1271_UNAVAILABLE",
  "PASSIVE_PREFLIGHT_FAILED",
  "ENDPOINT_BINDING_MISMATCH",
  "QUOTE_POLICY_REJECTED",
  "PREVIEW_GATE_REJECTED",
  "PREVIEW_GATE_UNAVAILABLE",
  "REPLAY_DETECTED",
  "REPLAY_STORE_UNAVAILABLE",
]);
export type QuoteProtocolErrorCode = z.infer<
  typeof quoteProtocolErrorCodeSchema
>;

const quoteSidecarBytes32Schema = quoteBytes32Schema.transform((value) =>
  value.toLowerCase(),
);
const quoteRefusalCodeSchema = z
  .string()
  .regex(/^(?:0x[a-fA-F0-9]{2}|[A-Z][A-Z0-9_]{1,63})$/)
  .transform((value) => (value.startsWith("0x") ? value.toLowerCase() : value));

export const quoteReplayStatusSchema = z.enum([
  "claimed",
  "duplicate",
  "not_attempted",
]);
export type QuoteReplayStatus = z.infer<typeof quoteReplayStatusSchema>;

export const quoteValidationGateStateSchema = z.enum([
  "pass",
  "fail",
  "unknown",
]);
export type QuoteValidationGateState = z.infer<
  typeof quoteValidationGateStateSchema
>;

export const quoteValidationGatesSchema = z
  .object({
    passivePreflight: quoteValidationGateStateSchema,
    endpointBinding: quoteValidationGateStateSchema,
    quoteSignature: quoteValidationGateStateSchema,
    quotePolicy: quoteValidationGateStateSchema,
    replay: quoteValidationGateStateSchema,
  })
  .strict();
export type QuoteValidationGates = z.infer<
  typeof quoteValidationGatesSchema
>;

export const quoteSidecarCandidateSchema = z
  .object({
    chainId: z.literal(56),
    tokenId: tokenIdSchema,
  })
  .strict();
export type QuoteSidecarCandidate = z.infer<
  typeof quoteSidecarCandidateSchema
>;

export const quoteMarketplaceEvaluationEvidenceSchema = z
  .object({
    schema: z.literal(QUOTE_MARKETPLACE_EVALUATION_EVIDENCE_SCHEMA),
    observedAt: isoUtcSchema,
    candidate: quoteSidecarCandidateSchema,
    passiveReportSha256: sha256Schema,
    passiveCandidateSha256: sha256Schema,
    passivePolicyFingerprint: sha256Schema,
    trustPolicySha256: sha256Schema,
    quoteEndpoint: quoteCanonicalHttpsUrlSchema,
    a2aRequestSha256: sha256Schema,
    a2aResponseSha256: sha256Schema,
    expectedProvider: addressSchema,
    providerKind: quoteProviderKindSchema,
    acceptedEnvelope: quoteAcceptedEnvelopeSchema,
    verification: verifiedQuoteEnvelopeSchema,
    signedTask: quoteMandatexSignedRebalanceTaskSchema,
    mandateSha256: sha256Schema,
    gates: z
      .object({
        passivePreflight: z.literal("pass"),
        endpointBinding: z.literal("pass"),
        quoteSignature: z.literal("pass"),
        quotePolicy: z.literal("pass"),
        finalChecks: z.literal("pass"),
      })
      .strict(),
  })
  .strict()
  .superRefine((evidence, context) => {
    if (
      evidence.expectedProvider !== evidence.verification.validatedProvider ||
      evidence.acceptedEnvelope.negotiation_hash.toLowerCase() !==
        evidence.verification.negotiationHash
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "verified quote evidence is internally inconsistent",
      });
    }
    if (
      (evidence.providerKind === "eoa" &&
        evidence.verification.signatureMethod !== "eip191") ||
      (evidence.providerKind === "erc1271" &&
        evidence.verification.signatureMethod !== "erc1271")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["verification", "signatureMethod"],
        message: "signature method must match provider kind",
      });
    }
  });
export type QuoteMarketplaceEvaluationEvidence = z.infer<
  typeof quoteMarketplaceEvaluationEvidenceSchema
>;

export const quoteSidecarSchema = z
  .object({
    schema: z.literal(QUOTE_SIDECAR_SCHEMA),
    observedAt: isoUtcSchema,
    outcome: z.enum(["valid", "refused", "invalid", "inconclusive"]),
    candidate: quoteSidecarCandidateSchema,
    passiveReportSha256: sha256Schema,
    passiveCandidateSha256: sha256Schema,
    passivePolicyFingerprint: sha256Schema,
    trustPolicySha256: sha256Schema,
    quoteEndpoint: quoteCanonicalHttpsUrlSchema,
    a2aRequestSha256: sha256Schema,
    a2aResponseSha256: sha256Schema.optional(),
    expectedProvider: addressSchema,
    validatedProvider: addressSchema.optional(),
    providerKind: quoteProviderKindSchema,
    signatureMethod: quoteSignatureMethodSchema.optional(),
    verifyingContract: addressSchema.optional(),
    requestHash: quoteSidecarBytes32Schema.optional(),
    responseHash: quoteSidecarBytes32Schema.optional(),
    negotiationHash: quoteSidecarBytes32Schema.optional(),
    negotiatedAt: quoteUnixSecondsSchema.optional(),
    quoteExpiresAt: quoteUnixSecondsSchema.optional(),
    replayKey: sha256Schema.optional(),
    replayStatus: quoteReplayStatusSchema,
    gates: quoteValidationGatesSchema,
    errorCode: quoteProtocolErrorCodeSchema.optional(),
    refusalCode: quoteRefusalCodeSchema.optional(),
  })
  .strict()
  .superRefine((sidecar, context) => {
    if (sidecar.outcome === "valid") {
      const required: ReadonlyArray<keyof typeof sidecar> = [
        "a2aResponseSha256",
        "validatedProvider",
        "signatureMethod",
        "verifyingContract",
        "requestHash",
        "responseHash",
        "negotiationHash",
        "replayKey",
        "negotiatedAt",
        "quoteExpiresAt",
      ];
      for (const key of required) {
        if (sidecar[key] === undefined) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required for a verified quote`,
          });
        }
      }
      for (const [gate, state] of Object.entries(sidecar.gates)) {
        if (state !== "pass") {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["gates", gate],
            message: "all gates must pass for a valid quote",
          });
        }
      }
      if (sidecar.replayStatus !== "claimed") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["replayStatus"],
          message: "valid quotes must have a claimed replay key",
        });
      }
      if (sidecar.errorCode !== undefined || sidecar.refusalCode !== undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "valid quote sidecars cannot contain failure codes",
        });
      }
      if (sidecar.quoteExpiresAt !== undefined) {
        const observedAtMs = new Date(sidecar.observedAt).valueOf();
        const quoteExpiresAtMs = sidecar.quoteExpiresAt * 1_000;
        if (
          quoteExpiresAtMs - observedAtMs <
          MIN_QUOTE_REMAINING_SECONDS * 1_000
        ) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["quoteExpiresAt"],
            message: `valid quotes must have at least ${MIN_QUOTE_REMAINING_SECONDS} seconds remaining`,
          });
        }
      }
    }

    if (sidecar.outcome === "refused" && sidecar.refusalCode === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["refusalCode"],
        message: "refusalCode is required for a refused quote",
      });
    }

    if (
      (sidecar.outcome === "invalid" || sidecar.outcome === "inconclusive") &&
      sidecar.errorCode === undefined
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["errorCode"],
        message: "errorCode is required for a failed quote verification",
      });
    }

    if (
      sidecar.outcome !== "refused" &&
      sidecar.refusalCode !== undefined
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["refusalCode"],
        message: "refusalCode is only valid for refused quotes",
      });
    }
    if (
      sidecar.outcome !== "invalid" &&
      sidecar.outcome !== "inconclusive" &&
      sidecar.errorCode !== undefined
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["errorCode"],
        message: "errorCode is only valid for invalid or inconclusive quotes",
      });
    }

    if (
      sidecar.replayStatus !== "not_attempted" &&
      sidecar.replayKey === undefined
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["replayKey"],
        message: "replayKey is required after a replay claim attempt",
      });
    }
    if (
      sidecar.signatureMethod !== undefined &&
      ((sidecar.providerKind === "eoa" && sidecar.signatureMethod !== "eip191") ||
        (sidecar.providerKind === "erc1271" &&
          sidecar.signatureMethod !== "erc1271"))
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["signatureMethod"],
        message: "signatureMethod must match providerKind",
      });
    }
    if (
      sidecar.negotiatedAt !== undefined &&
      sidecar.quoteExpiresAt !== undefined &&
      sidecar.quoteExpiresAt <= sidecar.negotiatedAt
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["quoteExpiresAt"],
        message: "quoteExpiresAt must be after negotiatedAt",
      });
    }
  });
export type QuoteSidecar = z.infer<typeof quoteSidecarSchema>;
