import {
  validateMarketplaceCategoryAttestationTrust,
  verifyMarketplaceCategoryAttestation,
  type MarketplaceCategoryAttestationTrust,
  type MarketplaceCategoryAttestationWire,
  type MarketplaceCategoryEvaluationRequest,
  type ValidatedMarketplaceCategoryAttestationTrust,
} from "./category-attestation.js";
import {
  canonicalIdentifierSchema,
  sha256Schema,
  unixSecondsSchema,
} from "./primitives.js";
import { deepFreeze, type DeepReadonly } from "./immutable.js";

import { z } from "zod";

export const MARKETPLACE_CATEGORY_CONDITION_RECEIPT_SCHEMA =
  "mandatex.marketplace.category-condition-receipt.v1" as const;

const categoryConditionReceiptSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_CONDITION_RECEIPT_SCHEMA),
    status: z.literal("category_condition_satisfied"),
    scope: z.literal("evaluation_only"),
    activationAuthorization: z.literal("none"),
    reservation: z.literal("none"),
    evidenceMode: z.literal("verifier_commitment_only"),
    replayPolicy: z.literal("reusable_until_expiry"),
    replayScope: z.literal("request_id"),
    issuedAt: unixSecondsSchema,
    expiresAt: unixSecondsSchema,
    validUntil: unixSecondsSchema,
    requestId: canonicalIdentifierSchema,
    mandateId: canonicalIdentifierSchema,
    category: z.enum(["grid", "yield", "health"]),
    adapterId: canonicalIdentifierSchema,
    evidenceSchema: canonicalIdentifierSchema,
    protocol: canonicalIdentifierSchema,
    candidate: z
      .object({
        chainId: z.literal(56),
        tokenId: z.string().regex(/^(?:0|[1-9][0-9]*)$/),
      })
      .strict(),
    deploymentSha256: sha256Schema,
    verifierPolicySha256: sha256Schema,
    artifactSha256: sha256Schema,
    evidenceSha256: sha256Schema,
    observedAt: unixSecondsSchema,
    observedBlock: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    observedBlockHash: z
      .string()
      .regex(/^0x[a-f0-9]{64}$/),
    evaluatedAt: unixSecondsSchema,
    attestationSha256: sha256Schema,
  })
  .strict();

export type MarketplaceCategoryConditionReceipt = DeepReadonly<
  z.infer<typeof categoryConditionReceiptSchema>
>;

export interface MarketplaceCategoryConditionEvaluatorOptions {
  readonly attestationTrust: MarketplaceCategoryAttestationTrust;
  readonly maxClockSkewSeconds: number;
  readonly clock: () => number;
}

export interface MarketplaceCategoryConditionEvaluator {
  readonly evaluateCategoryCondition: (
    input: MarketplaceCategoryConditionEvaluationInput,
  ) => MarketplaceCategoryConditionReceipt;
}

export interface MarketplaceCategoryConditionEvaluationInput {
  readonly request: MarketplaceCategoryEvaluationRequest;
  readonly attestation: MarketplaceCategoryAttestationWire;
}

export function createMarketplaceCategoryConditionEvaluator(
  options: MarketplaceCategoryConditionEvaluatorOptions,
): MarketplaceCategoryConditionEvaluator {
  if (options === null || typeof options !== "object") {
    throw new TypeError("category condition evaluator options must be an object");
  }
  const trust: ValidatedMarketplaceCategoryAttestationTrust =
    validateMarketplaceCategoryAttestationTrust(options.attestationTrust);
  if (
    !Number.isSafeInteger(options.maxClockSkewSeconds) ||
    options.maxClockSkewSeconds < 0 ||
    options.maxClockSkewSeconds > 300
  ) {
    throw new TypeError("category condition evaluator clock skew is invalid");
  }
  if (typeof options.clock !== "function") {
    throw new TypeError("category condition evaluator clock must be a function");
  }
  const maxClockSkewSeconds = options.maxClockSkewSeconds;
  const clock = options.clock;

  return Object.freeze({
    evaluateCategoryCondition(
      input: MarketplaceCategoryConditionEvaluationInput,
    ) {
      const evaluatedAt = readClock(clock);
      const verified = verifyMarketplaceCategoryAttestation({
        wire: input.attestation,
        request: input.request,
        evaluatedAt,
        maxClockSkewSeconds,
        trust,
      });
      const payload = verified.envelope.payload;
      return deepFreeze(
        categoryConditionReceiptSchema.parse({
          schema: MARKETPLACE_CATEGORY_CONDITION_RECEIPT_SCHEMA,
          status: "category_condition_satisfied",
          scope: verified.envelope.scope,
          activationAuthorization: verified.envelope.activationAuthorization,
          reservation: verified.envelope.reservation,
          replayPolicy: verified.envelope.replayPolicy,
          replayScope: verified.envelope.replayScope,
          issuedAt: verified.envelope.issuedAt,
          expiresAt: verified.envelope.expiresAt,
          validUntil: verified.validUntil,
          evidenceMode: verified.envelope.evidenceMode,
          requestId: payload.requestId,
          mandateId: payload.mandateId,
          category: payload.category,
          adapterId: payload.adapterId,
          evidenceSchema: payload.evidenceSchema,
          protocol: payload.protocol,
          candidate: payload.candidate,
          deploymentSha256: payload.deploymentSha256,
          verifierPolicySha256: verified.envelope.verifierPolicySha256,
          artifactSha256: payload.artifactSha256,
          evidenceSha256: payload.evidenceSha256,
          observedAt: payload.observedAt,
          observedBlock: payload.observedBlock,
          observedBlockHash: payload.observedBlockHash,
          evaluatedAt,
          attestationSha256: verified.attestationSha256,
        }),
      );
    },
  });
}

function readClock(clock: () => number): number {
  let value: number;
  try {
    value = clock();
  } catch (cause) {
    throw new TypeError("category condition evaluator clock failed", {
      cause,
    });
  }
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError("category condition evaluator clock returned an invalid time");
  }
  return value;
}

/** Internal schema export for contract tests without making it a signer API. */
export const marketplaceCategoryConditionReceiptSchema =
  categoryConditionReceiptSchema;
