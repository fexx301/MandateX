import {
  quoteMandatexRebalanceMandateSchema,
  rebalanceTransactionPlanSchema,
} from "@mandatex/agent-supply-verifier";
import { z } from "zod";

export const marketplaceCandidateSelectorSchema = z
  .object({
    chainId: z.literal(56),
    tokenId: z
      .string()
      .regex(/^(?:0|[1-9][0-9]*)$/)
      .refine((value) => BigInt(value) < 1n << 256n),
  })
  .strict();

export type MarketplaceCandidateSelector = Readonly<
  z.infer<typeof marketplaceCandidateSelectorSchema>
>;

export const marketplaceRequestPolicySchema = z
  .object({
    createdAt: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    maxClockSkewSeconds: z.number().int().min(0).max(300),
    maxPreviewAgeSeconds: z.number().int().min(5).max(3_600),
    maxAgentFeeUsdMicros: z
      .string()
      .regex(/^(?:0|[1-9][0-9]*)$/)
      .refine((value) => BigInt(value) < 1n << 256n),
  })
  .strict();

export const marketplaceEvaluationRequestSchema = z
  .object({
    mandate: quoteMandatexRebalanceMandateSchema,
    policy: marketplaceRequestPolicySchema,
    candidate: z
      .object({
        selector: marketplaceCandidateSelectorSchema,
        transactionPlan: rebalanceTransactionPlanSchema,
      })
      .strict(),
  })
  .strict()
  .superRefine((request, context) => {
    if (request.mandate.chain_id !== 56) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["mandate", "chain_id"],
        message: "the marketplace verifier runtime supports BSC chain ID 56 only",
      });
    }
    if (request.policy.createdAt >= request.mandate.expires_at) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["policy", "createdAt"],
        message: "marketplace mandate creation must precede mandate expiry",
      });
    }
    if (request.policy.createdAt >= request.mandate.permissions.expires_at) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["policy", "createdAt"],
        message: "marketplace mandate creation must precede permission expiry",
      });
    }
  });

export type MarketplaceRequestPolicy = Readonly<
  z.infer<typeof marketplaceRequestPolicySchema>
>;

export type MarketplaceEvaluationRequest = Readonly<
  z.infer<typeof marketplaceEvaluationRequestSchema>
>;
