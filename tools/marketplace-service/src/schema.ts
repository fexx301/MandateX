import {
  quoteMandatexRebalanceMandateSchema,
  rebalanceTransactionPlanSchema,
  type QuoteMandatexRebalanceMandate,
  type RebalanceTransactionPlan,
} from "@mandatex/agent-supply-verifier";
import { z } from "zod";

export const ACTIONABLE_QUOTE_REQUEST_ACKNOWLEDGEMENT =
  "I_ACKNOWLEDGE_ACTIONABLE_QUOTE_REQUESTS" as const;
export const OPERATOR_SIMULATION_ACKNOWLEDGEMENT =
  "I_ACKNOWLEDGE_OPERATOR_SUPPLIED_SIMULATIONS_ONLY" as const;

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
    candidates: z
      .array(
        z
          .object({
            selector: marketplaceCandidateSelectorSchema,
            transactionPlan: rebalanceTransactionPlanSchema,
          })
          .strict(),
      )
      .min(1)
      .max(8),
    acknowledgements: z
      .object({
        actionableQuoteRequests: z.literal(
          ACTIONABLE_QUOTE_REQUEST_ACKNOWLEDGEMENT,
        ),
        operatorSuppliedSimulations: z.literal(
          OPERATOR_SIMULATION_ACKNOWLEDGEMENT,
        ),
      })
      .strict(),
  })
  .strict();

export type MarketplaceRequestPolicy = Readonly<
  z.infer<typeof marketplaceRequestPolicySchema>
>;

export type MarketplaceCandidateRequest = Readonly<{
  selector: MarketplaceCandidateSelector;
  transactionPlan: RebalanceTransactionPlan;
}>;

export type MarketplaceEvaluationRequest = Readonly<{
  mandate: QuoteMandatexRebalanceMandate;
  policy: MarketplaceRequestPolicy;
  candidates: readonly MarketplaceCandidateRequest[];
  acknowledgements: Readonly<{
    actionableQuoteRequests: typeof ACTIONABLE_QUOTE_REQUEST_ACKNOWLEDGEMENT;
    operatorSuppliedSimulations: typeof OPERATOR_SIMULATION_ACKNOWLEDGEMENT;
  }>;
}>;
