import { createHash } from "node:crypto";

import { z } from "zod";

import {
  addressSchema,
  blockHashSchema,
  isoUtcSchema,
  sha256Schema,
  tokenIdSchema,
} from "../schema.js";
import { rebalanceTransactionPlanSchema } from "../preview/schema.js";
import { quoteMandatexSignedRebalanceTaskSchema } from "../quotes/schema.js";
import {
  ACTIVATION_PHASE_ORDER,
  ACTIVATION_SCHEMA_VERSION,
} from "./deployment.js";

export const ACTIVATION_STATE_SCHEMA =
  "mandatex.erc8183.activation-state.v1" as const;
export const ACTIVATION_REPORT_SCHEMA =
  "mandatex.erc8183.activation-report.v1" as const;
export const ACTIVATION_PREVIEW_SCHEMA =
  "mandatex.erc8183.activation-preview.v1" as const;
export const ACTIVATION_HEAD_SCHEMA =
  "mandatex.erc8183.activation-head.v1" as const;

const canonicalHexSchema = z
  .string()
  .regex(/^0x(?:[0-9a-f]{2})+$/, "expected lowercase byte-aligned hex")
  .max(131_072);
const bytes32Schema = z
  .string()
  .regex(/^0x[0-9a-f]{64}$/, "expected a 32-byte hex value")
  .transform((value) => value.toLowerCase());
const txHashSchema = bytes32Schema;
const uintDecimalSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/, "expected a canonical unsigned decimal integer");

export const activationOperationSchema = z.enum([
  "create_job",
  "register_job",
  "set_budget",
  "fund",
]);
export type ActivationOperation = z.infer<typeof activationOperationSchema>;

export const activationPhaseSchema = z.enum(ACTIVATION_PHASE_ORDER);
export type ActivationPhase = z.infer<typeof activationPhaseSchema>;

export const activationConditionSchema = z.enum([
  "ready",
  "broadcast_unknown",
  "reconcile_required",
  "cleanup_required",
  "aborted",
]);
export type ActivationCondition = z.infer<typeof activationConditionSchema>;

export const activationIntentSchema = z
  .object({
    operation: activationOperationSchema,
    from: addressSchema,
    to: addressSchema,
    valueWei: z.literal("0"),
    data: canonicalHexSchema,
    calldataSha256: sha256Schema,
  })
  .strict()
  .superRefine((intent, context) => {
    const digest = createHash("sha256")
      .update(Buffer.from(intent.data.slice(2), "hex"))
      .digest("hex");
    if (digest !== intent.calldataSha256) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["calldataSha256"],
        message: "calldata hash does not match the captured bytes",
      });
    }
  });
export type ActivationIntent = z.infer<typeof activationIntentSchema>;

export const activationBindingSchema = z
  .object({
    chainId: z.literal(56),
    tokenId: tokenIdSchema,
    client: addressSchema,
    provider: addressSchema,
    commerceProxy: addressSchema,
    commerceImplementation: addressSchema,
    commerceImplementationCodeHash: bytes32Schema,
    routerProxy: addressSchema,
    routerImplementation: addressSchema,
    routerImplementationCodeHash: bytes32Schema,
    policy: addressSchema,
    paymentToken: addressSchema,
    paymentTokenCodeHash: bytes32Schema,
    localReplayOnly: z.literal(true),
    replayKey: sha256Schema,
    negotiationHash: bytes32Schema,
    mandateSha256: sha256Schema,
    signedTaskSha256: sha256Schema,
    transactionPlanSha256: sha256Schema,
    previewSidecarSha256: sha256Schema,
    initialPreviewSha256: sha256Schema,
    previewBlockNumber: uintDecimalSchema,
    previewBlockHash: blockHashSchema,
    negotiatedAt: z.number().int().nonnegative(),
    quoteExpiresAt: z.number().int().positive(),
    jobExpiresAt: z.number().int().positive(),
    price: z.literal("0"),
    currency: addressSchema,
    jobDescription: z.string().min(1).max(16_384),
  })
  .strict();
export type ActivationBinding = z.infer<typeof activationBindingSchema>;

export const activationEventSchema = z.discriminatedUnion("name", [
  z
    .object({
      name: z.literal("JobCreated"),
      jobId: uintDecimalSchema,
      client: addressSchema,
      provider: addressSchema,
      evaluator: addressSchema,
      expiredAt: uintDecimalSchema,
      hook: addressSchema,
    })
    .strict(),
  z
    .object({
      name: z.literal("JobRegistered"),
      jobId: uintDecimalSchema,
      policy: addressSchema,
      client: addressSchema,
    })
    .strict(),
  z
    .object({
      name: z.literal("JobFunded"),
      jobId: uintDecimalSchema,
      client: addressSchema,
      provider: addressSchema,
      amount: uintDecimalSchema,
    })
    .strict(),
]);

export const activationReceiptSchema = z
  .object({
    operation: activationOperationSchema,
    transactionHash: txHashSchema,
    blockNumber: uintDecimalSchema,
    blockHash: blockHashSchema,
    blockTimestamp: z.number().int().positive(),
    status: z.literal("success"),
    from: addressSchema,
    to: addressSchema,
    valueWei: z.literal("0"),
    calldataSha256: sha256Schema,
    events: z.array(activationEventSchema).max(8),
  })
  .strict();
export type ActivationReceipt = z.infer<typeof activationReceiptSchema>;

export const activationSubmissionSchema = z
  .object({
    transactionHash: txHashSchema,
    recordedAt: isoUtcSchema,
  })
  .strict();
export type ActivationSubmission = z.infer<typeof activationSubmissionSchema>;

export const activationReconciliationSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.enum(["pending", "not_found", "reorged"]),
      transactionHash: txHashSchema,
      observedAt: isoUtcSchema,
    })
    .strict(),
  z
    .object({
      kind: z.literal("unconfirmed"),
      transactionHash: txHashSchema,
      observedAt: isoUtcSchema,
      blockNumber: uintDecimalSchema,
      blockHash: blockHashSchema,
      confirmationDepth: z.number().int().nonnegative(),
      requiredConfirmationDepth: z.number().int().positive(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("reverted"),
      transactionHash: txHashSchema,
      observedAt: isoUtcSchema,
      blockNumber: uintDecimalSchema,
      blockHash: blockHashSchema,
      confirmationDepth: z.number().int().nonnegative(),
    })
    .strict(),
]);
export type ActivationReconciliation = z.infer<
  typeof activationReconciliationSchema
>;

export const activationCleanupSchema = z
  .object({
    owner: z.enum(["mandatex_operator", "external_client"]),
    requiredActions: z
      .array(z.enum(["reject", "claimRefund", "markExpired"]))
      .max(3),
    note: z.string().min(1).max(512),
  })
  .strict();

export const activationStateSchema = z
  .object({
    schema: z.literal(ACTIVATION_STATE_SCHEMA),
    version: z.literal(ACTIVATION_SCHEMA_VERSION),
    activationId: z.string().regex(/^[a-f0-9]{64}$/),
    sequence: z.number().int().nonnegative(),
    parentStateSha256: sha256Schema.optional(),
    phase: activationPhaseSchema,
    condition: activationConditionSchema,
    createdAt: isoUtcSchema,
    updatedAt: isoUtcSchema,
    binding: activationBindingSchema,
    signedTask: quoteMandatexSignedRebalanceTaskSchema,
    transactionPlan: rebalanceTransactionPlanSchema,
    initialPreview: z.lazy(() => activationPreviewSchema),
    fundingPreview: z.lazy(() => activationPreviewSchema).optional(),
    jobId: uintDecimalSchema.optional(),
    intent: activationIntentSchema.optional(),
    submission: activationSubmissionSchema.optional(),
    reconciliation: activationReconciliationSchema.optional(),
    receipts: z.array(activationReceiptSchema).max(4),
    cleanup: activationCleanupSchema,
    errorCode: z
      .enum([
        "QUOTE_EXPIRED",
        "CANONICALITY_FAILED",
        "DEPLOYMENT_MISMATCH",
        "TRANSACTION_MISMATCH",
        "RECEIPT_REVERTED",
        "EVENT_MISMATCH",
        "JOB_STATE_MISMATCH",
        "PREVIEW_REQUIRED",
        "UNSUPPORTED_NONZERO_BUDGET",
        "BROADCAST_UNKNOWN",
        "SUBMISSION_MISMATCH",
      ])
      .optional(),
  })
  .strict()
  .superRefine((state, context) => {
    const prepared = state.phase.startsWith("PREPARED_");
    if (Date.parse(state.updatedAt) < Date.parse(state.createdAt)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["updatedAt"],
        message: "activation updates cannot predate creation",
      });
    }
    if (
      state.sequence === 0 &&
      (state.phase !== "PREPARED_CREATE" ||
        state.condition !== "ready" ||
        state.createdAt !== state.updatedAt)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sequence"],
        message: "sequence zero must be the initial prepared-create generation",
      });
    }
    if (prepared && state.intent === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["intent"],
        message: "a prepared activation phase requires one unsigned intent",
      });
    }
    if (!prepared && state.intent !== undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["intent"],
        message: "a confirmed activation phase cannot retain an unsigned intent",
      });
    }
    if (state.submission !== undefined && state.intent === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["submission"],
        message: "a recorded submission must remain bound to its prepared intent",
      });
    }
    if (
      state.reconciliation !== undefined &&
      (state.submission === undefined ||
        state.intent === undefined ||
        state.reconciliation.transactionHash !== state.submission.transactionHash)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reconciliation"],
        message: "reconciliation evidence must bind the recorded submission",
      });
    }
    if (
      state.condition === "broadcast_unknown" &&
      (state.intent === undefined || state.submission !== undefined)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["condition"],
        message: "broadcast_unknown requires an intent without a known transaction hash",
      });
    }
    if (
      state.condition === "reconcile_required" &&
      (state.intent === undefined || state.submission === undefined)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["condition"],
        message: "reconcile_required requires an intent and recorded submission",
      });
    }
    if (
      state.reconciliation?.kind === "reverted" &&
      state.condition !== "aborted" &&
      state.condition !== "cleanup_required"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["condition"],
        message: "a confirmed revert requires an evidence-derived terminal condition",
      });
    }
    if (
      (state.condition === "aborted" || state.condition === "cleanup_required") &&
      state.reconciliation?.kind !== "reverted"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["condition"],
        message: "terminal activation conditions require canonical revert evidence",
      });
    }
    if (
      (state.reconciliation?.kind === "reverted") !==
      (state.errorCode === "RECEIPT_REVERTED")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["errorCode"],
        message: "canonical revert evidence requires its exact stable error code",
      });
    }
    if (
      state.reconciliation !== undefined &&
      state.reconciliation.kind !== "reverted" &&
      state.condition !== "reconcile_required"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["condition"],
        message: "an unresolved observation must remain reconcile_required",
      });
    }
    if (state.condition === "ready" && state.submission !== undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["condition"],
        message: "a recorded submission must be reconciled before readiness",
      });
    }
    if (
      (state.condition === "broadcast_unknown") !==
      (state.errorCode === "BROADCAST_UNKNOWN")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["errorCode"],
        message: "broadcast uncertainty requires its exact stable error code",
      });
    }
    if (state.phase === "PREPARED_FUND" && state.fundingPreview === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["fundingPreview"],
        message: "funding requires a fresh activation preview",
      });
    }
    if (
      state.fundingPreview !== undefined &&
      state.phase !== "PREPARED_FUND" &&
      state.phase !== "FUNDED_CONFIRMED"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["fundingPreview"],
        message: "the funding preview is limited to the funding generations",
      });
    }
    if (
      (state.sequence === 0 && state.parentStateSha256 !== undefined) ||
      (state.sequence > 0 && state.parentStateSha256 === undefined)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["parentStateSha256"],
        message: "activation generations after sequence zero require a parent hash",
      });
    }
  });
export type ActivationState = z.infer<typeof activationStateSchema>;

export const activationPreviewSchema = z
  .object({
    schema: z.literal(ACTIVATION_PREVIEW_SCHEMA),
    observedAt: isoUtcSchema,
    blockNumber: uintDecimalSchema,
    blockHash: blockHashSchema,
    blockTimestamp: z.number().int().positive(),
    quoteExpiresAt: z.number().int().positive(),
    transactionPlanSha256: sha256Schema,
    signedTaskSha256: sha256Schema,
    allGatesPass: z.literal(true),
    validUntil: z.number().int().positive(),
  })
  .strict()
  .superRefine((preview, context) => {
    const observedSeconds = Math.floor(new Date(preview.observedAt).valueOf() / 1_000);
    if (observedSeconds !== preview.blockTimestamp) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["blockTimestamp"],
        message: "preview block timestamp must match observedAt",
      });
    }
    if (preview.validUntil > preview.quoteExpiresAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["validUntil"],
        message: "preview validity cannot outlive the quote",
      });
    }
  });
export type ActivationPreview = z.infer<typeof activationPreviewSchema>;

export const activationDeploymentObservationSchema = z
  .object({
    chainId: z.literal(56),
    headBlockNumber: uintDecimalSchema,
    blockNumber: uintDecimalSchema,
    blockHash: blockHashSchema,
    blockTimestamp: z.number().int().positive(),
    confirmationDepth: z.number().int().nonnegative(),
    commerceImplementation: addressSchema,
    commerceProxyCodeHash: bytes32Schema,
    commerceImplementationCodeHash: bytes32Schema,
    routerImplementation: addressSchema,
    routerProxyCodeHash: bytes32Schema,
    routerImplementationCodeHash: bytes32Schema,
    policyCodeHash: bytes32Schema,
    paymentToken: addressSchema,
    paymentTokenCodeHash: bytes32Schema,
    routerCommerce: addressSchema,
    policyCommerce: addressSchema,
    policyRouter: addressSchema,
    policyWhitelisted: z.boolean(),
    commercePaused: z.boolean(),
    routerPaused: z.boolean(),
    disputeWindowSeconds: uintDecimalSchema,
  })
  .strict();
export type ActivationDeploymentObservation = z.infer<
  typeof activationDeploymentObservationSchema
>;

export const activationJobObservationSchema = z
  .object({
    jobId: uintDecimalSchema,
    client: addressSchema,
    provider: addressSchema,
    evaluator: addressSchema,
    hook: addressSchema,
    descriptionSha256: sha256Schema,
    budget: uintDecimalSchema,
    expiredAt: uintDecimalSchema,
    status: z.enum(["OPEN", "FUNDED"]),
    hasBudget: z.boolean(),
    policy: addressSchema,
  })
  .strict();
export type ActivationJobObservation = z.infer<
  typeof activationJobObservationSchema
>;

export const activationReportSchema = z
  .object({
    schema: z.literal(ACTIVATION_REPORT_SCHEMA),
    activationId: z.string().regex(/^[a-f0-9]{64}$/),
    stateSha256: sha256Schema,
    observedAt: isoUtcSchema,
    phase: activationPhaseSchema,
    condition: activationConditionSchema,
    candidate: z.object({ chainId: z.literal(56), tokenId: tokenIdSchema }).strict(),
    client: addressSchema,
    provider: addressSchema,
    jobId: uintDecimalSchema.optional(),
    operation: activationOperationSchema.optional(),
    transactionHash: txHashSchema.optional(),
    calldataSha256: sha256Schema.optional(),
    blockNumber: uintDecimalSchema.optional(),
    blockHash: blockHashSchema.optional(),
    errorCode: z
      .enum([
        "QUOTE_EXPIRED",
        "CANONICALITY_FAILED",
        "DEPLOYMENT_MISMATCH",
        "TRANSACTION_MISMATCH",
        "RECEIPT_REVERTED",
        "EVENT_MISMATCH",
        "JOB_STATE_MISMATCH",
        "PREVIEW_REQUIRED",
        "UNSUPPORTED_NONZERO_BUDGET",
        "BROADCAST_UNKNOWN",
        "SUBMISSION_MISMATCH",
      ])
      .optional(),
    reconciliationOutcome: z
      .enum(["pending", "not_found", "unconfirmed", "reorged", "reverted"])
      .optional(),
    quoteExpiresAt: z.number().int().positive(),
    cleanup: activationCleanupSchema,
    classification: z.enum([
      "ACTIVATION_PREPARED",
      "ACTIVATION_CONFIRMED",
      "ACTIVATION_FUNDED_NOT_DELIVERED",
      "ACTIVATION_RECONCILE_REQUIRED",
      "ACTIVATION_CLEANUP_REQUIRED",
      "ACTIVATION_ABORTED",
    ]),
  })
  .strict();
export type ActivationReport = z.infer<typeof activationReportSchema>;

export const activationHeadSchema = z
  .object({
    schema: z.literal(ACTIVATION_HEAD_SCHEMA),
    activationId: z.string().regex(/^[a-f0-9]{64}$/),
    sequence: z.number().int().nonnegative(),
    stateSha256: sha256Schema,
    stateFile: z.string().regex(/^state-v1-[a-f0-9]{64}-[0-9]+-[a-f0-9]{64}\.json$/),
    reportSha256: sha256Schema,
    reportFile: z.string().regex(/^report-v1-[a-f0-9]{64}-[0-9]+-[a-f0-9]{64}\.json$/),
    updatedAt: isoUtcSchema,
  })
  .strict();
export type ActivationHead = z.infer<typeof activationHeadSchema>;

export function assertZeroBudgetBinding(binding: ActivationBinding): void {
  if (binding.price !== "0") {
    throw new Error("MandateX activation only supports zero-price quotes");
  }
  if (binding.currency !== binding.paymentToken) {
    throw new Error("zero-price activation currency must equal the payment token");
  }
}
