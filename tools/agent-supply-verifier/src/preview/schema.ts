import { z } from "zod";

import {
  addressSchema,
  blockHashSchema,
  isoUtcSchema,
  sha256Schema,
  tokenIdSchema,
} from "../schema.js";
import {
  quoteMarketplaceEvaluationEvidenceSchema,
  quoteSidecarSchema,
} from "../quotes/schema.js";

export const REBALANCE_TRANSACTION_PLAN_SCHEMA =
  "mandatex.rebalance.transaction-plan.v1" as const;
export const REBALANCE_PREVIEW_SIDECAR_SCHEMA =
  "mandatex.agent-supply.rebalance-preview.v1" as const;
export const MARKETPLACE_PREVIEW_EVALUATION_SCHEMA =
  "mandatex.agent-supply.marketplace-preview-evaluation.v1" as const;
export const MARKETPLACE_PREVIEW_EVIDENCE_SCHEMA =
  "mandatex.agent-supply.marketplace-preview-evidence.v1" as const;

const uint256DecimalSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/, "expected a canonical uint256 decimal")
  .refine((value) => BigInt(value) < 1n << 256n, "integer exceeds uint256");

const canonicalPlanAddressSchema = z
  .string()
  .regex(/^0x[0-9a-f]{40}$/, "expected a canonical lowercase EVM address");

const calldataSchema = z
  .string()
  .regex(/^0x(?:[a-f0-9]{2})+$/, "expected canonical lowercase byte-aligned calldata")
  .max(20_482, "calldata exceeds the 10 KiB safety bound");

export const rebalanceTransactionPlanSchema = z
  .object({
    schema: z.literal(REBALANCE_TRANSACTION_PLAN_SCHEMA),
    chainId: z.literal(56),
    from: canonicalPlanAddressSchema,
    to: canonicalPlanAddressSchema,
    valueWei: uint256DecimalSchema,
    data: calldataSchema,
  })
  .strict();
export type RebalanceTransactionPlan = z.infer<
  typeof rebalanceTransactionPlanSchema
>;

export const previewGateStateSchema = z.enum(["pass", "fail", "unknown"]);

export const rebalancePreviewGatesSchema = z
  .object({
    signedEvidence: previewGateStateSchema,
    freshState: previewGateStateSchema,
    identityOwner: previewGateStateSchema,
    positionAuthority: previewGateStateSchema,
    transactionPolicy: previewGateStateSchema,
    evmSimulation: previewGateStateSchema,
  })
  .strict();
export type RebalancePreviewGates = z.infer<
  typeof rebalancePreviewGatesSchema
>;

export const rebalancePreviewErrorCodeSchema = z.enum([
  "QUOTE_VALIDATION_FAILED",
  "QUOTE_VALIDATION_INCONCLUSIVE",
  "SIGNED_EVIDENCE_INVALID",
  "PREVIEW_STATE_INVALID",
  "PREVIEW_STATE_UNAVAILABLE",
  "IDENTITY_OWNER_MISMATCH",
  "CALLER_NOT_EOA",
  "POSITION_AUTHORITY_REJECTED",
  "TRANSACTION_PLAN_INVALID",
  "TRANSACTION_POLICY_REJECTED",
  "EVM_SIMULATION_REVERTED",
  "EVM_SIMULATION_INVALID",
  "PREVIEW_EXPIRED",
]);
export type RebalancePreviewErrorCode = z.infer<
  typeof rebalancePreviewErrorCodeSchema
>;

const previewDeadlineSchema = z.number().int().positive();

const decodedCallSchema = z.discriminatedUnion("method", [
  z
    .object({
      method: z.literal("decreaseLiquidity"),
      tokenId: tokenIdSchema,
      deadline: previewDeadlineSchema.optional(),
    })
    .strict(),
  z
    .object({
      method: z.literal("collect"),
      tokenId: tokenIdSchema,
      recipient: addressSchema,
    })
    .strict(),
  z
    .object({
      method: z.literal("mint"),
      lowerTick: z.number().int().min(-887_272).max(887_272),
      upperTick: z.number().int().min(-887_272).max(887_272),
      recipient: addressSchema,
      deadline: previewDeadlineSchema.optional(),
    })
    .strict(),
]);

export const marketplaceDecodedRebalancePlanSchema = z
  .object({
    plan: rebalanceTransactionPlanSchema,
    decrease: z
      .object({
        method: z.literal("decreaseLiquidity"),
        tokenId: tokenIdSchema,
        liquidity: uint256DecimalSchema,
        amount0Min: uint256DecimalSchema,
        amount1Min: uint256DecimalSchema,
        deadline: uint256DecimalSchema,
      })
      .strict(),
    collect: z
      .object({
        method: z.literal("collect"),
        tokenId: tokenIdSchema,
        recipient: addressSchema,
        amount0Max: uint256DecimalSchema,
        amount1Max: uint256DecimalSchema,
      })
      .strict(),
    mint: z
      .object({
        method: z.literal("mint"),
        token0: addressSchema,
        token1: addressSchema,
        fee: z.number().int().nonnegative().max(1_000_000),
        tickLower: z.number().int().min(-887_272).max(887_272),
        tickUpper: z.number().int().min(-887_272).max(887_272),
        amount0Desired: uint256DecimalSchema,
        amount1Desired: uint256DecimalSchema,
        amount0Min: uint256DecimalSchema,
        amount1Min: uint256DecimalSchema,
        recipient: addressSchema,
        deadline: uint256DecimalSchema,
      })
      .strict(),
    innerCalldata: z.array(calldataSchema).length(3),
    transactionPlanSha256: sha256Schema,
    calldataSha256: sha256Schema,
    decodedPlanSha256: sha256Schema,
  })
  .strict();
export type MarketplaceDecodedRebalancePlan = z.infer<
  typeof marketplaceDecodedRebalancePlanSchema
>;

const pancakeContractCodeSchema = z
  .object({
    bytes: z.number().int().nonnegative(),
    sha256: sha256Schema,
  })
  .strict();

const pancakeTokenStateSchema = z
  .object({
    address: addressSchema,
    code: pancakeContractCodeSchema,
    decimals: z.number().int().nonnegative().max(255),
    callerBalance: uint256DecimalSchema,
    callerAllowanceToPositionManager: uint256DecimalSchema,
  })
  .strict();

export const pancakeStateSnapshotSchema = z
  .object({
    chainId: z.literal(56),
    pin: z
      .object({
        mode: z.enum(["exact", "fresh"]),
        headBlockNumber: tokenIdSchema.nullable(),
        observedBlockNumber: tokenIdSchema,
        observedBlockHash: blockHashSchema,
        observedAt: tokenIdSchema,
        confirmationDepth: z.union([z.literal(2), z.null()]),
        requireCanonical: z.literal(true),
        attempts: z.number().int().positive(),
      })
      .strict(),
    identity: z
      .object({
        registryAddress: addressSchema,
        registryCode: pancakeContractCodeSchema,
        agentTokenId: tokenIdSchema,
        expectedProvider: addressSchema,
        currentOwner: addressSchema,
        providerCode: pancakeContractCodeSchema,
      })
      .strict(),
    deployments: z
      .object({
        factory: z
          .object({ address: addressSchema, code: pancakeContractCodeSchema })
          .strict(),
        deployer: z
          .object({ address: addressSchema, code: pancakeContractCodeSchema })
          .strict(),
        positionManager: z
          .object({
            address: addressSchema,
            code: pancakeContractCodeSchema,
            factory: addressSchema,
            deployer: addressSchema,
          })
          .strict(),
      })
      .strict(),
    pool: z
      .object({
        address: addressSchema,
        code: pancakeContractCodeSchema,
        factory: addressSchema,
        token0: addressSchema,
        token1: addressSchema,
        fee: z.number().int().nonnegative().max(1_000_000),
        tickSpacing: z.number().int().positive().max(1_774_544),
        sqrtPriceX96: uint256DecimalSchema,
        currentTick: z.number().int().min(-887_272).max(887_272),
        observationIndex: z.number().int().nonnegative().max(65_535),
        observationCardinality: z.number().int().nonnegative().max(65_535),
        observationCardinalityNext: z.number().int().nonnegative().max(65_535),
        feeProtocol: z.number().int().nonnegative().max(255),
        unlocked: z.boolean(),
        liquidity: uint256DecimalSchema,
      })
      .strict(),
    position: z
      .object({
        tokenId: tokenIdSchema,
        owner: addressSchema,
        approved: addressSchema,
        caller: addressSchema,
        callerApprovedForAll: z.boolean(),
        callerCanManage: z.boolean(),
        nonce: uint256DecimalSchema,
        operator: addressSchema,
        token0: addressSchema,
        token1: addressSchema,
        fee: z.number().int().nonnegative().max(1_000_000),
        tickLower: z.number().int().min(-887_272).max(887_272),
        tickUpper: z.number().int().min(-887_272).max(887_272),
        liquidity: uint256DecimalSchema,
        feeGrowthInside0LastX128: uint256DecimalSchema,
        feeGrowthInside1LastX128: uint256DecimalSchema,
        tokensOwed0: uint256DecimalSchema,
        tokensOwed1: uint256DecimalSchema,
      })
      .strict(),
    tokens: z
      .object({
        token0: pancakeTokenStateSchema,
        token1: pancakeTokenStateSchema,
      })
      .strict(),
  })
  .strict()
  .superRefine((snapshot, context) => {
    if (
      (snapshot.pin.mode === "exact" &&
        (snapshot.pin.headBlockNumber !== null ||
          snapshot.pin.confirmationDepth !== null)) ||
      (snapshot.pin.mode === "fresh" &&
        (snapshot.pin.headBlockNumber === null ||
          snapshot.pin.confirmationDepth !== 2))
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["pin"],
        message: "snapshot pin metadata does not match its mode",
      });
    }
  });

const marketplaceSnapshotCommitmentSchema = z
  .object({
    snapshotSha256: sha256Schema,
    snapshot: pancakeStateSnapshotSchema,
  })
  .strict();

const marketplacePreviewPolicySchema = z
  .object({
    authority: z.enum(["owner", "token_approval", "operator_approval"]),
    deadline: previewDeadlineSchema,
    calls: z.array(decodedCallSchema).length(3),
  })
  .strict();

export const marketplacePreviewEvaluationEvidenceSchema = z
  .object({
    schema: z.literal(MARKETPLACE_PREVIEW_EVIDENCE_SCHEMA),
    quoteEvidenceSha256: sha256Schema,
    mandateSha256: sha256Schema,
    transactionPlanSha256: sha256Schema,
    calldataSha256: sha256Schema,
    decodedPlanSha256: sha256Schema,
    decodedPlan: marketplaceDecodedRebalancePlanSchema,
    signedSnapshot: marketplaceSnapshotCommitmentSchema,
    freshSnapshot: marketplaceSnapshotCommitmentSchema,
    simulationRequestSha256: sha256Schema,
    simulationResponseSha256: sha256Schema,
    simulationResultSha256: sha256Schema,
    policy: marketplacePreviewPolicySchema,
    gates: z
      .object({
        signedEvidence: z.literal("pass"),
        freshState: z.literal("pass"),
        identityOwner: z.literal("pass"),
        positionAuthority: z.literal("pass"),
        transactionPolicy: z.literal("pass"),
        evmSimulation: z.literal("pass"),
      })
      .strict(),
  })
  .strict()
  .superRefine((evidence, context) => {
    if (
      evidence.signedSnapshot.snapshot.pin.mode !== "exact" ||
      evidence.freshSnapshot.snapshot.pin.mode !== "fresh" ||
      evidence.transactionPlanSha256 !==
        evidence.decodedPlan.transactionPlanSha256 ||
      evidence.calldataSha256 !== evidence.decodedPlan.calldataSha256 ||
      evidence.decodedPlanSha256 !== evidence.decodedPlan.decodedPlanSha256
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "marketplace preview evidence is internally inconsistent",
      });
    }
  });
export type MarketplacePreviewEvaluationEvidence = z.infer<
  typeof marketplacePreviewEvaluationEvidenceSchema
>;

export const marketplacePreviewEvaluationArtifactSchema = z
  .object({
    schema: z.literal(MARKETPLACE_PREVIEW_EVALUATION_SCHEMA),
    scope: z.literal("evaluation_only"),
    actionability: z.literal("unreserved"),
    outcome: z.literal("verified_unreserved"),
    observedAt: isoUtcSchema,
    replayStatus: z.literal("not_attempted"),
    candidate: z
      .object({ chainId: z.literal(56), tokenId: tokenIdSchema })
      .strict(),
    prospectiveReplayKey: sha256Schema,
    commitments: z
      .object({
        quoteEvidenceSha256: sha256Schema,
        previewEvidenceSha256: sha256Schema,
      })
      .strict(),
    evidence: z
      .object({
        quote: quoteMarketplaceEvaluationEvidenceSchema,
        preview: marketplacePreviewEvaluationEvidenceSchema,
      })
      .strict(),
  })
  .strict()
  .superRefine((artifact, context) => {
    if (
      artifact.observedAt !== artifact.evidence.quote.observedAt ||
      artifact.candidate.chainId !== artifact.evidence.quote.candidate.chainId ||
      artifact.candidate.tokenId !== artifact.evidence.quote.candidate.tokenId ||
      artifact.commitments.quoteEvidenceSha256 !==
        artifact.evidence.preview.quoteEvidenceSha256
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "marketplace evaluation artifact is internally inconsistent",
      });
    }
  });
export type MarketplacePreviewEvaluationArtifact = z.infer<
  typeof marketplacePreviewEvaluationArtifactSchema
>;

const previewSnapshotSchema = z
  .object({
    chainId: z.literal(56),
    headBlockNumber: tokenIdSchema,
    blockNumber: tokenIdSchema,
    blockHash: blockHashSchema,
    blockTimestamp: z.number().int().nonnegative(),
    confirmationDepth: z.literal(2),
    positionOwner: addressSchema,
    callerAuthority: z.enum(["owner", "token_approval", "operator_approval"]),
    currentTick: z.number().int().min(-887_272).max(887_272),
    positionLiquidity: tokenIdSchema,
  })
  .strict();

export const rebalancePreviewSidecarSchema = z
  .object({
    schema: z.literal(REBALANCE_PREVIEW_SIDECAR_SCHEMA),
    observedAt: isoUtcSchema,
    outcome: z.enum([
      "preview_simulation_passed",
      "refused",
      "invalid",
      "inconclusive",
    ]),
    classification: z.enum([
      "PREVIEW_SIMULATION_PASSED",
      "EXCLUDED",
      "INCONCLUSIVE",
    ]),
    operatorSuppliedPlan: z.literal(true),
    simulationOnly: z.literal(true),
    candidate: z
      .object({ chainId: z.literal(56), tokenId: tokenIdSchema })
      .strict(),
    quote: quoteSidecarSchema,
    mandateSha256: sha256Schema,
    transactionPlanSha256: sha256Schema,
    calldataSha256: sha256Schema,
    decodedPlanSha256: sha256Schema.optional(),
    simulationRequestSha256: sha256Schema.optional(),
    simulationResponseSha256: sha256Schema.optional(),
    simulationResultSha256: sha256Schema.optional(),
    snapshot: previewSnapshotSchema.optional(),
    calls: z.array(decodedCallSchema).max(3),
    gates: rebalancePreviewGatesSchema,
    errorCode: rebalancePreviewErrorCodeSchema.optional(),
  })
  .strict()
  .superRefine((sidecar, context) => {
    if (sidecar.outcome === "preview_simulation_passed") {
      if (sidecar.classification !== "PREVIEW_SIMULATION_PASSED") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["classification"],
          message: "a passing preview must use PREVIEW_SIMULATION_PASSED",
        });
      }
      if (sidecar.quote.outcome !== "valid") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["quote", "outcome"],
          message: "a passing preview requires a valid replay-claimed quote",
        });
      }
      if (
        sidecar.snapshot === undefined ||
        sidecar.decodedPlanSha256 === undefined ||
        sidecar.simulationRequestSha256 === undefined ||
        sidecar.simulationResponseSha256 === undefined ||
        sidecar.simulationResultSha256 === undefined ||
        sidecar.calls.length !== 3 ||
        Object.values(sidecar.gates).some((state) => state !== "pass")
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "a passing preview requires complete passing evidence",
        });
      }
      const [decrease, collect, mint] = sidecar.calls;
      if (
        decrease?.method !== "decreaseLiquidity" ||
        collect?.method !== "collect" ||
        mint?.method !== "mint" ||
        decrease.deadline === undefined ||
        mint.deadline === undefined ||
        decrease.deadline !== mint.deadline ||
        decrease.tokenId !== collect.tokenId ||
        collect.recipient !== sidecar.quote.validatedProvider ||
        mint.recipient !== sidecar.quote.validatedProvider ||
        mint.lowerTick >= mint.upperTick ||
        BigInt(decrease.deadline) * 1_000n <
          BigInt(new Date(sidecar.observedAt).valueOf()) + 30_000n
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["calls"],
          message: "a passing preview requires exact current call summaries",
        });
      }
      if (sidecar.errorCode !== undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["errorCode"],
          message: "a passing preview cannot contain an error code",
        });
      }
    } else if (sidecar.outcome === "inconclusive") {
      if (
        sidecar.classification !== "INCONCLUSIVE" ||
        sidecar.errorCode === undefined
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "an inconclusive preview requires its classification and error",
        });
      }
    } else {
      if (sidecar.classification !== "EXCLUDED") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["classification"],
          message: "a refused or invalid preview must be excluded",
        });
      }
      if (sidecar.outcome === "invalid" && sidecar.errorCode === undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["errorCode"],
          message: "an invalid preview requires an error code",
        });
      }
    }

    if (
      (sidecar.errorCode === "EVM_SIMULATION_REVERTED" ||
        sidecar.errorCode === "EVM_SIMULATION_INVALID") &&
      sidecar.gates.evmSimulation !== "fail"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["gates", "evmSimulation"],
        message: "a definitive simulation failure must fail its gate",
      });
    }
    if (
      sidecar.errorCode === "PREVIEW_EXPIRED" &&
      (sidecar.outcome !== "invalid" ||
        sidecar.gates.transactionPolicy !== "fail" ||
        sidecar.gates.evmSimulation !== "pass")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["gates"],
        message: "an expired preview must fail transaction policy after simulation",
      });
    }
  });
export type RebalancePreviewSidecar = z.infer<
  typeof rebalancePreviewSidecarSchema
>;
