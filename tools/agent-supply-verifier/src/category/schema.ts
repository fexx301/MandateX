import {
  GRID_ADAPTER_ID,
  GRID_EVIDENCE_SCHEMA,
  HEALTH_ADAPTER_ID,
  HEALTH_EVIDENCE_SCHEMA,
  RATIO_SCALE,
  SELECTOR_BORROW_BALANCE_STORED,
  SELECTOR_GET_ACCOUNT_LIQUIDITY,
  SELECTOR_GET_ASSETS_IN,
  SELECTOR_GET_USER_ACCOUNT_DATA,
  SELECTOR_SLOT0,
  SELECTOR_TOTAL_ASSETS,
  SELECTOR_TOTAL_SUPPLY,
  UINT256_MAX,
  V3_MAX_SQRT_RATIO,
  V3_MAX_TICK,
  V3_MIN_SQRT_RATIO,
  V3_MIN_TICK,
  VENUS_HEALTH_ADAPTER_ID,
  VENUS_HEALTH_EVIDENCE_SCHEMA,
  YIELD_ADAPTER_ID,
  YIELD_EVIDENCE_SCHEMA,
  adapterFailCodeSchema,
  adapterUnknownCodeSchema,
  addressCalldata,
  blockAnchorSchema,
  categoryEvidenceDocumentSchema,
  sha256HexSchema,
  unixSecondsSchema,
} from "@mandatex/category-adapters";
import { z } from "zod";

import { canonicalQuoteJson, computeQuoteSha256 } from "../quotes/protocol.js";
import { CATEGORY_ADAPTER_VALIDATION_PROFILES } from "./policy.js";

export const CATEGORY_EXECUTION_ARTIFACT_SCHEMA =
  "mandatex.agent-supply.category-execution-artifact.v1" as const;
export const CATEGORY_EXECUTION_RESULT_SCHEMA =
  "mandatex.agent-supply.category-execution-result.v1" as const;
export const CATEGORY_VERIFIER_POLICY_PROFILE =
  "mandatex.marketplace.verifier-policy.v2" as const;

export const categoryExecutionAdapterSchema = z.discriminatedUnion(
  "adapterId",
  [
    z
      .object({
        adapterId: z.literal(GRID_ADAPTER_ID),
        category: z.literal("grid"),
        evidenceSchema: z.literal(GRID_EVIDENCE_SCHEMA),
        protocol: z.literal("pancakeswap-v3"),
        validationProfile: z.literal(
          CATEGORY_ADAPTER_VALIDATION_PROFILES.grid,
        ),
      })
      .strict(),
    z
      .object({
        adapterId: z.literal(YIELD_ADAPTER_ID),
        category: z.literal("yield"),
        evidenceSchema: z.literal(YIELD_EVIDENCE_SCHEMA),
        protocol: z.literal("erc4626"),
        validationProfile: z.literal(
          CATEGORY_ADAPTER_VALIDATION_PROFILES.yield,
        ),
      })
      .strict(),
    z
      .object({
        adapterId: z.literal(HEALTH_ADAPTER_ID),
        category: z.literal("health"),
        evidenceSchema: z.literal(HEALTH_EVIDENCE_SCHEMA),
        protocol: z.literal("aave-v3"),
        validationProfile: z.literal(
          CATEGORY_ADAPTER_VALIDATION_PROFILES.aaveHealth,
        ),
      })
      .strict(),
    z
      .object({
        adapterId: z.literal(VENUS_HEALTH_ADAPTER_ID),
        category: z.literal("health"),
        evidenceSchema: z.literal(VENUS_HEALTH_EVIDENCE_SCHEMA),
        protocol: z.literal("venus"),
        validationProfile: z.literal(
          CATEGORY_ADAPTER_VALIDATION_PROFILES.venusHealth,
        ),
      })
      .strict(),
  ],
);

export const categoryReadAttemptSchema = z
  .object({
    label: z.string().min(1).max(64),
    to: z.string().regex(/^0x[0-9a-f]{40}$/),
    data: z.string().regex(/^0x(?:[0-9a-f]{2})+$/),
    requestSha256: sha256HexSchema,
    responseSha256: sha256HexSchema.optional(),
    outcome: z.enum(["success", "unavailable", "invalid_response"]),
  })
  .strict();
export type CategoryReadAttempt = Readonly<
  z.infer<typeof categoryReadAttemptSchema>
>;

export const categoryExecutionResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("pass"),
      evidenceSha256: sha256HexSchema,
      evidence: categoryEvidenceDocumentSchema,
    })
    .strict(),
  z
    .object({
      status: z.literal("fail"),
      code: adapterFailCodeSchema,
      message: z.string().min(1).max(1_000),
    })
    .strict(),
  z
    .object({
      status: z.literal("unknown"),
      code: adapterUnknownCodeSchema,
      message: z.string().min(1).max(1_000),
    })
    .strict(),
]);

export const categoryExecutionArtifactSchema = z
  .object({
    schema: z.literal(CATEGORY_EXECUTION_ARTIFACT_SCHEMA),
    chainId: z.literal(56),
    confirmationDepth: z.literal(2),
    deploymentSha256: sha256HexSchema,
    verifierPolicyProfile: z.literal(CATEGORY_VERIFIER_POLICY_PROFILE),
    verifierPolicySha256: sha256HexSchema,
    evaluatedAt: unixSecondsSchema,
    adapter: categoryExecutionAdapterSchema,
    anchor: blockAnchorSchema,
    reads: z.array(categoryReadAttemptSchema).min(1).max(4),
    result: categoryExecutionResultSchema,
  })
  .strict()
  .superRefine((artifact, context) => {
    const expectedReads = EXPECTED_READS_BY_ADAPTER[artifact.adapter.adapterId];
    if (artifact.reads.length !== expectedReads) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["reads"],
        message: `adapter requires exactly ${expectedReads} reads`,
      });
    }

    for (const [index, read] of artifact.reads.entries()) {
      if (read.outcome === "success" && read.responseSha256 === undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["reads", index, "responseSha256"],
          message: "successful reads require a response digest",
        });
      }
    }

    if (artifact.result.status !== "unknown") {
      for (const [index, read] of artifact.reads.entries()) {
        if (read.outcome !== "success" || read.responseSha256 === undefined) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["reads", index, "outcome"],
            message: "measured pass/fail results require successful reads",
          });
        }
      }
    }

    if (artifact.result.status === "fail") {
      if (
        !includesCode(
          FAIL_CODES_BY_ADAPTER[artifact.adapter.adapterId],
          artifact.result.code,
        )
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["result", "code"],
          message: "fail code does not belong to the declared adapter",
        });
      }
      return;
    }

    if (artifact.result.status === "unknown") {
      if (
        !includesCode(
          UNKNOWN_CODES_BY_ADAPTER[artifact.adapter.adapterId],
          artifact.result.code,
        )
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["result", "code"],
          message: "unknown code does not belong to the declared adapter",
        });
      }
      const allReadsSucceeded = artifact.reads.every(
        (read) =>
          read.outcome === "success" && read.responseSha256 !== undefined,
      );
      if (
        artifact.result.code === "READ_UNAVAILABLE" &&
        allReadsSucceeded
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["result", "code"],
          message: "READ_UNAVAILABLE requires at least one unsuccessful read",
        });
      } else if (
        artifact.result.code !== "READ_UNAVAILABLE" &&
        !allReadsSucceeded
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["reads"],
          message: "measured unknown results require successful reads",
        });
      }
      return;
    }

    const evidence = artifact.result.evidence;
    if (
      artifact.result.evidenceSha256 !==
      computeQuoteSha256(canonicalQuoteJson(evidence))
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["result", "evidenceSha256"],
        message: "pass evidence hash does not match the evidence document",
      });
    }
    if (
      evidence.adapterId !== artifact.adapter.adapterId ||
      evidence.category !== artifact.adapter.category ||
      evidence.protocol !== artifact.adapter.protocol ||
      evidence.schema !== artifact.adapter.evidenceSchema ||
      evidence.observedAt !== artifact.anchor.timestamp ||
      evidence.observedBlock !== artifact.anchor.number ||
      evidence.observedBlockHash !== artifact.anchor.hash ||
      evidence.reads.length !== artifact.reads.length
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["result", "evidence"],
        message: "pass evidence does not match the artifact provenance",
      });
      return;
    }
    for (const [index, observation] of evidence.reads.entries()) {
      const attempt = artifact.reads[index];
      if (
        attempt === undefined ||
        attempt.outcome !== "success" ||
        observation.label !== attempt.label ||
        observation.to !== attempt.to ||
        observation.requestSha256 !== attempt.requestSha256 ||
        observation.responseSha256 !== attempt.responseSha256
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["result", "evidence", "reads", index],
          message: "pass evidence read does not match the runtime attempt",
        });
      }
    }
    validatePassSemantics(
      {
        adapter: artifact.adapter,
        reads: artifact.reads,
        result: artifact.result,
      },
      context,
    );
  });

export type CategoryExecutionArtifact = Readonly<
  z.infer<typeof categoryExecutionArtifactSchema>
>;

export type CategoryExecutionPassArtifact = Readonly<
  Omit<CategoryExecutionArtifact, "result"> & {
    result: Extract<CategoryExecutionArtifact["result"], { status: "pass" }>;
  }
>;

export type TrustedCategoryExecution = Readonly<{
  schema: typeof CATEGORY_EXECUTION_RESULT_SCHEMA;
  outcome: "executed";
  artifactSha256: string;
  artifact: CategoryExecutionArtifact;
}>;

export type TrustedCategoryExecutionSuccess = Readonly<
  Omit<TrustedCategoryExecution, "artifact"> & {
    artifact: CategoryExecutionPassArtifact;
  }
>;

export type CategoryExecutionInconclusiveCode =
  | "CATEGORY_ADAPTER_NOT_CONFIGURED"
  | "CATEGORY_ADAPTER_SELECTION_REQUIRED"
  | "CATEGORY_BLOCK_PIN_UNAVAILABLE"
  | "CATEGORY_BLOCK_NONCANONICAL"
  | "CATEGORY_ADAPTER_EXECUTION_INVALID";

export type CategoryExecutionInconclusive = Readonly<{
  schema: typeof CATEGORY_EXECUTION_RESULT_SCHEMA;
  outcome: "inconclusive";
  category: "grid" | "yield" | "health";
  code: CategoryExecutionInconclusiveCode;
  message: string;
}>;

export type TrustedCategoryExecutionResult =
  | TrustedCategoryExecution
  | CategoryExecutionInconclusive;

const EXPECTED_READS_BY_ADAPTER = Object.freeze({
  [GRID_ADAPTER_ID]: 1,
  [YIELD_ADAPTER_ID]: 2,
  [HEALTH_ADAPTER_ID]: 1,
  [VENUS_HEALTH_ADAPTER_ID]: 3,
} as const);

const FAIL_CODES_BY_ADAPTER = Object.freeze({
  [GRID_ADAPTER_ID]: ["GRID_SPOT_OUTSIDE_BAND"],
  [YIELD_ADAPTER_ID]: ["YIELD_SHARE_PRICE_BELOW_FLOOR"],
  [HEALTH_ADAPTER_ID]: ["HEALTH_FACTOR_BELOW_FLOOR"],
  [VENUS_HEALTH_ADAPTER_ID]: [
    "VENUS_ACCOUNT_SHORTFALL",
    "VENUS_LIQUIDITY_BELOW_FLOOR",
  ],
} as const);

const READ_UNKNOWN_CODES = ["READ_UNAVAILABLE", "READ_RETURNDATA_MALFORMED"] as const;

const UNKNOWN_CODES_BY_ADAPTER = Object.freeze({
  [GRID_ADAPTER_ID]: [
    ...READ_UNKNOWN_CODES,
    "GRID_TICK_UNINTERPRETABLE",
    "GRID_SQRT_PRICE_IMPLAUSIBLE",
  ],
  [YIELD_ADAPTER_ID]: [
    ...READ_UNKNOWN_CODES,
    "YIELD_SHARE_PRICE_UNDEFINED",
  ],
  [HEALTH_ADAPTER_ID]: [
    ...READ_UNKNOWN_CODES,
    "HEALTH_NO_DEBT_POSITION",
  ],
  [VENUS_HEALTH_ADAPTER_ID]: [
    ...READ_UNKNOWN_CODES,
    "VENUS_LIQUIDITY_COMPUTATION_FAILED",
    "VENUS_NO_POSITION",
    "VENUS_NO_DEBT_POSITION",
    "VENUS_LIQUIDITY_INCONSISTENT",
  ],
} as const);

function includesCode(values: readonly string[], code: string): boolean {
  return values.includes(code);
}

type PassArtifactForValidation = Readonly<{
  adapter: z.infer<typeof categoryExecutionAdapterSchema>;
  reads: readonly z.infer<typeof categoryReadAttemptSchema>[];
  result: Extract<
    z.infer<typeof categoryExecutionResultSchema>,
    { status: "pass" }
  >;
}>;

function validatePassSemantics(
  artifact: PassArtifactForValidation,
  context: z.RefinementCtx,
): void {
  const evidence = artifact.result.evidence;
  switch (evidence.schema) {
    case GRID_EVIDENCE_SCHEMA: {
      requireExactRead(
        artifact,
        context,
        0,
        "slot0",
        evidence.subject.poolAddress,
        SELECTOR_SLOT0,
      );
      const sqrtPriceX96 = BigInt(evidence.metric.sqrtPriceX96);
      if (
        evidence.metric.spotTick < V3_MIN_TICK ||
        evidence.metric.spotTick > V3_MAX_TICK ||
        sqrtPriceX96 < V3_MIN_SQRT_RATIO ||
        sqrtPriceX96 > V3_MAX_SQRT_RATIO ||
        evidence.metric.spotTick < evidence.policy.lowerTick ||
        evidence.metric.spotTick > evidence.policy.upperTick
      ) {
        addPassSemanticIssue(context, "grid evidence does not satisfy the grid pass rule");
      }
      return;
    }
    case YIELD_EVIDENCE_SCHEMA: {
      requireExactRead(
        artifact,
        context,
        0,
        "totalAssets",
        evidence.subject.vaultAddress,
        SELECTOR_TOTAL_ASSETS,
      );
      requireExactRead(
        artifact,
        context,
        1,
        "totalSupply",
        evidence.subject.vaultAddress,
        SELECTOR_TOTAL_SUPPLY,
      );
      const totalAssets = BigInt(evidence.metric.totalAssets);
      const totalSupply = BigInt(evidence.metric.totalSupply);
      const sharePriceScaled = BigInt(evidence.metric.sharePriceScaled);
      const floor = BigInt(evidence.policy.minSharePriceScaled);
      if (
        totalSupply === 0n ||
        sharePriceScaled !== (totalAssets * RATIO_SCALE) / totalSupply ||
        sharePriceScaled < floor
      ) {
        addPassSemanticIssue(context, "yield evidence does not satisfy the yield pass rule");
      }
      return;
    }
    case HEALTH_EVIDENCE_SCHEMA: {
      requireExactRead(
        artifact,
        context,
        0,
        "getUserAccountData",
        evidence.subject.poolAddress,
        addressCalldata(
          SELECTOR_GET_USER_ACCOUNT_DATA,
          evidence.subject.accountAddress,
        ),
      );
      const healthFactor = BigInt(evidence.metric.healthFactorScaled);
      if (
        BigInt(evidence.metric.totalDebtBase) === 0n ||
        healthFactor === UINT256_MAX ||
        healthFactor < BigInt(evidence.policy.minHealthFactorScaled)
      ) {
        addPassSemanticIssue(context, "Aave evidence does not satisfy the health pass rule");
      }
      return;
    }
    case VENUS_HEALTH_EVIDENCE_SCHEMA: {
      requireExactRead(
        artifact,
        context,
        0,
        "getAccountLiquidity",
        evidence.subject.comptrollerAddress,
        addressCalldata(
          SELECTOR_GET_ACCOUNT_LIQUIDITY,
          evidence.subject.accountAddress,
        ),
      );
      requireExactRead(
        artifact,
        context,
        1,
        "getAssetsIn",
        evidence.subject.comptrollerAddress,
        addressCalldata(SELECTOR_GET_ASSETS_IN, evidence.subject.accountAddress),
      );
      requireExactRead(
        artifact,
        context,
        2,
        "borrowBalanceStored",
        evidence.subject.borrowMarketAddress,
        addressCalldata(
          SELECTOR_BORROW_BALANCE_STORED,
          evidence.subject.accountAddress,
        ),
      );
      if (
        BigInt(evidence.metric.shortfallUsdScaled) !== 0n ||
        evidence.metric.marketsEntered === 0 ||
        BigInt(evidence.metric.borrowBalanceStored) === 0n ||
        BigInt(evidence.metric.liquidityUsdScaled) <
          BigInt(evidence.policy.minLiquidityUsdScaled)
      ) {
        addPassSemanticIssue(context, "Venus evidence does not satisfy the health pass rule");
      }
      return;
    }
  }
}

function requireExactRead(
  artifact: PassArtifactForValidation,
  context: z.RefinementCtx,
  index: number,
  label: string,
  to: string,
  data: string,
): void {
  const read = artifact.reads[index];
  if (
    read === undefined ||
    read.label !== label ||
    read.to !== to ||
    read.data !== data
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["reads", index],
      message: "pass artifact read does not match its adapter evidence subject",
    });
  }
}

function addPassSemanticIssue(context: z.RefinementCtx, message: string): void {
  context.addIssue({
    code: z.ZodIssueCode.custom,
    path: ["result", "evidence", "metric"],
    message,
  });
}
