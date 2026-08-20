import {
  GRID_ADAPTER_ID,
  GRID_EVIDENCE_SCHEMA,
  HEALTH_ADAPTER_ID,
  HEALTH_EVIDENCE_SCHEMA,
  SELECTOR_BORROW_BALANCE_STORED,
  SELECTOR_GET_ACCOUNT_LIQUIDITY,
  SELECTOR_GET_ASSETS_IN,
  SELECTOR_GET_USER_ACCOUNT_DATA,
  SELECTOR_SLOT0,
  SELECTOR_TOTAL_ASSETS,
  SELECTOR_TOTAL_SUPPLY,
  VENUS_HEALTH_ADAPTER_ID,
  VENUS_HEALTH_EVIDENCE_SCHEMA,
  YIELD_ADAPTER_ID,
  YIELD_EVIDENCE_SCHEMA,
  addressCalldata,
  evaluateGrid,
  evaluateHealth,
  evaluateVenusHealth,
  evaluateYield,
  evmAddressSchema,
  gridAdapterConfigSchema,
  healthAdapterConfigSchema,
  tickSchema,
  uint256DecimalSchema,
  venusHealthAdapterConfigSchema,
  yieldAdapterConfigSchema,
  type AdapterResult,
  type CategoryEvidenceDocument,
  type PinnedBlockReader,
} from "@mandatex/category-adapters";
import { z } from "zod";

import type { ExpectedCategoryRead } from "./rpc.js";

export const CATEGORY_THRESHOLD_UNITS = Object.freeze({
  gridTick: "uniswap-v3-tick",
  yieldSharePrice: "1e18-share-price",
  aaveHealthFactor: "1e18-health-factor",
  venusUsd: "1e18-usd",
} as const);

const ONE_E18 = 10n ** 18n;
const MAX_SCALED_RATIO = 10n ** 36n;
const MAX_VENUS_LIQUIDITY_SCALED = 10n ** 30n;

const boundedDecimal = (minimum: bigint, maximum: bigint) =>
  uint256DecimalSchema
    .refine((value) => BigInt(value) >= minimum, "threshold is below the adapter range")
    .refine((value) => BigInt(value) <= maximum, "threshold exceeds the adapter range");

const gridScopeSchema = z
  .object({
    adapterId: z.literal(GRID_ADAPTER_ID),
    category: z.literal("grid"),
    evidenceSchema: z.literal(GRID_EVIDENCE_SCHEMA),
    protocol: z.literal("pancakeswap-v3"),
    subject: z.object({ poolAddress: evmAddressSchema }).strict(),
    conditionPolicy: z
      .object({
        unit: z.literal(CATEGORY_THRESHOLD_UNITS.gridTick),
        lowerTick: tickSchema,
        upperTick: tickSchema,
      })
      .strict()
      .superRefine((policy, context) => {
        if (policy.lowerTick >= policy.upperTick) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["upperTick"],
            message: "lowerTick must be less than upperTick",
          });
        }
      }),
  })
  .strict();

const yieldScopeSchema = z
  .object({
    adapterId: z.literal(YIELD_ADAPTER_ID),
    category: z.literal("yield"),
    evidenceSchema: z.literal(YIELD_EVIDENCE_SCHEMA),
    protocol: z.literal("erc4626"),
    subject: z.object({ vaultAddress: evmAddressSchema }).strict(),
    conditionPolicy: z
      .object({
        unit: z.literal(CATEGORY_THRESHOLD_UNITS.yieldSharePrice),
        minSharePriceScaled: boundedDecimal(ONE_E18, MAX_SCALED_RATIO),
      })
      .strict(),
  })
  .strict();

const aaveScopeSchema = z
  .object({
    adapterId: z.literal(HEALTH_ADAPTER_ID),
    category: z.literal("health"),
    evidenceSchema: z.literal(HEALTH_EVIDENCE_SCHEMA),
    protocol: z.literal("aave-v3"),
    subject: z
      .object({
        poolAddress: evmAddressSchema,
        accountAddress: evmAddressSchema,
      })
      .strict(),
    conditionPolicy: z
      .object({
        unit: z.literal(CATEGORY_THRESHOLD_UNITS.aaveHealthFactor),
        minHealthFactorScaled: boundedDecimal(ONE_E18 + 1n, MAX_SCALED_RATIO),
      })
      .strict(),
  })
  .strict();

const venusScopeSchema = z
  .object({
    adapterId: z.literal(VENUS_HEALTH_ADAPTER_ID),
    category: z.literal("health"),
    evidenceSchema: z.literal(VENUS_HEALTH_EVIDENCE_SCHEMA),
    protocol: z.literal("venus"),
    subject: z
      .object({
        comptrollerAddress: evmAddressSchema,
        accountAddress: evmAddressSchema,
        borrowMarketAddress: evmAddressSchema,
      })
      .strict(),
    conditionPolicy: z
      .object({
        unit: z.literal(CATEGORY_THRESHOLD_UNITS.venusUsd),
        minLiquidityUsdScaled: boundedDecimal(1n, MAX_VENUS_LIQUIDITY_SCALED),
      })
      .strict(),
  })
  .strict();

export const categoryExecutionScopeSchema = z.discriminatedUnion("adapterId", [
  gridScopeSchema,
  yieldScopeSchema,
  aaveScopeSchema,
  venusScopeSchema,
]);

export type CategoryExecutionScope = Readonly<
  z.infer<typeof categoryExecutionScopeSchema>
>;

export type CategoryScopeRuntime = Readonly<{
  expectedReads: readonly ExpectedCategoryRead[];
  evaluate: (reader: PinnedBlockReader) => Promise<AdapterResult<unknown>>;
  assertEvidence: (evidence: CategoryEvidenceDocument) => void;
}>;

export function parseCategoryExecutionScope(value: unknown): CategoryExecutionScope {
  return deepFreeze(categoryExecutionScopeSchema.parse(value));
}

/** Build the adapter invocation only from the signed mandate-derived scope. */
export function categoryScopeRuntime(value: unknown): CategoryScopeRuntime {
  const scope = parseCategoryExecutionScope(value);
  switch (scope.adapterId) {
    case GRID_ADAPTER_ID: {
      const { unit: _unit, ...conditionPolicy } = scope.conditionPolicy;
      const config = gridAdapterConfigSchema.parse({
        adapterId: scope.adapterId,
        protocol: scope.protocol,
        ...scope.subject,
        ...conditionPolicy,
      });
      return Object.freeze({
        expectedReads: Object.freeze([
          Object.freeze({
            label: "slot0",
            to: config.poolAddress,
            data: SELECTOR_SLOT0,
          }),
        ]),
        evaluate: (reader) => evaluateGrid(config, reader),
        assertEvidence: (evidence) => {
          if (
            evidence.schema !== GRID_EVIDENCE_SCHEMA ||
            evidence.subject.poolAddress !== scope.subject.poolAddress ||
            evidence.policy.lowerTick !== scope.conditionPolicy.lowerTick ||
            evidence.policy.upperTick !== scope.conditionPolicy.upperTick
          ) {
            throw new TypeError("grid evidence does not match the mandate scope");
          }
        },
      });
    }
    case YIELD_ADAPTER_ID: {
      const { unit: _unit, ...conditionPolicy } = scope.conditionPolicy;
      const config = yieldAdapterConfigSchema.parse({
        adapterId: scope.adapterId,
        protocol: scope.protocol,
        ...scope.subject,
        ...conditionPolicy,
      });
      return Object.freeze({
        expectedReads: Object.freeze([
          Object.freeze({
            label: "totalAssets",
            to: config.vaultAddress,
            data: SELECTOR_TOTAL_ASSETS,
          }),
          Object.freeze({
            label: "totalSupply",
            to: config.vaultAddress,
            data: SELECTOR_TOTAL_SUPPLY,
          }),
        ]),
        evaluate: (reader) => evaluateYield(config, reader),
        assertEvidence: (evidence) => {
          if (
            evidence.schema !== YIELD_EVIDENCE_SCHEMA ||
            evidence.subject.vaultAddress !== scope.subject.vaultAddress ||
            evidence.policy.minSharePriceScaled !==
              scope.conditionPolicy.minSharePriceScaled
          ) {
            throw new TypeError("yield evidence does not match the mandate scope");
          }
        },
      });
    }
    case HEALTH_ADAPTER_ID: {
      const { unit: _unit, ...conditionPolicy } = scope.conditionPolicy;
      const config = healthAdapterConfigSchema.parse({
        adapterId: scope.adapterId,
        protocol: scope.protocol,
        ...scope.subject,
        ...conditionPolicy,
      });
      return Object.freeze({
        expectedReads: Object.freeze([
          Object.freeze({
            label: "getUserAccountData",
            to: config.poolAddress,
            data: addressCalldata(
              SELECTOR_GET_USER_ACCOUNT_DATA,
              config.accountAddress,
            ),
          }),
        ]),
        evaluate: (reader) => evaluateHealth(config, reader),
        assertEvidence: (evidence) => {
          if (
            evidence.schema !== HEALTH_EVIDENCE_SCHEMA ||
            evidence.subject.poolAddress !== scope.subject.poolAddress ||
            evidence.subject.accountAddress !== scope.subject.accountAddress ||
            evidence.policy.minHealthFactorScaled !==
              scope.conditionPolicy.minHealthFactorScaled
          ) {
            throw new TypeError("Aave evidence does not match the mandate scope");
          }
        },
      });
    }
    case VENUS_HEALTH_ADAPTER_ID: {
      const { unit: _unit, ...conditionPolicy } = scope.conditionPolicy;
      const config = venusHealthAdapterConfigSchema.parse({
        adapterId: scope.adapterId,
        protocol: scope.protocol,
        ...scope.subject,
        ...conditionPolicy,
      });
      return Object.freeze({
        expectedReads: Object.freeze([
          Object.freeze({
            label: "getAccountLiquidity",
            to: config.comptrollerAddress,
            data: addressCalldata(
              SELECTOR_GET_ACCOUNT_LIQUIDITY,
              config.accountAddress,
            ),
          }),
          Object.freeze({
            label: "getAssetsIn",
            to: config.comptrollerAddress,
            data: addressCalldata(SELECTOR_GET_ASSETS_IN, config.accountAddress),
          }),
          Object.freeze({
            label: "borrowBalanceStored",
            to: config.borrowMarketAddress,
            data: addressCalldata(
              SELECTOR_BORROW_BALANCE_STORED,
              config.accountAddress,
            ),
          }),
        ]),
        evaluate: (reader) => evaluateVenusHealth(config, reader),
        assertEvidence: (evidence) => {
          if (
            evidence.schema !== VENUS_HEALTH_EVIDENCE_SCHEMA ||
            evidence.subject.comptrollerAddress !==
              scope.subject.comptrollerAddress ||
            evidence.subject.accountAddress !== scope.subject.accountAddress ||
            evidence.subject.borrowMarketAddress !==
              scope.subject.borrowMarketAddress ||
            evidence.policy.minLiquidityUsdScaled !==
              scope.conditionPolicy.minLiquidityUsdScaled
          ) {
            throw new TypeError("Venus evidence does not match the mandate scope");
          }
        },
      });
    }
  }
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    deepFreeze((object as Record<PropertyKey, unknown>)[key], seen);
  }
  return Object.freeze(value);
}
