import {
  CATEGORY_ADAPTER_REGISTRY,
  DEFAULT_MIN_HEALTH_FACTOR_SCALED,
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
  evmAddressSchema,
  tickSchema,
  uint256DecimalSchema,
  type GridAdapterConfig,
  type HealthAdapterConfig,
  type VenusHealthAdapterConfig,
  type YieldAdapterConfig,
} from "@mandatex/category-adapters";
import { z } from "zod";

import { canonicalQuoteJson, computeQuoteSha256 } from "../quotes/protocol.js";

export const CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA =
  "mandatex.marketplace.category-adapter-deployment.v2" as const;

export const CATEGORY_ADAPTER_VALIDATION_PROFILES = Object.freeze({
  grid: "mandatex.marketplace.adapter-pancakeswap-v3-grid-validation.v1",
  yield: "mandatex.marketplace.adapter-erc4626-yield-validation.v1",
  aaveHealth: "mandatex.marketplace.adapter-aave-v3-health-validation.v1",
  venusHealth: "mandatex.marketplace.adapter-venus-health-validation.v1",
} as const);

const readSchema = z
  .object({
    label: z.string().min(1).max(64),
    selector: z.string().regex(/^0x[0-9a-f]{8}$/),
    target: z.string().min(1).max(32),
  })
  .strict();

const gridConfigurationSchema = z
  .object({
    poolAddress: evmAddressSchema,
    lowerTick: tickSchema,
    upperTick: tickSchema,
  })
  .strict()
  .superRefine((configuration, context) => {
    if (configuration.lowerTick >= configuration.upperTick) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["upperTick"],
        message: "upperTick must be greater than lowerTick",
      });
    }
  });

const yieldConfigurationSchema = z
  .object({
    vaultAddress: evmAddressSchema,
    minSharePriceScaled: uint256DecimalSchema,
  })
  .strict();

const healthConfigurationSchema = z
  .object({
    poolAddress: evmAddressSchema,
    accountAddress: evmAddressSchema,
    minHealthFactorScaled: uint256DecimalSchema.default(
      DEFAULT_MIN_HEALTH_FACTOR_SCALED,
    ),
  })
  .strict();

const venusConfigurationSchema = z
  .object({
    comptrollerAddress: evmAddressSchema,
    accountAddress: evmAddressSchema,
    borrowMarketAddress: evmAddressSchema,
    minLiquidityUsdScaled: uint256DecimalSchema,
  })
  .strict();

const gridRegistry = CATEGORY_ADAPTER_REGISTRY.find(
  (entry) => entry.adapterId === GRID_ADAPTER_ID,
)!;
const yieldRegistry = CATEGORY_ADAPTER_REGISTRY.find(
  (entry) => entry.adapterId === YIELD_ADAPTER_ID,
)!;
const healthRegistry = CATEGORY_ADAPTER_REGISTRY.find(
  (entry) => entry.adapterId === HEALTH_ADAPTER_ID,
)!;
const venusRegistry = CATEGORY_ADAPTER_REGISTRY.find(
  (entry) => entry.adapterId === VENUS_HEALTH_ADAPTER_ID,
)!;

const gridEntrySchema = z
  .object({
    adapterId: z.literal(GRID_ADAPTER_ID),
    category: z.literal("grid"),
    enabled: z.boolean(),
    evidenceSchema: z.literal(GRID_EVIDENCE_SCHEMA),
    validationProfile: z.literal(CATEGORY_ADAPTER_VALIDATION_PROFILES.grid),
    protocol: z.literal("pancakeswap-v3"),
    metric: z.literal(gridRegistry.metric),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("slot0"),
        selector: z.literal(SELECTOR_SLOT0),
        target: z.literal("pool"),
      }),
    ]),
    configuration: gridConfigurationSchema.optional(),
  })
  .strict();

const yieldEntrySchema = z
  .object({
    adapterId: z.literal(YIELD_ADAPTER_ID),
    category: z.literal("yield"),
    enabled: z.boolean(),
    evidenceSchema: z.literal(YIELD_EVIDENCE_SCHEMA),
    validationProfile: z.literal(CATEGORY_ADAPTER_VALIDATION_PROFILES.yield),
    protocol: z.literal("erc4626"),
    metric: z.literal(yieldRegistry.metric),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("totalAssets"),
        selector: z.literal(SELECTOR_TOTAL_ASSETS),
        target: z.literal("vault"),
      }),
      readSchema.extend({
        label: z.literal("totalSupply"),
        selector: z.literal(SELECTOR_TOTAL_SUPPLY),
        target: z.literal("vault"),
      }),
    ]),
    configuration: yieldConfigurationSchema.optional(),
  })
  .strict();

const healthEntrySchema = z
  .object({
    adapterId: z.literal(HEALTH_ADAPTER_ID),
    category: z.literal("health"),
    enabled: z.boolean(),
    evidenceSchema: z.literal(HEALTH_EVIDENCE_SCHEMA),
    validationProfile: z.literal(
      CATEGORY_ADAPTER_VALIDATION_PROFILES.aaveHealth,
    ),
    protocol: z.literal("aave-v3"),
    metric: z.literal(healthRegistry.metric),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("getUserAccountData"),
        selector: z.literal(SELECTOR_GET_USER_ACCOUNT_DATA),
        target: z.literal("pool"),
      }),
    ]),
    configuration: healthConfigurationSchema.optional(),
  })
  .strict();

const venusEntrySchema = z
  .object({
    adapterId: z.literal(VENUS_HEALTH_ADAPTER_ID),
    category: z.literal("health"),
    enabled: z.boolean(),
    evidenceSchema: z.literal(VENUS_HEALTH_EVIDENCE_SCHEMA),
    validationProfile: z.literal(
      CATEGORY_ADAPTER_VALIDATION_PROFILES.venusHealth,
    ),
    protocol: z.literal("venus"),
    metric: z.literal(venusRegistry.metric),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("getAccountLiquidity"),
        selector: z.literal(SELECTOR_GET_ACCOUNT_LIQUIDITY),
        target: z.literal("comptroller"),
      }),
      readSchema.extend({
        label: z.literal("getAssetsIn"),
        selector: z.literal(SELECTOR_GET_ASSETS_IN),
        target: z.literal("comptroller"),
      }),
      readSchema.extend({
        label: z.literal("borrowBalanceStored"),
        selector: z.literal(SELECTOR_BORROW_BALANCE_STORED),
        target: z.literal("borrowMarket"),
      }),
    ]),
    configuration: venusConfigurationSchema.optional(),
  })
  .strict();

export const categoryAdapterDeploymentEntrySchema = z.discriminatedUnion(
  "adapterId",
  [gridEntrySchema, yieldEntrySchema, healthEntrySchema, venusEntrySchema],
);

const normalizedCategoryAdapterDeploymentSchema = z
  .object({
    schema: z.literal(CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA),
    chainId: z.literal(56),
    adapters: z.array(categoryAdapterDeploymentEntrySchema).length(4),
  })
  .strict()
  .superRefine((manifest, context) => {
    const expected = new Set([
      GRID_ADAPTER_ID,
      YIELD_ADAPTER_ID,
      HEALTH_ADAPTER_ID,
      VENUS_HEALTH_ADAPTER_ID,
    ]);
    const ids = manifest.adapters.map((entry) => entry.adapterId);
    if (
      new Set(ids).size !== ids.length ||
      ids.some((adapterId) => !expected.has(adapterId))
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapters"],
        message: "deployment must contain exactly one entry per registered adapter ID",
      });
    }

    const enabledByCategory = new Map<string, number[]>();
    for (const [index, entry] of manifest.adapters.entries()) {
      const hasConfiguration = Object.hasOwn(entry, "configuration");
      if (entry.enabled !== hasConfiguration || entry.configuration === undefined && hasConfiguration) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["adapters", index, "configuration"],
          message:
            "enabled entries require configuration and disabled entries must omit it",
        });
      }
      if (entry.enabled) {
        const indexes = enabledByCategory.get(entry.category) ?? [];
        indexes.push(index);
        enabledByCategory.set(entry.category, indexes);
      }
    }
    for (const [category, indexes] of enabledByCategory) {
      if (indexes.length <= 1) continue;
      for (const index of indexes) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["adapters", index, "enabled"],
          message: `at most one adapter may be enabled for category ${category}`,
        });
      }
    }
  })
  .transform((manifest) => ({
    ...manifest,
    adapters: [...manifest.adapters].sort((left, right) =>
      left.adapterId < right.adapterId ? -1 : left.adapterId > right.adapterId ? 1 : 0,
    ),
  }));

export const categoryAdapterDeploymentManifestSchema =
  normalizedCategoryAdapterDeploymentSchema;

type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer Item)[]
    ? readonly DeepReadonly<Item>[]
    : T extends object
      ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
      : T;

export type CategoryAdapterDeploymentManifest = DeepReadonly<
  z.infer<typeof categoryAdapterDeploymentManifestSchema>
>;
export type CategoryAdapterDeploymentEntry = DeepReadonly<
  z.infer<typeof categoryAdapterDeploymentEntrySchema>
>;
export type EnabledCategoryAdapterDeploymentEntry = Extract<
  CategoryAdapterDeploymentEntry,
  { readonly enabled: true }
>;

export type CategoryAdapterRuntimeConfig =
  | GridAdapterConfig
  | YieldAdapterConfig
  | HealthAdapterConfig
  | VenusHealthAdapterConfig;

export function parseCategoryAdapterDeploymentManifest(
  value: unknown,
): CategoryAdapterDeploymentManifest {
  return deepFreeze(categoryAdapterDeploymentManifestSchema.parse(value));
}

export function categoryAdapterDeploymentSha256(value: unknown): string {
  return computeQuoteSha256(
    canonicalQuoteJson(parseCategoryAdapterDeploymentManifest(value)),
  );
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
