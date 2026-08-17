import { canonicalSha256 } from "@mandatex/marketplace-core";
import { z } from "zod";

/**
 * Inactive service-owned deployment identity for the category adapters.
 *
 * This is deliberately a separate contract from the active verifier-policy
 * manifest. The verifier does not import adapter code from this package; it
 * cross-checks this closed-world description before a future activation.
 */
export const MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA =
  "mandatex.marketplace.category-adapter-deployment.v2" as const;

export const MARKETPLACE_CATEGORY_ADAPTER_IDS = Object.freeze([
  "aave-v3-health-v1",
  "erc4626-yield-v1",
  "pancakeswap-v3-grid-v1",
  "venus-health-v1",
] as const);

/** Validation profiles are adapter-specific, not merely category-specific. */
export const MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES = Object.freeze({
  grid: "mandatex.marketplace.adapter-pancakeswap-v3-grid-validation.v1",
  yield: "mandatex.marketplace.adapter-erc4626-yield-validation.v1",
  aaveHealth: "mandatex.marketplace.adapter-aave-v3-health-validation.v1",
  venusHealth: "mandatex.marketplace.adapter-venus-health-validation.v1",
} as const);

const evmAddressSchema = z
  .string()
  .regex(/^0x[0-9a-f]{40}$/, "expected a lowercase 0x-prefixed EVM address");

const uint256DecimalSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]{0,77})$/, "expected a canonical uint256 decimal")
  .refine((value) => BigInt(value) < 1n << 256n, {
    message: "integer is outside uint256 range",
  });

const v3TickSchema = z.number().int().min(-887_272).max(887_272);

const readSchema = z
  .object({
    label: z.string().min(1).max(64),
    selector: z.string().regex(/^0x[0-9a-f]{8}$/),
    target: z.string().min(1).max(32),
  })
  .strict();

const gridDeploymentSchema = z
  .object({
    adapterId: z.literal("pancakeswap-v3-grid-v1"),
    category: z.literal("grid"),
    enabled: z.boolean(),
    evidenceSchema: z.literal("mandatex.category.grid-evidence.v1"),
    validationProfile: z.literal(
      MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.grid,
    ),
    protocol: z.literal("pancakeswap-v3"),
    metric: z.literal("pool slot0().tick versus the declared grid band"),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("slot0"),
        selector: z.literal("0x3850c7bd"),
        target: z.literal("pool"),
      }),
    ]),
    configuration: z
      .object({
        poolAddress: evmAddressSchema,
        lowerTick: v3TickSchema,
        upperTick: v3TickSchema,
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
      })
      .optional(),
  })
  .strict();

const yieldDeploymentSchema = z
  .object({
    adapterId: z.literal("erc4626-yield-v1"),
    category: z.literal("yield"),
    enabled: z.boolean(),
    evidenceSchema: z.literal("mandatex.category.yield-evidence.v1"),
    validationProfile: z.literal(
      MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.yield,
    ),
    protocol: z.literal("erc4626"),
    metric: z.literal(
      "totalAssets/totalSupply share price versus a declared floor",
    ),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("totalAssets"),
        selector: z.literal("0x01e1d114"),
        target: z.literal("vault"),
      }),
      readSchema.extend({
        label: z.literal("totalSupply"),
        selector: z.literal("0x18160ddd"),
        target: z.literal("vault"),
      }),
    ]),
    configuration: z
      .object({
        vaultAddress: evmAddressSchema,
        minSharePriceScaled: uint256DecimalSchema,
      })
      .strict()
      .optional(),
  })
  .strict();

const aaveHealthDeploymentSchema = z
  .object({
    adapterId: z.literal("aave-v3-health-v1"),
    category: z.literal("health"),
    enabled: z.boolean(),
    evidenceSchema: z.literal("mandatex.category.health-evidence.v1"),
    validationProfile: z.literal(
      MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.aaveHealth,
    ),
    protocol: z.literal("aave-v3"),
    metric: z.literal("getUserAccountData().healthFactor versus a declared floor"),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("getUserAccountData"),
        selector: z.literal("0xbf92857c"),
        target: z.literal("pool"),
      }),
    ]),
    configuration: z
      .object({
        poolAddress: evmAddressSchema,
        accountAddress: evmAddressSchema,
        minHealthFactorScaled: uint256DecimalSchema.default(
          "1100000000000000000",
        ),
      })
      .strict()
      .optional(),
  })
  .strict();

const venusHealthDeploymentSchema = z
  .object({
    adapterId: z.literal("venus-health-v1"),
    category: z.literal("health"),
    enabled: z.boolean(),
    evidenceSchema: z.literal("mandatex.category.venus-health-evidence.v1"),
    validationProfile: z.literal(
      MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.venusHealth,
    ),
    protocol: z.literal("venus"),
    metric: z.literal(
      "getAccountLiquidity() excess liquidity and shortfall plus monitored-market borrowBalanceStored() versus a declared floor",
    ),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("getAccountLiquidity"),
        selector: z.literal("0x5ec88c79"),
        target: z.literal("comptroller"),
      }),
      readSchema.extend({
        label: z.literal("getAssetsIn"),
        selector: z.literal("0xabfceffc"),
        target: z.literal("comptroller"),
      }),
      readSchema.extend({
        label: z.literal("borrowBalanceStored"),
        selector: z.literal("0x95dd9193"),
        target: z.literal("borrowMarket"),
      }),
    ]),
    configuration: z
      .object({
        comptrollerAddress: evmAddressSchema,
        accountAddress: evmAddressSchema,
        borrowMarketAddress: evmAddressSchema,
        minLiquidityUsdScaled: uint256DecimalSchema,
      })
      .strict()
      .optional(),
  })
  .strict();

export const marketplaceCategoryAdapterDeploymentEntrySchema =
  z.discriminatedUnion("adapterId", [
    gridDeploymentSchema,
    yieldDeploymentSchema,
    aaveHealthDeploymentSchema,
    venusHealthDeploymentSchema,
  ]);

const normalizedCategoryAdapterDeploymentManifestSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA),
    chainId: z.literal(56),
    adapters: z
      .array(marketplaceCategoryAdapterDeploymentEntrySchema)
      .length(MARKETPLACE_CATEGORY_ADAPTER_IDS.length),
  })
  .strict()
  .superRefine((manifest, context) => {
    const adapterIds = manifest.adapters.map((entry) => entry.adapterId);
    const expected = new Set(MARKETPLACE_CATEGORY_ADAPTER_IDS);
    if (
      new Set(adapterIds).size !== adapterIds.length ||
      adapterIds.length !== expected.size ||
      adapterIds.some((adapterId) => !expected.has(adapterId))
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapters"],
        message: "adapter deployment must contain exactly one entry for each registered adapter ID",
      });
    }

    const enabledByCategory = new Map<string, number[]>();
    for (const [index, entry] of manifest.adapters.entries()) {
      const hasConfiguration = Object.hasOwn(entry, "configuration");
      if (entry.enabled !== hasConfiguration) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["adapters", index, "configuration"],
          message:
            "enabled adapter entries require configuration and disabled entries must omit it",
        });
      }
      if (hasConfiguration && entry.configuration === undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["adapters", index, "configuration"],
          message: "configuration must not be explicitly undefined",
        });
      }
      if (entry.enabled) {
        const indexes = enabledByCategory.get(entry.category) ?? [];
        indexes.push(index);
        enabledByCategory.set(entry.category, indexes);
      }
    }

    for (const [category, indexes] of enabledByCategory) {
      if (indexes.length > 1) {
        for (const index of indexes) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["adapters", index, "enabled"],
            message: `at most one adapter may be enabled for category ${category} until trusted provenance carries an adapter ID`,
          });
        }
      }
    }
  });

export const marketplaceCategoryAdapterDeploymentManifestSchema =
  normalizedCategoryAdapterDeploymentManifestSchema.transform((manifest) => ({
    ...manifest,
    adapters: [...manifest.adapters].sort((left, right) =>
      left.adapterId < right.adapterId ? -1 : left.adapterId > right.adapterId ? 1 : 0,
    ),
  }));

type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer Item)[]
    ? readonly DeepReadonly<Item>[]
    : T extends object
      ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
      : T;

export type MarketplaceCategoryAdapterDeploymentManifest = DeepReadonly<
  z.infer<typeof marketplaceCategoryAdapterDeploymentManifestSchema>
>;

export type MarketplaceCategoryAdapterDeploymentEntry = DeepReadonly<
  z.infer<typeof marketplaceCategoryAdapterDeploymentEntrySchema>
>;

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

/** Parse, normalize, detach, and freeze the adapter deployment identity. */
export function parseMarketplaceCategoryAdapterDeploymentManifest(
  value: unknown,
): MarketplaceCategoryAdapterDeploymentManifest {
  return deepFreeze(
    marketplaceCategoryAdapterDeploymentManifestSchema.parse(value),
  );
}

/** Hashes the normalized manifest; callers must provide the full four-entry set. */
export function marketplaceCategoryAdapterDeploymentSha256(value: unknown): string {
  return canonicalSha256(parseMarketplaceCategoryAdapterDeploymentManifest(value));
}
