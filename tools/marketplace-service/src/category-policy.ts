import { canonicalSha256 } from "@mandatex/marketplace-core";
import { z } from "zod";

/**
 * Service-owned deployment identity for signer-free category execution.
 *
 * This remains separate from the locked v1 attestation policy. The category
 * verifier policy v2 binds this closed-world description and cross-checks it
 * against the adapter executor before any evidence is produced.
 */
export const MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA =
  "mandatex.marketplace.category-adapter-deployment.v2" as const;

export const MARKETPLACE_CATEGORY_SUCCESSOR_DEPLOYMENT_SCHEMA =
  "mandatex.marketplace.category-successor-deployment.v1" as const;

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
        minHealthFactorScaled: uint256DecimalSchema,
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

const staticGridDeploymentSchema = gridDeploymentSchema.omit({
  configuration: true,
});
const staticYieldDeploymentSchema = yieldDeploymentSchema.omit({
  configuration: true,
});
const staticAaveHealthDeploymentSchema = aaveHealthDeploymentSchema.omit({
  configuration: true,
});
const staticVenusHealthDeploymentSchema = venusHealthDeploymentSchema.omit({
  configuration: true,
});

export const marketplaceCategoryAdapterDeploymentEntrySchema =
  z.discriminatedUnion("adapterId", [
    gridDeploymentSchema,
    yieldDeploymentSchema,
    aaveHealthDeploymentSchema,
    venusHealthDeploymentSchema,
  ]);

export const marketplaceCategorySuccessorDeploymentEntrySchema =
  z.discriminatedUnion("adapterId", [
    staticGridDeploymentSchema,
    staticYieldDeploymentSchema,
    staticAaveHealthDeploymentSchema,
    staticVenusHealthDeploymentSchema,
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

    for (const [index, entry] of manifest.adapters.entries()) {
      const hasConfiguration = Object.hasOwn(entry, "configuration");
      if (!entry.enabled && hasConfiguration) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["adapters", index, "configuration"],
          message:
            "disabled adapter entries must omit configuration",
        });
      }
      if (hasConfiguration && entry.configuration === undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["adapters", index, "configuration"],
          message: "configuration must not be explicitly undefined",
        });
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

const categorySuccessorInfrastructureSchema = z
  .object({
    erc8004Registry: evmAddressSchema,
    pancakeV3Factory: evmAddressSchema,
    aavePoolAddressesProvider: evmAddressSchema.nullable(),
    venusComptroller: evmAddressSchema,
  })
  .strict();

// The root key itself is supplied through the separately managed trust
// controller, but its identity is part of the static successor deployment.
// This prevents an app-controlled controller from silently selecting a
// different root under an otherwise matching policy and bundle.
const categorySuccessorTrustRootSchema = z
  .object({
    keyId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
    publicKeyFingerprintSha256: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

export const marketplaceCategorySuccessorDeploymentManifestSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_SUCCESSOR_DEPLOYMENT_SCHEMA),
    chainId: z.literal(56),
    trustRoot: categorySuccessorTrustRootSchema,
    infrastructure: categorySuccessorInfrastructureSchema,
    adapters: z
      .array(marketplaceCategorySuccessorDeploymentEntrySchema)
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
        message:
          "successor deployment must contain exactly one static entry for each registered adapter ID",
      });
    }
  })
  .transform((manifest) => ({
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

export type MarketplaceCategorySuccessorDeploymentManifest = DeepReadonly<
  z.infer<typeof marketplaceCategorySuccessorDeploymentManifestSchema>
>;

export type MarketplaceCategorySuccessorTrustRoot = DeepReadonly<
  z.infer<typeof categorySuccessorTrustRootSchema>
>;

export type MarketplaceCategorySuccessorDeploymentEntry = DeepReadonly<
  z.infer<typeof marketplaceCategorySuccessorDeploymentEntrySchema>
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

/** Parse, normalize, detach, and freeze the static successor deployment. */
export function parseMarketplaceCategorySuccessorDeploymentManifest(
  value: unknown,
): MarketplaceCategorySuccessorDeploymentManifest {
  return deepFreeze(
    marketplaceCategorySuccessorDeploymentManifestSchema.parse(value),
  );
}

export function marketplaceCategorySuccessorDeploymentSha256(
  value: unknown,
): string {
  return canonicalSha256(
    parseMarketplaceCategorySuccessorDeploymentManifest(value),
  );
}

/**
 * The executor still consumes its legacy static adapter registry shape. This
 * projection is deterministic and contains no mandate-specific configuration.
 */
export function marketplaceCategorySuccessorExecutorDeployment(
  value: unknown,
): MarketplaceCategoryAdapterDeploymentManifest {
  const deployment = parseMarketplaceCategorySuccessorDeploymentManifest(value);
  return parseMarketplaceCategoryAdapterDeploymentManifest({
    schema: MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
    chainId: deployment.chainId,
    adapters: deployment.adapters,
  });
}
