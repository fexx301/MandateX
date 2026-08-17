import { canonicalSha256 } from "@mandatex/marketplace-core";
import { z } from "zod";

/**
 * This is a service-owned, inactive deployment contract. The literals mirror
 * `tools/category-adapters`, but the verifier does not import adapter code: the
 * manifest is the auditable boundary that will be cross-checked before a future
 * category is enabled.
 */
export const MARKETPLACE_CATEGORY_DEPLOYMENT_SCHEMA =
  "mandatex.marketplace.category-deployment.v1" as const;

export const MARKETPLACE_CATEGORY_VALIDATION_PROFILES = Object.freeze({
  grid: "mandatex.marketplace.category-grid-validation.v1",
  yield: "mandatex.marketplace.category-yield-validation.v1",
  health: "mandatex.marketplace.category-health-validation.v1",
} as const);

const evmAddressSchema = z
  .string()
  .regex(/^0x[0-9a-f]{40}$/, "expected a lowercase 0x-prefixed EVM address");

const uint256DecimalSchema = z
  .string()
  .regex(
    /^(?:0|[1-9][0-9]{0,77})$/,
    "expected a canonical uint256 decimal",
  )
  .refine((value) => BigInt(value) < 1n << 256n, {
    message: "integer is outside uint256 range",
  });

const v3TickSchema = z.number().int().min(-887_272).max(887_272);

const readSchema = z
  .object({
    label: z.string().min(1).max(64),
    selector: z.string().regex(/^0x[0-9a-f]{8}$/),
  })
  .strict();

const gridDeploymentSchema = z
  .object({
    category: z.literal("grid"),
    enabled: z.boolean(),
    adapterId: z.literal("pancakeswap-v3-grid-v1"),
    evidenceSchema: z.literal("mandatex.category.grid-evidence.v1"),
    validationProfile: z.literal(
      MARKETPLACE_CATEGORY_VALIDATION_PROFILES.grid,
    ),
    protocol: z.literal("pancakeswap-v3"),
    metric: z.literal("pool slot0().tick versus the declared grid band"),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("slot0"),
        selector: z.literal("0x3850c7bd"),
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
    category: z.literal("yield"),
    enabled: z.boolean(),
    adapterId: z.literal("erc4626-yield-v1"),
    evidenceSchema: z.literal("mandatex.category.yield-evidence.v1"),
    validationProfile: z.literal(
      MARKETPLACE_CATEGORY_VALIDATION_PROFILES.yield,
    ),
    protocol: z.literal("erc4626"),
    metric: z.literal(
      "totalAssets/totalSupply share price versus a declared floor",
    ),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("totalAssets"),
        selector: z.literal("0x01e1d114"),
      }),
      readSchema.extend({
        label: z.literal("totalSupply"),
        selector: z.literal("0x18160ddd"),
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

const healthDeploymentSchema = z
  .object({
    category: z.literal("health"),
    enabled: z.boolean(),
    adapterId: z.literal("aave-v3-health-v1"),
    evidenceSchema: z.literal("mandatex.category.health-evidence.v1"),
    validationProfile: z.literal(
      MARKETPLACE_CATEGORY_VALIDATION_PROFILES.health,
    ),
    protocol: z.literal("aave-v3"),
    metric: z.literal("getUserAccountData().healthFactor versus a declared floor"),
    reads: z.tuple([
      readSchema.extend({
        label: z.literal("getUserAccountData"),
        selector: z.literal("0xbf92857c"),
      }),
    ]),
    configuration: z
      .object({
        poolAddress: evmAddressSchema,
        accountAddress: evmAddressSchema,
        // Materialize the adapter's documented default before hashing.
        minHealthFactorScaled: uint256DecimalSchema.default(
          "1100000000000000000",
        ),
      })
      .strict()
      .optional(),
  })
  .strict();

export const marketplaceCategoryDeploymentEntrySchema = z.discriminatedUnion(
  "category",
  [gridDeploymentSchema, yieldDeploymentSchema, healthDeploymentSchema],
);

const normalizedCategoryDeploymentManifestSchema = z
  .object({
    schema: z.literal(MARKETPLACE_CATEGORY_DEPLOYMENT_SCHEMA),
    chainId: z.literal(56),
    categories: z
      .array(marketplaceCategoryDeploymentEntrySchema)
      .length(3),
  })
  .strict()
  .superRefine((manifest, context) => {
    const categories = manifest.categories.map((entry) => entry.category);
    const adapterIds = manifest.categories.map((entry) => entry.adapterId);
    if (
      new Set(categories).size !== categories.length ||
      new Set(categories).size !== 3 ||
      !["grid", "health", "yield"].every((category) =>
        categories.includes(category as (typeof categories)[number]),
      )
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categories"],
        message:
          "category deployment must contain exactly one grid, health, and yield entry",
      });
    }
    if (new Set(adapterIds).size !== adapterIds.length) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["categories"],
        message: "category adapter IDs must be unique",
      });
    }
    for (const [index, entry] of manifest.categories.entries()) {
      const hasConfiguration = Object.hasOwn(entry, "configuration");
      if (entry.enabled !== hasConfiguration) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["categories", index, "configuration"],
          message:
            "enabled category entries require configuration and disabled entries must omit it",
        });
      }
      if (hasConfiguration && entry.configuration === undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["categories", index, "configuration"],
          message: "configuration must not be explicitly undefined",
        });
      }
    }
  });

export const marketplaceCategoryDeploymentManifestSchema =
  normalizedCategoryDeploymentManifestSchema.transform((manifest) => ({
    ...manifest,
    categories: [...manifest.categories].sort((left, right) =>
      left.category < right.category ? -1 : left.category > right.category ? 1 : 0,
    ),
  }));

type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends readonly (infer Item)[]
    ? readonly DeepReadonly<Item>[]
    : T extends object
      ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
      : T;

export type MarketplaceCategoryDeploymentManifest = DeepReadonly<
  z.infer<typeof marketplaceCategoryDeploymentManifestSchema>
>;

export type MarketplaceCategoryDeploymentEntry = DeepReadonly<
  z.infer<typeof marketplaceCategoryDeploymentEntrySchema>
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

/** Parse, normalize, detach, and freeze the deployment identity. */
export function parseMarketplaceCategoryDeploymentManifest(
  value: unknown,
): MarketplaceCategoryDeploymentManifest {
  return deepFreeze(marketplaceCategoryDeploymentManifestSchema.parse(value));
}

/** Hashes the normalized manifest; callers must provide the full manifest. */
export function marketplaceCategoryDeploymentSha256(value: unknown): string {
  return canonicalSha256(parseMarketplaceCategoryDeploymentManifest(value));
}
