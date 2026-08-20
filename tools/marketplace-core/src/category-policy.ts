import type { UnsupportedCode } from "./codes.js";
import { deepFreeze } from "./immutable.js";
import type { MarketplaceCategory } from "./primitives.js";

/**
 * The closed category-to-receipt mapping used by Marketplace Core v1.
 *
 * This module deliberately contains metadata only. It does not discover or
 * execute adapters, read deployment configuration, or import the adapter
 * package. The verifier owns category execution. The adapter registry below is
 * an integration allowlist, not a category activation switch; the compact v2
 * attestation still carries no adapter ID and non-rebalancing categories remain
 * explicitly unsupported until a successor contract binds both.
 */
export const MARKETPLACE_REBALANCING_ADAPTER =
  "pancakeswap-v3-rebalancing-v1" as const;

export const MARKETPLACE_GRID_ADAPTER = "pancakeswap-v3-grid-v1" as const;
export const MARKETPLACE_YIELD_ADAPTER = "erc4626-yield-v1" as const;
export const MARKETPLACE_AAVE_HEALTH_ADAPTER = "aave-v3-health-v1" as const;
export const MARKETPLACE_VENUS_HEALTH_ADAPTER = "venus-health-v1" as const;

export const MARKETPLACE_GRID_EVIDENCE_SCHEMA =
  "mandatex.category.grid-evidence.v1" as const;
export const MARKETPLACE_YIELD_EVIDENCE_SCHEMA =
  "mandatex.category.yield-evidence.v1" as const;
export const MARKETPLACE_HEALTH_EVIDENCE_SCHEMA =
  "mandatex.category.health-evidence.v1" as const;
export const MARKETPLACE_VENUS_HEALTH_EVIDENCE_SCHEMA =
  "mandatex.category.venus-health-evidence.v1" as const;

export type MarketplaceCategoryAdapterId =
  | typeof MARKETPLACE_GRID_ADAPTER
  | typeof MARKETPLACE_YIELD_ADAPTER
  | typeof MARKETPLACE_AAVE_HEALTH_ADAPTER
  | typeof MARKETPLACE_VENUS_HEALTH_ADAPTER;

export type MarketplaceCategoryAdapterRegistryEntry = Readonly<{
  readonly adapterId: MarketplaceCategoryAdapterId;
  readonly category: Exclude<MarketplaceCategory, "rebalancing">;
  readonly evidenceSchema:
    | typeof MARKETPLACE_GRID_EVIDENCE_SCHEMA
    | typeof MARKETPLACE_YIELD_EVIDENCE_SCHEMA
    | typeof MARKETPLACE_HEALTH_EVIDENCE_SCHEMA
    | typeof MARKETPLACE_VENUS_HEALTH_EVIDENCE_SCHEMA;
}>;

const categoryAdapterRegistry = {
  [MARKETPLACE_GRID_ADAPTER]: {
    adapterId: MARKETPLACE_GRID_ADAPTER,
    category: "grid",
    evidenceSchema: MARKETPLACE_GRID_EVIDENCE_SCHEMA,
  },
  [MARKETPLACE_YIELD_ADAPTER]: {
    adapterId: MARKETPLACE_YIELD_ADAPTER,
    category: "yield",
    evidenceSchema: MARKETPLACE_YIELD_EVIDENCE_SCHEMA,
  },
  [MARKETPLACE_AAVE_HEALTH_ADAPTER]: {
    adapterId: MARKETPLACE_AAVE_HEALTH_ADAPTER,
    category: "health",
    evidenceSchema: MARKETPLACE_HEALTH_EVIDENCE_SCHEMA,
  },
  [MARKETPLACE_VENUS_HEALTH_ADAPTER]: {
    adapterId: MARKETPLACE_VENUS_HEALTH_ADAPTER,
    category: "health",
    evidenceSchema: MARKETPLACE_VENUS_HEALTH_EVIDENCE_SCHEMA,
  },
} as const satisfies Readonly<
  Record<MarketplaceCategoryAdapterId, MarketplaceCategoryAdapterRegistryEntry>
>;

/**
 * Adapter-ID keyed, recursively frozen metadata. Health intentionally has two
 * entries: the signed Core payload carries no adapter ID, and Aave/Venus are
 * distinct protocols rather than interchangeable configurations.
 */
export const CATEGORY_ADAPTER_REGISTRY = deepFreeze(categoryAdapterRegistry);

/** Descriptive alias for consumers that prefer the longer Core namespace. */
export const MARKETPLACE_CATEGORY_ADAPTER_REGISTRY = CATEGORY_ADAPTER_REGISTRY;

export type MarketplaceCategoryAdapterIds = readonly [
  typeof MARKETPLACE_GRID_ADAPTER,
  typeof MARKETPLACE_YIELD_ADAPTER,
  typeof MARKETPLACE_AAVE_HEALTH_ADAPTER,
  typeof MARKETPLACE_VENUS_HEALTH_ADAPTER,
];

/** Stable registry order for callers that need to enumerate the closed set. */
export const MARKETPLACE_CATEGORY_ADAPTER_IDS = deepFreeze(
  [
    MARKETPLACE_GRID_ADAPTER,
    MARKETPLACE_YIELD_ADAPTER,
    MARKETPLACE_AAVE_HEALTH_ADAPTER,
    MARKETPLACE_VENUS_HEALTH_ADAPTER,
  ] as const,
) as MarketplaceCategoryAdapterIds;

export type MarketplaceHealthAdapterIds = readonly [
  typeof MARKETPLACE_AAVE_HEALTH_ADAPTER,
  typeof MARKETPLACE_VENUS_HEALTH_ADAPTER,
];

export const MARKETPLACE_HEALTH_ADAPTERS = deepFreeze(
  [MARKETPLACE_AAVE_HEALTH_ADAPTER, MARKETPLACE_VENUS_HEALTH_ADAPTER] as const,
) as MarketplaceHealthAdapterIds;

type SupportedCategoryPolicy = Readonly<{
  readonly evaluationSupport: "supported";
  readonly receiptAdapter: Readonly<{
    readonly status: "supported";
    readonly name: typeof MARKETPLACE_REBALANCING_ADAPTER;
  }>;
}>;

type UnsupportedCategoryPolicy = Readonly<{
  readonly evaluationSupport: "unsupported";
  readonly receiptAdapter: Readonly<{
    readonly status: "unsupported";
    readonly code: UnsupportedCode;
  }>;
}>;

export type MarketplaceCategoryPolicy =
  | SupportedCategoryPolicy
  | UnsupportedCategoryPolicy;

const categoryPolicies = {
  rebalancing: {
    evaluationSupport: "supported",
    receiptAdapter: {
      status: "supported",
      name: MARKETPLACE_REBALANCING_ADAPTER,
    },
  },
  grid: {
    evaluationSupport: "unsupported",
    receiptAdapter: {
      status: "unsupported",
      code: "CATEGORY_GRID_UNSUPPORTED",
    },
  },
  yield: {
    evaluationSupport: "unsupported",
    receiptAdapter: {
      status: "unsupported",
      code: "CATEGORY_YIELD_UNSUPPORTED",
    },
  },
  health: {
    evaluationSupport: "unsupported",
    receiptAdapter: {
      status: "unsupported",
      code: "CATEGORY_HEALTH_UNSUPPORTED",
    },
  },
} as const satisfies Readonly<
  Record<MarketplaceCategory, MarketplaceCategoryPolicy>
>;

/** Immutable and exhaustive; keep this table free of runtime adapter code. */
export const CATEGORY_POLICIES: Readonly<
  Record<MarketplaceCategory, MarketplaceCategoryPolicy>
> = deepFreeze(categoryPolicies);
