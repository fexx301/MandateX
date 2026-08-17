import type { UnsupportedCode } from "./codes.js";
import { deepFreeze } from "./immutable.js";
import type { MarketplaceCategory } from "./primitives.js";

/**
 * The closed category-to-receipt mapping used by Core v1.
 *
 * This is metadata only. It does not discover or execute adapters, and changing
 * an entry to `supported` is not sufficient to activate a category: the
 * evaluator still contains category-specific gates that require a versioned
 * activation change.
 */
export const MARKETPLACE_REBALANCING_ADAPTER =
  "pancakeswap-v3-rebalancing-v1" as const;

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
export const CATEGORY_POLICIES = deepFreeze(categoryPolicies);
