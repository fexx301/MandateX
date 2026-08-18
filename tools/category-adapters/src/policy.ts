import { z } from "zod";

import { adapterIdSchema, evmAddressSchema, tickSchema, uint256DecimalSchema } from "./primitives.js";

/**
 * Adapter identities, evidence schema versions, and the configuration each
 * adapter needs.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THRESHOLDS HERE ARE GLOBAL POLICY, NOT USER POLICY. This is a real limitation
 * and it is recorded rather than hidden.
 *
 * The frozen v2 mandate schema has no field in which a user can express a metric
 * threshold for these three categories — `mandate.rebalancing` is the only
 * category-specific policy object, and the signed payload carries only
 * `{ category, observedAt }` for grid, yield and health. So a user cannot
 * currently say "keep my health factor above 1.8". The floor is set by whoever
 * deploys the verifier, applies to every mandate in that category, and is frozen
 * into the verifier policy hash.
 *
 * That is a coherent v1 — the floor is auditable, and it is committed rather than
 * ambient — but it is not the same product as per-user thresholds, and the
 * marketplace UI must not imply otherwise. Making thresholds user-supplied means
 * a new mandate-schema field, which is a coordinated contract version, not a
 * unilateral change.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * NO ADDRESS HAS A DEFAULT. Every contract address is required configuration.
 * A default would be inherited silently by whoever forgot to set it, and an
 * address that is valid-looking but wrong — right protocol, wrong chain — reads
 * a contract that answers the call and returns a confidently wrong number. The
 * operator pins addresses from each protocol's own published deployment record;
 * this package refuses to guess on their behalf.
 */

export const GRID_ADAPTER_ID = "pancakeswap-v3-grid-v1" as const;
export const YIELD_ADAPTER_ID = "erc4626-yield-v1" as const;
export const HEALTH_ADAPTER_ID = "aave-v3-health-v1" as const;
export const VENUS_HEALTH_ADAPTER_ID = "venus-health-v1" as const;

export const GRID_EVIDENCE_SCHEMA = "mandatex.category.grid-evidence.v1" as const;
export const YIELD_EVIDENCE_SCHEMA = "mandatex.category.yield-evidence.v1" as const;
export const HEALTH_EVIDENCE_SCHEMA = "mandatex.category.health-evidence.v1" as const;
export const VENUS_HEALTH_EVIDENCE_SCHEMA =
  "mandatex.category.venus-health-evidence.v1" as const;

/**
 * Verified function selectors. Computed with `viem.toFunctionSelector`, not
 * recalled — a wrong selector does not error, it calls a different function or
 * hits the fallback, and either way the number that comes back looks fine.
 */
export const SELECTOR_SLOT0 = "0x3850c7bd" as const; // slot0()
export const SELECTOR_TOTAL_ASSETS = "0x01e1d114" as const; // totalAssets()
export const SELECTOR_TOTAL_SUPPLY = "0x18160ddd" as const; // totalSupply()
export const SELECTOR_GET_USER_ACCOUNT_DATA = "0xbf92857c" as const; // getUserAccountData(address)
export const SELECTOR_GET_ACCOUNT_LIQUIDITY = "0x5ec88c79" as const; // getAccountLiquidity(address)
export const SELECTOR_GET_ASSETS_IN = "0xabfceffc" as const; // getAssetsIn(address)
export const SELECTOR_BORROW_BALANCE_STORED = "0x95dd9193" as const; // borrowBalanceStored(address)

/** Fixed scale for every ratio this package derives. */
export const RATIO_SCALE = 10n ** 18n;

/**
 * Uniswap-v3 `TickMath` bounds, which PancakeSwap v3 inherits unchanged.
 *
 * These are narrower than the ABI types that carry them — the legal tick range is
 * a small fraction of `int24`, and the legal sqrt-price range a small fraction of
 * `uint160`. That gap is the useful part: a contract that answers a `slot0()` call
 * with a word which decodes cleanly as an `int24` but lies outside `[MIN_TICK,
 * MAX_TICK]` is not a v3 pool, and checking the protocol bound catches it where
 * checking only the ABI width does not.
 */
export const V3_MIN_TICK = -887_272;
export const V3_MAX_TICK = 887_272;
export const V3_MIN_SQRT_RATIO = 4_295_128_739n;
export const V3_MAX_SQRT_RATIO =
  1_461_446_703_485_210_103_287_273_052_203_988_822_378_723_970_342n;

/**
 * Aave reports a health factor scaled by 1e18 and liquidates below 1.0.
 *
 * The default floor is 1.1, not 1.0. A floor at exactly 1.0 would pass an
 * account that is one adverse price tick from being liquidatable, which is a
 * true statement about the present block and a useless one about the next.
 */
export const DEFAULT_MIN_HEALTH_FACTOR_SCALED = "1100000000000000000" as const;

export const gridAdapterConfigSchema = z
  .object({
    adapterId: z.literal(GRID_ADAPTER_ID),
    protocol: z.literal("pancakeswap-v3"),
    /** The v3-style pool whose `slot0().tick` is the live price. */
    poolAddress: evmAddressSchema,
    /**
     * The declared grid band, in pool ticks. Required, with no default: a grid's
     * band is the strategy, so a default band would be a different strategy
     * silently substituted for the configured one.
     */
     lowerTick: tickSchema,
     upperTick: tickSchema,
  })
  .strict()
  .superRefine((config, context) => {
    if (config.lowerTick >= config.upperTick) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["upperTick"],
        message: "upperTick must be greater than lowerTick",
      });
    }
  });
export type GridAdapterConfig = z.infer<typeof gridAdapterConfigSchema>;

export const yieldAdapterConfigSchema = z
  .object({
    adapterId: z.literal(YIELD_ADAPTER_ID),
    protocol: z.literal("erc4626"),
    vaultAddress: evmAddressSchema,
    /**
     * Floor for share price, in **asset atomic units per 10^18 share atomic
     * units**. Required, with no default, because a defensible default does not
     * exist: the number depends on the vault's asset and its own share unit.
     *
     * Expressing the metric in atomic units is deliberate. The obvious
     * alternative — read `decimals()` on the vault and the asset and normalize —
     * adds two reads and a class of bug where a decimals mismatch scales the
     * ratio by a factor of 10^12 while still producing a plausible number. In
     * atomic units there is nothing to mismatch.
     */
    minSharePriceScaled: uint256DecimalSchema,
  })
  .strict();
export type YieldAdapterConfig = z.infer<typeof yieldAdapterConfigSchema>;

export const healthAdapterConfigSchema = z
  .object({
    adapterId: z.literal(HEALTH_ADAPTER_ID),
    protocol: z.literal("aave-v3"),
    /** The Aave v3 `Pool` for the target market. */
    poolAddress: evmAddressSchema,
    /** The account whose position is being monitored. */
    accountAddress: evmAddressSchema,
    /** 1e18-scaled floor. Defaults to 1.1; see the constant above. */
    minHealthFactorScaled: uint256DecimalSchema.default(DEFAULT_MIN_HEALTH_FACTOR_SCALED),
  })
  .strict();
export type HealthAdapterConfig = z.infer<typeof healthAdapterConfigSchema>;

/**
 * Venus lending health.
 *
 * Venus is a Compound-v2 fork, so it does not expose a health factor at all.
 * `getAccountLiquidity` returns `(error, liquidity, shortfall)` — an absolute USD
 * buffer above the collateral requirement, or an absolute amount below it, with at
 * most one of the two nonzero. This is a **different adapter, not a configuration
 * of the Aave one**: three words with different meanings, and no ratio anywhere.
 *
 * Honest limitation, stated because it is easy to miss: an absolute USD floor does
 * not scale with position size the way a health factor does. A $10,000 buffer is
 * ample on a $50,000 position and thin on a $5,000,000 one, and Venus gives no
 * single call that normalizes it. Deriving a true ratio would need per-market
 * borrow balances, which is far past "one real metric". So this metric is weaker
 * than the Aave one and the floor has to be set with the monitored position's size
 * in mind. That is recorded rather than hidden.
 */
export const venusHealthAdapterConfigSchema = z
  .object({
    adapterId: z.literal(VENUS_HEALTH_ADAPTER_ID),
    protocol: z.literal("venus"),
    /** The Venus Comptroller (Unitroller proxy) for the target deployment. */
    comptrollerAddress: evmAddressSchema,
    accountAddress: evmAddressSchema,
    /**
     * The vToken market whose borrow balance defines "has debt".
     *
     * Required, and the reason this adapter needs three reads rather than two.
     * Venus exposes borrow balances only per market, so establishing that an
     * account actually owes something means naming the market to ask. Without it
     * the adapter can only see that markets were *entered*, which includes enabling
     * an asset as collateral without ever borrowing — and a collateral-only account
     * would pass a health mandate that is vacuous for it.
     *
     * Naming one market was chosen over fanning out across every entered market:
     * the fan-out is unbounded (52 markets exist on BSC today), its cost scales with
     * someone else's position, and it would make the read count non-deterministic,
     * which the pinned-block evidence shape depends on being fixed.
     */
    borrowMarketAddress: evmAddressSchema,
    /**
     * Minimum excess liquidity in 1e18-scaled USD. Required, with no default,
     * because a defensible default cannot exist for an absolute amount — see the
     * limitation above.
     */
    minLiquidityUsdScaled: uint256DecimalSchema,
  })
  .strict();
export type VenusHealthAdapterConfig = z.infer<typeof venusHealthAdapterConfigSchema>;

export const categoryAdapterConfigSchema = z.discriminatedUnion("adapterId", [
  z.object({ adapterId: z.literal(GRID_ADAPTER_ID) }).passthrough(),
  z.object({ adapterId: z.literal(YIELD_ADAPTER_ID) }).passthrough(),
  z.object({ adapterId: z.literal(HEALTH_ADAPTER_ID) }).passthrough(),
  z.object({ adapterId: z.literal(VENUS_HEALTH_ADAPTER_ID) }).passthrough(),
]);

/**
 * The registry a verifier deployment pins, and the exact set of values that must
 * be hashed into the verifier policy digest.
 *
 * **Keyed by adapter ID, not by category.** `health` has two entries, because BSC
 * has two lending protocols with incompatible interfaces and the live agents
 * observed on chain use Venus rather than Aave. A table keyed by category could
 * not express that, and would silently pick one protocol for a category whose
 * supply uses the other.
 *
 * Enabling a category is three coordinated changes, per the integration
 * boundary: one static Core policy entry, a verifier-policy-hash update, and a
 * paired signer/evaluator redeploy. This table is the input to the second of
 * those. If a threshold changes and the digest does not, the deployment is
 * signing under a policy identity that no longer describes it.
 */
export const CATEGORY_ADAPTER_REGISTRY = Object.freeze([
  Object.freeze({
    category: "grid" as const,
    adapterId: GRID_ADAPTER_ID,
    evidenceSchema: GRID_EVIDENCE_SCHEMA,
    protocol: "pancakeswap-v3" as const,
    metric: "pool slot0().tick versus the declared grid band",
    reads: 1,
  }),
  Object.freeze({
    category: "yield" as const,
    adapterId: YIELD_ADAPTER_ID,
    evidenceSchema: YIELD_EVIDENCE_SCHEMA,
    protocol: "erc4626" as const,
    metric: "totalAssets/totalSupply share price versus a declared floor",
    reads: 2,
  }),
  Object.freeze({
    category: "health" as const,
    adapterId: HEALTH_ADAPTER_ID,
    evidenceSchema: HEALTH_EVIDENCE_SCHEMA,
    protocol: "aave-v3" as const,
    metric: "getUserAccountData().healthFactor versus a declared floor",
    reads: 1,
  }),
  Object.freeze({
    category: "health" as const,
    adapterId: VENUS_HEALTH_ADAPTER_ID,
    evidenceSchema: VENUS_HEALTH_EVIDENCE_SCHEMA,
    protocol: "venus" as const,
    metric:
      "getAccountLiquidity() excess liquidity and shortfall plus monitored-market borrowBalanceStored() versus a declared floor",
    reads: 3,
  }),
]);

export function assertAdapterIdShape(value: string): string {
  return adapterIdSchema.parse(value);
}
