import { addressCalldata, decodeDynamicArrayLength, decodeUint256, wordCount } from "./abi.js";
import { venusHealthEvidenceSchema, type VenusHealthEvidence } from "./evidence.js";
import {
  SELECTOR_GET_ACCOUNT_LIQUIDITY,
  SELECTOR_GET_ASSETS_IN,
  VENUS_HEALTH_ADAPTER_ID,
  VENUS_HEALTH_EVIDENCE_SCHEMA,
  venusHealthAdapterConfigSchema,
} from "./policy.js";
import type { PinnedBlockReader } from "./reader.js";
import { failResult, passResult, unknownResult, type AdapterResult } from "./result.js";

/**
 * `getAccountLiquidity(address)` returns three words.
 *
 * Compound-family contracts report failure *in band* — a nonzero first word rather
 * than a revert — so the error code has to be checked explicitly. Skipping it means
 * reading `liquidity` and `shortfall` out of a response that has already announced
 * itself as meaningless, and since a failed computation returns zeros, the result
 * would look like a position with no buffer rather than like an error.
 */
const WORD_ERROR = 0;
const WORD_LIQUIDITY = 1;
const WORD_SHORTFALL = 2;
const EXPECTED_WORDS = 3;

/**
 * Venus lending-health adapter — two reads, one metric.
 *
 * This exists because Aave is not what BSC lending agents actually use. Every live
 * health agent found on chain 56 during the supply research monitors Venus, and
 * Venus is a Compound-v2 fork with no health factor at all: `getAccountLiquidity`
 * returns an absolute USD buffer above the collateral requirement, or an absolute
 * amount below it, with at most one of the two nonzero. Three words with different
 * meanings and no ratio anywhere — a different adapter, not a reconfiguration of
 * the Aave one.
 *
 * The interesting case, and the reason for the second read: Venus reports both "no
 * position at all" and "a position with exactly zero buffer" as
 * `liquidity == 0 && shortfall == 0`. Those two states deserve opposite verdicts —
 * nothing to maintain versus the riskiest non-liquidatable state there is — and one
 * call cannot tell them apart. `getAssetsIn` disambiguates by returning the markets
 * the account has entered. Without it this adapter would have to treat a maximally
 * leveraged position and an empty account identically.
 *
 * KNOWN LIMITATION, and it is narrower than the Aave sibling's guarantee. This
 * adapter detects *no position*, not *no debt*. `getAssetsIn` returns the markets an
 * account has **entered**, which includes enabling an asset as collateral without
 * ever borrowing against it. So a collateral-only account has `marketsEntered > 0`,
 * a large `liquidity`, `shortfall == 0` — and passes, even though it has no debt to
 * maintain and a mandate to hold health above a floor is vacuous for it.
 *
 * `aave-v3-health-v1` does not have this hole: it reads `totalDebtBase` directly and
 * refuses the no-debt case outright. Closing it here needs a borrow balance, which
 * Venus only exposes per market (`borrowBalanceStored` on each vToken), so it means
 * either an unbounded fan-out over the entered markets or a new required config field
 * naming the market to monitor. That is a config-shape change, so it is recorded for
 * decision rather than taken unilaterally — see `plan.md` §7.
 */
export async function evaluateVenusHealth(
  input: unknown,
  reader: PinnedBlockReader,
): Promise<AdapterResult<VenusHealthEvidence>> {
  const config = venusHealthAdapterConfigSchema.parse(input);

  const [liquidityOutcome, assetsOutcome] = await Promise.all([
    reader.call({
      label: "getAccountLiquidity",
      to: config.comptrollerAddress,
      data: addressCalldata(SELECTOR_GET_ACCOUNT_LIQUIDITY, config.accountAddress),
    }),
    reader.call({
      label: "getAssetsIn",
      to: config.comptrollerAddress,
      data: addressCalldata(SELECTOR_GET_ASSETS_IN, config.accountAddress),
    }),
  ]);
  if (liquidityOutcome === undefined || assetsOutcome === undefined) {
    return unknownResult(VENUS_HEALTH_ADAPTER_ID, "health", "READ_UNAVAILABLE");
  }

  if (wordCount(liquidityOutcome.data) !== EXPECTED_WORDS) {
    return unknownResult(VENUS_HEALTH_ADAPTER_ID, "health", "READ_RETURNDATA_MALFORMED");
  }
  const error = decodeUint256(liquidityOutcome.data, WORD_ERROR);
  const liquidity = decodeUint256(liquidityOutcome.data, WORD_LIQUIDITY);
  const shortfall = decodeUint256(liquidityOutcome.data, WORD_SHORTFALL);
  const marketsEntered = decodeDynamicArrayLength(assetsOutcome.data);
  if (
    error === undefined ||
    liquidity === undefined ||
    shortfall === undefined ||
    marketsEntered === undefined
  ) {
    return unknownResult(VENUS_HEALTH_ADAPTER_ID, "health", "READ_RETURNDATA_MALFORMED");
  }

  // In-band error first: everything below it would be reading zeros as data.
  if (error !== 0n) {
    return unknownResult(
      VENUS_HEALTH_ADAPTER_ID,
      "health",
      "VENUS_LIQUIDITY_COMPUTATION_FAILED",
    );
  }

  // The protocol's own invariant. If it does not hold, the response is not
  // describing a state Venus can be in, so nothing derived from it is trustworthy —
  // including a comparison that might otherwise have passed on the liquidity leg.
  if (liquidity > 0n && shortfall > 0n) {
    return unknownResult(VENUS_HEALTH_ADAPTER_ID, "health", "VENUS_LIQUIDITY_INCONSISTENT");
  }

  const evidence = venusHealthEvidenceSchema.parse({
    schema: VENUS_HEALTH_EVIDENCE_SCHEMA,
    category: "health",
    protocol: config.protocol,
    adapterId: VENUS_HEALTH_ADAPTER_ID,
    observedAt: reader.anchor.timestamp,
    observedBlock: reader.anchor.number,
    observedBlockHash: reader.anchor.hash,
    subject: {
      comptrollerAddress: config.comptrollerAddress,
      accountAddress: config.accountAddress,
    },
    policy: { minLiquidityUsdScaled: config.minLiquidityUsdScaled },
    metric: {
      liquidityUsdScaled: liquidity.toString(10),
      shortfallUsdScaled: shortfall.toString(10),
      marketsEntered,
    },
    reads: [liquidityOutcome.observation, assetsOutcome.observation],
  } satisfies VenusHealthEvidence);

  // No markets entered means there is no position to maintain, so there is nothing
  // to measure. Checked before the shortfall branch so an empty account can never be
  // reported as liquidatable. Note this is weaker than Aave's no-debt refusal: an
  // account that entered a market as collateral but never borrowed reads as a
  // position here. See the limitation in this file's header.
  if (marketsEntered === 0) {
    return unknownResult(VENUS_HEALTH_ADAPTER_ID, "health", "VENUS_NO_POSITION");
  }

  // A shortfall is liquidatable now, which is a stronger statement than "under the
  // floor", so it gets its own code rather than being folded into the comparison.
  if (shortfall > 0n) {
    return failResult(VENUS_HEALTH_ADAPTER_ID, "health", "VENUS_ACCOUNT_SHORTFALL");
  }

  return liquidity >= BigInt(config.minLiquidityUsdScaled)
    ? passResult(VENUS_HEALTH_ADAPTER_ID, "health", evidence)
    : failResult(VENUS_HEALTH_ADAPTER_ID, "health", "VENUS_LIQUIDITY_BELOW_FLOOR");
}
