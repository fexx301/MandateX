import { addressCalldata, decodeDynamicArrayLength, decodeUint256, wordCount } from "./abi.js";
import { venusHealthEvidenceSchema, type VenusHealthEvidence } from "./evidence.js";
import {
  SELECTOR_BORROW_BALANCE_STORED,
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
 * The third read closes what was previously a documented gap. `getAssetsIn` reports
 * markets *entered*, which includes enabling an asset as collateral without ever
 * borrowing, so on two reads a collateral-only account passed a mandate that is
 * vacuous for it — strictly weaker than the Aave sibling, which reads
 * `totalDebtBase` and refuses the no-debt case outright. `borrowBalanceStored` on a
 * named market now supplies the missing fact, so both adapters refuse no-debt for
 * the same reason. Resolved per Codex's decision to name one market rather than fan
 * out across every entered market: the fan-out is unbounded, its cost scales with
 * someone else's position, and it would make the read count non-deterministic.
 *
 * MEASURED, NOT ASSUMED: `borrowBalanceStored(address)` is declared in Compound v2
 * as returning a single `uint`, but the live Venus vTokens on BSC return **three**
 * words, with the balance in word 0 and two trailing zero words. Verified against a
 * real ~10,000 USDT borrow on vUSDT. So this reads word 0 and requires only that a
 * word be present, exactly as the grid adapter tolerates a fork appending fields to
 * `slot0()`. Requiring exactly one word — the natural reading of the declared ABI —
 * would make this adapter report `READ_RETURNDATA_MALFORMED` against every real
 * Venus market.
 */
export async function evaluateVenusHealth(
  input: unknown,
  reader: PinnedBlockReader,
): Promise<AdapterResult<VenusHealthEvidence>> {
  const config = venusHealthAdapterConfigSchema.parse(input);

  const [liquidityOutcome, assetsOutcome, borrowOutcome] = await Promise.all([
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
    reader.call({
      label: "borrowBalanceStored",
      to: config.borrowMarketAddress,
      data: addressCalldata(SELECTOR_BORROW_BALANCE_STORED, config.accountAddress),
    }),
  ]);
  if (
    liquidityOutcome === undefined ||
    assetsOutcome === undefined ||
    borrowOutcome === undefined
  ) {
    return unknownResult(VENUS_HEALTH_ADAPTER_ID, "health", "READ_UNAVAILABLE");
  }

  if (wordCount(liquidityOutcome.data) !== EXPECTED_WORDS) {
    return unknownResult(VENUS_HEALTH_ADAPTER_ID, "health", "READ_RETURNDATA_MALFORMED");
  }
  const error = decodeUint256(liquidityOutcome.data, WORD_ERROR);
  const liquidity = decodeUint256(liquidityOutcome.data, WORD_LIQUIDITY);
  const shortfall = decodeUint256(liquidityOutcome.data, WORD_SHORTFALL);
  const marketsEntered = decodeDynamicArrayLength(assetsOutcome.data);
  // At least one word, not exactly one. See the note in this file's header: the
  // live vTokens return three.
  const borrowWords = wordCount(borrowOutcome.data);
  const borrowBalance =
    borrowWords !== undefined && borrowWords >= 1
      ? decodeUint256(borrowOutcome.data, 0)
      : undefined;
  if (
    error === undefined ||
    liquidity === undefined ||
    shortfall === undefined ||
    marketsEntered === undefined ||
    borrowBalance === undefined
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
      borrowMarketAddress: config.borrowMarketAddress,
    },
    policy: { minLiquidityUsdScaled: config.minLiquidityUsdScaled },
    metric: {
      liquidityUsdScaled: liquidity.toString(10),
      shortfallUsdScaled: shortfall.toString(10),
      marketsEntered,
      borrowBalanceStored: borrowBalance.toString(10),
    },
    reads: [liquidityOutcome.observation, assetsOutcome.observation, borrowOutcome.observation],
  } satisfies VenusHealthEvidence);

  // No markets entered means there is no position at all. Checked before the
  // shortfall branch so an empty account can never be reported as liquidatable.
  if (marketsEntered === 0) {
    return unknownResult(VENUS_HEALTH_ADAPTER_ID, "health", "VENUS_NO_POSITION");
  }

  // Entered a market but owes nothing in the monitored one. This is the branch the
  // third read exists for: a collateral-only account has nothing to maintain, so a
  // health mandate is vacuous for it and passing it would overstate what was
  // verified. Same verdict the Aave adapter reaches from `totalDebtBase`.
  if (borrowBalance === 0n) {
    return unknownResult(VENUS_HEALTH_ADAPTER_ID, "health", "VENUS_NO_DEBT_POSITION");
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
