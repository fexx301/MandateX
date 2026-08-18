import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalSha256,
  displaySafeQuoteProjectionPayloadSchema,
} from "@mandatex/marketplace-core";

import { UINT256_MAX, decodeDynamicArrayLength, decodeInt24, decodeUint256, wordCount } from "./abi.js";
import {
  categoryEvidenceDocumentSchema,
  toSignedCategoryEvidence,
  type CategoryEvidenceDocument,
} from "./evidence.js";
import { evaluateGrid } from "./grid.js";
import { evaluateHealth } from "./health.js";
import {
  CATEGORY_ADAPTER_REGISTRY,
  DEFAULT_MIN_HEALTH_FACTOR_SCALED,
  GRID_ADAPTER_ID,
  HEALTH_ADAPTER_ID,
  VENUS_HEALTH_ADAPTER_ID,
  YIELD_ADAPTER_ID,
} from "./policy.js";
import type { BlockAnchor } from "./primitives.js";
import type { CallOutcome, PinnedBlockReader } from "./reader.js";
import { sha256Hex } from "./reader.js";
import { categoryGateObservation, type AdapterResult } from "./result.js";
import { evaluateVenusHealth } from "./venus-health.js";
import { evaluateYield } from "./yield.js";

/**
 * Adapter smoke suite. No network, no clock, no chain.
 *
 * Every read is served by a stub whose return data is constructed byte by byte in
 * this file, which is what makes the failure cases testable at all: an
 * `eth_call` against a live pool cannot be made to return a tick outside int24,
 * a vault with zero shares on demand, or Aave's no-debt sentinel. Those are
 * exactly the branches where a wrong answer is silent, so they are the ones that
 * most need a deterministic test.
 *
 * The two groups that carry the most weight are F and G. Group F hands finished
 * evidence to Marketplace Core's *own* canonicalizer and its own strict payload
 * schema, so compatibility with the frozen contract is demonstrated by the
 * contract's parser rather than asserted by me. Group G checks the claims the
 * hand-off document makes about this package, so the README cannot drift away
 * from the code without a test going red.
 */

const REPO_ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..");
const BASELINE_VECTOR = join(
  REPO_ROOT,
  "fixtures",
  "attestations",
  "vectors",
  "valid",
  "baseline.json",
);

let passed = 0;
const failures: string[] = [];

function check(name: string, ok: boolean, detail?: string): void {
  if (ok) {
    passed += 1;
    return;
  }
  failures.push(detail === undefined ? name : `${name} — ${detail}`);
}

function group(title: string): void {
  process.stdout.write(`\n  ${title}\n`);
}

// ── stub chain ───────────────────────────────────────────────────────────────

const ANCHOR: BlockAnchor = Object.freeze({
  number: 41_000_000,
  hash: `0x${"ab".repeat(32)}`,
  timestamp: 1_760_000_000,
});

/** One 32-byte word of unsigned hex. */
function word(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

/** One 32-byte word holding a two's-complement signed value. */
function signedWord(value: bigint): string {
  const normalized = value < 0n ? (1n << 256n) + value : value;
  return word(normalized);
}

function returndata(...words: string[]): string {
  return `0x${words.join("")}`;
}

/**
 * A reader bound to one block, serving canned return data by label.
 *
 * A label mapped to `undefined` models a transport failure; a label absent from
 * the map is a programming error in the test and throws loudly rather than
 * silently becoming an `unknown` result that would make a broken test look green.
 */
function stubReader(
  responses: Readonly<Record<string, string | undefined>>,
  anchor: BlockAnchor = ANCHOR,
): PinnedBlockReader & { readonly calls: string[] } {
  const calls: string[] = [];
  return {
    anchor,
    calls,
    async call(request): Promise<CallOutcome | undefined> {
      calls.push(request.label);
      if (!(request.label in responses)) {
        throw new Error(`stub has no response for label "${request.label}"`);
      }
      const data = responses[request.label];
      if (data === undefined) return undefined;
      return {
        data,
        observation: {
          label: request.label,
          to: request.to,
          requestSha256: sha256Hex(`${request.to}:${request.data}`),
          responseSha256: sha256Hex(data),
        },
      };
    },
  };
}

const POOL = "0x1111111111111111111111111111111111111111";
const VAULT = "0x2222222222222222222222222222222222222222";
const AAVE_POOL = "0x3333333333333333333333333333333333333333";
const ACCOUNT = "0x4444444444444444444444444444444444444444";

const GRID_CONFIG = {
  adapterId: GRID_ADAPTER_ID,
  protocol: "pancakeswap-v3",
  poolAddress: POOL,
  lowerTick: -1_000,
  upperTick: 1_000,
} as const;

const YIELD_CONFIG = {
  adapterId: YIELD_ADAPTER_ID,
  protocol: "erc4626",
  vaultAddress: VAULT,
  minSharePriceScaled: "1000000000000000000",
} as const;

const HEALTH_CONFIG = {
  adapterId: HEALTH_ADAPTER_ID,
  protocol: "aave-v3",
  poolAddress: AAVE_POOL,
  accountAddress: ACCOUNT,
  minHealthFactorScaled: "1100000000000000000",
} as const;

/** sqrtPriceX96 at tick 0, i.e. 2^96. Inside the v3 legal range. */
const VALID_SQRT_PRICE = 79_228_162_514_264_337_593_543_950_336n;

/** `slot0()` return data: 7 words, tick at index 1. */
function slot0(tick: bigint, sqrtPriceX96 = VALID_SQRT_PRICE): string {
  return returndata(
    word(sqrtPriceX96),
    signedWord(tick),
    word(0n),
    word(0n),
    word(0n),
    word(0n),
    word(1n),
  );
}

/** `getUserAccountData()` return data: 6 words, health factor at index 5. */
function accountData(
  collateral: bigint,
  debt: bigint,
  healthFactor: bigint,
): string {
  return returndata(
    word(collateral),
    word(debt),
    word(0n),
    word(8_000n),
    word(7_500n),
    word(healthFactor),
  );
}

async function main(): Promise<void> {
  process.stdout.write("category-adapters smoke\n");

  // ── A. ABI decoding ────────────────────────────────────────────────────────
  group("ABI decoding");

  check("a full word decodes as an unsigned integer", decodeUint256(returndata(word(12_345n)), 0) === 12_345n);
  check("a negative int24 sign-extends correctly", decodeInt24(returndata(signedWord(-887n)), 0) === -887);
  check("a positive int24 decodes unchanged", decodeInt24(returndata(signedWord(887n)), 0) === 887);
  check("the int24 minimum decodes", decodeInt24(returndata(signedWord(-8_388_608n)), 0) === -8_388_608);
  check(
    "a value one below the int24 minimum is refused rather than truncated",
    decodeInt24(returndata(signedWord(-8_388_609n)), 0) === undefined,
  );
  check(
    "non-hex payloads decode to undefined rather than NaN",
    decodeUint256("0xnothex", 0) === undefined && wordCount("0xnothex") === undefined,
  );
  check(
    "a payload that is not a whole number of words is refused",
    wordCount(`0x${"ff".repeat(31)}`) === undefined,
  );
  check(
    "reading past the end of the data returns undefined",
    decodeUint256(returndata(word(1n)), 4) === undefined,
  );

  // ── B. Grid ────────────────────────────────────────────────────────────────
  group("Grid adapter");

  const gridInside = await evaluateGrid(GRID_CONFIG, stubReader({ slot0: slot0(250n) }));
  check("a tick inside the band passes", gridInside.status === "pass", gridInside.status);
  check(
    "the passing evidence records the measured tick",
    gridInside.status === "pass" && gridInside.evidence.metric.spotTick === 250,
  );
  check(
    "the passing evidence records the band it was judged against",
    gridInside.status === "pass" &&
      gridInside.evidence.policy.lowerTick === -1_000 &&
      gridInside.evidence.policy.upperTick === 1_000,
  );
  check(
    "observedAt comes from the block, not the local clock",
    gridInside.status === "pass" && gridInside.evidence.observedAt === ANCHOR.timestamp,
  );

  for (const [label, tick] of [["lower", -1_000n], ["upper", 1_000n]] as const) {
    const edge = await evaluateGrid(GRID_CONFIG, stubReader({ slot0: slot0(tick) }));
    check(`a tick exactly on the ${label} edge passes`, edge.status === "pass", edge.status);
  }

  const gridOutside = await evaluateGrid(GRID_CONFIG, stubReader({ slot0: slot0(1_001n) }));
  check(
    "a tick above the band fails as a measured violation",
    gridOutside.status === "fail" && gridOutside.code === "GRID_SPOT_OUTSIDE_BAND",
    gridOutside.status,
  );

  const gridBelow = await evaluateGrid(GRID_CONFIG, stubReader({ slot0: slot0(-1_001n) }));
  check(
    "a tick below the band fails too",
    gridBelow.status === "fail" && gridBelow.code === "GRID_SPOT_OUTSIDE_BAND",
  );

  const gridDown = await evaluateGrid(GRID_CONFIG, stubReader({ slot0: undefined }));
  check(
    "an unreachable pool is unknown, not fail — an outage is not evidence of a bad grid",
    gridDown.status === "unknown" && gridDown.code === "READ_UNAVAILABLE",
    gridDown.status,
  );

  const gridShort = await evaluateGrid(
    GRID_CONFIG,
    stubReader({ slot0: returndata(word(1n)) }),
  );
  check(
    "return data too short to hold a tick is unknown",
    gridShort.status === "unknown" && gridShort.code === "READ_RETURNDATA_MALFORMED",
    gridShort.status,
  );

  const gridWrongContract = await evaluateGrid(
    GRID_CONFIG,
    stubReader({ slot0: returndata(word(1n), word(2n ** 200n), word(0n)) }),
  );
  check(
    "a word that is not an int24 means the address is not a pool",
    gridWrongContract.status === "unknown" &&
      gridWrongContract.code === "GRID_TICK_UNINTERPRETABLE",
    gridWrongContract.status,
  );

  const gridExtended = await evaluateGrid(
    GRID_CONFIG,
    stubReader({
      slot0: returndata(
        word(VALID_SQRT_PRICE),
        signedWord(0n),
        ...Array.from({ length: 9 }, () => word(0n)),
      ),
    }),
  );
  check(
    "a fork returning extra slot0 fields still works",
    gridExtended.status === "pass",
    gridExtended.status,
  );

  // The two protocol-bound checks. Both words below decode cleanly at the ABI
  // level, which is exactly why the bounds are needed.
  const gridWideSqrt = await evaluateGrid(
    GRID_CONFIG,
    stubReader({ slot0: slot0(0n, UINT256_MAX) }),
  );
  check(
    "a sqrt price wider than uint160 is refused even though the tick is in band",
    gridWideSqrt.status === "unknown" && gridWideSqrt.code === "GRID_SQRT_PRICE_IMPLAUSIBLE",
    gridWideSqrt.status,
  );

  const gridLowSqrt = await evaluateGrid(GRID_CONFIG, stubReader({ slot0: slot0(0n, 1n) }));
  check(
    "a sqrt price below the v3 minimum is refused",
    gridLowSqrt.status === "unknown" && gridLowSqrt.code === "GRID_SQRT_PRICE_IMPLAUSIBLE",
    gridLowSqrt.status,
  );

  // An all-`f` word is the case that found this gap: it is a legal int24 of -1,
  // sits inside the configured band, and would have passed on the tick alone.
  const gridAllOnes = await evaluateGrid(
    GRID_CONFIG,
    stubReader({ slot0: `0x${"f".repeat(64 * 7)}` }),
  );
  check(
    "an all-ones slot0 does not pass, despite decoding as an in-band tick of -1",
    gridAllOnes.status !== "pass",
    gridAllOnes.status,
  );

  const gridWideTick = await evaluateGrid(
    { ...GRID_CONFIG, lowerTick: -8_000_000, upperTick: 8_000_000 },
    stubReader({ slot0: slot0(1_000_000n) }),
  );
  check(
    "a tick inside int24 but outside the v3 range is refused, even with a band that would admit it",
    gridWideTick.status === "unknown" && gridWideTick.code === "GRID_TICK_UNINTERPRETABLE",
    gridWideTick.status,
  );

  // ── C. Yield ───────────────────────────────────────────────────────────────
  group("Yield adapter");

  const yieldAbove = await evaluateYield(
    YIELD_CONFIG,
    stubReader({
      totalAssets: returndata(word(2_000n * 10n ** 18n)),
      totalSupply: returndata(word(1_000n * 10n ** 18n)),
    }),
  );
  check("a share price above the floor passes", yieldAbove.status === "pass", yieldAbove.status);
  check(
    "share price is computed at 1e18 scale with integer arithmetic",
    yieldAbove.status === "pass" &&
      yieldAbove.evidence.metric.sharePriceScaled === "2000000000000000000",
    yieldAbove.status === "pass" ? yieldAbove.evidence.metric.sharePriceScaled : yieldAbove.status,
  );
  check(
    "both operands are recorded so the division is reproducible",
    yieldAbove.status === "pass" &&
      yieldAbove.evidence.metric.totalAssets === "2000000000000000000000" &&
      yieldAbove.evidence.metric.totalSupply === "1000000000000000000000",
  );
  check(
    "both reads went to the same pinned block",
    yieldAbove.status === "pass" &&
      yieldAbove.evidence.reads.length === 2 &&
      yieldAbove.evidence.observedBlock === ANCHOR.number,
  );

  const yieldAtFloor = await evaluateYield(
    YIELD_CONFIG,
    stubReader({
      totalAssets: returndata(word(10n ** 18n)),
      totalSupply: returndata(word(10n ** 18n)),
    }),
  );
  check("a share price exactly at the floor passes", yieldAtFloor.status === "pass", yieldAtFloor.status);

  const yieldBelow = await evaluateYield(
    YIELD_CONFIG,
    stubReader({
      totalAssets: returndata(word(10n ** 18n - 1n)),
      totalSupply: returndata(word(10n ** 18n)),
    }),
  );
  check(
    "a share price one atomic unit below the floor fails",
    yieldBelow.status === "fail" && yieldBelow.code === "YIELD_SHARE_PRICE_BELOW_FLOOR",
    yieldBelow.status,
  );

  const yieldEmpty = await evaluateYield(
    YIELD_CONFIG,
    stubReader({
      totalAssets: returndata(word(0n)),
      totalSupply: returndata(word(0n)),
    }),
  );
  check(
    "an empty vault is unknown — share price is undefined, not low",
    yieldEmpty.status === "unknown" && yieldEmpty.code === "YIELD_SHARE_PRICE_UNDEFINED",
    yieldEmpty.status,
  );

  const yieldHalfDown = await evaluateYield(
    YIELD_CONFIG,
    stubReader({ totalAssets: returndata(word(1n)), totalSupply: undefined }),
  );
  check(
    "one failed read of the two is unknown, not a half-computed ratio",
    yieldHalfDown.status === "unknown" && yieldHalfDown.code === "READ_UNAVAILABLE",
    yieldHalfDown.status,
  );

  const yieldLong = await evaluateYield(
    YIELD_CONFIG,
    stubReader({
      totalAssets: returndata(word(1n), word(2n)),
      totalSupply: returndata(word(1n)),
    }),
  );
  check(
    "a multi-word answer to totalAssets is malformed, not an extension",
    yieldLong.status === "unknown" && yieldLong.code === "READ_RETURNDATA_MALFORMED",
    yieldLong.status,
  );

  // The precision claim, stated as a test rather than a comment: a ratio whose
  // low digits matter is preserved exactly. Through a double, this share price
  // would round and compare equal to the floor.
  const yieldPrecision = await evaluateYield(
    { ...YIELD_CONFIG, minSharePriceScaled: "1000000000000000001" },
    stubReader({
      totalAssets: returndata(word(10n ** 36n)),
      totalSupply: returndata(word(10n ** 18n)),
    }),
  );
  check(
    "an 18-decimal comparison keeps its low digits",
    yieldPrecision.status === "pass" &&
      yieldPrecision.evidence.metric.sharePriceScaled === (10n ** 36n).toString(10),
    yieldPrecision.status,
  );

  // ── D. Health ──────────────────────────────────────────────────────────────
  group("Health adapter");

  const healthy = await evaluateHealth(
    HEALTH_CONFIG,
    stubReader({ getUserAccountData: accountData(5_000n, 1_000n, 2n * 10n ** 18n) }),
  );
  check("a health factor above the floor passes", healthy.status === "pass", healthy.status);
  check(
    "the evidence records the floor applied",
    healthy.status === "pass" &&
      healthy.evidence.policy.minHealthFactorScaled === "1100000000000000000",
  );
  check(
    "the evidence records debt and collateral alongside the factor",
    healthy.status === "pass" &&
      healthy.evidence.metric.totalDebtBase === "1000" &&
      healthy.evidence.metric.totalCollateralBase === "5000",
  );

  const unhealthy = await evaluateHealth(
    HEALTH_CONFIG,
    stubReader({ getUserAccountData: accountData(5_000n, 4_900n, 10n ** 18n) }),
  );
  check(
    "a health factor of 1.0 is below the 1.1 floor and fails",
    unhealthy.status === "fail" && unhealthy.code === "HEALTH_FACTOR_BELOW_FLOOR",
    unhealthy.status,
  );

  // The sentinel. This is the bug the adapter exists to not have.
  const sentinel = await evaluateHealth(
    HEALTH_CONFIG,
    stubReader({ getUserAccountData: accountData(5_000n, 0n, UINT256_MAX) }),
  );
  check(
    "the uint256-max no-debt sentinel is unknown, not the healthiest possible pass",
    sentinel.status === "unknown" && sentinel.code === "HEALTH_NO_DEBT_POSITION",
    sentinel.status,
  );

  // Second witness on its own: debt is zero but the sentinel is absent.
  const zeroDebtOnly = await evaluateHealth(
    HEALTH_CONFIG,
    stubReader({ getUserAccountData: accountData(5_000n, 0n, 5n * 10n ** 18n) }),
  );
  check(
    "zero debt alone is enough to withhold a pass, without the sentinel",
    zeroDebtOnly.status === "unknown" && zeroDebtOnly.code === "HEALTH_NO_DEBT_POSITION",
    zeroDebtOnly.status,
  );

  const healthShort = await evaluateHealth(
    HEALTH_CONFIG,
    stubReader({ getUserAccountData: returndata(word(1n), word(2n), word(3n)) }),
  );
  check(
    "return data with the wrong word count is unknown, not decoded anyway",
    healthShort.status === "unknown" && healthShort.code === "READ_RETURNDATA_MALFORMED",
    healthShort.status,
  );

  const healthDown = await evaluateHealth(
    HEALTH_CONFIG,
    stubReader({ getUserAccountData: undefined }),
  );
  check(
    "an unreachable lending pool is unknown",
    healthDown.status === "unknown" && healthDown.code === "READ_UNAVAILABLE",
  );

  const healthDefaulted = await evaluateHealth(
    {
      adapterId: HEALTH_ADAPTER_ID,
      protocol: "aave-v3",
      poolAddress: AAVE_POOL,
      accountAddress: ACCOUNT,
    },
    stubReader({ getUserAccountData: accountData(5_000n, 1_000n, 10n ** 18n) }),
  );
  check(
    "the default floor is above 1.0, so an account at exactly liquidation threshold does not pass",
    healthDefaulted.status === "fail",
    healthDefaulted.status,
  );
  check(
    "the documented default floor is the one the code uses",
    DEFAULT_MIN_HEALTH_FACTOR_SCALED === "1100000000000000000",
  );

  const healthCalldata = stubReader({
    getUserAccountData: accountData(5_000n, 1_000n, 2n * 10n ** 18n),
  });
  await evaluateHealth(HEALTH_CONFIG, healthCalldata);
  check("the health read is a single call", healthCalldata.calls.length === 1);

  // ── D2. Venus health ───────────────────────────────────────────────────────
  group("Venus health adapter");

  // Verbatim from the live Venus Comptroller on chain 56. The zero address has
  // entered no markets, so this is the real no-position response.
  const LIVE_VENUS_ASSETS_IN =
    "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000";

  const VENUS_CONFIG = {
    adapterId: VENUS_HEALTH_ADAPTER_ID,
    protocol: "venus",
    comptrollerAddress: "0x5555555555555555555555555555555555555555",
    accountAddress: ACCOUNT,
    borrowMarketAddress: "0x6666666666666666666666666666666666666666",
    minLiquidityUsdScaled: (1_000n * 10n ** 18n).toString(10),
  } as const;

  /** `getAccountLiquidity()` return data: (error, liquidity, shortfall). */
  const liquidityData = (error: bigint, liquidity: bigint, shortfall: bigint): string =>
    returndata(word(error), word(liquidity), word(shortfall));

  /** `getAssetsIn()` return data: offset then length, elements omitted when zero. */
  const assetsInData = (count: number): string =>
    returndata(
      word(32n),
      word(BigInt(count)),
      ...Array.from({ length: count }, (_, index) => word(BigInt(index + 1))),
    );

  /**
   * `borrowBalanceStored()` return data in the shape the **live** vTokens actually
   * use: three words with the balance in word 0. Compound declares a single `uint`,
   * so building the default this way means every Venus test also exercises the
   * tolerance that keeps the adapter working against real markets.
   */
  const borrowData = (balance: bigint): string =>
    returndata(word(balance), word(0n), word(0n));

  const DEFAULT_BORROW = 4_200n * 10n ** 18n;

  /** stubReader with a nonzero borrow balance unless a case overrides it. */
  const venusReader = (
    responses: Readonly<Record<string, string | undefined>>,
  ): ReturnType<typeof stubReader> =>
    stubReader({ borrowBalanceStored: borrowData(DEFAULT_BORROW), ...responses });

  const venusLive = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 0n, 0n),
      getAssetsIn: LIVE_VENUS_ASSETS_IN,
    }),
  );
  check(
    "the real on-chain no-position response is unknown, not a zero-buffer failure",
    venusLive.status === "unknown" && venusLive.code === "VENUS_NO_POSITION",
    venusLive.status,
  );

  const venusHealthy = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 5_000n * 10n ** 18n, 0n),
      getAssetsIn: assetsInData(2),
    }),
  );
  check("liquidity above the floor passes", venusHealthy.status === "pass", venusHealthy.status);
  check(
    "the evidence records markets entered, so no-position stays distinguishable later",
    venusHealthy.status === "pass" && venusHealthy.evidence.metric.marketsEntered === 2,
  );
  check(
    "the Venus evidence declares the health category under the venus protocol",
    venusHealthy.status === "pass" &&
      venusHealthy.evidence.category === "health" &&
      venusHealthy.evidence.protocol === "venus",
  );

  // Documents the known limitation in venus-health.ts rather than leaving it silent.
  // A collateral-only account — markets entered, no borrows — is indistinguishable
  // from a healthy borrower through `getAssetsIn`, so it passes. The Aave sibling
  // refuses the equivalent case via `totalDebtBase`. If this is ever fixed with a
  // borrow-balance read, this assertion must be consciously inverted, which is the
  // point of asserting it.
  const venusCollateralOnly = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 9_000n * 10n ** 18n, 0n),
      getAssetsIn: assetsInData(1),
      // Entered a market as collateral, borrowed nothing. Ample liquidity, no
      // shortfall — the exact shape that passed on two reads.
      borrowBalanceStored: borrowData(0n),
    }),
  );
  check(
    "GAP CLOSED: a collateral-only account no longer passes — markets entered is not debt",
    venusCollateralOnly.status === "unknown" &&
      venusCollateralOnly.code === "VENUS_NO_DEBT_POSITION",
    venusCollateralOnly.status,
  );
  check(
    "the Aave and Venus adapters now refuse no-debt for the same reason",
    venusCollateralOnly.status === "unknown" && sentinel.status === "unknown",
  );

  // The live return shape. Compound declares one word; the real vTokens return
  // three. Both must work, and a real balance must be read from word 0.
  const venusLiveBorrowShape = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 9_000n * 10n ** 18n, 0n),
      getAssetsIn: assetsInData(2),
      borrowBalanceStored: returndata(word(10_000_024_862_639_051_791_976n), word(0n), word(0n)),
    }),
  );
  check(
    "a three-word borrow response, as the live vTokens return, reads the balance from word 0",
    venusLiveBorrowShape.status === "pass" &&
      venusLiveBorrowShape.evidence.metric.borrowBalanceStored ===
        "10000024862639051791976",
    venusLiveBorrowShape.status,
  );

  const venusSingleWordBorrow = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 9_000n * 10n ** 18n, 0n),
      getAssetsIn: assetsInData(2),
      borrowBalanceStored: returndata(word(500n)),
    }),
  );
  check(
    "a one-word borrow response, as Compound declares, also works",
    venusSingleWordBorrow.status === "pass",
    venusSingleWordBorrow.status,
  );

  const venusBorrowDown = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 9_000n * 10n ** 18n, 0n),
      getAssetsIn: assetsInData(2),
      borrowBalanceStored: undefined,
    }),
  );
  check(
    "an unreachable borrow market is unknown, not an assumed zero debt",
    venusBorrowDown.status === "unknown" && venusBorrowDown.code === "READ_UNAVAILABLE",
    venusBorrowDown.status,
  );

  const venusBorrowMalformed = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 9_000n * 10n ** 18n, 0n),
      getAssetsIn: assetsInData(2),
      borrowBalanceStored: "0x",
    }),
  );
  check(
    "empty borrow return data is malformed, not zero debt",
    venusBorrowMalformed.status === "unknown" &&
      venusBorrowMalformed.code === "READ_RETURNDATA_MALFORMED",
    venusBorrowMalformed.status,
  );

  const venusReadCount = venusReader({
    getAccountLiquidity: liquidityData(0n, 9_000n * 10n ** 18n, 0n),
    getAssetsIn: assetsInData(2),
  });
  await evaluateVenusHealth(VENUS_CONFIG, venusReadCount);
  check(
    "the Venus adapter issues exactly three reads, and the count is deterministic",
    venusReadCount.calls.length === 3 &&
      new Set(venusReadCount.calls).size === 3,
    venusReadCount.calls.join(","),
  );

  const venusThin = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 999n * 10n ** 18n, 0n),
      getAssetsIn: assetsInData(1),
    }),
  );
  check(
    "liquidity below the floor fails",
    venusThin.status === "fail" && venusThin.code === "VENUS_LIQUIDITY_BELOW_FLOOR",
    venusThin.status,
  );

  const venusShortfall = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 0n, 250n * 10n ** 18n),
      getAssetsIn: assetsInData(3),
    }),
  );
  check(
    "a shortfall is its own failure, stronger than being under the floor",
    venusShortfall.status === "fail" && venusShortfall.code === "VENUS_ACCOUNT_SHORTFALL",
    venusShortfall.status,
  );

  // Ordering matters: an account with no markets must never be reported
  // liquidatable, even if the liquidity call somehow reports a shortfall.
  const venusEmptyWithShortfall = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 0n, 250n * 10n ** 18n),
      getAssetsIn: assetsInData(0),
    }),
  );
  check(
    "an account in no markets is never reported liquidatable",
    venusEmptyWithShortfall.status === "unknown" &&
      venusEmptyWithShortfall.code === "VENUS_NO_POSITION",
    venusEmptyWithShortfall.status,
  );

  const venusError = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(9n, 0n, 0n),
      getAssetsIn: assetsInData(2),
    }),
  );
  check(
    "an in-band error code is unknown, not a position with no buffer",
    venusError.status === "unknown" && venusError.code === "VENUS_LIQUIDITY_COMPUTATION_FAILED",
    venusError.status,
  );

  const venusInconsistent = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: liquidityData(0n, 10n ** 18n, 10n ** 18n),
      getAssetsIn: assetsInData(2),
    }),
  );
  check(
    "both liquidity and shortfall nonzero violates Venus's invariant and is refused",
    venusInconsistent.status === "unknown" &&
      venusInconsistent.code === "VENUS_LIQUIDITY_INCONSISTENT",
    venusInconsistent.status,
  );

  const venusShort = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({
      getAccountLiquidity: returndata(word(0n), word(0n)),
      getAssetsIn: assetsInData(1),
    }),
  );
  check(
    "a two-word liquidity response is malformed",
    venusShort.status === "unknown" && venusShort.code === "READ_RETURNDATA_MALFORMED",
    venusShort.status,
  );

  const venusDown = await evaluateVenusHealth(
    VENUS_CONFIG,
    venusReader({ getAccountLiquidity: undefined, getAssetsIn: assetsInData(1) }),
  );
  check(
    "an unreachable comptroller is unknown",
    venusDown.status === "unknown" && venusDown.code === "READ_UNAVAILABLE",
  );

  // Dynamic-array header decoding, including the hostile-offset case.
  check(
    "the live getAssetsIn response decodes to zero markets",
    decodeDynamicArrayLength(LIVE_VENUS_ASSETS_IN) === 0,
  );
  check("a populated array decodes its length", decodeDynamicArrayLength(assetsInData(3)) === 3);
  check(
    "an offset pointing past the end of the data is refused",
    decodeDynamicArrayLength(returndata(word(320n), word(1n))) === undefined,
  );
  check(
    "a length longer than the words present is refused",
    decodeDynamicArrayLength(returndata(word(32n), word(9n))) === undefined,
  );
  check(
    "a non-word-aligned offset is refused",
    decodeDynamicArrayLength(returndata(word(33n), word(0n))) === undefined,
  );

  // ── E. Fail-closed discipline ──────────────────────────────────────────────
  group("Fail-closed discipline");

  // Two different error classes, deliberately handled two different ways.
  // Malformed *configuration* is a deployment fault and throws at the boundary,
  // because a verifier running with an unparseable adapter config should not
  // start rather than emit `unknown` for every request until someone notices.
  // Malformed *chain data* is a runtime condition and must never throw, because
  // an exception escaping an adapter would take down the request path that is
  // supposed to fail closed.
  let configThrew = false;
  try {
    await evaluateGrid({ ...GRID_CONFIG, poolAddress: "not-an-address" }, stubReader({}));
  } catch {
    configThrew = true;
  }
  check("a malformed address in configuration throws at the boundary", configThrew);

  let degenerateThrew = false;
  try {
    await evaluateGrid({ ...GRID_CONFIG, lowerTick: 10, upperTick: 10 }, stubReader({}));
  } catch {
    degenerateThrew = true;
  }
  check("a degenerate grid band is rejected as configuration", degenerateThrew);

  const hostile = [
    "0x",
    "0xzz",
    `0x${"f".repeat(63)}`,
    `0x${"f".repeat(64 * 8)}`,
    returndata(word(UINT256_MAX)),
  ];
  let hostileThrew: string | undefined;
  for (const data of hostile) {
    for (const run of [
      () => evaluateGrid(GRID_CONFIG, stubReader({ slot0: data })),
      () => evaluateYield(YIELD_CONFIG, stubReader({ totalAssets: data, totalSupply: data })),
      () => evaluateHealth(HEALTH_CONFIG, stubReader({ getUserAccountData: data })),
    ]) {
      try {
        await run();
      } catch (error) {
        hostileThrew = `${data.slice(0, 12)}… threw: ${(error as Error).message}`;
      }
    }
  }
  check("no adapter throws on hostile chain data", hostileThrew === undefined, hostileThrew);

  // Grid and health both have an invariant that hostile data violates, so both
  // refuse it. Yield does not, and that is recorded here rather than papered over:
  // `totalAssets == totalSupply == type(uint256).max` is a legal uint256 pair and
  // ERC-4626 places no bound on either, so the share price is exactly 1.0 and the
  // adapter passes. There is no principled check to add — inventing a ceiling
  // would reject real vaults to make this line look better. What protects the
  // yield path is the operator-pinned vault address, not a plausibility bound.
  const yieldSaturated = await evaluateYield(
    YIELD_CONFIG,
    stubReader({
      totalAssets: returndata(word(UINT256_MAX)),
      totalSupply: returndata(word(UINT256_MAX)),
    }),
  );
  check(
    "a saturated vault yields share price 1.0 with no invariant to violate",
    yieldSaturated.status === "pass" &&
      yieldSaturated.evidence.metric.sharePriceScaled === "1000000000000000000",
    yieldSaturated.status,
  );
  check(
    "grid refuses all-ones data on a protocol bound",
    (await evaluateGrid(GRID_CONFIG, stubReader({ slot0: `0x${"f".repeat(64 * 8)}` }))).status !==
      "pass",
  );
  check(
    "health refuses all-ones data on the no-debt sentinel",
    (await evaluateHealth(
      HEALTH_CONFIG,
      stubReader({ getUserAccountData: `0x${"f".repeat(64 * 6)}` }),
    )).status !== "pass",
  );

  const results: AdapterResult<unknown>[] = [gridInside, gridOutside, gridDown];
  check(
    "the Core gate value is the adapter status unchanged",
    results.every((result) => categoryGateObservation(result) === result.status),
  );

  // The structural claim from result.ts: an adapter has nowhere to report a
  // digest of its own evidence. Any hash-shaped key must be either the block hash
  // or a transport observation inside `reads`.
  const documents: CategoryEvidenceDocument[] = [
    gridInside.status === "pass" ? gridInside.evidence : undefined,
    yieldAbove.status === "pass" ? yieldAbove.evidence : undefined,
    healthy.status === "pass" ? healthy.evidence : undefined,
    venusHealthy.status === "pass" ? venusHealthy.evidence : undefined,
  ].filter((value): value is CategoryEvidenceDocument => value !== undefined);
  check("all four adapters produced evidence to inspect", documents.length === 4);

  const strayDigests: string[] = [];
  const walk = (value: unknown, path: string): void => {
    if (Array.isArray(value)) {
      value.forEach((entry, index) => walk(entry, `${path}[${index}]`));
      return;
    }
    if (value === null || typeof value !== "object") return;
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      const next = `${path}.${key}`;
      if (/sha256$|hash$|digest$/i.test(key)) {
        const permitted = next.endsWith(".observedBlockHash") || /\.reads\[\d+\]\./.test(next);
        if (!permitted) strayDigests.push(next);
      }
      walk(entry, next);
    }
  };
  for (const document of documents) walk(document, "$");
  check(
    "no evidence document carries a digest of itself for the verifier to trust",
    strayDigests.length === 0,
    strayDigests.join(", "),
  );

  // ── F. Marketplace Core compatibility ──────────────────────────────────────
  group("Marketplace Core compatibility");

  for (const document of documents) {
    check(
      `${document.adapterId} evidence round-trips its own schema`,
      categoryEvidenceDocumentSchema.safeParse(document).success,
    );
  }

  let canonicalError: string | undefined;
  const digests: string[] = [];
  for (const document of documents) {
    try {
      digests.push(canonicalSha256(document));
    } catch (error) {
      canonicalError = `${document.adapterId}: ${(error as Error).message}`;
    }
  }
  check(
    "every evidence document survives Core's own canonicalizer",
    canonicalError === undefined && digests.length === 4,
    canonicalError,
  );
  check(
    "each canonical digest is 64 hex characters",
    digests.every((digest) => /^[0-9a-f]{64}$/.test(digest)),
  );
  check(
    "the two health adapters produce distinct digests despite sharing a category",
    new Set(digests).size === 4,
  );

  // Canonicalization must be insensitive to key order, or the verifier and any
  // auditor recomputing the hash from stored JSON would disagree.
  const [firstDocument] = documents;
  if (firstDocument !== undefined) {
    const reordered = Object.fromEntries(
      Object.entries(firstDocument as Record<string, unknown>).reverse(),
    );
    check(
      "the canonical digest is independent of key order",
      canonicalSha256(reordered) === canonicalSha256(firstDocument),
    );
  }

  // Substitute grid evidence into a payload already known to be valid, and let
  // Core's strict schema decide. This is the check that would catch drift between
  // this package and the frozen contract.
  const vector = JSON.parse(readFileSync(BASELINE_VECTOR, "utf8")) as {
    wire: string | Record<string, unknown>;
  };
  const wire = (typeof vector.wire === "string" ? JSON.parse(vector.wire) : vector.wire) as {
    payload: Record<string, unknown>;
  };
  check(
    "the baseline fixture payload is valid before substitution",
    displaySafeQuoteProjectionPayloadSchema.safeParse(wire.payload).success,
  );

  const gridDocument = documents.find((document) => document.category === "grid");
  if (gridDocument !== undefined) {
    const substituted = {
      ...wire.payload,
      category: "grid",
      categoryEvidence: toSignedCategoryEvidence(gridDocument),
    };
    const accepted = displaySafeQuoteProjectionPayloadSchema.safeParse(substituted);
    check(
      "Core accepts a projection carrying the narrowed grid evidence",
      accepted.success,
      accepted.success ? undefined : JSON.stringify(accepted.error.issues.slice(0, 2)),
    );

    // The reason a display sidecar is necessary rather than optional: Core's
    // schema is strict, so the metric cannot ride along in the signed payload.
    const overstuffed = {
      ...wire.payload,
      category: "grid",
      categoryEvidence: {
        ...toSignedCategoryEvidence(gridDocument),
        spotTick: gridDocument.metric.spotTick,
      },
    };
    check(
      "Core rejects the same projection with a metric added to the evidence",
      !displaySafeQuoteProjectionPayloadSchema.safeParse(overstuffed).success,
    );

    check(
      "the narrowed evidence carries exactly category and observedAt",
      JSON.stringify(Object.keys(toSignedCategoryEvidence(gridDocument)).sort()) ===
        JSON.stringify(["category", "observedAt"]),
    );
  }

  // ── G. Registry and hand-off integrity ─────────────────────────────────────
  group("Registry and hand-off integrity");

  check("the registry covers four adapters", CATEGORY_ADAPTER_REGISTRY.length === 4);
  check(
    "the registry categories are grid, yield and health twice",
    JSON.stringify(CATEGORY_ADAPTER_REGISTRY.map((entry) => entry.category).sort()) ===
      JSON.stringify(["grid", "health", "health", "yield"]),
  );
  check(
    "every registered adapter id is unique — the registry is keyed by adapter, not category",
    new Set(CATEGORY_ADAPTER_REGISTRY.map((entry) => entry.adapterId)).size === 4,
  );
  check(
    "health has two adapters on two different protocols",
    CATEGORY_ADAPTER_REGISTRY.filter((entry) => entry.category === "health").length === 2 &&
      new Set(
        CATEGORY_ADAPTER_REGISTRY.filter((entry) => entry.category === "health").map(
          (entry) => entry.protocol,
        ),
      ).size === 2,
  );
  check(
    "every registered adapter id ends in a version suffix",
    CATEGORY_ADAPTER_REGISTRY.every((entry) => /-v\d+$/.test(entry.adapterId)),
  );
  check(
    "every registered evidence schema is versioned under the mandatex.category namespace",
    CATEGORY_ADAPTER_REGISTRY.every((entry) =>
      /^mandatex\.category\.[a-z-]+\.v\d+$/.test(entry.evidenceSchema),
    ),
  );
  check(
    "the registry's declared read counts match what the adapters actually issue",
    CATEGORY_ADAPTER_REGISTRY.every((entry) => {
      const document = documents.find((candidate) => candidate.adapterId === entry.adapterId);
      return document !== undefined && document.reads.length === entry.reads;
    }),
  );
  check(
    "each adapter stamps its own id into its evidence",
    documents.every((document) =>
      CATEGORY_ADAPTER_REGISTRY.some(
        (entry) =>
          entry.adapterId === document.adapterId && entry.evidenceSchema === document.schema,
      ),
    ),
  );

  // ── report ─────────────────────────────────────────────────────────────────
  process.stdout.write(`\n${passed}/${passed + failures.length} checks passed\n`);
  if (failures.length > 0) {
    process.stdout.write("\nfailures:\n");
    for (const failure of failures) process.stdout.write(`  ✗ ${failure}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write("all category adapter checks passed\n");
}

await main();
