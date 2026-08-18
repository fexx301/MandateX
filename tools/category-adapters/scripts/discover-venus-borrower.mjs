/**
 * Finds a live Venus borrower and runs the real health adapter against it.
 *
 *   node scripts/discover-venus-borrower.mjs [--market vUSDT] [--blocks 3000] [--floor 1000]
 *
 * Why this exists: the lending-health adapter needs an account that actually owes
 * something. An account with no debt is not a weaker test case, it is a different
 * one — the adapter correctly returns VENUS_NO_DEBT_POSITION, because a mandate to
 * hold a health factor above a floor is vacuous for an account with nothing
 * borrowed. So a demonstration needs a real borrower.
 *
 * It does NOT need to be your borrower. Every call the adapter makes is a read, so
 * monitoring is possible without holding any key. That is the whole point of the
 * category: evidence about an on-chain position, produced by observation.
 *
 * This script hardcodes no borrower. It reads recent Borrow events and tests the
 * candidates, because a hardcoded address is a demo that breaks silently the day
 * that account repays.
 *
 * READ-ONLY. No transaction is ever sent, no key is touched, no wallet path is
 * read. If you want an account you control instead, fork BSC with Anvil and open a
 * position there — that is the only transaction path this project permits.
 */

import { evaluateVenusHealth } from "../dist/index.js";
import {
  addressWord,
  captureAnchor,
  createPinnedReader,
  createRpc,
  decodeString,
} from "./live-reader.mjs";

const COMPTROLLER = "0xfd36e2c2a6789db23113685031d7f16329158384";
const SELECTOR_GET_ALL_MARKETS = "0xb0772d0b";
const SELECTOR_SYMBOL = "0x95d89b41";
// Borrow(address borrower, uint256 borrowAmount, uint256 accountBorrows, uint256 totalBorrows)
const TOPIC_BORROW = "0x13ed6866d4e1ee6da46f845c46d7e54120883d75c5ea9a2dacc1c4ca8984ab80";

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

const wantMarket = arg("market", "vUSDT");
const scanBlocks = Number(arg("blocks", "3000"));
const floorUsd = BigInt(arg("floor", "1000"));

const rpc = createRpc();
const anchor = await captureAnchor(rpc);
console.log(`pinned block ${anchor.number}  ${new Date(anchor.timestamp * 1000).toISOString()}`);

// ── locate the market ────────────────────────────────────────────────────────
const marketsRaw = await rpc("eth_call", [
  { to: COMPTROLLER, data: SELECTOR_GET_ALL_MARKETS },
  anchor.hash,
]);
const body = marketsRaw.slice(2);
const count = Number.parseInt(body.slice(64, 128), 16);
const markets = [];
for (let i = 0; i < count; i += 1) {
  markets.push(`0x${body.slice(128 + i * 64 + 24, 128 + (i + 1) * 64)}`);
}

let market;
for (const address of markets) {
  const symbol = decodeString(
    await rpc("eth_call", [{ to: address, data: SELECTOR_SYMBOL }, anchor.hash]),
  );
  if (symbol === wantMarket) {
    market = { address, symbol };
    break;
  }
}
if (market === undefined) {
  console.error(`no market named ${wantMarket} among ${count} Venus markets`);
  process.exit(1);
}
console.log(`market ${market.symbol} ${market.address}  (of ${count} Venus markets)\n`);

// ── collect candidate borrowers from recent Borrow events ────────────────────
const from = anchor.number - scanBlocks;
let logs = [];
try {
  logs = await rpc("eth_getLogs", [
    {
      address: market.address,
      topics: [TOPIC_BORROW],
      fromBlock: `0x${from.toString(16)}`,
      toBlock: `0x${anchor.number.toString(16)}`,
    },
  ]);
} catch (error) {
  console.error(`log scan failed (${error.message}); widen --blocks or try later`);
  process.exit(1);
}

const borrowers = [...new Set(logs.map((log) => `0x${log.data.slice(2, 66).slice(24)}`))];
console.log(`${logs.length} Borrow events over ${scanBlocks} blocks -> ${borrowers.length} distinct borrowers`);
if (borrowers.length === 0) {
  console.error("none found; widen --blocks (Venus borrows are intermittent)");
  process.exit(1);
}

// ── run the real adapter against each ────────────────────────────────────────
const config = {
  adapterId: "venus-health-v1",
  protocol: "venus",
  comptrollerAddress: COMPTROLLER,
  borrowMarketAddress: market.address,
  minLiquidityUsdScaled: (floorUsd * 10n ** 18n).toString(10),
};

const usable = [];
for (const account of borrowers.slice(0, 8)) {
  const reader = createPinnedReader(rpc, anchor);
  const result = await evaluateVenusHealth({ ...config, accountAddress: account }, reader);
  const line = [`  ${account}`, result.status.padEnd(7)];
  if (result.status === "pass") {
    const metric = result.evidence.metric;
    const usd = (value) => (BigInt(value) / 10n ** 18n).toString();
    line.push(
      `liquidity $${usd(metric.liquidityUsdScaled)}`,
      `borrow ${usd(metric.borrowBalanceStored)}`,
      `markets ${metric.marketsEntered}`,
    );
    usable.push({ account, result });
  } else {
    line.push(result.code);
  }
  console.log(line.join("  "));
}

// ── report ───────────────────────────────────────────────────────────────────
console.log();
if (usable.length === 0) {
  console.log("No borrower passed. That is a real answer, not a failure: every candidate");
  console.log("either repaid, holds no debt in this market, or sits under the floor.");
  console.log(`Try a different --market, a wider --blocks, or a lower --floor.`);
  process.exit(2);
}

const chosen = usable[0];
console.log(`${usable.length} of ${Math.min(borrowers.length, 8)} produce verifiable PASS evidence.\n`);
console.log("Paste-ready adapter configuration:\n");
console.log(
  JSON.stringify(
    {
      adapterId: "venus-health-v1",
      protocol: "venus",
      comptrollerAddress: COMPTROLLER,
      accountAddress: chosen.account,
      borrowMarketAddress: market.address,
      minLiquidityUsdScaled: config.minLiquidityUsdScaled,
    },
    null,
    2,
  ),
);
console.log(`
Label this honestly wherever it is shown: it is a live read-only observation of a
public third-party position, not an account this project controls. It proves the
adapter produces real evidence from mainnet. It does not imply a mandate
relationship with that account's owner.

The position can change or close at any time. Re-run this script rather than
pinning the address into anything permanent.`);
