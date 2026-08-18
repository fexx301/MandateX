/**
 * Verifies whether an address is a usable ERC-4626 vault for the yield adapter,
 * and can discover live candidates when you do not have one.
 *
 *   node scripts/verify-erc4626.mjs 0xVault [0xVault2 ...]
 *   node scripts/verify-erc4626.mjs --discover [--blocks 5000]
 *
 * Why a verifier rather than a list of addresses: the yield adapter deliberately
 * ships no default vault, because a valid-looking wrong address is worse than a
 * missing one. It reads a contract that answers the call and returns a confidently
 * wrong number. So the only safe way to choose a vault is to call it and check what
 * comes back, which is what this does.
 *
 * What "usable" means here, and each condition is checked rather than assumed:
 *
 *   1. code exists at the address
 *   2. totalAssets() returns exactly one word
 *   3. totalSupply() returns exactly one word
 *   4. totalSupply() is non-zero, so share price is defined rather than 0/0
 *   5. the real adapter, run against it at a pinned block, returns a verdict
 *
 * Condition 4 is the one people skip. An empty vault is not a low share price, it
 * is an undefined one, and the adapter reports YIELD_SHARE_PRICE_UNDEFINED rather
 * than dividing by zero or inventing a value.
 *
 * READ-ONLY. Nothing is signed, sent, funded or broadcast.
 */

import { evaluateYield } from "../dist/index.js";
import {
  addressWord,
  captureAnchor,
  createPinnedReader,
  createRpc,
  decodeString,
} from "./live-reader.mjs";

const SELECTOR_TOTAL_ASSETS = "0x01e1d114";
const SELECTOR_TOTAL_SUPPLY = "0x18160ddd";
const SELECTOR_ASSET = "0x38d52e0f";
const SELECTOR_SYMBOL = "0x95d89b41";
const SELECTOR_DECIMALS = "0x313ce567";
// Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares)
const TOPIC_DEPOSIT = "0xdcbc1c05240f31ff3ad067ef1ee35ce4997762752e3a095284754544f4c709d7";

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}
const words = (hex) =>
  typeof hex === "string" && hex.startsWith("0x") && (hex.length - 2) % 64 === 0
    ? (hex.length - 2) / 64
    : undefined;
const uint = (hex, index = 0) => BigInt(`0x${hex.slice(2 + index * 64, 2 + (index + 1) * 64)}`);

const rpc = createRpc();
const anchor = await captureAnchor(rpc);
console.log(`pinned block ${anchor.number}  ${new Date(anchor.timestamp * 1000).toISOString()}\n`);

let candidates = process.argv.slice(2).filter((a) => /^0x[0-9a-fA-F]{40}$/.test(a));

if (process.argv.includes("--discover")) {
  const scan = Number(arg("blocks", "5000"));
  const only = arg("address", undefined);
  const from = anchor.number - scan;
  console.log(
    only === undefined
      ? `scanning ${scan} blocks for ERC-4626 Deposit events (unfiltered)...`
      : `scanning ${scan} blocks of ${only} for ERC-4626 Deposit events...`,
  );
  const filter = {
    topics: [TOPIC_DEPOSIT],
    fromBlock: `0x${from.toString(16)}`,
    toBlock: `0x${anchor.number.toString(16)}`,
  };
  if (only !== undefined) filter.address = only;
  let logs = [];
  try {
    logs = await rpc("eth_getLogs", [filter]);
  } catch (error) {
    console.error(`  log scan failed: ${error.message}\n`);
    // Be precise about the cause. Shrinking the block range does NOT fix this:
    // public BSC endpoints refuse a getLogs request with no `address` filter
    // regardless of range, which is a different failure from a range cap.
    if (/specify an address|address in your request/i.test(error.message)) {
      console.error("  Cause: public BSC endpoints refuse an unfiltered getLogs. This is not a");
      console.error("  block-range limit - narrowing --blocks will not help. Two ways forward:");
      console.error("    - scan one known contract:  --discover --address 0xVault");
      console.error("    - or verify candidates directly:  verify-erc4626.mjs 0xVault ...");
      console.error("  Unfiltered discovery needs an endpoint that permits it (a dedicated node).");
    } else {
      console.error("  Try a smaller --blocks, or pass candidate addresses directly.");
    }
    process.exit(1);
  }
  const seen = [...new Set(logs.map((log) => log.address.toLowerCase()))];
  console.log(`  ${logs.length} Deposit events -> ${seen.length} distinct emitters\n`);
  candidates = seen.slice(0, 10);
}

if (candidates.length === 0) {
  console.error("usage: verify-erc4626.mjs 0xVault [...]   |   --discover [--blocks N]");
  process.exit(1);
}

const usable = [];
for (const vault of candidates) {
  console.log(`── ${vault}`);
  const fail = (why) => console.log(`   REJECTED  ${why}`);

  const code = await rpc("eth_getCode", [vault, anchor.hash]).catch(() => "0x");
  if (!code || code === "0x") {
    fail("no code at this address");
    continue;
  }

  const assetsRaw = await rpc("eth_call", [{ to: vault, data: SELECTOR_TOTAL_ASSETS }, anchor.hash]).catch(() => null);
  if (assetsRaw === null) {
    fail("totalAssets() reverted - not an ERC-4626 vault");
    continue;
  }
  if (words(assetsRaw) !== 1) {
    fail(`totalAssets() returned ${words(assetsRaw) ?? "malformed"} words, expected 1`);
    continue;
  }

  const supplyRaw = await rpc("eth_call", [{ to: vault, data: SELECTOR_TOTAL_SUPPLY }, anchor.hash]).catch(() => null);
  if (supplyRaw === null || words(supplyRaw) !== 1) {
    fail("totalSupply() missing or not one word");
    continue;
  }

  const totalAssets = uint(assetsRaw);
  const totalSupply = uint(supplyRaw);
  if (totalSupply === 0n) {
    fail("totalSupply() is zero - share price is undefined, not low");
    continue;
  }

  const sharePrice = (totalAssets * 10n ** 18n) / totalSupply;
  const symbol = decodeString(
    await rpc("eth_call", [{ to: vault, data: SELECTOR_SYMBOL }, anchor.hash]).catch(() => null),
  );
  const assetRaw = await rpc("eth_call", [{ to: vault, data: SELECTOR_ASSET }, anchor.hash]).catch(() => null);
  const asset = assetRaw && words(assetRaw) === 1 ? `0x${assetRaw.slice(26)}` : "unknown";

  console.log(`   symbol        ${symbol ?? "?"}`);
  console.log(`   asset()       ${asset}${assetRaw === null ? "  (absent - suspicious for 4626)" : ""}`);
  console.log(`   totalAssets   ${totalAssets}`);
  console.log(`   totalSupply   ${totalSupply}`);
  console.log(`   share price   ${sharePrice}  (asset atomic per 1e18 share atomic)`);

  // Run the real adapter, so this reports what the verifier would actually decide
  // rather than this script's opinion of it.
  const reader = createPinnedReader(rpc, anchor);
  const result = await evaluateYield(
    {
      adapterId: "erc4626-yield-v1",
      protocol: "erc4626",
      vaultAddress: vault.toLowerCase(),
      // Floor set 10% under the live price, so a healthy vault passes and the
      // number below is a starting point rather than a recommendation.
      minSharePriceScaled: ((sharePrice * 90n) / 100n).toString(10),
    },
    reader,
  );
  console.log(`   adapter       ${result.status}${result.status === "pass" ? "" : `  ${result.code}`}`);
  if (result.status === "pass") usable.push({ vault, symbol, sharePrice });
}

console.log();
if (usable.length === 0) {
  console.log("No usable vault among the candidates. That is a real result: most contracts");
  console.log("are not ERC-4626, and the adapter refusing them is the fail-closed path working.");
  process.exit(2);
}

const pick = usable[0];
console.log(`${usable.length} usable vault(s). Paste-ready configuration for ${pick.symbol ?? pick.vault}:\n`);
const floor = (pick.sharePrice * 90n) / 100n;
console.log(
  JSON.stringify(
    {
      adapterId: "erc4626-yield-v1",
      protocol: "erc4626",
      vaultAddress: pick.vault,
      minSharePriceScaled: floor.toString(10),
    },
    null,
    2,
  ),
);
console.log(`
minSharePriceScaled above is the live share price minus 10%. Choose it yourself:
it is the drawdown you are willing to call acceptable, in asset atomic units per
1e18 share atomic units. There is no correct default, which is why the adapter
requires the field and ships none.

Re-check before pinning it: a vault's share price moves, and a floor set above the
current price will fail immediately.`);
