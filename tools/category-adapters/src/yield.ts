import { decodeUint256, wordCount } from "./abi.js";
import { yieldEvidenceSchema, type YieldEvidence } from "./evidence.js";
import {
  RATIO_SCALE,
  SELECTOR_TOTAL_ASSETS,
  SELECTOR_TOTAL_SUPPLY,
  YIELD_ADAPTER_ID,
  YIELD_EVIDENCE_SCHEMA,
  yieldAdapterConfigSchema,
} from "./policy.js";
import type { PinnedBlockReader } from "./reader.js";
import { failResult, passResult, unknownResult, type AdapterResult } from "./result.js";

/**
 * Yield adapter — two reads, one derived metric.
 *
 * Share price is `totalAssets / totalSupply`, the standard ERC-4626 solvency
 * ratio. Both reads happen at the same pinned block by construction (see
 * `PinnedBlockReader`), which matters more here than anywhere else in this
 * package: sampling the numerator and denominator one block apart across a
 * deposit yields a share price that never existed at any block, and it looks
 * entirely reasonable.
 *
 * The arithmetic is `BigInt` throughout and the result is floor-divided at a
 * fixed 1e18 scale. No float appears at any point — an 18-decimal ratio through
 * an IEEE double loses its low digits, and the loss is largest exactly where a
 * threshold comparison is closest.
 */
export async function evaluateYield(
  input: unknown,
  reader: PinnedBlockReader,
): Promise<AdapterResult<YieldEvidence>> {
  const config = yieldAdapterConfigSchema.parse(input);

  const [assetsOutcome, supplyOutcome] = await Promise.all([
    reader.call({
      label: "totalAssets",
      to: config.vaultAddress,
      data: SELECTOR_TOTAL_ASSETS,
    }),
    reader.call({
      label: "totalSupply",
      to: config.vaultAddress,
      data: SELECTOR_TOTAL_SUPPLY,
    }),
  ]);
  if (assetsOutcome === undefined || supplyOutcome === undefined) {
    return unknownResult(YIELD_ADAPTER_ID, "yield", "READ_UNAVAILABLE");
  }

  // Both must be exactly one word. Unlike `slot0()`, these return a single
  // uint256 by specification, so a longer response is not a compatible extension
  // — it is a different function.
  if (wordCount(assetsOutcome.data) !== 1 || wordCount(supplyOutcome.data) !== 1) {
    return unknownResult(YIELD_ADAPTER_ID, "yield", "READ_RETURNDATA_MALFORMED");
  }
  const totalAssets = decodeUint256(assetsOutcome.data, 0);
  const totalSupply = decodeUint256(supplyOutcome.data, 0);
  if (totalAssets === undefined || totalSupply === undefined) {
    return unknownResult(YIELD_ADAPTER_ID, "yield", "READ_RETURNDATA_MALFORMED");
  }

  // An empty vault is `unknown`, not `fail`. With no shares outstanding the ratio
  // is 0/0 — undefined, not low — and calling that a policy violation would
  // report a fresh or fully-withdrawn vault as unhealthy. It is also the division
  // that would otherwise throw.
  if (totalSupply === 0n) {
    return unknownResult(YIELD_ADAPTER_ID, "yield", "YIELD_SHARE_PRICE_UNDEFINED");
  }

  const sharePriceScaled = (totalAssets * RATIO_SCALE) / totalSupply;

  const evidence = yieldEvidenceSchema.parse({
    schema: YIELD_EVIDENCE_SCHEMA,
    category: "yield",
    protocol: config.protocol,
    adapterId: YIELD_ADAPTER_ID,
    observedAt: reader.anchor.timestamp,
    observedBlock: reader.anchor.number,
    observedBlockHash: reader.anchor.hash,
    subject: { vaultAddress: config.vaultAddress },
    policy: { minSharePriceScaled: config.minSharePriceScaled },
    metric: {
      totalAssets: totalAssets.toString(10),
      totalSupply: totalSupply.toString(10),
      sharePriceScaled: sharePriceScaled.toString(10),
    },
    reads: [assetsOutcome.observation, supplyOutcome.observation],
  } satisfies YieldEvidence);

  return sharePriceScaled >= BigInt(config.minSharePriceScaled)
    ? passResult(YIELD_ADAPTER_ID, "yield", evidence)
    : failResult(YIELD_ADAPTER_ID, "yield", "YIELD_SHARE_PRICE_BELOW_FLOOR");
}
