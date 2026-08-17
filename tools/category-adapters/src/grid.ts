import { UINT160_MAX, decodeInt24, decodeUint256, wordCount } from "./abi.js";
import { gridEvidenceSchema, type GridEvidence } from "./evidence.js";
import {
  GRID_ADAPTER_ID,
  GRID_EVIDENCE_SCHEMA,
  SELECTOR_SLOT0,
  V3_MAX_SQRT_RATIO,
  V3_MAX_TICK,
  V3_MIN_SQRT_RATIO,
  V3_MIN_TICK,
  gridAdapterConfigSchema,
} from "./policy.js";
import type { PinnedBlockReader } from "./reader.js";
import { failResult, passResult, unknownResult, type AdapterResult } from "./result.js";

/**
 * Grid adapter — one read, one metric.
 *
 * The metric is the pool's live tick from `slot0()`, checked against the grid's
 * declared band. A grid strategy is a ladder of orders across a price range; if
 * spot has left that range the ladder is not being traded against, so "is spot
 * inside the band" is the shallowest check that is still a real statement about
 * whether the strategy is operating. It is one `eth_call` and it cannot be
 * satisfied by a stale cache, because the tick is read at a pinned block whose
 * hash travels in the evidence.
 *
 * What this deliberately does not claim: nothing here says the grid is
 * *profitable*, that its orders are funded, or that the agent placed them. Those
 * need order-level state that a single pool read cannot see. The evidence
 * document says exactly what was measured and no more, which is why the metric is
 * spelled out in the registry rather than described as "grid health".
 */
export async function evaluateGrid(
  input: unknown,
  reader: PinnedBlockReader,
): Promise<AdapterResult<GridEvidence>> {
  const config = gridAdapterConfigSchema.parse(input);

  const outcome = await reader.call({
    label: "slot0",
    to: config.poolAddress,
    data: SELECTOR_SLOT0,
  });
  if (outcome === undefined) {
    return unknownResult(GRID_ADAPTER_ID, "grid", "READ_UNAVAILABLE");
  }

  // slot0() returns 7 words on a v3-style pool. Requiring at least 2 rather than
  // exactly 7 keeps this working across forks that append fields, while still
  // refusing a response too short to contain the tick. Requiring exactly 7 would
  // turn a compatible pool into an outage; requiring nothing would decode the
  // tick out of whatever happened to be at word 1.
  const words = wordCount(outcome.data);
  if (words === undefined || words < 2) {
    return unknownResult(GRID_ADAPTER_ID, "grid", "READ_RETURNDATA_MALFORMED");
  }

  const sqrtPriceX96 = decodeUint256(outcome.data, 0);
  const spotTick = decodeInt24(outcome.data, 1);
  if (sqrtPriceX96 === undefined) {
    return unknownResult(GRID_ADAPTER_ID, "grid", "READ_RETURNDATA_MALFORMED");
  }
  if (spotTick === undefined) {
    // The word decoded, but not as an int24. That is not a transport problem — it
    // means the address answered a `slot0()` call with something that is not a
    // tick, so the configured address is not a compatible pool.
    return unknownResult(GRID_ADAPTER_ID, "grid", "GRID_TICK_UNINTERPRETABLE");
  }

  // Both fields are then checked against the protocol's own bounds, which are far
  // narrower than the ABI types carrying them. This is not belt-and-braces: a word
  // of all-`f` bytes decodes as a perfectly legal `int24` of -1, which would sit
  // inside most configured bands and pass. It is only implausible once you look at
  // the same word as `sqrtPriceX96`, where it exceeds `uint160` outright. Checking
  // one field and not the other leaves a contract that returns garbage able to
  // produce a confident pass.
  if (
    sqrtPriceX96 > UINT160_MAX ||
    sqrtPriceX96 < V3_MIN_SQRT_RATIO ||
    sqrtPriceX96 > V3_MAX_SQRT_RATIO
  ) {
    return unknownResult(GRID_ADAPTER_ID, "grid", "GRID_SQRT_PRICE_IMPLAUSIBLE");
  }
  if (spotTick < V3_MIN_TICK || spotTick > V3_MAX_TICK) {
    return unknownResult(GRID_ADAPTER_ID, "grid", "GRID_TICK_UNINTERPRETABLE");
  }

  const evidence = gridEvidenceSchema.parse({
    schema: GRID_EVIDENCE_SCHEMA,
    category: "grid",
    protocol: config.protocol,
    adapterId: GRID_ADAPTER_ID,
    observedAt: reader.anchor.timestamp,
    observedBlock: reader.anchor.number,
    observedBlockHash: reader.anchor.hash,
    subject: { poolAddress: config.poolAddress },
    policy: { lowerTick: config.lowerTick, upperTick: config.upperTick },
    metric: { spotTick, sqrtPriceX96: sqrtPriceX96.toString(10) },
    reads: [outcome.observation],
  } satisfies GridEvidence);

  // Inclusive on both edges: a grid whose spot sits exactly on its boundary tick
  // is still within its declared range, and excluding the edges would fail a
  // correctly-operating grid on an off-by-one.
  const inside =
    spotTick >= config.lowerTick && spotTick <= config.upperTick;
  return inside
    ? passResult(GRID_ADAPTER_ID, "grid", evidence)
    : failResult(GRID_ADAPTER_ID, "grid", "GRID_SPOT_OUTSIDE_BAND");
}
