export const MIN_REBALANCE_TICK = -887_272;
export const MAX_REBALANCE_TICK = 887_272;
export const MAX_REBALANCE_TICK_SPACING =
  MAX_REBALANCE_TICK - MIN_REBALANCE_TICK;

export function deriveNearestCenteredExactRange(
  currentTick: number,
  targetWidthTicks: number,
  tickSpacing: number,
): { readonly lower: number; readonly upper: number } {
  const lower =
    Math.floor(
      (2 * currentTick - targetWidthTicks + tickSpacing) /
        (2 * tickSpacing),
    ) * tickSpacing;
  return { lower, upper: lower + targetWidthTicks };
}
