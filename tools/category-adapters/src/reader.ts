import { createHash } from "node:crypto";

import type { BlockAnchor, ReadObservation } from "./primitives.js";

/**
 * The read surface an adapter is given.
 *
 * Two properties are enforced by the *shape* of this interface rather than by
 * convention or by a test, because both are the kind of thing that is easy to
 * violate accidentally and invisible when violated:
 *
 * 1. **All reads in one evidence document are at one block.** The reader carries
 *    its own `anchor` and exposes no way to name a block per call. An adapter
 *    therefore cannot straddle two blocks, so it cannot derive a ratio from a
 *    numerator and denominator sampled either side of a state change. For the
 *    yield adapter that is not hypothetical: `totalAssets` and `totalSupply`
 *    read one block apart during a deposit produce a share price that never
 *    existed.
 *
 * 2. **Adapters have no transport, no environment, and no clock.** There is no
 *    URL, no fetch, no `process.env`, and no `Date.now()` reachable from an
 *    adapter. Transport pinning, retry policy and endpoint trust stay in the
 *    verifier runtime that already owns them, and time comes from
 *    `anchor.timestamp`. An adapter that could open its own socket would be a
 *    second, unpinned trust path into the signing service.
 */
export interface PinnedBlockReader {
  readonly anchor: BlockAnchor;
  /**
   * Performs one `eth_call` at the pinned block.
   *
   * Resolves to `undefined` for any transport-level failure rather than
   * throwing. Adapters are required to return fail-closed results rather than
   * reject, so a reader that threw would push every caller into a try/catch
   * whose omission is silent until an endpoint goes down.
   */
  call(request: {
    readonly label: string;
    readonly to: string;
    readonly data: string;
  }): Promise<CallOutcome | undefined>;
}

export type CallOutcome = Readonly<{
  data: string;
  observation: ReadObservation;
}>;

/** Digest helper for readers that need to record request/response bytes. */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
