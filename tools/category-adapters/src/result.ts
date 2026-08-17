import { z } from "zod";

import { adapterIdSchema } from "./primitives.js";

/**
 * The fail-closed result type every adapter returns.
 *
 * The three states are deliberately the same three as Marketplace Core's
 * `gateObservationSchema` — `pass` / `fail` / `unknown` — because that is the
 * enum the result has to land in. A verified adapter run sets
 * `verification.category`, and Core already knows what to do with each state:
 * `fail` produces an exclusion, `unknown` produces an inconclusive finding, and
 * both are non-eligible. Inventing a fourth state here would have to be
 * flattened into that enum somewhere, and the flattening is where a "degraded"
 * or "partial" reading would quietly become a pass.
 *
 * The distinction that carries the weight:
 *
 *   fail    — the metric was read successfully and violates policy.
 *   unknown — the metric could not be established at all.
 *
 * These are not interchangeable, and conflating them is the specific failure
 * this taxonomy exists to prevent. An unreachable RPC endpoint is not evidence
 * that a position is unhealthy, and reporting it as `fail` would manufacture a
 * finding out of an outage. Equally, a health factor genuinely under the floor is
 * not "inconclusive" — it is a measured violation, and downgrading it to
 * `unknown` would understate a real risk. Every code below is assigned to one
 * state on that basis alone.
 */
export const adapterFailCodeSchema = z.enum([
  "GRID_SPOT_OUTSIDE_BAND",
  "YIELD_SHARE_PRICE_BELOW_FLOOR",
  "HEALTH_FACTOR_BELOW_FLOOR",
  "VENUS_ACCOUNT_SHORTFALL",
  "VENUS_LIQUIDITY_BELOW_FLOOR",
]);
export type AdapterFailCode = z.infer<typeof adapterFailCodeSchema>;

export const adapterUnknownCodeSchema = z.enum([
  // Transport. The call did not come back, or did not come back usable.
  "READ_UNAVAILABLE",
  "READ_RETURNDATA_MALFORMED",
  // Domain states where the metric is genuinely undefined rather than bad.
  "YIELD_SHARE_PRICE_UNDEFINED",
  "HEALTH_NO_DEBT_POSITION",
  // Venus reports a computation error in-band rather than reverting, and its
  // liquidity/shortfall pair has an invariant that can be checked.
  "VENUS_LIQUIDITY_COMPUTATION_FAILED",
  "VENUS_NO_POSITION",
  "VENUS_LIQUIDITY_INCONSISTENT",
  // The pool answered, but not with a state a v3 pool can be in.
  "GRID_TICK_UNINTERPRETABLE",
  "GRID_SQRT_PRICE_IMPLAUSIBLE",
]);
export type AdapterUnknownCode = z.infer<typeof adapterUnknownCodeSchema>;

const messages: Readonly<Record<AdapterFailCode | AdapterUnknownCode, string>> =
  Object.freeze({
    GRID_SPOT_OUTSIDE_BAND:
      "The pool's current tick is outside the configured grid band, so the grid is not operating over live price.",
    YIELD_SHARE_PRICE_BELOW_FLOOR:
      "The vault's share price is below the configured floor.",
    HEALTH_FACTOR_BELOW_FLOOR:
      "The account's health factor is below the configured floor.",
    VENUS_ACCOUNT_SHORTFALL:
      "The account is below its Venus collateral requirement and is liquidatable.",
    VENUS_LIQUIDITY_BELOW_FLOOR:
      "The account's excess Venus liquidity is below the configured floor.",
    VENUS_LIQUIDITY_COMPUTATION_FAILED:
      "Venus returned a nonzero error code instead of a liquidity result, so the metric could not be established.",
    VENUS_NO_POSITION:
      "The account has entered no Venus markets, so there is no collateral position to maintain.",
    VENUS_LIQUIDITY_INCONSISTENT:
      "Venus reported both excess liquidity and a shortfall, which the protocol's own invariant forbids.",
    READ_UNAVAILABLE:
      "A required on-chain read did not complete, so the metric could not be established.",
    READ_RETURNDATA_MALFORMED:
      "A required on-chain read returned data that is not a well-formed static-ABI response.",
    YIELD_SHARE_PRICE_UNDEFINED:
      "The vault has no shares outstanding, so share price is undefined rather than low.",
    HEALTH_NO_DEBT_POSITION:
      "The account has no outstanding debt, so there is no health factor to maintain.",
    GRID_TICK_UNINTERPRETABLE:
      "The pool returned a tick outside the range a v3 pool can hold, so the configured address is not a compatible pool.",
    GRID_SQRT_PRICE_IMPLAUSIBLE:
      "The pool returned a sqrt price outside the range a v3 pool can hold, so the configured address is not a compatible pool.",
  });

export type AdapterCategory = "grid" | "yield" | "health";

export type AdapterPass<Evidence> = Readonly<{
  status: "pass";
  adapterId: string;
  category: AdapterCategory;
  evidence: Evidence;
}>;

export type AdapterFail = Readonly<{
  status: "fail";
  adapterId: string;
  category: AdapterCategory;
  code: AdapterFailCode;
  message: string;
}>;

export type AdapterUnknown = Readonly<{
  status: "unknown";
  adapterId: string;
  category: AdapterCategory;
  code: AdapterUnknownCode;
  message: string;
}>;

/**
 * Note what this union does *not* contain: any field in which an adapter could
 * report a digest of its own evidence.
 *
 * That absence is structural, not an oversight. The integration contract
 * requires the verifier to canonicalize and hash evidence itself and to not
 * trust a digest supplied by an adapter, and the most durable way to honour that
 * is to leave the adapter with nowhere to put one. If the field existed, some
 * future caller would eventually read it instead of recomputing — and a
 * compromised or merely buggy adapter would then be choosing the commitment that
 * gets signed. The evidence documents are plain canonical-JSON data; the hash is
 * the verifier's to compute, over bytes it derived.
 */
export type AdapterResult<Evidence> =
  | AdapterPass<Evidence>
  | AdapterFail
  | AdapterUnknown;

export function passResult<Evidence>(
  adapterId: string,
  category: AdapterCategory,
  evidence: Evidence,
): AdapterPass<Evidence> {
  return Object.freeze({
    status: "pass" as const,
    adapterId: adapterIdSchema.parse(adapterId),
    category,
    evidence,
  });
}

export function failResult(
  adapterId: string,
  category: AdapterCategory,
  code: AdapterFailCode,
): AdapterFail {
  return Object.freeze({
    status: "fail" as const,
    adapterId: adapterIdSchema.parse(adapterId),
    category,
    code,
    message: messages[code],
  });
}

export function unknownResult(
  adapterId: string,
  category: AdapterCategory,
  code: AdapterUnknownCode,
): AdapterUnknown {
  return Object.freeze({
    status: "unknown" as const,
    adapterId: adapterIdSchema.parse(adapterId),
    category,
    code,
    message: messages[code],
  });
}

/**
 * The gate value to write into `verification.category` for a result.
 *
 * Trivial by construction, and that is the point — the mapping is an identity on
 * the status field, so there is no translation layer in which a `fail` could
 * become anything else.
 */
export function categoryGateObservation<Evidence>(
  result: AdapterResult<Evidence>,
): "pass" | "fail" | "unknown" {
  return result.status;
}
