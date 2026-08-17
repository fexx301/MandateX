import { z } from "zod";

/**
 * Shared primitives for category evidence.
 *
 * The hard constraint shaping this file: Marketplace Core's `canonicalSha256`
 * rejects any number that is not a finite safe integer, and the evidence
 * documents produced here are hashed with exactly that function. So every
 * on-chain `uint256` is carried as a decimal *string*, and every ratio is an
 * integer at a declared scale. There are no floats anywhere in this package,
 * and no bigints in any serialized shape — a bigint would not survive
 * `JSON.stringify`, and a float would either be rejected by canonicalization or
 * silently lose the low digits of an 18-decimal value.
 */

export const evmAddressSchema = z
  .string()
  .trim()
  .regex(/^0x[0-9a-f]{40}$/, "expected a lowercase 0x-prefixed EVM address");

export const bytes32Schema = z
  .string()
  .trim()
  .regex(/^0x[0-9a-f]{64}$/, "expected a lowercase 0x-prefixed 32-byte hash");

export const sha256HexSchema = z
  .string()
  .trim()
  .regex(/^[0-9a-f]{64}$/, "expected lowercase sha-256 hex");

/**
 * A `uint256` as a decimal string with no leading zeros. Bounded at 78 digits
 * because `type(uint256).max` is 78 digits, so anything longer is not a uint256
 * regardless of what produced it.
 */
export const uint256DecimalSchema = z
  .string()
  .trim()
  .regex(/^(0|[1-9][0-9]{0,77})$/, "expected a uint256 as a decimal string");

/** Unix seconds. Safe-integer bounded so it survives canonicalization. */
export const unixSecondsSchema = z
  .number()
  .int()
  .nonnegative()
  .max(4_102_444_800, "expected a unix timestamp before the year 2100");

export const blockNumberSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

/** Uniswap-v3-style tick. */
export const tickSchema = z.number().int().min(-8_388_608).max(8_388_607);

/**
 * Adapter identifier. Matches the shape Core already uses for the one supported
 * adapter (`pancakeswap-v3-rebalancing-v1`), so the three added here read as
 * members of the same family rather than a parallel naming scheme.
 */
export const adapterIdSchema = z
  .string()
  .trim()
  .regex(
    /^[a-z0-9][a-z0-9-]*-v[0-9]+$/,
    "expected a lowercase adapter id ending in a version suffix",
  );

/**
 * The block every read in one evidence document is pinned to.
 *
 * `timestamp` is the *block's* timestamp, not the local clock. That distinction
 * is the reason this type exists: the signed v2 payload carries only
 * `{ category, observedAt }` for these three categories, so `observedAt` is the
 * entire freshness claim a consumer gets. Sourcing it from the local clock would
 * make it the verifier's opinion about when it ran; sourcing it from the block
 * makes it a statement about the chain state actually measured, which is what a
 * downstream staleness check needs in order to mean anything.
 */
export const blockAnchorSchema = z
  .object({
    number: blockNumberSchema,
    hash: bytes32Schema,
    timestamp: unixSecondsSchema,
  })
  .strict();
export type BlockAnchor = z.infer<typeof blockAnchorSchema>;

/**
 * Digests of one `eth_call` request and its response.
 *
 * These are digests of *transport observations*, which is a different thing from
 * a digest of the evidence. The verifier owns the evidence hash and recomputes
 * it (see the note in `result.ts`); these let an auditor confirm which exact
 * bytes were exchanged to produce a metric, mirroring what the existing preview
 * path already records as `requestSha256` / `responseSha256`.
 */
export const readObservationSchema = z
  .object({
    label: z.string().trim().min(1).max(64),
    to: evmAddressSchema,
    requestSha256: sha256HexSchema,
    responseSha256: sha256HexSchema,
  })
  .strict();
export type ReadObservation = z.infer<typeof readObservationSchema>;

/** Compares two uint256 decimal strings without going through a float. */
export function compareUint256Decimal(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}
