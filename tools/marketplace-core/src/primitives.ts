import { z } from "zod";

export const MAX_CANDIDATES = 8 as const;

export const marketplaceCategorySchema = z.enum([
  "rebalancing",
  "grid",
  "yield",
  "health",
]);
export type MarketplaceCategory = z.infer<typeof marketplaceCategorySchema>;

export const canonicalIdentifierSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/, "expected a canonical identifier");

export const unixSecondsSchema = z
  .number()
  .int()
  .positive()
  .max(Number.MAX_SAFE_INTEGER);

export const blockNumberSchema = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER);

export const addressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/, "expected an EVM address")
  .transform((value) => value.toLowerCase());

export const bytes32Schema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{64}$/, "expected a bytes32 value")
  .transform((value) => value.toLowerCase());

export const sha256Schema = z
  .string()
  .regex(/^[a-f0-9]{64}$/, "expected a lowercase SHA-256 digest");

export const uint256DecimalSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/, "expected a canonical unsigned decimal integer")
  .refine((value) => {
    try {
      return BigInt(value) < 1n << 256n;
    } catch {
      return false;
    }
  }, "integer is outside uint256 range");

export const tokenIdSchema = uint256DecimalSchema;
export const usdMicrosSchema = uint256DecimalSchema;
export const basisPointsSchema = z.number().int().min(0).max(10_000);
export const tickSchema = z.number().int().min(-887_272).max(887_272);

export const protocolIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9._-]*$/, "expected a lowercase protocol identifier");

export const callIdSchema = z.string().trim().min(1).max(256);

export const gateObservationSchema = z.enum(["pass", "fail", "unknown"]);
export type GateObservation = z.infer<typeof gateObservationSchema>;

export function compareCanonicalStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function sortUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareCanonicalStrings);
}

export function candidateId(chainId: number, tokenId: string): string {
  return `${chainId}:${tokenId}`;
}

export interface CandidateKey {
  readonly chainId: number;
  readonly tokenId: string;
}

export function compareCandidateKeys(
  left: CandidateKey,
  right: CandidateKey,
): number {
  if (left.chainId !== right.chainId) return left.chainId - right.chainId;
  const leftTokenId = BigInt(left.tokenId);
  const rightTokenId = BigInt(right.tokenId);
  return leftTokenId < rightTokenId ? -1 : leftTokenId > rightTokenId ? 1 : 0;
}
