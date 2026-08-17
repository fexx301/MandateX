import { z } from "zod";

import {
  adapterIdSchema,
  blockNumberSchema,
  bytes32Schema,
  evmAddressSchema,
  readObservationSchema,
  tickSchema,
  uint256DecimalSchema,
  unixSecondsSchema,
} from "./primitives.js";
import {
  GRID_EVIDENCE_SCHEMA,
  HEALTH_EVIDENCE_SCHEMA,
  YIELD_EVIDENCE_SCHEMA,
} from "./policy.js";

/**
 * Evidence documents.
 *
 * These are what a `pass` carries, and they are the payload the verifier
 * canonicalizes and hashes into the artifact committed by
 * `sourceCommitments.quoteValidationSha256`. They do **not** travel in the signed
 * v2 projection: that carries only `{ category, observedAt }` for grid, yield and
 * health, which is the frozen contract and is not being renegotiated here. So
 * these documents are the entire audit trail for how a category verdict was
 * reached, and anything omitted here is unrecoverable later.
 *
 * All four schemas share one shape, so a reviewer reads the second and third for
 * free:
 *
 *   subject — the addresses observed
 *   policy  — the thresholds applied, recorded per-document
 *   metric  — what was measured
 *   reads   — digests of the exact calls that produced the metric
 *
 * `policy` is embedded rather than referenced on purpose. Thresholds are global
 * deployment configuration (see `policy.ts`), so an evidence document that named
 * a threshold only by reference would be uninterpretable the moment the
 * deployment's configuration moved on. Recording the value applied means a stored
 * artifact still answers "what was this judged against" years later, without
 * anyone having to reconstruct which config was live at that block.
 *
 * Every schema is `.strict()`, and none has a field for a digest of itself. See
 * the note on `AdapterResult` in `result.ts` for why that absence is load-bearing.
 */

const evidenceEnvelopeShape = {
  adapterId: adapterIdSchema,
  observedAt: unixSecondsSchema,
  observedBlock: blockNumberSchema,
  observedBlockHash: bytes32Schema,
  reads: z.array(readObservationSchema).min(1).max(4),
} as const;

export const gridEvidenceSchema = z
  .object({
    schema: z.literal(GRID_EVIDENCE_SCHEMA),
    category: z.literal("grid"),
    protocol: z.literal("pancakeswap-v3"),
    ...evidenceEnvelopeShape,
    subject: z.object({ poolAddress: evmAddressSchema }).strict(),
    policy: z
      .object({ lowerTick: tickSchema, upperTick: tickSchema })
      .strict(),
    metric: z
      .object({
        /** `slot0().tick` — the pool's live tick. */
        spotTick: tickSchema,
        /**
         * `slot0().sqrtPriceX96`, recorded alongside the tick because the tick is
         * a floor of the true price. Two different prices inside one tick give
         * the same tick, so an auditor re-deriving the verdict from the tick alone
         * cannot reproduce a borderline case; the raw sqrt price can.
         */
        sqrtPriceX96: uint256DecimalSchema,
      })
      .strict(),
  })
  .strict();
export type GridEvidence = z.infer<typeof gridEvidenceSchema>;

export const yieldEvidenceSchema = z
  .object({
    schema: z.literal(YIELD_EVIDENCE_SCHEMA),
    category: z.literal("yield"),
    protocol: z.literal("erc4626"),
    ...evidenceEnvelopeShape,
    subject: z.object({ vaultAddress: evmAddressSchema }).strict(),
    policy: z.object({ minSharePriceScaled: uint256DecimalSchema }).strict(),
    metric: z
      .object({
        totalAssets: uint256DecimalSchema,
        totalSupply: uint256DecimalSchema,
        /**
         * `totalAssets * 10^18 / totalSupply` — asset atomic units per 10^18
         * share atomic units, floor-divided. Both operands are recorded above so
         * the division is independently reproducible rather than asserted.
         */
        sharePriceScaled: uint256DecimalSchema,
      })
      .strict(),
  })
  .strict();
export type YieldEvidence = z.infer<typeof yieldEvidenceSchema>;

export const healthEvidenceSchema = z
  .object({
    schema: z.literal(HEALTH_EVIDENCE_SCHEMA),
    category: z.literal("health"),
    protocol: z.literal("aave-v3"),
    ...evidenceEnvelopeShape,
    subject: z
      .object({
        poolAddress: evmAddressSchema,
        accountAddress: evmAddressSchema,
      })
      .strict(),
    policy: z.object({ minHealthFactorScaled: uint256DecimalSchema }).strict(),
    metric: z
      .object({
        /** 1e18-scaled, as Aave reports it. */
        healthFactorScaled: uint256DecimalSchema,
        /**
         * Recorded because it is the second, independent witness to the no-debt
         * case. Aave returns `type(uint256).max` as the health factor when an
         * account has no borrows; `totalDebtBase == 0` says the same thing from a
         * different field, and the adapter requires only one of them to refuse to
         * call the position healthy.
         */
        totalDebtBase: uint256DecimalSchema,
        totalCollateralBase: uint256DecimalSchema,
      })
      .strict(),
  })
  .strict();
export type HealthEvidence = z.infer<typeof healthEvidenceSchema>;

export const categoryEvidenceDocumentSchema = z.discriminatedUnion("schema", [
  gridEvidenceSchema,
  yieldEvidenceSchema,
  healthEvidenceSchema,
]);
export type CategoryEvidenceDocument = z.infer<typeof categoryEvidenceDocumentSchema>;

/**
 * Projects an evidence document down to the two fields the frozen v2 payload
 * actually carries for these categories.
 *
 * This exists so the narrowing happens in one reviewable place. The detail is not
 * dropped — it stays in the hashed artifact — but the signed projection must
 * contain exactly `{ category, observedAt }` and nothing else, because
 * `unsupportedCategoryEvidenceSchema` in Core is `.strict()` and would reject any
 * additional field outright. A caller assembling the payload by hand would find
 * that out at verification time; calling this makes it impossible to get wrong.
 */
export function toSignedCategoryEvidence(
  document: CategoryEvidenceDocument,
): Readonly<{ category: "grid" | "yield" | "health"; observedAt: number }> {
  return Object.freeze({
    category: document.category,
    observedAt: document.observedAt,
  });
}
