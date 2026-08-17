// Display projection: turns Core's evaluation result into the comparison view
// the API serves.
//
// This file exists mainly to enforce one honesty rule, recorded in plan.md §4.
//
// Core's ranking has six weighted factors totalling 100 points. Two of them —
// `mandateFit` (30) and `executionReadiness` (20) — are pinned at 10000 bps for
// every candidate that reaches ranking at all, because a candidate that failed
// either one was already excluded and never gets scored. So 50 of the 100 weight
// points are identical across every row of the comparison and cannot change any
// ordering.
//
// Rendering all six as if they were scored factors would misrepresent how the
// ranking works: a reader would conclude that half the decision came from fit and
// readiness, when in fact the entire ordering is decided by the other four.
//
// So the projection splits them. Four factors are reported as scoring, with a
// score renormalized over the 50 points that actually vary. The other two are
// reported as eligibility confirmations at explicitly zero discriminating weight.
// Core's own six-factor number is still included, labelled, so nothing is hidden.
//
// The split is not hardcoded blindly. If a supposedly-pinned factor is ever
// observed at a value other than 10000, it is reclassified as scoring and a
// warning is attached to the response. That way the API self-corrects if Core's
// ranking changes, instead of silently understating a factor that has started to
// discriminate.

import { STRATEGY_WEIGHTS, type MarketplaceEvaluationResult } from "@mandatex/marketplace-core";

import type { RejectedAttestation } from "./core.js";

/**
 * Factors that carry the same value for every ranked candidate, so contribute
 * nothing to the ordering. Derived from plan.md §4; verified at runtime below.
 */
const PINNED_FACTOR_KEYS = ["mandateFit", "executionReadiness"] as const;

/** The value pinned factors are fixed at. Observing anything else is the signal to reclassify. */
const PINNED_SCORE_BPS = 10_000;

type FactorKey = keyof typeof STRATEGY_WEIGHTS;

const ALL_FACTOR_KEYS = Object.keys(STRATEGY_WEIGHTS) as readonly FactorKey[];

export interface DisplayFactor {
  readonly key: FactorKey;
  readonly weight: number;
  readonly scoreBps: number;
  readonly weightedPoints: number;
}

export interface DisplayConfirmation {
  readonly key: FactorKey;
  /** Weight this factor carries in Core's total, retained for traceability. */
  readonly weightInCoreTotal: number;
  /** Always 0: it is identical across candidates and cannot affect ordering. */
  readonly discriminatingWeight: 0;
  readonly scoreBps: number;
  readonly note: string;
}

export interface DisplayScore {
  /**
   * Ranking score over the factors that actually vary, in basis points.
   * This is what the comparison view should sort and display as "the score".
   */
  readonly discriminatingScoreBps: number;
  readonly discriminatingWeightPoints: number;
  readonly factors: readonly DisplayFactor[];
  readonly confirmations: readonly DisplayConfirmation[];
  /** Core's six-factor score, including the 50 non-discriminating points. */
  readonly coreScoreBps: number;
  readonly coreWeightedTotal: number;
}

export interface DisplayFinding {
  readonly kind: string;
  readonly code: string;
  readonly message: string;
}

export interface DisplayCandidate {
  readonly quoteId: string;
  readonly candidate: unknown;
  readonly outcome: string;
  readonly ranked: boolean;
  readonly score: DisplayScore | null;
  readonly findings: readonly DisplayFinding[];
  readonly quote: unknown;
}

export interface ComparisonView {
  readonly mandateId: string;
  readonly category: string;
  readonly evaluatedAt: number;
  readonly effect: "evaluation_only";
  /** Ranked best-first over discriminating score. Excluded candidates follow, unranked. */
  readonly candidates: readonly DisplayCandidate[];
  readonly summary: {
    readonly submitted: number;
    readonly verified: number;
    readonly rejectedAtVerification: number;
    readonly eligible: number;
    readonly excluded: number;
    readonly inconclusive: number;
    readonly unsupported: number;
  };
  /** Attestations that never entered the comparison because verification failed. */
  readonly unverified: readonly RejectedAttestation[];
  readonly receipt: unknown;
  readonly rankingBasis: {
    readonly note: string;
    readonly discriminatingWeightPoints: number;
    readonly confirmationWeightPoints: number;
  };
  /** Non-fatal integrity notices. Empty in normal operation. */
  readonly warnings: readonly string[];
}

interface CoreFactor {
  readonly weight: number;
  readonly scoreBps: number;
  readonly weightedPoints: number;
}

const CONFIRMATION_NOTE =
  "Eligibility confirmation, not a scored factor: identical for every ranked candidate, " +
  "so it cannot change the ordering. A candidate failing this check is excluded before ranking.";

function projectScore(
  score: { factors: Record<string, CoreFactor>; weightedTotal: number; scoreBps: number },
  warnings: string[],
  quoteId: string,
): DisplayScore {
  const factors: DisplayFactor[] = [];
  const confirmations: DisplayConfirmation[] = [];

  for (const key of ALL_FACTOR_KEYS) {
    const factor = score.factors[key];
    if (factor === undefined) {
      warnings.push(
        `ranking factor "${key}" is missing from Core's score for quote ${quoteId}; ` +
          "the displayed score is incomplete",
      );
      continue;
    }

    const declaredPinned = (PINNED_FACTOR_KEYS as readonly string[]).includes(key);
    const actuallyPinned = declaredPinned && factor.scoreBps === PINNED_SCORE_BPS;

    if (declaredPinned && !actuallyPinned) {
      // Core's ranking changed. Score it rather than under-report it, and say so.
      warnings.push(
        `ranking factor "${key}" was expected to be pinned at ${PINNED_SCORE_BPS} bps but ` +
          `quote ${quoteId} scored ${factor.scoreBps} bps; it is now treated as a scoring ` +
          "factor. Update PINNED_FACTOR_KEYS in display.ts and plan.md §4.",
      );
    }

    if (actuallyPinned) {
      confirmations.push({
        key,
        weightInCoreTotal: factor.weight,
        discriminatingWeight: 0,
        scoreBps: factor.scoreBps,
        note: CONFIRMATION_NOTE,
      });
    } else {
      factors.push({
        key,
        weight: factor.weight,
        scoreBps: factor.scoreBps,
        weightedPoints: factor.weightedPoints,
      });
    }
  }

  const discriminatingWeightPoints = factors.reduce((total, factor) => total + factor.weight, 0);
  const discriminatingPoints = factors.reduce((total, factor) => total + factor.weightedPoints, 0);

  // Renormalize over the varying weight only, so a score of 10000 bps means
  // "best possible on everything that actually differs" rather than being
  // inflated by 50 points every candidate receives for free.
  const discriminatingScoreBps =
    discriminatingWeightPoints === 0
      ? 0
      : Math.round(discriminatingPoints / discriminatingWeightPoints);

  return {
    discriminatingScoreBps,
    discriminatingWeightPoints,
    factors,
    confirmations,
    coreScoreBps: score.scoreBps,
    coreWeightedTotal: score.weightedTotal,
  };
}

/**
 * Join Core's quotes and decisions into one ranked comparison view.
 *
 * Ordering: eligible candidates first, best discriminating score first, ties
 * broken by quoteId so the ordering is deterministic and reproducible. Everything
 * not eligible follows, so the view never buries an exclusion reason below a
 * scored row.
 */
export function buildComparisonView(input: {
  readonly result: MarketplaceEvaluationResult | null;
  readonly submitted: number;
  readonly unverified: readonly RejectedAttestation[];
  readonly mandateId: string;
  readonly category: string;
  readonly evaluatedAt: number;
}): ComparisonView {
  const warnings: string[] = [];
  const candidates: DisplayCandidate[] = [];

  const confirmationWeightPoints = PINNED_FACTOR_KEYS.reduce(
    (total, key) => total + STRATEGY_WEIGHTS[key],
    0,
  );

  if (input.result !== null) {
    const quotesById = new Map(input.result.quotes.map((quote) => [quote.quoteId, quote]));

    for (const decision of input.result.decisions) {
      const quote = quotesById.get(decision.quoteId);
      if (quote === undefined) {
        warnings.push(
          `decision for quote ${decision.quoteId} has no matching quote in the result set`,
        );
      }
      candidates.push({
        quoteId: decision.quoteId,
        candidate: decision.candidate,
        outcome: decision.outcome,
        ranked: decision.score !== null,
        score:
          decision.score === null
            ? null
            : projectScore(
                decision.score as unknown as {
                  factors: Record<string, CoreFactor>;
                  weightedTotal: number;
                  scoreBps: number;
                },
                warnings,
                decision.quoteId,
              ),
        findings: decision.findings.map((finding) => ({
          kind: finding.kind,
          code: finding.code,
          message: finding.message,
        })),
        quote: quote ?? null,
      });
    }
  }

  candidates.sort((left, right) => {
    const leftEligible = left.outcome === "eligible" ? 0 : 1;
    const rightEligible = right.outcome === "eligible" ? 0 : 1;
    if (leftEligible !== rightEligible) return leftEligible - rightEligible;

    const leftScore = left.score?.discriminatingScoreBps ?? -1;
    const rightScore = right.score?.discriminatingScoreBps ?? -1;
    if (leftScore !== rightScore) return rightScore - leftScore;

    return left.quoteId < right.quoteId ? -1 : left.quoteId > right.quoteId ? 1 : 0;
  });

  const count = (outcome: string): number =>
    candidates.filter((candidate) => candidate.outcome === outcome).length;

  return {
    mandateId: input.mandateId,
    category: input.category,
    evaluatedAt: input.evaluatedAt,
    effect: "evaluation_only",
    candidates,
    summary: {
      submitted: input.submitted,
      verified: candidates.length,
      rejectedAtVerification: input.unverified.length,
      eligible: count("eligible"),
      excluded: count("excluded"),
      inconclusive: count("inconclusive"),
      unsupported: count("unsupported"),
    },
    unverified: input.unverified,
    receipt: input.result?.receipt ?? null,
    rankingBasis: {
      note:
        `Ordering is decided by ${100 - confirmationWeightPoints} of Core's 100 weight points. ` +
        `The remaining ${confirmationWeightPoints} (${PINNED_FACTOR_KEYS.join(", ")}) are ` +
        "identical for every ranked candidate and are reported as eligibility confirmations " +
        "rather than scores.",
      discriminatingWeightPoints: 100 - confirmationWeightPoints,
      confirmationWeightPoints,
    },
    warnings,
  };
}
