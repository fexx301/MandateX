// The ONLY module in this app that imports Marketplace Core.
//
// Core is owned by the other agent and under active development. Keeping every
// call to it behind this one file means a contract change is a single-file repair
// rather than a sweep through route handlers, and it keeps the app honest about
// what it is: a consumer of a frozen contract, not a participant in the trust
// decision. This app does not verify signatures itself and does not reimplement
// any rule — it hands Core the wire bytes and reports what Core decided.
//
// One structural problem is solved here. `evaluateMarketplaceV2` maps over the
// attestation set and verifies each one inline, so a single bad attestation
// throws and takes the whole request with it. That is the right security
// behaviour — fail closed, never rank partially-verified material — but it loses
// the one thing a comparison view has to show: WHICH candidate was rejected and
// why. So evaluation runs in two passes:
//
//   1. Classify — call Core once per attestation to learn accept/reject per
//      candidate. Rankings from these calls are discarded; they are not
//      meaningful for a one-candidate set.
//   2. Rank — call Core once more over only the survivors. The ranking the API
//      returns therefore always comes from a single authoritative Core call over
//      the exact set being compared.
//
// Cost is N+1 verifications for N candidates, bounded by Core's MAX_CANDIDATES.

import {
  MarketplaceCoreError,
  createMarketplaceCoreV2,
  marketplaceMandateSchema,
  type MarketplaceAttestationTrust,
  type MarketplaceEvaluationResult,
} from "@mandatex/marketplace-core";

import type { AppConfig } from "./config.js";

/** Why one attestation did not make it into the comparison. */
export interface RejectedAttestation {
  readonly index: number;
  readonly code: string;
  readonly message: string;
}

export interface EvaluationSuccess {
  readonly ok: true;
  /** Present only when at least one attestation survived verification. */
  readonly result: MarketplaceEvaluationResult | null;
  readonly accepted: readonly number[];
  readonly rejected: readonly RejectedAttestation[];
}

export interface EvaluationFailure {
  readonly ok: false;
  /** A Core error code when Core produced one, otherwise a local code. */
  readonly code: string;
  readonly message: string;
  /** Set when the failure is attributable to the request rather than the server. */
  readonly clientFault: boolean;
}

export type EvaluationOutcome = EvaluationSuccess | EvaluationFailure;

/** Narrow an unknown thrown value into a code and message without assuming its type. */
function describeError(cause: unknown): { code: string; message: string } {
  if (cause instanceof MarketplaceCoreError) {
    return { code: cause.code, message: cause.message };
  }
  const code =
    typeof cause === "object" && cause !== null && typeof (cause as { code?: unknown }).code === "string"
      ? (cause as { code: string }).code
      : "EVALUATION_FAILED";
  const message = cause instanceof Error ? cause.message : String(cause);
  return { code, message: message.split("\n")[0] ?? message };
}

/**
 * A Core error code names a rule the *request* broke, so it is a client fault.
 * An error without a code came from somewhere we did not anticipate and is ours.
 */
function isClientFault(cause: unknown): boolean {
  return cause instanceof MarketplaceCoreError;
}

export class MarketplaceEvaluator {
  private readonly core: { evaluateMarketplaceV2: (input: { mandate: unknown; attestations: readonly string[] }) => MarketplaceEvaluationResult };

  private constructor(
    core: MarketplaceEvaluator["core"],
    readonly trustFingerprint: string,
  ) {
    this.core = core;
  }

  /**
   * Build an evaluator, validating the pinned trust material through Core.
   *
   * Trust is validated once at construction rather than per request: if the
   * pinned key is malformed the process should refuse to start, not serve
   * traffic that fails every request with a confusing signature error.
   *
   * `clock` exists for the fixture smoke test, whose vectors are frozen at a
   * fixed instant with a 300-second TTL and so are permanently expired against a
   * real clock. It is intentionally a constructor argument and NOT readable from
   * the environment: a settable clock would switch off freshness and expiry
   * enforcement wholesale, which is most of what the attestation contract buys.
   */
  static create(config: AppConfig, clock: () => number = () => Math.floor(Date.now() / 1000)): MarketplaceEvaluator {
    const trust: MarketplaceAttestationTrust = {
      keyId: config.trust.keyId,
      publicKeySpkiDer: Buffer.from(config.trust.publicKeySpkiDerHex, "hex"),
      publicKeyFingerprintSha256: config.trust.publicKeyFingerprintSha256,
      verifierPolicySha256: config.trust.verifierPolicySha256,
    };

    const core = createMarketplaceCoreV2({
      attestationTrust: trust,
      maxClockSkewSeconds: config.maxClockSkewSeconds,
      clock,
    });

    return new MarketplaceEvaluator(core, config.trust.publicKeyFingerprintSha256);
  }

  /** Parse a mandate through Core's schema. Core is the authority on validity. */
  parseMandate(mandate: unknown): { ok: true; mandate: unknown } | EvaluationFailure {
    const parsed = marketplaceMandateSchema.safeParse(mandate);
    if (parsed.success) return { ok: true, mandate: parsed.data };

    const first = parsed.error.issues[0];
    return {
      ok: false,
      code: "MANDATE_INVALID",
      message:
        first === undefined
          ? "mandate did not satisfy the marketplace mandate schema"
          : `mandate.${first.path.join(".") || "(root)"}: ${first.message}`,
      clientFault: true,
    };
  }

  /**
   * Verify and rank a set of attestation wire strings against a mandate.
   *
   * `attestations` must be the exact wire text as issued. Never re-serialize an
   * attestation before passing it here: canonical-encoding defects are part of
   * what Core checks, and a parse/serialize round-trip repairs them silently,
   * turning a rejection into a false acceptance.
   */
  evaluate(mandate: unknown, attestations: readonly string[]): EvaluationOutcome {
    const parsed = this.parseMandate(mandate);
    if (parsed.ok !== true) return parsed;

    // Pass 1 — classify each attestation in isolation.
    const accepted: number[] = [];
    const rejected: RejectedAttestation[] = [];

    for (const [index, wire] of attestations.entries()) {
      try {
        this.core.evaluateMarketplaceV2({ mandate: parsed.mandate, attestations: [wire] });
        accepted.push(index);
      } catch (cause) {
        if (!isClientFault(cause)) {
          const described = describeError(cause);
          return { ok: false, ...described, clientFault: false };
        }
        rejected.push({ index, ...describeError(cause) });
      }
    }

    if (accepted.length === 0) {
      // Every candidate failed verification. That is a complete answer, not an
      // error: the caller gets the per-candidate reasons and an empty comparison.
      return { ok: true, result: null, accepted, rejected };
    }

    // Pass 2 — rank the survivors in one authoritative call.
    try {
      const survivors = accepted.map((index) => attestations[index] as string);
      const result = this.core.evaluateMarketplaceV2({
        mandate: parsed.mandate,
        attestations: survivors,
      });
      return { ok: true, result, accepted, rejected };
    } catch (cause) {
      // Every survivor verified alone, so a failure here is a property of the
      // SET — duplicate quote ids, candidate-set limits, cross-candidate rules.
      // Reporting it as a set-level fault is more accurate than blaming one
      // candidate, and Core's code says which rule it was.
      const described = describeError(cause);
      return { ok: false, ...described, clientFault: isClientFault(cause) };
    }
  }
}
