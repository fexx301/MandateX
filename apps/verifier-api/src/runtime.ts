// The only module that imports Codex's verifier packages.
//
// Same containment rule as apps/marketplace-api/src/core.ts: those packages are
// owned by the other agent and under active development, so every call into them
// lives behind one file. A contract change is a single-file repair.
//
// What this wraps: `createMarketplaceVerifierRuntime` needs four things — a
// manifest, a passive run report, a quote trust file, and an outbound transport.
// The first three are artifacts produced by an agent-supply-verifier passive run
// against a live agent; they are not in the repository because they describe a
// specific agent observed at a specific time. The transport is real:
// `PinnedHttpsTransport` performs bounded, origin-pinned HTTPS with an RPC
// method allowlist.
//
// The runtime is therefore OPTIONAL at boot. When artifacts are absent the
// service still serves its trust identity, which is what the marketplace app
// needs in order to prove lockstep key agreement. Making evaluation a
// precondition for booting would mean the trust boundary cannot be stood up until
// the entire supply pipeline is finished — exactly backwards, since the boundary
// is what everything else is verified against.

import {
  computeQuoteSha256,
  manifestFileSchema,
  PinnedHttpsTransport,
  quoteTrustFileSchema,
  runReportSchema,
  serializeQuoteTrustFile,
} from "@mandatex/agent-supply-verifier";
import {
  createMarketplaceVerifierRuntime,
  marketplaceVerifierPolicySha256,
  MarketplaceServiceError,
  type MarketplaceEvaluationAttestationResult,
  type MarketplaceVerifierRuntime,
} from "@mandatex/marketplace-service";

import { signingKeyPkcs8Der, type VerifierConfig } from "./config.js";

export interface EvaluationFault {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
  /** True when the request is at fault rather than the service. */
  readonly clientFault: boolean;
}

export type EvaluationOutcome =
  | { readonly ok: true; readonly result: MarketplaceEvaluationAttestationResult }
  | EvaluationFault;

function describe(cause: unknown): { code: string; message: string } {
  if (cause instanceof MarketplaceServiceError) {
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
 * Codes that name a defect in the submitted request rather than in the service.
 *
 * Everything else — a failed upstream evaluation, a broken artifact set, an
 * integrity failure — is the service's problem and must not be reported as the
 * caller's fault, because a 4xx tells the caller to change their request when the
 * fix is on this side.
 */
const CLIENT_FAULT_CODES = new Set(["REQUEST_INVALID"]);

export class Verifier {
  private constructor(
    private readonly runtime: MarketplaceVerifierRuntime | null,
    readonly policySha256: string | null,
    readonly runtimeDetail: string,
  ) {}

  get canEvaluate(): boolean {
    return this.runtime !== null;
  }

  /**
   * Build the verifier, tolerating an absent artifact set.
   *
   * A malformed artifact set is NOT tolerated: if the files exist but do not
   * satisfy the schemas, or the derived policy hash disagrees with the pinned
   * one, that is a misconfiguration that would otherwise surface as attestations
   * consumers reject for reasons they cannot diagnose. It throws.
   */
  static create(config: VerifierConfig, clock: () => number = () => Math.floor(Date.now() / 1000)): Verifier {
    if (config.artifacts === null) {
      return new Verifier(null, config.verifierPolicySha256, config.artifactsDetail);
    }

    const transport = new PinnedHttpsTransport();

    // Parse all three artifacts against the verifier's own schemas rather than
    // casting. The files come off disk as `unknown`, and a cast would carry a
    // malformed artifact set all the way to the first signature, where the failure
    // would surface as attestations that consumers reject for reasons nobody can
    // trace back to a bad JSON file. `.parse` throws here instead, at boot.
    const manifest = manifestFileSchema.parse(config.artifacts.manifest);
    const passiveReport = runReportSchema.parse(config.artifacts.passiveReport);
    const trustFile = quoteTrustFileSchema.parse(config.artifacts.trustFile);

    // The runtime cross-checks the policy hash it derives from the artifacts
    // against the one it is given, and throws on disagreement. Deriving it here
    // when nothing is pinned means a fresh deployment does not need the operator
    // to compute a hash by hand; pinning it in production means a silent artifact
    // swap cannot change what the service claims to be.
    const derived = marketplaceVerifierPolicySha256({
      passivePolicyFingerprint: passiveReport.policyFingerprint,
      trustPolicySha256: computeQuoteSha256(serializeQuoteTrustFile(trustFile)),
    });
    const policySha256 = config.verifierPolicySha256 ?? derived;

    if (config.verifierPolicySha256 !== null && config.verifierPolicySha256 !== derived) {
      throw new MarketplaceServiceError(
        "VERIFIER_CONFIGURATION_INVALID",
        `MANDATEX_VERIFIER_POLICY_SHA256 is pinned to ${config.verifierPolicySha256} but the ` +
          `configured artifacts derive ${derived}. Either the artifacts changed without the pin ` +
          "being updated, or the pin is wrong. Refusing to sign under a policy identity that " +
          "does not describe this configuration.",
      );
    }

    const runtime = createMarketplaceVerifierRuntime({
      keyId: config.keyId,
      privateKeyPkcs8Der: signingKeyPkcs8Der(config),
      verifierPolicySha256: policySha256,
      clock,
      verifier: {
        manifest,
        passiveReport,
        trustFile,
        transport,
      },
    });

    return new Verifier(runtime, policySha256, config.artifactsDetail);
  }

  /**
   * Evaluate a request and, if it verifies, issue a signed attestation.
   *
   * A `not_attested` outcome is a SUCCESS at this layer: the verifier did its job
   * and the candidate did not qualify. Reporting it as an error would conflate
   * "the agent failed verification" with "the verifier is broken", which are
   * opposite signals to whoever is on call.
   */
  async evaluate(request: unknown): Promise<EvaluationOutcome> {
    if (this.runtime === null) {
      return {
        ok: false,
        code: "VERIFIER_NOT_CONFIGURED",
        message:
          "no agent is configured for evaluation, so this service cannot issue attestations. " +
          this.runtimeDetail,
        clientFault: false,
      };
    }

    try {
      const result = await this.runtime.evaluateAndAttest({
        request: request as Parameters<MarketplaceVerifierRuntime["evaluateAndAttest"]>[0]["request"],
      });
      return { ok: true, result };
    } catch (cause) {
      const described = describe(cause);
      return { ...described, ok: false, clientFault: CLIENT_FAULT_CODES.has(described.code) };
    }
  }
}
