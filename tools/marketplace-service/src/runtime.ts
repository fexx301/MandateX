import {
  assertTrustedMarketplaceEvaluationSuccess,
  validateTrustedPreviewForMarketplaceEvaluation,
  type TrustedPreviewMarketplaceEvaluationFailure,
  type ValidateTrustedPreviewForMarketplaceEvaluationOptions,
} from "@mandatex/agent-supply-verifier";
import type { MarketplaceAttestationTrust } from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "./errors.js";
import {
  createMarketplaceAttestationSigner,
  type IssuedMarketplaceEvaluationAttestation,
  type MarketplaceAttestationSignerOptions,
} from "./issuer.js";
import {
  marketplaceEvaluationRequestSchema,
  type MarketplaceEvaluationRequest,
} from "./schema.js";

export type MarketplaceVerifierInvocation = Omit<
  ValidateTrustedPreviewForMarketplaceEvaluationOptions,
  "candidate" | "mandate" | "transactionPlan"
>;

export interface EvaluateAndAttestMarketplaceInput {
  readonly request: MarketplaceEvaluationRequest;
}

export type MarketplaceEvaluationNotAttested = Readonly<{
  outcome: "not_attested";
  verifierResult: TrustedPreviewMarketplaceEvaluationFailure;
}>;

export type MarketplaceEvaluationAttested = Readonly<
  { outcome: "attested" } & IssuedMarketplaceEvaluationAttestation
>;

export type MarketplaceEvaluationAttestationResult =
  | MarketplaceEvaluationNotAttested
  | MarketplaceEvaluationAttested;

export interface MarketplaceVerifierRuntime {
  readonly pinnedTrust: MarketplaceAttestationTrust;
  readonly evaluateAndAttest: (
    input: EvaluateAndAttestMarketplaceInput,
  ) => Promise<MarketplaceEvaluationAttestationResult>;
}

export interface MarketplaceVerifierRuntimeOptions
  extends MarketplaceAttestationSignerOptions {
  readonly verifier: MarketplaceVerifierInvocation;
}

export function createMarketplaceVerifierRuntime(
  options: MarketplaceVerifierRuntimeOptions,
): MarketplaceVerifierRuntime {
  const signer = createMarketplaceAttestationSigner(options);
  const verifier = parseVerifierInvocation(options.verifier);

  return Object.freeze({
    get pinnedTrust(): MarketplaceAttestationTrust {
      return signer.pinnedTrust;
    },
    async evaluateAndAttest(
      input: EvaluateAndAttestMarketplaceInput,
    ): Promise<MarketplaceEvaluationAttestationResult> {
      if (input === null || typeof input !== "object") {
        throw new MarketplaceServiceError(
          "REQUEST_INVALID",
          "marketplace verifier invocation must be an object",
        );
      }
      assertExactKeys(input, ["request"]);
      const parsed = marketplaceEvaluationRequestSchema.safeParse(input.request);
      if (!parsed.success) {
        throw new MarketplaceServiceError(
          "REQUEST_INVALID",
          "marketplace evaluation request is invalid",
          { cause: parsed.error },
        );
      }
      const request = parsed.data;
      let result;
      try {
        result = await validateTrustedPreviewForMarketplaceEvaluation({
          manifest: verifier.manifest,
          passiveReport: verifier.passiveReport,
          trustFile: verifier.trustFile,
          transport: verifier.transport,
          mandate: request.mandate,
          candidate: request.candidate.selector,
          transactionPlan: request.candidate.transactionPlan,
          ...(verifier.now === undefined ? {} : { now: verifier.now }),
          ...(verifier.randomUUID === undefined
            ? {}
            : { randomUUID: verifier.randomUUID }),
        });
      } catch (cause) {
        throw new MarketplaceServiceError(
          "VERIFIER_EVALUATION_FAILED",
          "the replay-free marketplace verifier evaluation failed",
          { cause },
        );
      }

      if (result.outcome !== "verified_unreserved") {
        return Object.freeze({
          outcome: "not_attested",
          verifierResult: result,
        });
      }

      try {
        assertTrustedMarketplaceEvaluationSuccess(result);
      } catch (cause) {
        throw new MarketplaceServiceError(
          "ARTIFACT_INTEGRITY_INVALID",
          "marketplace verifier success lacks trusted in-process provenance",
          { cause },
        );
      }

      const issued = signer.issueVerified(request, result);
      return Object.freeze({ outcome: "attested", ...issued });
    },
  });
}

function parseVerifierInvocation(
  value: MarketplaceVerifierInvocation,
): MarketplaceVerifierInvocation {
  if (value === null || typeof value !== "object") {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "marketplace verifier runtime configuration must be an object",
    );
  }
  try {
    assertExactKeys(value, [
      "manifest",
      "now",
      "passiveReport",
      "randomUUID",
      "transport",
      "trustFile",
    ]);
    for (const requiredKey of [
      "manifest",
      "passiveReport",
      "transport",
      "trustFile",
    ] as const) {
      if (!Object.hasOwn(value, requiredKey)) {
        throw new TypeError(`missing verifier configuration: ${requiredKey}`);
      }
    }
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "marketplace verifier runtime configuration contains unsupported fields",
      { cause },
    );
  }
  return value;
}

function assertExactKeys(
  value: object,
  allowedKeys: readonly string[],
): void {
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(value);
  const allowed = new Set(allowedKeys);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.some((key) => typeof key !== "string" || !allowed.has(key))
  ) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "marketplace verifier invocation contains unsupported fields",
    );
  }
}
