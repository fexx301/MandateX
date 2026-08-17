import {
  assertTrustedMarketplaceEvaluationSuccess,
  computeQuoteSha256,
  manifestFileSchema,
  quoteTrustFileSchema,
  runReportSchema,
  serializeQuoteTrustFile,
  validateTrustedPreviewForMarketplaceEvaluation,
  type TrustedPreviewMarketplaceEvaluationFailure,
  type ValidateTrustedPreviewForMarketplaceEvaluationOptions,
} from "@mandatex/agent-supply-verifier";
import type { MarketplaceAttestationTrust } from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "./errors.js";
import {
  createMarketplaceAttestationSigner,
  marketplaceVerifierPolicySha256,
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
  const verifier = parseVerifierInvocation(options.verifier);
  const configuredPolicySha256 = marketplaceVerifierPolicySha256({
    passivePolicyFingerprint: verifier.passiveReport.policyFingerprint,
    trustPolicySha256: computeQuoteSha256(
      serializeQuoteTrustFile(verifier.trustFile),
    ),
  });
  if (configuredPolicySha256 !== options.verifierPolicySha256) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the pinned verifier-policy hash does not match the fixed verifier configuration",
    );
  }
  const signer = createMarketplaceAttestationSigner(options);

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
    assertPlainDataObject(value, [
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
    const manifest = deepFreeze(manifestFileSchema.parse(value.manifest));
    const passiveReport = deepFreeze(runReportSchema.parse(value.passiveReport));
    const trustFile = deepFreeze(quoteTrustFileSchema.parse(value.trustFile));
    const transport = captureTransport(value.transport);
    const now = captureOptionalFunction(value.now, "now");
    const randomUUID = captureOptionalFunction(value.randomUUID, "randomUUID");
    return Object.freeze({
      manifest,
      passiveReport,
      trustFile,
      transport,
      ...(now === undefined ? {} : { now }),
      ...(randomUUID === undefined ? {} : { randomUUID }),
    });
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "marketplace verifier runtime configuration contains unsupported fields",
      { cause },
    );
  }
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

function assertPlainDataObject(
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
    throw new TypeError("verifier configuration must be a plain exact object");
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new TypeError(
        "verifier configuration must contain enumerable data properties only",
      );
    }
  }
}

function captureTransport(
  value: MarketplaceVerifierInvocation["transport"],
): MarketplaceVerifierInvocation["transport"] {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function") ||
    typeof value.request !== "function"
  ) {
    throw new TypeError("verifier transport must expose a request function");
  }
  const receiver = value;
  const request = value.request;
  return Object.freeze({
    request: (route) => request.call(receiver, route),
  });
}

function captureOptionalFunction<T extends (...args: never[]) => unknown>(
  value: T | undefined,
  label: string,
): T | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "function") {
    throw new TypeError(`verifier ${label} must be a function`);
  }
  return value;
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    deepFreeze((object as Record<PropertyKey, unknown>)[key], seen);
  }
  return Object.freeze(value);
}
