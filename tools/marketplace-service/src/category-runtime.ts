import {
  assertTrustedCategoryExecution,
  createCategoryAdapterExecutor,
  type BoundedHttpResponse,
  type TransportRoute,
  type TrustedCategoryExecutionResult,
} from "@mandatex/agent-supply-verifier";

import { MarketplaceServiceError } from "./errors.js";
import {
  marketplaceVerifierPolicyV2Manifest,
  marketplaceVerifierPolicyV2Sha256,
  type MarketplaceVerifierPolicyV2Identity,
  type MarketplaceVerifierPolicyV2Manifest,
} from "./category-verifier-policy.js";

export interface MarketplaceCategoryVerifierRuntimeOptions {
  readonly policyIdentity: MarketplaceVerifierPolicyV2Identity;
  readonly deployment: unknown;
  readonly verifierPolicySha256: string;
  readonly transport: {
    readonly request: (route: TransportRoute) => Promise<BoundedHttpResponse>;
  };
  readonly clock: () => number;
  readonly randomUUID: () => string;
}

export interface MarketplaceCategoryVerifierRuntime {
  readonly policy: MarketplaceVerifierPolicyV2Manifest;
  readonly policySha256: string;
  readonly deploymentSha256: string;
  readonly evaluateCategory: (input: {
    readonly category: "grid" | "yield" | "health";
  }) => Promise<TrustedCategoryExecutionResult>;
}

/**
 * Creates the signer-free category verifier boundary. This object deliberately
 * has no private key, attestation issuer, or generic artifact-signing method.
 */
export function createMarketplaceCategoryVerifierRuntime(
  options: MarketplaceCategoryVerifierRuntimeOptions,
): MarketplaceCategoryVerifierRuntime {
  assertRuntimeOptions(options);
  let policy: MarketplaceVerifierPolicyV2Manifest;
  let policySha256: string;
  try {
    policy = marketplaceVerifierPolicyV2Manifest(options.policyIdentity);
    policySha256 = marketplaceVerifierPolicyV2Sha256(options.policyIdentity);
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the category verifier policy identity or deployment is invalid",
      { cause },
    );
  }
  if (policySha256 !== options.verifierPolicySha256) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the pinned category verifier-policy hash does not match the category deployment",
    );
  }

  let executor: ReturnType<typeof createCategoryAdapterExecutor>;
  try {
    executor = createCategoryAdapterExecutor({
      deployment: options.deployment,
      verifierPolicySha256: policySha256,
      transport: options.transport,
      clock: options.clock,
      randomUUID: options.randomUUID,
    });
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the category verifier executor configuration is invalid",
      { cause },
    );
  }
  if (executor.deploymentSha256 !== policy.categoryPolicy.deploymentSha256) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the verifier and service category deployment hashes do not match",
    );
  }

  return Object.freeze({
    policy,
    policySha256,
    deploymentSha256: executor.deploymentSha256,
    async evaluateCategory(input: {
      readonly category: "grid" | "yield" | "health";
    }): Promise<TrustedCategoryExecutionResult> {
      let result: TrustedCategoryExecutionResult;
      try {
        result = await executor.evaluate(input);
      } catch (cause) {
        throw new MarketplaceServiceError(
          "VERIFIER_EVALUATION_FAILED",
          "the category verifier execution failed",
          { cause },
        );
      }
      if (result.outcome === "executed") {
        try {
          assertTrustedCategoryExecution(result, executor);
        } catch (cause) {
          throw new MarketplaceServiceError(
            "ARTIFACT_INTEGRITY_INVALID",
            "category verifier success lacks trusted in-process provenance",
            { cause },
          );
        }
      }
      return result;
    },
  });
}

function assertRuntimeOptions(
  value: unknown,
): asserts value is MarketplaceCategoryVerifierRuntimeOptions {
  if (value === null || typeof value !== "object") {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options must be an object",
    );
  }
  const object = value as object;
  const keys = Reflect.ownKeys(object);
  const allowed = new Set([
    "policyIdentity",
    "deployment",
    "verifierPolicySha256",
    "transport",
    "clock",
    "randomUUID",
  ]);
  if (
    (Object.getPrototypeOf(object) !== Object.prototype &&
      Object.getPrototypeOf(object) !== null) ||
    keys.some((key) => typeof key !== "string" || !allowed.has(key))
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options contain unsupported fields",
    );
  }
  for (const key of [
    "policyIdentity",
    "deployment",
    "verifierPolicySha256",
    "transport",
    "clock",
    "randomUUID",
  ]) {
    if (!Object.hasOwn(object, key)) {
      throw new MarketplaceServiceError(
        "VERIFIER_CONFIGURATION_INVALID",
        `category verifier runtime options are missing: ${key}`,
      );
    }
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new MarketplaceServiceError(
        "VERIFIER_CONFIGURATION_INVALID",
        "category verifier runtime options must contain enumerable data properties only",
      );
    }
  }
  if (
    typeof (value as MarketplaceCategoryVerifierRuntimeOptions).verifierPolicySha256 !==
      "string" ||
    !/^[a-f0-9]{64}$/.test(
      (value as MarketplaceCategoryVerifierRuntimeOptions).verifierPolicySha256,
    ) ||
    typeof (value as MarketplaceCategoryVerifierRuntimeOptions).clock !==
      "function" ||
    typeof (value as MarketplaceCategoryVerifierRuntimeOptions).randomUUID !==
      "function" ||
    (value as MarketplaceCategoryVerifierRuntimeOptions).transport === null ||
    typeof (value as MarketplaceCategoryVerifierRuntimeOptions).transport !==
      "object" ||
    typeof (value as MarketplaceCategoryVerifierRuntimeOptions).transport.request !==
      "function"
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options contain invalid transport, clock, UUID, or policy values",
    );
  }
}
