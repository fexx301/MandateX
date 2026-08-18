import {
  assertTrustedCategoryExecution,
  createCategoryAdapterExecutor,
  type BoundedHttpResponse,
  type TransportRoute,
  type TrustedCategoryExecutionResult,
} from "@mandatex/agent-supply-verifier";
import { canonicalSha256 } from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "./errors.js";
import {
  marketplaceVerifierPolicyV2Manifest,
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
  const runtimeOptions = parseRuntimeOptions(options);
  let policy: MarketplaceVerifierPolicyV2Manifest;
  let policySha256: string;
  try {
    policy = marketplaceVerifierPolicyV2Manifest(runtimeOptions.policyIdentity);
    policySha256 = canonicalSha256(policy);
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the category verifier policy identity or deployment is invalid",
      { cause },
    );
  }
  if (policySha256 !== runtimeOptions.verifierPolicySha256) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the pinned category verifier-policy hash does not match the category deployment",
    );
  }

  let executor: ReturnType<typeof createCategoryAdapterExecutor>;
  try {
    executor = createCategoryAdapterExecutor({
      deployment: runtimeOptions.deployment,
      verifierPolicySha256: policySha256,
      transport: runtimeOptions.transport,
      clock: runtimeOptions.clock,
      randomUUID: runtimeOptions.randomUUID,
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

function parseRuntimeOptions(
  value: unknown,
): MarketplaceCategoryVerifierRuntimeOptions {
  if (value === null || typeof value !== "object") {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options must be an object",
    );
  }
  const object = value as object;
  const allowedKeys = [
    "policyIdentity",
    "deployment",
    "verifierPolicySha256",
    "transport",
    "clock",
    "randomUUID",
  ] as const;
  let prototype: object | null;
  let keys: readonly PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(object);
    keys = Reflect.ownKeys(object);
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options contain unsupported fields",
      { cause },
    );
  }
  const allowed = new Set<string>(allowedKeys);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== allowedKeys.length ||
    keys.some((key) => typeof key !== "string" || !allowed.has(key))
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options contain unsupported fields",
    );
  }

  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of allowedKeys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(object, key);
    } catch (cause) {
      throw new MarketplaceServiceError(
        "VERIFIER_CONFIGURATION_INVALID",
        "category verifier runtime options contain unsupported fields",
        { cause },
      );
    }
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
    Object.defineProperty(snapshot, key, {
      value: descriptor.value,
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }

  const verifierPolicySha256 = snapshot.verifierPolicySha256;
  const clock = snapshot.clock;
  const randomUUID = snapshot.randomUUID;
  if (
    typeof verifierPolicySha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(verifierPolicySha256) ||
    typeof clock !== "function" ||
    typeof randomUUID !== "function"
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options contain invalid transport, clock, UUID, or policy values",
    );
  }

  return Object.freeze({
    policyIdentity: snapshot.policyIdentity as MarketplaceVerifierPolicyV2Identity,
    deployment: snapshot.deployment,
    verifierPolicySha256,
    transport: captureTransport(snapshot.transport),
    clock: clock as () => number,
    randomUUID: randomUUID as () => string,
  });
}

function captureTransport(
  value: unknown,
): MarketplaceCategoryVerifierRuntimeOptions["transport"] {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function")
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options contain invalid transport, clock, UUID, or policy values",
    );
  }
  let request: unknown;
  try {
    request = Reflect.get(value, "request");
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options contain invalid transport, clock, UUID, or policy values",
      { cause },
    );
  }
  if (typeof request !== "function") {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime options contain invalid transport, clock, UUID, or policy values",
    );
  }
  const receiver = value;
  return Object.freeze({
    request: (route: TransportRoute) => request.call(receiver, route),
  });
}
