import {
  BSC_CATEGORY_RPC_LIMITS,
  BSC_CATEGORY_STATE_READ_SELECTORS,
  BSC_MAINNET_RPC_ORIGIN,
  CATEGORY_CONFIRMATION_DEPTH,
  CATEGORY_EXECUTION_ARTIFACT_SCHEMA,
  CATEGORY_EXECUTION_RESULT_SCHEMA,
  CATEGORY_VERIFIER_POLICY_PROFILE,
  categoryAdapterDeploymentSha256 as verifierCategoryAdapterDeploymentSha256,
  parseCategoryAdapterDeploymentManifest,
} from "@mandatex/agent-supply-verifier";
import { canonicalSha256 } from "@mandatex/marketplace-core";

import {
  marketplaceVerifierPolicyManifest,
  type MarketplaceVerifierPolicyIdentity,
  type MarketplaceVerifierPolicyManifest,
} from "./issuer.js";
import {
  MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
  marketplaceCategoryAdapterDeploymentSha256,
  parseMarketplaceCategoryAdapterDeploymentManifest,
  type MarketplaceCategoryAdapterDeploymentManifest,
} from "./category-policy.js";

/** The category execution policy is deliberately a separate versioned contract. */
export const MARKETPLACE_VERIFIER_POLICY_V2_SCHEMA =
  "mandatex.marketplace.verifier-policy.v2" as const;

export const MARKETPLACE_VERIFIER_POLICY_V2_PROFILES = Object.freeze({
  categoryVerifierPolicy: CATEGORY_VERIFIER_POLICY_PROFILE,
  categoryResult: "mandatex.marketplace.category-verifier-result.v1",
  categoryCanonicalization: "mandatex.agent-supply.canonical-quote-json.v1",
  categoryBlockPinning:
    "mandatex.agent-supply.category-block-pinning.head-minus-confirmations.v1",
  categoryTransport:
    "mandatex.agent-supply.bsc-category-pinned-https-transport.v1",
} as const);

export interface MarketplaceVerifierPolicyV2Identity
  extends MarketplaceVerifierPolicyIdentity {
  /** The complete four-entry deployment, before or after normalization. */
  readonly categoryAdapterDeployment: unknown;
}

export interface MarketplaceVerifierPolicyV2Manifest {
  readonly schema: typeof MARKETPLACE_VERIFIER_POLICY_V2_SCHEMA;
  readonly base: MarketplaceVerifierPolicyManifest;
  readonly profiles: typeof MARKETPLACE_VERIFIER_POLICY_V2_PROFILES;
  readonly contracts: Readonly<{
    readonly categoryDeployment: typeof MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA;
    readonly categoryExecutionArtifact: typeof CATEGORY_EXECUTION_ARTIFACT_SCHEMA;
    readonly categoryExecutionResult: typeof CATEGORY_EXECUTION_RESULT_SCHEMA;
  }>;
  readonly categoryPolicy: Readonly<{
    readonly chainId: 56;
    readonly confirmationDepth: typeof CATEGORY_CONFIRMATION_DEPTH;
    readonly rpcOrigin: typeof BSC_MAINNET_RPC_ORIGIN;
    readonly rpcLimits: typeof BSC_CATEGORY_RPC_LIMITS;
    readonly allowedStateReadSelectors: typeof BSC_CATEGORY_STATE_READ_SELECTORS;
    readonly deploymentSha256: string;
    readonly deployment: MarketplaceCategoryAdapterDeploymentManifest;
  }>;
}

export function marketplaceVerifierPolicyV2Manifest(
  identity: MarketplaceVerifierPolicyV2Identity,
): MarketplaceVerifierPolicyV2Manifest {
  assertExactPlainObject(
    identity,
    ["passivePolicyFingerprint", "trustPolicySha256", "categoryAdapterDeployment"],
    ["passivePolicyFingerprint", "trustPolicySha256", "categoryAdapterDeployment"],
  );

  const base = marketplaceVerifierPolicyManifest({
    passivePolicyFingerprint: identity.passivePolicyFingerprint,
    trustPolicySha256: identity.trustPolicySha256,
  });
  const deployment = parseMarketplaceCategoryAdapterDeploymentManifest(
    identity.categoryAdapterDeployment,
  );
  const verifierDeployment = parseCategoryAdapterDeploymentManifest(deployment);
  const deploymentSha256 = marketplaceCategoryAdapterDeploymentSha256(deployment);
  const verifierDeploymentSha256 = verifierCategoryAdapterDeploymentSha256(
    verifierDeployment,
  );
  if (deploymentSha256 !== verifierDeploymentSha256) {
    throw new TypeError(
      "service and verifier category deployment canonical hashes diverge",
    );
  }

  return deepFreeze({
    schema: MARKETPLACE_VERIFIER_POLICY_V2_SCHEMA,
    base,
    profiles: MARKETPLACE_VERIFIER_POLICY_V2_PROFILES,
    contracts: {
      categoryDeployment: MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
      categoryExecutionArtifact: CATEGORY_EXECUTION_ARTIFACT_SCHEMA,
      categoryExecutionResult: CATEGORY_EXECUTION_RESULT_SCHEMA,
    },
    categoryPolicy: {
      chainId: 56,
      confirmationDepth: CATEGORY_CONFIRMATION_DEPTH,
      rpcOrigin: BSC_MAINNET_RPC_ORIGIN,
      rpcLimits: BSC_CATEGORY_RPC_LIMITS,
      allowedStateReadSelectors: BSC_CATEGORY_STATE_READ_SELECTORS,
      deploymentSha256,
      deployment,
    },
  });
}

export function marketplaceVerifierPolicyV2Sha256(
  identity: MarketplaceVerifierPolicyV2Identity,
): string {
  return canonicalSha256(marketplaceVerifierPolicyV2Manifest(identity));
}

function assertExactPlainObject(
  value: unknown,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    throw new TypeError("verifier policy identity must be a plain object");
  }
  const object = value as object;
  const prototype = Object.getPrototypeOf(object);
  const keys = Reflect.ownKeys(object);
  const allowed = new Set(allowedKeys);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.some((key) => typeof key !== "string" || !allowed.has(key))
  ) {
    throw new TypeError("verifier policy identity contains unsupported fields");
  }
  for (const key of requiredKeys) {
    if (!Object.hasOwn(object, key)) {
      throw new TypeError(`verifier policy identity is missing: ${key}`);
    }
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new TypeError(
        "verifier policy identity must contain enumerable data properties only",
      );
    }
  }
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
