import {
  assertTrustedCategoryExecution,
  createCategoryAdapterExecutor,
  createCategoryExecutionBindingCapability,
  createCategorySnapshotCapability,
  type CategoryAdapterExecutionInput,
  type CategoryAdapterDeploymentManifest,
  type BoundedHttpResponse,
  type BoundCategoryExecutionSuccess,
  type CategoryExecutionBindingContext,
  type CategoryExecutionBindingCapability,
  type CategorySnapshot,
  type CategorySnapshotCapability,
  type CategorySnapshotHandle,
  type ResolvedCategoryAdapterSelection,
  type TransportRoute,
  type TrustedCategoryExecutionResult,
} from "@mandatex/agent-supply-verifier";
import { canonicalSha256 } from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "./errors.js";
import {
  marketplaceCategorySuccessorPolicyManifest,
  marketplaceVerifierPolicyV2Manifest,
  type MarketplaceCategoryProvenanceRoots,
  type MarketplaceCategorySuccessorPolicyIdentity,
  type MarketplaceCategorySuccessorPolicyManifest,
  type MarketplaceVerifierPolicyV2Identity,
  type MarketplaceVerifierPolicyV2Manifest,
} from "./category-verifier-policy.js";
import { marketplaceCategorySuccessorExecutorDeployment } from "./category-policy.js";
import type { MarketplaceCategorySuccessorTrustRoot } from "./category-policy.js";

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

export interface MarketplaceCategoryVerifierRuntime<
  Policy extends MarketplaceVerifierPolicyV2Manifest | MarketplaceCategorySuccessorPolicyManifest =
    MarketplaceVerifierPolicyV2Manifest,
> {
  readonly policy: Policy;
  readonly policySha256: string;
  readonly deploymentSha256: string;
  readonly evaluateCategory: (
    input: CategoryAdapterExecutionInput,
  ) => Promise<TrustedCategoryExecutionResult>;
  /**
   * Executes and binds one result to the exact mandate/candidate context in the
   * same verifier-owned call. The returned result remains executor-authenticated
   * and cannot be rebound to a different context by the signer.
   */
  readonly evaluateCategoryBound: (
    input: CategoryAdapterExecutionInput,
    context: CategoryExecutionBindingContext,
  ) => Promise<TrustedCategoryExecutionResult>;
  /** Executes a mandate-owned scope against static deployment policy. */
  readonly evaluateCategoryScopeBound: (
    scope: unknown,
    context: CategoryExecutionBindingContext,
  ) => Promise<TrustedCategoryExecutionResult>;
  /**
   * Executes a mandate-owned scope against one verifier-captured block anchor.
   * Identity and target capabilities use the same anchor before this method is
   * called; the executor revalidates it and keeps the result capability-bound.
   */
  readonly evaluateCategoryScopeAtAnchorBound: (
    scope: unknown,
    anchor: CategorySnapshot["anchor"],
    context: CategoryExecutionBindingContext,
  ) => Promise<TrustedCategoryExecutionResult>;
  readonly evaluateCategoryScopeAtSnapshotBound: (
    scope: unknown,
    snapshot: CategorySnapshotHandle,
    context: CategoryExecutionBindingContext,
  ) => Promise<TrustedCategoryExecutionResult>;
  /** Re-checks the private executor/context capability before a signature. */
  readonly assertCategoryExecutionBound: (
    value: unknown,
    context: CategoryExecutionBindingContext,
  ) => asserts value is BoundCategoryExecutionSuccess;
}

export interface PrivateMarketplaceCategorySuccessorVerifierRuntime
  extends MarketplaceCategoryVerifierRuntime<MarketplaceCategorySuccessorPolicyManifest> {
  readonly trustRoot: MarketplaceCategorySuccessorTrustRoot;
  readonly infrastructure: MarketplaceCategoryProvenanceRoots;
}

export interface PrivateMarketplaceCategorySuccessorVerifierRuntimeOptions {
  readonly policyIdentity: MarketplaceCategorySuccessorPolicyIdentity;
  readonly verifierPolicySha256: string;
  readonly transport: {
    readonly request: (route: TransportRoute) => Promise<BoundedHttpResponse>;
  };
  readonly clock: () => number;
  readonly randomUUID: () => string;
}

const trustedCategoryVerifierRuntimes = new WeakSet<object>();
const trustedCategorySuccessorVerifierRuntimes = new WeakSet<object>();
const categoryRuntimeSnapshotCapabilities = new WeakMap<
  object,
  CategorySnapshotCapability
>();

/**
 * Creates the signer-free category verifier boundary. This object deliberately
 * has no private key, attestation issuer, or generic artifact-signing method.
 */
export function createMarketplaceCategoryVerifierRuntime(
  options: MarketplaceCategoryVerifierRuntimeOptions,
): MarketplaceCategoryVerifierRuntime {
  const runtimeOptions = parseRuntimeOptions(options);
  let policy: MarketplaceVerifierPolicyV2Manifest;
  try {
    policy = marketplaceVerifierPolicyV2Manifest(runtimeOptions.policyIdentity);
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the category verifier policy identity or deployment is invalid",
      { cause },
    );
  }
  const policySha256 = canonicalSha256(policy);
  if (policySha256 !== runtimeOptions.verifierPolicySha256) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the pinned category verifier-policy hash does not match the category deployment",
    );
  }

  return createResolvedCategoryVerifierRuntime({
    policy,
    policySha256,
    executionDeployment: runtimeOptions.deployment,
    expectedExecutionDeploymentSha256: policy.categoryPolicy.deploymentSha256,
    releaseDeploymentSha256: policy.categoryPolicy.deploymentSha256,
    transport: runtimeOptions.transport,
    clock: runtimeOptions.clock,
    randomUUID: runtimeOptions.randomUUID,
  });
}

/** Private successor factory. No caller-controlled deployment or root override exists. */
export function createPrivateMarketplaceCategorySuccessorVerifierRuntime(
  options: PrivateMarketplaceCategorySuccessorVerifierRuntimeOptions,
): PrivateMarketplaceCategorySuccessorVerifierRuntime {
  const runtimeOptions = parseSuccessorRuntimeOptions(options);
  let policy: MarketplaceCategorySuccessorPolicyManifest;
  try {
    policy = marketplaceCategorySuccessorPolicyManifest(
      runtimeOptions.policyIdentity,
    );
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the successor verifier policy identity or deployment is invalid",
      { cause },
    );
  }
  const policySha256 = canonicalSha256(policy);
  if (policySha256 !== runtimeOptions.verifierPolicySha256) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the pinned successor verifier-policy hash does not match the static deployment",
    );
  }
  const runtime = createResolvedCategoryVerifierRuntime({
    policy,
    policySha256,
    executionDeployment: marketplaceCategorySuccessorExecutorDeployment(
      policy.categoryPolicy.deployment,
    ),
    expectedExecutionDeploymentSha256:
      policy.categoryPolicy.executionDeploymentSha256,
    releaseDeploymentSha256: policy.categoryPolicy.deploymentSha256,
    trustRoot: policy.categoryPolicy.trustRoot,
    infrastructure: policy.categoryPolicy.infrastructure,
    transport: runtimeOptions.transport,
    clock: runtimeOptions.clock,
    randomUUID: runtimeOptions.randomUUID,
  }) as PrivateMarketplaceCategorySuccessorVerifierRuntime;
  trustedCategorySuccessorVerifierRuntimes.add(runtime);
  return runtime;
}

function createResolvedCategoryVerifierRuntime<
  Policy extends MarketplaceVerifierPolicyV2Manifest | MarketplaceCategorySuccessorPolicyManifest,
>(input: Readonly<{
  readonly policy: Policy;
  readonly policySha256: string;
  readonly executionDeployment: unknown;
  readonly expectedExecutionDeploymentSha256: string;
  readonly releaseDeploymentSha256: string;
  readonly trustRoot?: MarketplaceCategorySuccessorTrustRoot;
  readonly infrastructure?: MarketplaceCategoryProvenanceRoots;
  readonly transport: MarketplaceCategoryVerifierRuntimeOptions["transport"];
  readonly clock: () => number;
  readonly randomUUID: () => string;
}>): MarketplaceCategoryVerifierRuntime<Policy> {
  const policy = input.policy;
  const policySha256 = input.policySha256;

  let executor: ReturnType<typeof createCategoryAdapterExecutor>;
  let snapshotCapability: CategorySnapshotCapability;
  try {
    snapshotCapability = createCategorySnapshotCapability({
      transport: input.transport,
      randomUUID: input.randomUUID,
    });
    executor = createCategoryAdapterExecutor({
      deployment: input.executionDeployment,
      verifierPolicySha256: policySha256,
      transport: input.transport,
      clock: input.clock,
      randomUUID: input.randomUUID,
      snapshotCapability,
    });
  } catch (cause) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the category verifier executor configuration is invalid",
      { cause },
    );
  }
  if (executor.deploymentSha256 !== input.expectedExecutionDeploymentSha256) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "the verifier and service category deployment hashes do not match",
    );
  }

  // Keep mandate/candidate context inside the verifier-owned capability before
  // the first RPC await. A post-hoc binder would allow a caller to mutate the
  // context while adapter I/O is in flight.
  const bindingCapability = createCategoryExecutionBindingCapability(executor);

  const evaluateCategory = async (
    input: CategoryAdapterExecutionInput,
  ): Promise<TrustedCategoryExecutionResult> => {
    const parsedInput = parseCategoryInput(input);
    let result: TrustedCategoryExecutionResult;
    try {
      result = await executor.evaluate(parsedInput);
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
  };

  const evaluateCategoryBound = async (
    input: CategoryAdapterExecutionInput,
    context: CategoryExecutionBindingContext,
  ): Promise<TrustedCategoryExecutionResult> => {
    const selection = resolveInputSelection(input, executor.deployment);
    if (selection === undefined) return evaluateCategory(input);

    let result: TrustedCategoryExecutionResult;
    try {
      result = await bindingCapability.evaluateBound({
        selection,
        mandate: context.mandate,
        candidate: context.candidate,
      });
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
  };

  const evaluateCategoryScopeBound = async (
    scope: unknown,
    context: CategoryExecutionBindingContext,
  ): Promise<TrustedCategoryExecutionResult> => {
    return evaluateCategoryScopeAtAnchorBoundInternal(scope, undefined, context);
  };

  const evaluateCategoryScopeAtAnchorBound = async (
    scope: unknown,
    anchor: CategorySnapshot["anchor"],
    context: CategoryExecutionBindingContext,
  ): Promise<TrustedCategoryExecutionResult> => {
    return evaluateCategoryScopeAtAnchorBoundInternal(scope, anchor, context);
  };

  const evaluateCategoryScopeAtSnapshotBound = async (
    scope: unknown,
    snapshot: CategorySnapshotHandle,
    context: CategoryExecutionBindingContext,
  ): Promise<TrustedCategoryExecutionResult> => {
    snapshotCapability.assertOpaqueActive(snapshot);
    return evaluateCategoryScopeAtSnapshotBoundInternal(scope, snapshot, context);
  };

  const evaluateCategoryScopeAtSnapshotBoundInternal = async (
    scope: unknown,
    snapshot: CategorySnapshotHandle,
    context: CategoryExecutionBindingContext,
  ): Promise<TrustedCategoryExecutionResult> => {
    if (scope === null || typeof scope !== "object") {
      throw new MarketplaceServiceError(
        "REQUEST_INVALID",
        "category scope must be an object",
      );
    }
    const value = scope as {
      readonly category?: unknown;
      readonly adapterId?: unknown;
    };
    const selection = resolveSelection(value);
    let result: TrustedCategoryExecutionResult;
    try {
      result = await executor.evaluateScopeAtSnapshot(scope, snapshot);
    } catch (cause) {
      throw new MarketplaceServiceError(
        "VERIFIER_EVALUATION_FAILED",
        "the category verifier scope execution failed",
        { cause },
      );
    }
    if (result.outcome === "executed" && result.artifact.result.status === "pass") {
      try {
        assertTrustedCategoryExecution(result, executor);
        bindingCapability.bind(result, selection, context);
      } catch (cause) {
        throw new MarketplaceServiceError(
          "ARTIFACT_INTEGRITY_INVALID",
          "category verifier scope result lacks trusted binding",
          { cause },
        );
      }
    }
    return result;
  };

  const evaluateCategoryScopeAtAnchorBoundInternal = async (
    scope: unknown,
    anchor: CategorySnapshot["anchor"] | undefined,
    context: CategoryExecutionBindingContext,
  ): Promise<TrustedCategoryExecutionResult> => {
    if (scope === null || typeof scope !== "object") {
      throw new MarketplaceServiceError(
        "REQUEST_INVALID",
        "category scope must be an object",
      );
    }
    const value = scope as {
      readonly category?: unknown;
      readonly adapterId?: unknown;
    };
    const selection = resolveSelection(value);
    let result: TrustedCategoryExecutionResult;
    try {
      result =
        anchor === undefined
          ? await executor.evaluateScope(scope)
          : await executor.evaluateScopeAtAnchor(scope, anchor);
    } catch (cause) {
      throw new MarketplaceServiceError(
        "VERIFIER_EVALUATION_FAILED",
        "the category verifier scope execution failed",
        { cause },
      );
    }
    if (result.outcome === "executed" && result.artifact.result.status === "pass") {
      try {
        assertTrustedCategoryExecution(result, executor);
        bindingCapability.bind(result, selection, context);
      } catch (cause) {
        throw new MarketplaceServiceError(
          "ARTIFACT_INTEGRITY_INVALID",
          "category verifier scope result lacks trusted binding",
          { cause },
        );
      }
    }
    return result;
  };

  const assertCategoryExecutionBound = (
    value: unknown,
    context: CategoryExecutionBindingContext,
  ): asserts value is BoundCategoryExecutionSuccess => {
    if (value === null || typeof value !== "object") {
      throw new MarketplaceServiceError(
        "ARTIFACT_INTEGRITY_INVALID",
        "category verifier result is not an object",
      );
    }
    const result = value as {
      readonly artifact?: {
        readonly adapter?: {
          readonly category?: unknown;
          readonly adapterId?: unknown;
        };
      };
    };
    const adapter = result.artifact?.adapter;
    const selection = resolveSelection(adapter);
    try {
      const assertBound: CategoryExecutionBindingCapability["assertBound"] =
        bindingCapability.assertBound;
      assertBound(
        value,
        selection,
        context,
      );
    } catch (cause) {
      throw new MarketplaceServiceError(
        "ARTIFACT_INTEGRITY_INVALID",
        "category verifier result is not bound to the requested context",
        { cause },
      );
    }
  };

  const runtime = Object.freeze({
    policy,
    policySha256,
    deploymentSha256: input.releaseDeploymentSha256,
    ...(input.trustRoot === undefined ? {} : { trustRoot: input.trustRoot }),
    ...(input.infrastructure === undefined
      ? {}
      : { infrastructure: input.infrastructure }),
    evaluateCategory,
    evaluateCategoryBound,
    evaluateCategoryScopeBound,
    evaluateCategoryScopeAtAnchorBound,
    evaluateCategoryScopeAtSnapshotBound,
    assertCategoryExecutionBound,
  });
  trustedCategoryVerifierRuntimes.add(runtime);
  categoryRuntimeSnapshotCapabilities.set(runtime, snapshotCapability);
  return runtime;
}

export function assertPrivateMarketplaceCategorySuccessorVerifierRuntime(
  value: unknown,
): asserts value is PrivateMarketplaceCategorySuccessorVerifierRuntime {
  if (
    value === null ||
    typeof value !== "object" ||
    !trustedCategorySuccessorVerifierRuntimes.has(value)
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category successor issuance requires the static-policy verifier factory",
    );
  }
}

/** Private package-internal access for the unexported successor orchestrator. */
export function privateCategorySnapshotCapabilityForRuntime(
  value: MarketplaceCategoryVerifierRuntime<any>,
): CategorySnapshotCapability {
  assertMarketplaceCategoryVerifierRuntime(value);
  const capability = categoryRuntimeSnapshotCapabilities.get(value);
  if (capability === undefined) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier runtime lost its snapshot capability",
    );
  }
  return capability;
}

export function assertMarketplaceCategoryVerifierRuntime(
  value: unknown,
): asserts value is MarketplaceCategoryVerifierRuntime {
  if (
    value === null ||
    typeof value !== "object" ||
    !trustedCategoryVerifierRuntimes.has(value)
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category issuer requires a verifier runtime created by the service factory",
    );
  }
}

function resolveSelection(
  adapter: unknown,
): ResolvedCategoryAdapterSelection {
  if (adapter === null || typeof adapter !== "object") {
    throw new MarketplaceServiceError(
      "ARTIFACT_INTEGRITY_INVALID",
      "category verifier result lacks a registered adapter identity",
    );
  }
  const value = adapter as {
    readonly category?: unknown;
    readonly adapterId?: unknown;
  };
  if (value.category === "grid" && value.adapterId === "pancakeswap-v3-grid-v1") {
    return { category: "grid", adapterId: "pancakeswap-v3-grid-v1" };
  }
  if (value.category === "yield" && value.adapterId === "erc4626-yield-v1") {
    return { category: "yield", adapterId: "erc4626-yield-v1" };
  }
  if (value.category === "health" && value.adapterId === "aave-v3-health-v1") {
    return { category: "health", adapterId: "aave-v3-health-v1" };
  }
  if (value.category === "health" && value.adapterId === "venus-health-v1") {
    return { category: "health", adapterId: "venus-health-v1" };
  }
  throw new MarketplaceServiceError(
    "ARTIFACT_INTEGRITY_INVALID",
    "category verifier result lacks a registered adapter identity",
  );
}

function resolveInputSelection(
  input: unknown,
  deployment: CategoryAdapterDeploymentManifest,
): ResolvedCategoryAdapterSelection | undefined {
  const parsed = parseCategoryInput(input);
  if (parsed.adapterId !== undefined) {
    return resolveSelection(parsed);
  }
  const enabled = deployment.adapters.filter(
    (entry) =>
      entry.enabled &&
      entry.configuration !== undefined &&
      entry.category === parsed.category,
  );
  if (enabled.length !== 1) return undefined;
  return resolveSelection(enabled[0]);
}

function parseCategoryInput(
  value: unknown,
): CategoryAdapterExecutionInput {
  if (value === null || typeof value !== "object") {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "category verifier input must be an object",
    );
  }
  const object = value as object;
  const keys = Reflect.ownKeys(object);
  if (
    (keys.length !== 1 && keys.length !== 2) ||
    !keys.includes("category") ||
    keys.some(
      (key) =>
        typeof key !== "string" ||
        (key !== "category" && key !== "adapterId"),
    )
  ) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "category verifier input contains unsupported fields",
    );
  }
  const values = new Map<string, unknown>();
  for (const key of keys) {
    if (typeof key !== "string") {
      throw new MarketplaceServiceError(
        "REQUEST_INVALID",
        "category verifier input contains unsupported fields",
      );
    }
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new MarketplaceServiceError(
        "REQUEST_INVALID",
        "category verifier input must contain data properties",
      );
    }
    values.set(key, descriptor.value);
  }
  const category = values.get("category");
  const adapterId = values.get("adapterId");
  if (
    category !== "grid" &&
    category !== "yield" &&
    category !== "health"
  ) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "category verifier input contains an invalid category",
    );
  }
  const hasAdapterId = keys.includes("adapterId");
  if (!hasAdapterId) return { category };
  if (adapterId === undefined) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "category verifier input contains an invalid adapter ID",
    );
  }
  if (
    adapterId !== "pancakeswap-v3-grid-v1" &&
    adapterId !== "erc4626-yield-v1" &&
    adapterId !== "aave-v3-health-v1" &&
    adapterId !== "venus-health-v1"
  ) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "category verifier input contains an invalid adapter ID",
    );
  }
  return { category, adapterId } as CategoryAdapterExecutionInput;
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

function parseSuccessorRuntimeOptions(
  value: unknown,
): PrivateMarketplaceCategorySuccessorVerifierRuntimeOptions {
  if (value === null || typeof value !== "object") {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "successor verifier runtime options must be an object",
    );
  }
  const object = value as object;
  const allowedKeys = [
    "policyIdentity",
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
      "successor verifier runtime options contain unsupported fields",
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
      "successor verifier runtime options contain unsupported fields",
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
        "successor verifier runtime options contain unsupported fields",
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
        "successor verifier runtime options must contain enumerable data properties only",
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
      "successor verifier runtime options contain invalid transport, clock, UUID, or policy values",
    );
  }

  return Object.freeze({
    policyIdentity:
      snapshot.policyIdentity as MarketplaceCategorySuccessorPolicyIdentity,
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
