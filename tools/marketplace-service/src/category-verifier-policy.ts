import { createHash } from "node:crypto";
import { isIP } from "node:net";

import {
  BSC_CATEGORY_RPC_LIMITS,
  BSC_CATEGORY_STATE_READ_SELECTORS,
  BSC_MAINNET_RPC_ORIGIN,
  CATEGORY_CONFIRMATION_DEPTH,
  CATEGORY_EXECUTION_ARTIFACT_SCHEMA,
  CATEGORY_EXECUTION_RESULT_SCHEMA,
  CATEGORY_VERIFIER_POLICY_PROFILE,
  MAX_CATEGORY_IDENTITY_AGE_SECONDS,
  categoryAdapterDeploymentSha256 as verifierCategoryAdapterDeploymentSha256,
  parseCategoryAdapterDeploymentManifest,
} from "@mandatex/agent-supply-verifier";
import {
  CATEGORY_PRODUCTION_READ_DESCRIPTORS,
  MARKETPLACE_CATEGORY_ADAPTER_IDS,
  canonicalSha256,
  categoryStaticReadProfileForAdapterSha256,
} from "@mandatex/marketplace-core";

import {
  marketplaceVerifierPolicyManifest,
  type MarketplaceVerifierPolicyIdentity,
  type MarketplaceVerifierPolicyManifest,
} from "./issuer.js";
import {
  MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
  MARKETPLACE_CATEGORY_SUCCESSOR_DEPLOYMENT_SCHEMA,
  marketplaceCategoryAdapterDeploymentSha256,
  marketplaceCategorySuccessorDeploymentSha256,
  marketplaceCategorySuccessorExecutorDeployment,
  parseMarketplaceCategoryAdapterDeploymentManifest,
  parseMarketplaceCategorySuccessorDeploymentManifest,
  type MarketplaceCategoryAdapterDeploymentManifest,
  type MarketplaceCategorySuccessorDeploymentManifest,
  type MarketplaceCategorySuccessorTrustRoot,
} from "./category-policy.js";

/** The category execution policy is deliberately a separate versioned contract. */
export const MARKETPLACE_VERIFIER_POLICY_V2_SCHEMA =
  "mandatex.marketplace.verifier-policy.v2" as const;

export const MARKETPLACE_VERIFIER_POLICY_V2_PROFILES = Object.freeze({
  categoryVerifierPolicy: CATEGORY_VERIFIER_POLICY_PROFILE,
  categoryCanonicalization: "mandatex.agent-supply.canonical-quote-json.v1",
  categoryBlockPinning:
    "mandatex.agent-supply.category-block-pinning.head-minus-confirmations.v1",
  categoryTransport:
    "mandatex.agent-supply.bsc-category-pinned-https-transport.v1",
} as const);

export const MARKETPLACE_CATEGORY_SUCCESSOR_POLICY_PROFILES = Object.freeze({
  categoryVerifierPolicy: CATEGORY_VERIFIER_POLICY_PROFILE,
  categoryAdapterSelection:
    "mandatex.agent-supply.category-adapter-selection.explicit-id.v1",
  categoryCanonicalization: "mandatex.agent-supply.canonical-quote-json.v1",
  categoryBlockPinning:
    "mandatex.agent-supply.category-block-pinning.head-minus-confirmations.v1",
  categoryTransport:
    "mandatex.agent-supply.bsc-category-pinned-https-transport.v1",
  categorySuccessorContract:
    "mandatex.marketplace.category-successor-contract.v1",
  categoryIdentityBinding: "mandatex.agent-supply.erc8004-owner-of.v1",
  categoryTargetObservation:
    "mandatex.marketplace.category-target-observation.v1",
  categoryTargetProvenance:
    "mandatex.agent-supply.category-target-provenance.dynamic-root-bound.v1",
  categoryActiveReport: "mandatex.marketplace.derived-active-candidate-report.v1",
  categoryReleaseModes:
    "mandatex.marketplace.category-release.adapter-id-service-mode.v1",
} as const);

export const MARKETPLACE_VERIFIER_POLICY_V2_SUCCESSOR_SCHEMA =
  "mandatex.marketplace.category-successor-policy.v1" as const;

export type MarketplaceCategoryProvenanceRoots = Readonly<{
  readonly erc8004Registry: string;
  readonly pancakeV3Factory: string;
  readonly aavePoolAddressesProvider: string | null;
  readonly venusComptroller: string;
}>;

export type MarketplaceCategorySuccessorPolicyAdapterMode = Readonly<{
  readonly adapterId: (typeof MARKETPLACE_CATEGORY_ADAPTER_IDS)[number];
  readonly serviceMode: "observe_only" | "transactional";
  readonly enabled: boolean;
  readonly readProfileId: string;
  readonly readProfileSha256: string;
  readonly actionProfileId: string | null;
  readonly actionProfileSha256: string | null;
  readonly minimumTargetAssurance:
    | "interface_only_unendorsed"
    | "protocol_instance_verified";
}>;

export interface MarketplaceVerifierPolicyV2Identity
  extends MarketplaceVerifierPolicyIdentity {
  /** The complete four-entry deployment, before or after normalization. */
  readonly categoryAdapterDeployment: unknown;
}

export interface MarketplaceCategorySuccessorPolicyIdentity
  extends MarketplaceVerifierPolicyIdentity {
  /** Static adapter registry and every verifier-owned infrastructure root. */
  readonly categorySuccessorDeployment: unknown;
  /** Exact quote endpoint and EIP-712/EIP-1271 verifying contract identity. */
  readonly quotePolicy: unknown;
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
  const capturedIdentity = snapshotExactPlainObject(
    identity,
    ["passivePolicyFingerprint", "trustPolicySha256", "categoryAdapterDeployment"],
    ["passivePolicyFingerprint", "trustPolicySha256", "categoryAdapterDeployment"],
  );

  const base = marketplaceVerifierPolicyManifest({
    passivePolicyFingerprint:
      capturedIdentity.passivePolicyFingerprint as string,
    trustPolicySha256: capturedIdentity.trustPolicySha256 as string,
  });
  const deployment = parseMarketplaceCategoryAdapterDeploymentManifest(
    capturedIdentity.categoryAdapterDeployment,
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

/**
 * Static successor release policy, kept separate from the legacy v2 digest
 * surface. The v2 manifest remains byte-for-byte compatible while successor
 * consumers can bind the category deployment and provenance roots directly.
 */
export type MarketplaceCategorySuccessorPolicyManifest = Readonly<{
  readonly schema: typeof MARKETPLACE_VERIFIER_POLICY_V2_SUCCESSOR_SCHEMA;
  readonly base: MarketplaceVerifierPolicyManifest;
  readonly profiles: typeof MARKETPLACE_CATEGORY_SUCCESSOR_POLICY_PROFILES;
  readonly contracts: Readonly<{
    readonly categoryDeployment: typeof MARKETPLACE_CATEGORY_SUCCESSOR_DEPLOYMENT_SCHEMA;
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
    readonly executionDeploymentSha256: string;
    readonly deployment: MarketplaceCategorySuccessorDeploymentManifest;
    readonly trustRoot: MarketplaceCategorySuccessorTrustRoot;
    readonly infrastructure: MarketplaceCategoryProvenanceRoots;
  }>;
  readonly successorPolicy: Readonly<{
    readonly schema: typeof MARKETPLACE_VERIFIER_POLICY_V2_SUCCESSOR_SCHEMA;
    readonly scope: "evaluation_only";
    readonly activationAuthorization: "none";
    readonly reservation: "none";
    readonly replayPolicy: "reusable_until_expiry";
    readonly quote: Readonly<{
      readonly requestSchema: "mandatex.marketplace.category-quote-request.v1";
      readonly attestationSchema: "mandatex.marketplace.category-quote-attestation.v1";
      readonly endpoint: string;
      readonly endpointSha256: string;
      readonly domain: Readonly<{
        readonly chainId: 56;
        readonly verifyingContract: string;
      }>;
      readonly maxTtlSeconds: 300;
      readonly minimumRemainingValiditySeconds: 30;
      readonly challengeClock: "verifier_current_clock";
    }>;
    readonly identity: Readonly<{
      readonly profile: "mandatex.agent-supply.erc8004-owner-of.v1";
      readonly maxAgeSeconds: typeof MAX_CATEGORY_IDENTITY_AGE_SECONDS;
    }>;
    readonly target: Readonly<{
      readonly observationSchema: "mandatex.marketplace.category-target-observation.v1";
      readonly provenanceProfile: "mandatex.agent-supply.category-target-provenance.dynamic-root-bound.v1";
      readonly roots: MarketplaceCategoryProvenanceRoots;
      readonly arbitraryNomination: true;
      readonly sameCanonicalBlock: true;
      readonly proxyProfiles: readonly ["none", "eip1967", "beacon", "other-reviewed"];
    }>;
    readonly report: Readonly<{
      readonly schema: "mandatex.marketplace.derived-active-candidate-report.v1";
      readonly statusProfile: "mode-aware-successor-v1";
      readonly conditionWeight: 0;
      readonly unendorsedTargets: "disclose_and_allow_observe_only_hireability";
    }>;
    readonly release: Readonly<{
      readonly adapterModeKey: "adapterId x serviceMode";
      readonly productionActivation: "disabled";
      readonly observeOnly: "private_attestation_only";
      readonly transactional: "disabled_pending_principal_authorization";
      readonly adapterModes: readonly MarketplaceCategorySuccessorPolicyAdapterMode[];
    }>;
  }>;
}>;

export function marketplaceCategorySuccessorPolicyManifest(
  identity: MarketplaceCategorySuccessorPolicyIdentity,
): MarketplaceCategorySuccessorPolicyManifest {
  const capturedIdentity = snapshotExactPlainObject(
    identity,
    [
      "passivePolicyFingerprint",
      "quotePolicy",
      "trustPolicySha256",
      "categorySuccessorDeployment",
    ],
    [
      "passivePolicyFingerprint",
      "quotePolicy",
      "trustPolicySha256",
      "categorySuccessorDeployment",
    ],
  );
  const base = marketplaceVerifierPolicyManifest({
    passivePolicyFingerprint: capturedIdentity.passivePolicyFingerprint as string,
    trustPolicySha256: capturedIdentity.trustPolicySha256 as string,
  });
  const deployment = parseMarketplaceCategorySuccessorDeploymentManifest(
    capturedIdentity.categorySuccessorDeployment,
  );
  const quotePolicy = parseSuccessorQuotePolicy(capturedIdentity.quotePolicy);
  const executionDeployment = marketplaceCategorySuccessorExecutorDeployment(deployment);
  const serviceExecutionDeploymentSha256 =
    marketplaceCategoryAdapterDeploymentSha256(executionDeployment);
  const verifierExecutionDeploymentSha256 = verifierCategoryAdapterDeploymentSha256(
    parseCategoryAdapterDeploymentManifest(executionDeployment),
  );
  if (serviceExecutionDeploymentSha256 !== verifierExecutionDeploymentSha256) {
    throw new TypeError(
      "service and verifier successor execution deployment hashes diverge",
    );
  }
  const infrastructure = deployment.infrastructure;
  const adapterModes = MARKETPLACE_CATEGORY_ADAPTER_IDS.flatMap((adapterId) => {
    const deploymentEntry = deployment.adapters.find(
      (entry) => entry.adapterId === adapterId,
    );
    if (deploymentEntry === undefined) {
      throw new TypeError(`successor deployment is missing adapter ${adapterId}`);
    }
    const readProfileId =
      CATEGORY_PRODUCTION_READ_DESCRIPTORS[adapterId].profileId;
    const readProfileSha256 =
      categoryStaticReadProfileForAdapterSha256(adapterId);
    const observeAssurance =
      adapterId === "erc4626-yield-v1" ||
      (adapterId === "aave-v3-health-v1" &&
        infrastructure.aavePoolAddressesProvider === null)
        ? ("interface_only_unendorsed" as const)
        : ("protocol_instance_verified" as const);
    return [
      {
        adapterId,
        serviceMode: "observe_only" as const,
        enabled: deploymentEntry.enabled,
        readProfileId,
        readProfileSha256,
        actionProfileId: null,
        actionProfileSha256: null,
        minimumTargetAssurance: observeAssurance,
      },
      {
        adapterId,
        serviceMode: "transactional" as const,
        enabled: false,
        readProfileId,
        readProfileSha256,
        actionProfileId: null,
        actionProfileSha256: null,
        minimumTargetAssurance: "protocol_instance_verified" as const,
      },
    ];
  });
  return deepFreeze({
    schema: MARKETPLACE_VERIFIER_POLICY_V2_SUCCESSOR_SCHEMA,
    base,
    profiles: MARKETPLACE_CATEGORY_SUCCESSOR_POLICY_PROFILES,
    contracts: {
      categoryDeployment: MARKETPLACE_CATEGORY_SUCCESSOR_DEPLOYMENT_SCHEMA,
      categoryExecutionArtifact: CATEGORY_EXECUTION_ARTIFACT_SCHEMA,
      categoryExecutionResult: CATEGORY_EXECUTION_RESULT_SCHEMA,
    },
    categoryPolicy: {
      chainId: 56,
      confirmationDepth: CATEGORY_CONFIRMATION_DEPTH,
      rpcOrigin: BSC_MAINNET_RPC_ORIGIN,
      rpcLimits: BSC_CATEGORY_RPC_LIMITS,
      allowedStateReadSelectors: BSC_CATEGORY_STATE_READ_SELECTORS,
      deploymentSha256: marketplaceCategorySuccessorDeploymentSha256(deployment),
      executionDeploymentSha256: serviceExecutionDeploymentSha256,
      deployment,
      trustRoot: deployment.trustRoot,
      infrastructure,
    },
    successorPolicy: {
      schema: MARKETPLACE_VERIFIER_POLICY_V2_SUCCESSOR_SCHEMA,
      scope: "evaluation_only",
      activationAuthorization: "none",
      reservation: "none",
      replayPolicy: "reusable_until_expiry",
      quote: {
        requestSchema: "mandatex.marketplace.category-quote-request.v1",
        attestationSchema: "mandatex.marketplace.category-quote-attestation.v1",
        endpoint: quotePolicy.endpoint,
        endpointSha256: createHash("sha256")
          .update(quotePolicy.endpoint, "utf8")
          .digest("hex"),
        domain: {
          chainId: 56,
          verifyingContract: quotePolicy.verifyingContract,
        },
        maxTtlSeconds: 300,
        minimumRemainingValiditySeconds: 30,
        challengeClock: "verifier_current_clock",
      },
      identity: {
        profile: "mandatex.agent-supply.erc8004-owner-of.v1",
        maxAgeSeconds: MAX_CATEGORY_IDENTITY_AGE_SECONDS,
      },
      target: {
        observationSchema: "mandatex.marketplace.category-target-observation.v1",
        provenanceProfile: "mandatex.agent-supply.category-target-provenance.dynamic-root-bound.v1",
        roots: infrastructure,
        arbitraryNomination: true,
        sameCanonicalBlock: true,
        proxyProfiles: ["none", "eip1967", "beacon", "other-reviewed"],
      },
      report: {
        schema: "mandatex.marketplace.derived-active-candidate-report.v1",
        statusProfile: "mode-aware-successor-v1",
        conditionWeight: 0,
        unendorsedTargets: "disclose_and_allow_observe_only_hireability",
      },
      release: {
        adapterModeKey: "adapterId x serviceMode",
        productionActivation: "disabled",
        observeOnly: "private_attestation_only",
        transactional: "disabled_pending_principal_authorization",
        adapterModes,
      },
    },
  });
}

export function marketplaceCategorySuccessorPolicySha256(
  identity: MarketplaceCategorySuccessorPolicyIdentity,
): string {
  return canonicalSha256(marketplaceCategorySuccessorPolicyManifest(identity));
}

function snapshotExactPlainObject(
  value: unknown,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object") {
    throw new TypeError("verifier policy identity must be a plain object");
  }
  const object = value as object;
  let prototype: object | null;
  let keys: readonly PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(object);
    keys = Reflect.ownKeys(object);
  } catch {
    throw new TypeError("verifier policy identity contains unsupported fields");
  }
  const allowed = new Set(allowedKeys);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.some((key) => typeof key !== "string" || !allowed.has(key))
  ) {
    throw new TypeError("verifier policy identity contains unsupported fields");
  }
  const keySet = new Set(keys);
  for (const key of requiredKeys) {
    if (!keySet.has(key)) {
      throw new TypeError(`verifier policy identity is missing: ${key}`);
    }
  }
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(object, key);
    } catch {
      throw new TypeError("verifier policy identity contains unsupported fields");
    }
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new TypeError(
        "verifier policy identity must contain enumerable data properties only",
      );
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value,
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
  return Object.freeze(snapshot);
}

/**
 * Captures the quote trust-domain identity into the successor policy digest.
 * The endpoint rules intentionally mirror the verifier's quote transport so a
 * policy cannot hash an endpoint that the runtime would later reject or
 * normalize differently.
 */
function parseSuccessorQuotePolicy(value: unknown): Readonly<{
  readonly endpoint: string;
  readonly verifyingContract: string;
}> {
  const quote = snapshotExactPlainObject(
    value,
    ["endpoint", "verifyingContract"],
    ["endpoint", "verifyingContract"],
  );
  const endpoint = quote.endpoint;
  if (typeof endpoint !== "string") {
    throw new TypeError("successor quote policy endpoint must be an HTTPS URL");
  }
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch (cause) {
    throw new TypeError("successor quote policy endpoint must be an HTTPS URL", {
      cause,
    });
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.hostname.endsWith(".") ||
    isIP(url.hostname) !== 0 ||
    (url.port !== "" && url.port !== "443") ||
    url.href !== endpoint
  ) {
    throw new TypeError("successor quote policy endpoint is not canonical");
  }
  const verifyingContract = quote.verifyingContract;
  if (
    typeof verifyingContract !== "string" ||
    !/^0x[0-9a-f]{40}$/.test(verifyingContract)
  ) {
    throw new TypeError(
      "successor quote policy verifying contract must be a lowercase EVM address",
    );
  }
  return Object.freeze({ endpoint, verifyingContract });
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
