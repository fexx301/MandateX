import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";

import {
  BSC_MAINNET_RPC_ORIGIN,
  BSC_CATEGORY_TARGET_BEACON_SLOT,
  BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT,
  categoryQuoteCommitments,
  categoryQuoteEip191Message,
  categoryQuoteRequestKeccak256,
  type BoundedHttpResponse,
  type TransportRoute,
} from "@mandatex/agent-supply-verifier";
import { privateKeyToAccount } from "viem/accounts";

import {
  canonicalSha256,
  categoryReadArgumentBindingSha256,
  categoryReadCalldataSha256,
  categoryStaticReadProfileSha256,
  marketplaceMandateV2Schema,
  marketplaceCategoryQuoteRequestSchema,
  MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE,
  type MarketplaceMandateV2,
  type MarketplaceCategoryQuoteRequest,
} from "@mandatex/marketplace-core";
import {
  MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA,
  MARKETPLACE_MANDATE_V2_SCHEMA,
} from "@mandatex/marketplace-core/internal/successor-contract";
import {
  createMarketplaceCategoryTrustController,
  createMarketplaceCategoryTrustStateStore,
} from "@mandatex/marketplace-core/internal/trust-controller";
import {
  marketplaceTrustBundleDurableStateSchema,
  marketplaceTrustBundleUnsignedSchema,
  marketplaceTrustBundleSigningMessage,
  marketplaceTrustReleaseDefinitionSha256,
  serializeMarketplaceTrustBundle,
  MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA,
  MARKETPLACE_TRUST_BUNDLE_AUDIENCE,
  MARKETPLACE_TRUST_BUNDLE_ISSUER,
  MARKETPLACE_TRUST_BUNDLE_SCHEMA,
  MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE,
  MARKETPLACE_TRUST_KEY_SCHEMA,
  MARKETPLACE_TRUST_RELEASE_SCHEMA,
  type MarketplaceTrustBundleDurableState,
} from "@mandatex/marketplace-core/internal/trust-bundle";
import {
  MARKETPLACE_CATEGORY_ADAPTER_IDS,
  MARKETPLACE_CATEGORY_SUCCESSOR_DEPLOYMENT_SCHEMA,
  marketplaceCategorySuccessorDeploymentSha256,
  parseMarketplaceCategorySuccessorDeploymentManifest,
  type MarketplaceCategorySuccessorDeploymentManifest,
} from "../src/category-policy.js";
import {
  marketplaceCategorySuccessorPolicySha256,
  type MarketplaceCategorySuccessorPolicyIdentity,
} from "../src/category-verifier-policy.js";
import {
  createPrivateMarketplaceCategorySuccessorVerifierRuntime,
  type PrivateMarketplaceCategorySuccessorVerifierRuntime,
} from "../src/category-runtime.js";
import {
  createPrivateCategoryIssuanceRecordStore,
  createPrivateCategorySuccessorOrchestrator,
  type PrivateCategorySuccessorOrchestrator,
  type PrivateCategorySuccessorIssueInput,
} from "../src/category-successor-orchestrator.js";
import {
  createManagedEd25519Signer,
  type ManagedEd25519Signer,
} from "../src/managed-ed25519-signer.js";
import {
  categorySuccessorDeployment,
  categorySuccessorQuotePolicy,
} from "./category-fixture.js";

export const QUOTE_ENDPOINT = categorySuccessorQuotePolicy().endpoint;
export const QUOTE_VERIFYING_CONTRACT =
  categorySuccessorQuotePolicy().verifyingContract;
export const CANDIDATE_REGISTRY =
  "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432";
export const CANDIDATE_OWNER =
  "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
export const CANDIDATE_TOKEN_ID = "7";
export const PANCAKE_FACTORY =
  "0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865";
export const GRID_POOL = "0x1111111111111111111111111111111111111111";
export const YIELD_VAULT = "0x2222222222222222222222222222222222222222";
export const AAVE_POOL = "0x3333333333333333333333333333333333333334";
export const HEALTH_ACCOUNT = "0x4444444444444444444444444444444444444444";
export const VENUS_COMPTROLLER =
  "0x5555555555555555555555555555555555555555";
export const VENUS_MARKET = "0x6666666666666666666666666666666666666666";

export const ADAPTER_CASES = Object.freeze([
  {
    adapterId: "aave-v3-health-v1",
    category: "health",
    protocol: "aave-v3",
  },
  {
    adapterId: "erc4626-yield-v1",
    category: "yield",
    protocol: "erc4626",
  },
  {
    adapterId: "pancakeswap-v3-grid-v1",
    category: "grid",
    protocol: "pancakeswap-v3",
  },
  {
    adapterId: "venus-health-v1",
    category: "health",
    protocol: "venus",
  },
] as const);

export type SuccessorAdapterId = (typeof ADAPTER_CASES)[number]["adapterId"];
export type SuccessorFixtureOptions = Readonly<{
  readonly reservationMode?: "claimed" | "existing" | "in_progress";
  readonly existingRecord?: unknown;
  readonly malformedQuote?: boolean;
  readonly adapterPass?: boolean;
  readonly adapterOutcome?: "pass" | "fail";
  readonly adapterResults?: Partial<Record<SuccessorAdapterId, "pass" | "fail">>;
  readonly reorgAtHeaderCall?: number;
  readonly canonicalityLoss?: boolean;
  readonly advanceTrustBeforePermitUse?: boolean;
  readonly trustAdvancementBeforePermitUse?: boolean;
  readonly commitFailureAfterWrite?: boolean;
  /** Build the orchestrator with a controller root that disagrees with policy. */
  readonly trustRootMismatch?: boolean;
  /** Build the controller with a quote domain that disagrees with policy. */
  readonly trustQuoteDomainMismatch?: boolean;
  /** Sign a release whose mode projection intentionally diverges from policy. */
  readonly trustReleaseModeMismatch?: boolean;
  /** Select the release used by the private orchestrator. */
  readonly releaseId?: "fixture-release-r1" | "fixture-release-r2";
  /** Prove removed runtime quote overrides remain rejected as extra fields. */
  readonly legacyQuoteOverride?: "endpoint" | "verifying_contract";
}>;

export type SuccessorFixtureCounters = {
  attestationUuidCalls: number;
  signerCalls: number;
  rpcUuidCalls: number;
  quoteCalls: number;
  headerCalls: number;
  reserveCalls: number;
  commitCalls: number;
  releaseCalls: number;
  trustPrepareCalls: number;
  trustPermitCalls: number;
  trustWithPermitCalls: number;
};

export type SuccessorFixture = Readonly<{
  deployment: MarketplaceCategorySuccessorDeploymentManifest;
  policyIdentity: MarketplaceCategorySuccessorPolicyIdentity;
  verifier: PrivateMarketplaceCategorySuccessorVerifierRuntime;
  orchestrator: PrivateCategorySuccessorOrchestrator;
  transport: { readonly request: (route: TransportRoute) => Promise<BoundedHttpResponse> };
  routes: TransportRoute[];
  counters: SuccessorFixtureCounters;
  issuance: {
    readonly record: () => unknown;
    readonly reservation: () => unknown;
    readonly setExistingRecord: (record: unknown) => void;
  };
  trust: {
    readonly bundleWire: string;
    readonly snapshot: () => {
      readonly state: MarketplaceTrustBundleDurableState | undefined;
      readonly stateSha256: string | undefined;
    };
    readonly advance: () => void;
  };
  signer: ManagedEd25519Signer;
  trustBundleWire: string;
  quoteEndpoint: string;
  quoteVerifyingContract: string;
  ownerAddress: string;
  makeIssueInput: (adapterId: SuccessorAdapterId) => PrivateCategorySuccessorIssueInput;
}>;

const NOW = 1_700_000_000;
const HEAD_BLOCK = 100;
const ANCHOR_BLOCK = HEAD_BLOCK - 2;
const ANCHOR_HASH = `0x${"ab".repeat(32)}`;
const REORG_HASH = `0x${"cd".repeat(32)}`;
const ANCHOR_TIMESTAMP = NOW - 10;
const PASSIVE_POLICY_FINGERPRINT = "aa".repeat(32);
const TRUST_POLICY_SHA256 = "bb".repeat(32);
const ROOT_KEY_ID = "fixture-root-k1";
const SIGNER_KEY_ID = "fixture-signer-k1";
const ROOT_KEYS = generateKeyPairSync("ed25519");
const SIGNER_KEYS = generateKeyPairSync("ed25519");
const PROVIDER_ACCOUNT = privateKeyToAccount(`0x${"12".repeat(32)}`);

export function createSuccessorFixture(
  options: SuccessorFixtureOptions = {},
): SuccessorFixture {
  const counters: SuccessorFixtureCounters = {
    attestationUuidCalls: 0,
    signerCalls: 0,
    rpcUuidCalls: 0,
    quoteCalls: 0,
    headerCalls: 0,
    reserveCalls: 0,
    commitCalls: 0,
    releaseCalls: 0,
    trustPrepareCalls: 0,
    trustPermitCalls: 0,
    trustWithPermitCalls: 0,
  };
  const routes: TransportRoute[] = [];
  const ownerAddress = PROVIDER_ACCOUNT.address.toLowerCase();
  const rootPublicKeySpkiDer = exportedSpki(ROOT_KEYS.publicKey);
  const signerPublicKeySpkiDer = exportedSpki(SIGNER_KEYS.publicKey);
  const rootFingerprint = fingerprint(ROOT_KEYS.publicKey);
  const signerFingerprint = fingerprint(SIGNER_KEYS.publicKey);

  const deploymentInput = {
    ...categorySuccessorDeployment(),
    trustRoot: {
      keyId: ROOT_KEY_ID,
      publicKeyFingerprintSha256: rootFingerprint,
    },
  };
  const deployment = parseMarketplaceCategorySuccessorDeploymentManifest(
    deploymentInput,
  );
  const categoryDeploymentSha256 = marketplaceCategorySuccessorDeploymentSha256(
    deployment,
  );
  const policyIdentity: MarketplaceCategorySuccessorPolicyIdentity = {
    passivePolicyFingerprint: PASSIVE_POLICY_FINGERPRINT,
    trustPolicySha256: TRUST_POLICY_SHA256,
    categorySuccessorDeployment: deployment,
    quotePolicy: categorySuccessorQuotePolicy(),
  };
  const verifierPolicySha256 = marketplaceCategorySuccessorPolicySha256(
    policyIdentity,
  );
  const releaseId = options.releaseId ?? "fixture-release-r1";
  const trustBundleWire = makeTrustBundleWire({
    rootKeyId: ROOT_KEY_ID,
    signerKeyId: SIGNER_KEY_ID,
    rootPublicKeySpkiDer,
    signerPublicKeySpkiDer,
    signerFingerprint,
    verifierPolicySha256,
    categoryDeploymentSha256,
    trustReleaseModeMismatch: options.trustReleaseModeMismatch === true,
    releaseId,
  });

  let trustState: MarketplaceTrustBundleDurableState | undefined;
  let trustStateSha256: string | undefined;
  let trustRevisionTail = Promise.resolve();
  let trustAdvanced = false;
  const trustStateStore = createMarketplaceCategoryTrustStateStore({
    load: async () => ({ state: trustState, stateSha256: trustStateSha256 }),
    compareAndSwap: async (input: any) => {
      const expected = input.expectedStateSha256 as string | undefined;
      if (expected !== trustStateSha256) {
        return trustReceipt("conflict", input, trustState);
      }
      trustState = input.nextState;
      trustStateSha256 = input.nextStateSha256;
      return trustReceipt("committed", input, trustState);
    },
    withRevision: async <T>(expected: string, operation: () => Promise<T>) => {
      let release!: () => void;
      const prior = trustRevisionTail;
      trustRevisionTail = new Promise<void>((resolve) => {
        release = resolve;
      });
      await prior;
      try {
        const shouldAdvance =
          !trustAdvanced &&
          (options.advanceTrustBeforePermitUse === true ||
            options.trustAdvancementBeforePermitUse === true);
        if (shouldAdvance) advanceTrust();
        if (expected !== trustStateSha256) {
          throw new Error("fixture trust revision fence rejected stale state");
        }
        return await operation();
      } finally {
        release();
      }
    },
  });

  const trustControllerBase = createMarketplaceCategoryTrustController({
    root: {
      keyId: options.trustRootMismatch === true ? `${ROOT_KEY_ID}-mismatch` : ROOT_KEY_ID,
      publicKeySpkiDer: rootPublicKeySpkiDer,
      publicKeyFingerprintSha256: rootFingerprint,
    },
    quoteVerifyingContract:
      options.trustQuoteDomainMismatch === true
        ? "0x4444444444444444444444444444444444444444"
        : QUOTE_VERIFYING_CONTRACT,
    rollbackFloor: { generation: 0, revocationEpoch: 0 },
    stateStore: trustStateStore,
    clock: () => NOW,
  });
  const signer = createManagedEd25519Signer({
    keyId: SIGNER_KEY_ID,
    custody: "non_exportable_managed",
    backendProfile: "fixture-memory-kms-v1",
    publicKeySpkiDer: signerPublicKeySpkiDer,
    publicKeyFingerprintSha256: signerFingerprint,
    signRaw: async (message) => {
      counters.signerCalls += 1;
      return sign(null, Buffer.from(message), SIGNER_KEYS.privateKey);
    },
  });

  let issuanceRecord: any;
  let reservationValue: any;
  const reservationMode = options.reservationMode ?? "claimed";
  const issuanceStore = createPrivateCategoryIssuanceRecordStore({
    reserve: async ({ idempotencyKey }: any) => {
      counters.reserveCalls += 1;
      if (reservationMode === "in_progress") {
        reservationValue = { status: "in_progress" };
        return reservationValue;
      }
      if (reservationMode === "existing") {
        const record = issuanceRecord ?? options.existingRecord;
        if (record !== undefined) {
          reservationValue = { status: "existing", record };
          return reservationValue;
        }
      }
      reservationValue = { status: "claimed", token: `fixture-token-${counters.reserveCalls}` };
      return reservationValue;
    },
    commit: async ({ record }: any) => {
      counters.commitCalls += 1;
      issuanceRecord = record;
      if (options.commitFailureAfterWrite === true) {
        throw new Error("fixture lost the commit response after writing");
      }
    },
    release: async () => {
      counters.releaseCalls += 1;
    },
  });

  let headerCall = 0;
  const reorgAt = options.reorgAtHeaderCall ?? (options.canonicalityLoss ? 2 : undefined);
  const transport = {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      routes.push(route);
      if (route.kind === "a2a-quote") {
        counters.quoteCalls += 1;
        return jsonResponse(await quoteResponse(route.body, ownerAddress, options.malformedQuote === true));
      }
      if (!("body" in route)) throw new Error(`unexpected fixture route ${route.kind}`);
      const request = parseRouteBody(route.body);
      let result: unknown;
      if (route.kind === "bsc-rpc" || route.kind === "bsc-quote-rpc") {
        result = identityResult(route, request, ownerAddress);
      } else if (route.kind === "bsc-category-rpc") {
        result = categoryResult(route, request, options, counters);
      } else if (route.kind === "bsc-category-target-rpc") {
        result = targetResult(route, request, deployment, options);
      } else {
        throw new Error(`unexpected fixture route ${route.kind}`);
      }
      if (route.kind === "bsc-category-rpc" && route.purpose === "block-header") {
        headerCall += 1;
        counters.headerCalls = headerCall;
        if (reorgAt !== undefined && headerCall === reorgAt) {
          result = blockHeader(route.approvedBlockNumber, REORG_HASH);
        }
      }
      const body = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }));
      return boundedResponse(body);
    },
  };

  const verifier = createPrivateMarketplaceCategorySuccessorVerifierRuntime({
    policyIdentity,
    verifierPolicySha256,
    transport,
    clock: () => NOW,
    randomUUID: () => {
      counters.rpcUuidCalls += 1;
      return `rpc-${counters.rpcUuidCalls}`;
    },
  });
  const orchestrator = createPrivateCategorySuccessorOrchestrator({
    verifier,
    transport,
    erc1271Check: async () => true,
    trustController: trustControllerBase,
    trustBundleWire,
    releaseId,
    signer,
    issuanceStore,
    clock: () => NOW,
    randomUUID: () => {
      counters.attestationUuidCalls += 1;
      return `attestation-${counters.attestationUuidCalls}`;
    },
    rpcRandomUUID: () => {
      counters.rpcUuidCalls += 1;
      return `rpc-${counters.rpcUuidCalls}`;
    },
    ...(options.legacyQuoteOverride === "endpoint"
      ? { quoteEndpoint: "https://runtime-override.example/category-quote" }
      : {}),
    ...(options.legacyQuoteOverride === "verifying_contract"
      ? {
          quoteVerifyingContract:
            "0x4444444444444444444444444444444444444444",
        }
      : {}),
  } as never);

  function advanceTrust(): void {
    if (trustState === undefined) return;
    trustState = marketplaceTrustBundleDurableStateSchema.parse({
      ...trustState,
      generation: trustState.generation + 1,
      bundleSha256: "ee".repeat(32),
    });
    trustStateSha256 = canonicalSha256(trustState);
    trustAdvanced = true;
  }

  const fixture = {
    deployment,
    policyIdentity,
    verifier,
    orchestrator,
    transport,
    routes,
    counters,
    issuance: {
      record: () => issuanceRecord,
      reservation: () => reservationValue,
      setExistingRecord: (record: unknown) => {
        issuanceRecord = record;
      },
    },
    trust: {
      bundleWire: trustBundleWire,
      snapshot: () => ({ state: trustState, stateSha256: trustStateSha256 }),
      advance: advanceTrust,
    },
    signer,
    trustBundleWire,
    quoteEndpoint: QUOTE_ENDPOINT,
    quoteVerifyingContract: QUOTE_VERIFYING_CONTRACT,
    ownerAddress,
    makeIssueInput: (adapterId: SuccessorAdapterId) => makeSuccessorIssueInput(adapterId),
  } as const;
  return fixture;
}

export function makeSuccessorIssueInput(
  adapterId: SuccessorAdapterId,
): PrivateCategorySuccessorIssueInput {
  const entry = ADAPTER_CASES.find((candidate) => candidate.adapterId === adapterId)!;
  const scope = scopeForAdapter(adapterId);
  const mandate = marketplaceMandateV2Schema.parse({
    schema: MARKETPLACE_MANDATE_V2_SCHEMA,
    mandateId: `fixture-mandate-${adapterId}`,
    category: entry.category,
    adapterId,
    chainId: 56,
    createdAt: NOW - 100,
    expiresAt: NOW + 600,
    maxClockSkewSeconds: 30,
    maxEvidenceAgeSeconds: 300,
    serviceMode: "observe_only",
    categoryScope: scope,
    actionPermissions: [],
    maxSpendUsdMicros: "0",
    permissionsExpiresAt: NOW + 300,
  }) as MarketplaceMandateV2;
  const request = marketplaceCategoryQuoteRequestSchema.parse({
    schema: MARKETPLACE_CATEGORY_QUOTE_REQUEST_SCHEMA,
    requestId: `fixture-request-${adapterId}`,
    mandateId: mandate.mandateId,
    mandateSha256: canonicalSha256(mandate),
    category: mandate.category,
    adapterId,
    protocol: entry.protocol,
    categoryScope: scope,
    categoryScopeSha256: canonicalSha256(scope),
    candidate: { chainId: 56, tokenId: CANDIDATE_TOKEN_ID },
    serviceMode: "observe_only",
    actionPermissions: [],
    actionPermissionsSha256: canonicalSha256([]),
    maxSpendUsdMicros: "0",
    permissionsExpiresAt: NOW + 240,
    nonce: `fixture-nonce-${adapterId}`,
    issuedAt: NOW - 50,
    expiresAt: NOW + 240,
  }) as MarketplaceCategoryQuoteRequest;
  return { mandate, request };
}

function scopeForAdapter(adapterId: SuccessorAdapterId): unknown {
  switch (adapterId) {
    case "pancakeswap-v3-grid-v1":
      return {
        adapterId,
        category: "grid",
        evidenceSchema: "mandatex.category.grid-evidence.v1",
        protocol: "pancakeswap-v3",
        subject: { poolAddress: GRID_POOL },
        conditionPolicy: {
          unit: "uniswap-v3-tick",
          lowerTick: -100,
          upperTick: 100,
        },
      };
    case "erc4626-yield-v1":
      return {
        adapterId,
        category: "yield",
        evidenceSchema: "mandatex.category.yield-evidence.v1",
        protocol: "erc4626",
        subject: { vaultAddress: YIELD_VAULT },
        conditionPolicy: {
          unit: "1e18-share-price",
          minSharePriceScaled: "1000000000000000000",
        },
      };
    case "aave-v3-health-v1":
      return {
        adapterId,
        category: "health",
        evidenceSchema: "mandatex.category.health-evidence.v1",
        protocol: "aave-v3",
        subject: { poolAddress: AAVE_POOL, accountAddress: HEALTH_ACCOUNT },
        conditionPolicy: {
          unit: "1e18-health-factor",
          minHealthFactorScaled: "1100000000000000000",
        },
      };
    case "venus-health-v1":
      return {
        adapterId,
        category: "health",
        evidenceSchema: "mandatex.category.venus-health-evidence.v1",
        protocol: "venus",
        subject: {
          comptrollerAddress: VENUS_COMPTROLLER,
          accountAddress: HEALTH_ACCOUNT,
          borrowMarketAddress: VENUS_MARKET,
        },
        conditionPolicy: {
          unit: "1e18-usd",
          minLiquidityUsdScaled: "100",
        },
      };
  }
}

function makeTrustBundleWire(input: {
  rootKeyId: string;
  signerKeyId: string;
  rootPublicKeySpkiDer: Uint8Array;
  signerPublicKeySpkiDer: Uint8Array;
  signerFingerprint: string;
  verifierPolicySha256: string;
  categoryDeploymentSha256: string;
  trustReleaseModeMismatch: boolean;
  releaseId: "fixture-release-r1" | "fixture-release-r2";
}): string {
  const modes = [...ADAPTER_CASES]
    .sort((a, b) => a.adapterId.localeCompare(b.adapterId))
    .map((entry) => ({
      adapterId: entry.adapterId,
      serviceMode: "observe_only" as const,
      readProfileId: profileForAdapter(entry.adapterId).profileId,
      readProfileSha256: categoryStaticReadProfileSha256(profileForAdapter(entry.adapterId)),
      actionProfileId: null,
      actionProfileSha256: null,
      minimumTargetAssurance:
        input.trustReleaseModeMismatch &&
        entry.adapterId === "pancakeswap-v3-grid-v1"
          ? ("interface_only_unendorsed" as const)
          : entry.adapterId === "erc4626-yield-v1" ||
              entry.adapterId === "aave-v3-health-v1"
            ? ("interface_only_unendorsed" as const)
            : ("protocol_instance_verified" as const),
    }));
  const releases = [input.releaseId].map((releaseId) => {
    const releasePartial = {
      schema: MARKETPLACE_TRUST_RELEASE_SCHEMA,
      releaseId,
      attestationSchema: MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA,
      signatureProfile: MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE,
      verifierPolicySha256: input.verifierPolicySha256,
      categoryDeploymentSha256: input.categoryDeploymentSha256,
      enabledAdapterModes: modes,
      definitionSha256: "0".repeat(64),
      lifecycle: "active" as const,
      lifecycleChangedAt: NOW - 160,
      notBefore: NOW - 200,
      notAfter: NOW + 3_600,
      revokedAt: null,
      revocationEpoch: null,
    };
    return {
      ...releasePartial,
      definitionSha256: marketplaceTrustReleaseDefinitionSha256(releasePartial),
    };
  });
  const unsigned = marketplaceTrustBundleUnsignedSchema.parse({
    schema: MARKETPLACE_TRUST_BUNDLE_SCHEMA,
    signatureProfile: MARKETPLACE_TRUST_BUNDLE_SIGNATURE_PROFILE,
    issuer: MARKETPLACE_TRUST_BUNDLE_ISSUER,
    audience: MARKETPLACE_TRUST_BUNDLE_AUDIENCE,
    rootKeyId: input.rootKeyId,
    generation: 1,
    revocationEpoch: 0,
    issuedAt: NOW - 150,
    expiresAt: NOW + 3_000,
    activeSignerKeyId: input.signerKeyId,
    activeReleaseId: releases[0]!.releaseId,
    keys: [
      {
        schema: MARKETPLACE_TRUST_KEY_SCHEMA,
        keyId: input.signerKeyId,
        algorithm: "Ed25519",
        publicKeyEncoding: "spki-der",
        publicKeySpkiDerBase64: Buffer.from(input.signerPublicKeySpkiDer).toString("base64"),
        publicKeyFingerprintSha256: input.signerFingerprint,
        lifecycle: "active",
        lifecycleChangedAt: NOW - 160,
        notBefore: NOW - 200,
        notAfter: NOW + 3_600,
        revokedAt: null,
        revocationEpoch: null,
      },
    ],
    releases,
    authorizations: releases.map((release) => ({
        schema: MARKETPLACE_TRUST_AUTHORIZATION_SCHEMA,
        keyId: input.signerKeyId,
        releaseId: release.releaseId,
        channel: "production" as const,
        notBefore: NOW - 200,
        notAfter: NOW + 3_600,
      })),
    keyTombstones: [],
    releaseTombstones: [],
    revokedKeyFingerprints: [],
  });
  const signature = sign(
    null,
    marketplaceTrustBundleSigningMessage(unsigned),
    ROOT_KEYS.privateKey,
  ).toString("hex");
  return serializeMarketplaceTrustBundle({ ...unsigned, signature });
}

function profileForAdapter(adapterId: SuccessorAdapterId): any {
  const descriptors: Record<string, readonly { role: string; callId: string; selector: string }[]> = {
    "pancakeswap-v3-grid-v1": [{ role: "pool", callId: "slot0()", selector: "0x3850c7bd" }],
    "erc4626-yield-v1": [
      { role: "vault", callId: "totalAssets()", selector: "0x01e1d114" },
      { role: "vault", callId: "totalSupply()", selector: "0x18160ddd" },
    ],
    "aave-v3-health-v1": [{ role: "pool", callId: "getUserAccountData(address)", selector: "0xbf92857c" }],
    "venus-health-v1": [
      { role: "borrowMarket", callId: "borrowBalanceStored(address)", selector: "0x95dd9193" },
      { role: "comptroller", callId: "getAccountLiquidity(address)", selector: "0x5ec88c79" },
      { role: "comptroller", callId: "getAssetsIn(address)", selector: "0xabfceffc" },
    ],
  };
  const descriptorsForAdapter = descriptors[adapterId]!;
  return {
    schema: "mandatex.marketplace.category-read-profile.v1",
    profileId:
      adapterId === "pancakeswap-v3-grid-v1"
        ? "pancakeswap-v3-grid-observation-v1"
        : adapterId === "erc4626-yield-v1"
          ? "erc4626-yield-observation-v1"
          : adapterId === "aave-v3-health-v1"
            ? "aave-v3-health-observation-v1"
            : "venus-health-observation-v1",
    adapterId,
    reads: descriptorsForAdapter.map((read) => ({
      ...read,
      target: targetForRole(adapterId, read.role),
      argumentBindingSha256:
        adapterId === "aave-v3-health-v1" || adapterId === "venus-health-v1"
          ? categoryReadArgumentBindingSha256(HEALTH_ACCOUNT)
          : categoryReadArgumentBindingSha256(),
      calldataSha256:
        adapterId === "aave-v3-health-v1" || adapterId === "venus-health-v1"
          ? categoryReadCalldataSha256(read.selector, HEALTH_ACCOUNT)
          : categoryReadCalldataSha256(read.selector),
      responseSha256: "00".repeat(32),
    })),
  };
}

function targetForRole(adapterId: SuccessorAdapterId, role: string): string {
  if (adapterId === "pancakeswap-v3-grid-v1") return GRID_POOL;
  if (adapterId === "erc4626-yield-v1") return YIELD_VAULT;
  if (adapterId === "aave-v3-health-v1") return AAVE_POOL;
  return role === "borrowMarket" ? VENUS_MARKET : VENUS_COMPTROLLER;
}

async function quoteResponse(body: string, owner: string, malformed: boolean): Promise<unknown> {
  const request = JSON.parse(body) as any;
  const challenge = request.params.message.parts[0].data.challenge;
  const requestKeccak256 = categoryQuoteRequestKeccak256(challenge);
  const response = {
    schema: "mandatex.agent-supply.category-quote-response.v1",
    accepted: true,
    relation: "candidate_accepts_service_for_subject",
    providerAuthority: "erc8004_registered_owner",
    providerAddress: owner,
    providerKind: "eoa",
    requestKeccak256,
    negotiatedAt: challenge.issuedAt + 1,
    quoteExpiresAt: challenge.expiresAt - 1,
  };
  const commitments = categoryQuoteCommitments({ challenge, response });
  const signature = await PROVIDER_ACCOUNT.signMessage({
    message: categoryQuoteEip191Message(commitments.negotiationKeccak256),
  });
  const envelope = {
    schema: "mandatex.agent-supply.category-quote-envelope.v1",
    challenge,
    response,
    requestKeccak256: commitments.requestKeccak256,
    responseKeccak256: commitments.responseKeccak256,
    negotiationKeccak256: commitments.negotiationKeccak256,
    providerSignature: malformed ? "0x00" : signature,
  };
  return {
    jsonrpc: "2.0",
    id: request.id,
    result: {
      kind: "message",
      role: "agent",
      messageId: "fixture-message-1",
      parts: [{ kind: "data", data: envelope }],
    },
  };
}

function identityResult(route: any, request: any, owner: string): unknown {
  switch (route.purpose ?? request.method) {
    case "chain-id":
    case "eth_chainId":
      return "0x38";
    case "head-block-number":
    case "eth_blockNumber":
      return `0x${HEAD_BLOCK.toString(16)}`;
    case "block-header":
    case "eth_getBlockByNumber":
      return blockHeader(route.approvedBlockNumber ?? request.params?.[0], ANCHOR_HASH);
    case "contract-code":
    case "eth_getCode": {
      const address = route.approvedTargets?.[0] ?? request.params?.[0];
      return String(address).toLowerCase() === owner ? "0x" : "0x60006000";
    }
    case "eth_call":
      return addressWord(owner);
    default:
      return "0x";
  }
}

function categoryResult(route: any, request: any, options: SuccessorFixtureOptions, counters: SuccessorFixtureCounters): unknown {
  switch (route.purpose) {
    case "chain-id":
      return "0x38";
    case "head-block-number":
      return `0x${HEAD_BLOCK.toString(16)}`;
    case "block-header":
      return blockHeader(route.approvedBlockNumber, ANCHOR_HASH);
    case "state-read": {
      const selector = String(route.approvedCalldata).slice(0, 10).toLowerCase();
      const adapterId = adapterFromSelector(selector, route.approvedTargets?.[0]);
      const pass = options.adapterResults?.[adapterId] ?? options.adapterOutcome ?? (options.adapterPass === false ? "fail" : "pass");
      return stateResult(selector, pass === "pass");
    }
    default:
      counters.rpcUuidCalls += 0;
      return "0x";
  }
}

function targetResult(route: any, request: any, deployment: MarketplaceCategorySuccessorDeploymentManifest, options: SuccessorFixtureOptions): unknown {
  switch (route.purpose) {
    case "chain-id":
      return "0x38";
    case "head-block-number":
      return `0x${HEAD_BLOCK.toString(16)}`;
    case "block-header":
      return blockHeader(route.approvedBlockNumber, ANCHOR_HASH);
    case "contract-code":
      return "0x60006000";
    case "proxy-slot":
      return `0x${"00".repeat(32)}`;
    case "provenance-read": {
      const selector = String(route.approvedCalldata).slice(0, 10).toLowerCase();
      if (isCategoryStateSelector(selector)) {
        const adapterId = adapterFromSelector(selector, route.approvedTargets?.[0]);
        const pass =
          options.adapterResults?.[adapterId] ??
          options.adapterOutcome ??
          (options.adapterPass === false ? "fail" : "pass");
        return stateResult(selector, pass === "pass");
      }
      if (selector === "0xc45a0155") return addressWord(deployment.infrastructure.pancakeV3Factory);
      if (selector === "0x5fe3b567") return addressWord(deployment.infrastructure.venusComptroller);
      if (selector === "0x8e8f294b") return wordHex(1n);
      if (selector === "0x026b1d5f") return addressWord(route.approvedTargets?.[0] ?? AAVE_POOL);
      return wordHex(1n);
    }
    default:
      return "0x";
  }
}

function adapterFromSelector(selector: string, target: string | undefined): SuccessorAdapterId {
  if (selector === "0x3850c7bd") return "pancakeswap-v3-grid-v1";
  if (selector === "0x01e1d114" || selector === "0x18160ddd") return "erc4626-yield-v1";
  if (selector === "0xbf92857c") return "aave-v3-health-v1";
  if (target === VENUS_MARKET || selector === "0x95dd9193" || selector === "0x5ec88c79" || selector === "0xabfceffc") return "venus-health-v1";
  return "venus-health-v1";
}

function stateResult(selector: string, pass: boolean): string {
  if (selector === "0x3850c7bd") {
    return `0x${[
      2n ** 96n,
      pass ? 0n : 1000n,
      0n,
      1n,
      1n,
      0n,
      1n,
    ]
      .map(word)
      .join("")}`;
  }
  if (selector === "0x01e1d114") return wordHex(pass ? 200n : 50n);
  if (selector === "0x18160ddd") return wordHex(100n);
  if (selector === "0xbf92857c") return `${[1000n, 500n, 0n, 0n, 0n, pass ? 2_000_000_000_000_000_000n : 0n].map(word).join("")}`.replace(/^/, "0x");
  if (selector === "0x5ec88c79") return `${word(0n)}${word(pass ? 200n : 0n)}${word(pass ? 0n : 1n)}`.replace(/^/, "0x");
  if (selector === "0xabfceffc") return `${word(32n)}${word(1n)}${word(BigInt(HEALTH_ACCOUNT))}`.replace(/^/, "0x");
  if (selector === "0x95dd9193") return `${word(50n)}${word(0n)}${word(0n)}`.replace(/^/, "0x");
  return wordHex(1n);
}

function isCategoryStateSelector(selector: string): boolean {
  return (
    selector === "0x3850c7bd" ||
    selector === "0x01e1d114" ||
    selector === "0x18160ddd" ||
    selector === "0xbf92857c" ||
    selector === "0x5ec88c79" ||
    selector === "0xabfceffc" ||
    selector === "0x95dd9193"
  );
}

function parseRouteBody(body: string): any {
  return JSON.parse(body);
}

function blockHeader(blockNumber: unknown, hash: string): unknown {
  const number = typeof blockNumber === "string" ? blockNumber : `0x${ANCHOR_BLOCK.toString(16)}`;
  return { number, hash, timestamp: `0x${ANCHOR_TIMESTAMP.toString(16)}` };
}

function boundedResponse(body: Uint8Array): BoundedHttpResponse {
  const now = new Date(NOW * 1000).toISOString();
  return {
    status: 200,
    contentType: "application/json",
    retryAfter: null,
    rateLimitRemaining: null,
    body,
    responseSha256: createHash("sha256").update(body).digest("hex"),
    resolvedAddress: "93.184.216.34",
    startedAt: now,
    finishedAt: now,
    latencyMs: 1,
  };
}

function jsonResponse(value: unknown): BoundedHttpResponse {
  return boundedResponse(Buffer.from(JSON.stringify(value)));
}

function trustReceipt(status: "committed" | "conflict", input: any, state: MarketplaceTrustBundleDurableState | undefined): unknown {
  return {
    status,
    expectedStateSha256: input.expectedStateSha256,
    committedStateSha256: state === undefined ? undefined : canonicalSha256(state),
    bundleSha256: state?.bundleSha256,
    generation: state?.generation,
    revocationEpoch: state?.revocationEpoch,
  };
}

function addressWord(address: string): string {
  return `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}`;
}

function word(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

function wordHex(value: bigint): string {
  return `0x${word(value)}`;
}

function exportedSpki(key: KeyObject): Buffer {
  const value = key.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(value)) throw new TypeError("expected SPKI DER");
  return value;
}

function fingerprint(key: KeyObject): string {
  return createHash("sha256").update(exportedSpki(key)).digest("hex");
}
