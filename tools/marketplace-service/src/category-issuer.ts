import {
  type BoundCategoryExecutionSuccess,
  type CategoryExecutionPassArtifact,
  type CategoryExecutionBindingContext,
} from "@mandatex/agent-supply-verifier";
import {
  MARKETPLACE_CATEGORY_ATTESTATION_AUDIENCE,
  MARKETPLACE_CATEGORY_ATTESTATION_EVIDENCE_MODE,
  MARKETPLACE_CATEGORY_ATTESTATION_ISSUER,
  MARKETPLACE_CATEGORY_ATTESTATION_SCHEMA,
  MARKETPLACE_CATEGORY_ATTESTATION_SIGNATURE_PROFILE,
  MAX_MARKETPLACE_CATEGORY_ATTESTATION_TTL_SECONDS,
  canonicalSha256,
  marketplaceCategoryAttestationSigningMessage,
  marketplaceCategoryAttestationUnsignedSchema,
  marketplaceCategoryEvaluationRequestSchema,
  serializeMarketplaceCategoryAttestation,
  type MarketplaceCategoryAttestation,
  type MarketplaceCategoryAttestationTrust,
  type MarketplaceCategoryEvaluationRequest,
} from "@mandatex/marketplace-core";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signEd25519,
  type KeyObject,
} from "node:crypto";

import {
  assertMarketplaceCategoryVerifierRuntime,
  type MarketplaceCategoryVerifierRuntime,
} from "./category-runtime.js";
import { MarketplaceServiceError } from "./errors.js";

export interface MarketplaceCategoryIssuerOptions {
  readonly verifier: MarketplaceCategoryVerifierRuntime;
  readonly keyId: string;
  readonly privateKeyPkcs8Der: Uint8Array;
  readonly verifierPolicySha256: string;
  readonly categoryDeploymentSha256: string;
  readonly clock: () => number;
  readonly randomUUID: () => string;
}

export interface IssuedMarketplaceCategoryConditionAttestation {
  readonly request: MarketplaceCategoryEvaluationRequest;
  readonly attestation: MarketplaceCategoryAttestation;
  readonly wire: string;
}

export interface MarketplaceCategoryNotAttested {
  readonly status: "not_attested";
  readonly category: "grid" | "yield" | "health";
  readonly adapterId: string;
  readonly code: string;
  readonly message: string;
}

export interface MarketplaceCategoryIssuer {
  readonly pinnedTrust: MarketplaceCategoryAttestationTrust;
  readonly evaluateAndAttestCategory: (
    request: MarketplaceCategoryEvaluationRequest,
  ) => Promise<
    IssuedMarketplaceCategoryConditionAttestation | MarketplaceCategoryNotAttested
  >;
}

/**
 * Private category condition signer. It has no generic payload signer and
 * accepts no caller-supplied artifact or projection.
 */
export function createMarketplaceCategoryIssuer(
  options: MarketplaceCategoryIssuerOptions,
): MarketplaceCategoryIssuer {
  const issuerOptions = parseIssuerOptions(options);
  assertMarketplaceCategoryVerifierRuntime(issuerOptions.verifier);
  const {
    privateKey,
    publicKeyFingerprintSha256,
    publicKeySpkiDer,
  } = parsePrivateKey(issuerOptions.privateKeyPkcs8Der);
  const verifier = issuerOptions.verifier;
  const keyId = issuerOptions.keyId;
  const verifierPolicySha256 = issuerOptions.verifierPolicySha256;
  const categoryDeploymentSha256 = issuerOptions.categoryDeploymentSha256;
  const clock = issuerOptions.clock;
  const randomUUID = issuerOptions.randomUUID;
  if (
    verifierPolicySha256 !== verifier.policySha256 ||
    categoryDeploymentSha256 !== verifier.deploymentSha256
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category issuer pins do not match the verifier runtime",
    );
  }

  return Object.freeze({
    get pinnedTrust(): MarketplaceCategoryAttestationTrust {
      return Object.freeze({
        keyId,
        publicKeySpkiDer: Uint8Array.from(publicKeySpkiDer),
        publicKeyFingerprintSha256,
        verifierPolicySha256,
        categoryDeploymentSha256,
      });
    },
    async evaluateAndAttestCategory(
      input: MarketplaceCategoryEvaluationRequest,
    ) {
      const request = deepFreeze(parseRequest(input));
      assertRequestMatchesDeployment(request, verifier);
      const context: CategoryExecutionBindingContext = Object.freeze({
        mandate: request.mandate,
        candidate: request.candidate,
      });
      let result;
      try {
        result = await verifier.evaluateCategoryScopeBound(
          {
            adapterId: request.adapterId,
            category: request.category,
            evidenceSchema: request.evidenceSchema,
            protocol: request.protocol,
            subject: request.subject,
            conditionPolicy: categoryConditionPolicyForVerifier(request),
          },
          context,
        );
      } catch (cause) {
        if (cause instanceof MarketplaceServiceError) throw cause;
        throw new MarketplaceServiceError(
          "VERIFIER_EVALUATION_FAILED",
          "category verifier execution failed",
          { cause },
        );
      }
      if (
        result.outcome !== "executed" ||
        result.artifact.result.status !== "pass"
      ) {
        if (result.outcome === "inconclusive") {
          return Object.freeze({
            status: "not_attested" as const,
            category: result.category,
            adapterId: request.adapterId,
            code: result.code,
            message: result.message,
          });
        }
        throw new MarketplaceServiceError(
          "VERIFIER_EVALUATION_FAILED",
          "category verifier did not produce a pass result",
        );
      }
      const assertBound: (
        value: unknown,
        context: CategoryExecutionBindingContext,
      ) => asserts value is BoundCategoryExecutionSuccess =
        verifier.assertCategoryExecutionBound;
      try {
        assertBound(result, context);
      } catch (cause) {
        if (cause instanceof MarketplaceServiceError) throw cause;
        throw new MarketplaceServiceError(
          "ARTIFACT_INTEGRITY_INVALID",
          "category verifier result is not bound to the requested context",
          { cause },
        );
      }
      const artifact = result.artifact as CategoryExecutionPassArtifact;
      try {
        assertArtifactMatchesRequest(request, artifact, verifier);
      } catch (cause) {
        if (cause instanceof MarketplaceServiceError) throw cause;
        throw new MarketplaceServiceError(
          "ARTIFACT_INTEGRITY_INVALID",
          "category verifier artifact could not be validated",
          { cause },
        );
      }
      const unsigned = buildUnsignedAttestation(
        request,
        artifact,
        {
          keyId,
          verifierPolicySha256,
          categoryDeploymentSha256,
          clock,
          randomUUID,
        },
      );
      let signature: string;
      try {
        signature = signEd25519(
          null,
          marketplaceCategoryAttestationSigningMessage(unsigned),
          privateKey,
        ).toString("hex");
      } catch (cause) {
        throw new MarketplaceServiceError(
          "SIGNING_FAILED",
          "category issuer could not sign its attestation",
          { cause },
        );
      }
      const attestation = {
        ...unsigned,
        signature,
      } satisfies MarketplaceCategoryAttestation;
      let wire: string;
      try {
        wire = serializeMarketplaceCategoryAttestation(attestation);
      } catch (cause) {
        throw new MarketplaceServiceError(
          "ATTESTATION_SIGNER_INVALID",
          "category issuer could not serialize its strict attestation envelope",
          { cause },
        );
      }
      return deepFreeze({
        request,
        attestation,
        wire,
      });
    },
  });
}

function categoryConditionPolicyForVerifier(
  request: MarketplaceCategoryEvaluationRequest,
): Readonly<Record<string, unknown>> {
  switch (request.adapterId) {
    case "pancakeswap-v3-grid-v1":
      return Object.freeze({ unit: "uniswap-v3-tick", ...request.policy });
    case "erc4626-yield-v1":
      return Object.freeze({ unit: "1e18-share-price", ...request.policy });
    case "aave-v3-health-v1":
      return Object.freeze({ unit: "1e18-health-factor", ...request.policy });
    case "venus-health-v1":
      return Object.freeze({ unit: "1e18-usd", ...request.policy });
  }
}

type AttestationConstructionOptions = Readonly<{
  keyId: string;
  verifierPolicySha256: string;
  categoryDeploymentSha256: string;
  clock: () => number;
  randomUUID: () => string;
}>;

function buildUnsignedAttestation(
  request: MarketplaceCategoryEvaluationRequest,
  artifact: CategoryExecutionPassArtifact,
  options: AttestationConstructionOptions,
) {
  const issuedAt = readClock(options.clock);
  const evidence = artifact.result.evidence;
  assertIssuanceChronology(request, artifact, issuedAt);
  const expiresAt = Math.min(
    issuedAt + MAX_MARKETPLACE_CATEGORY_ATTESTATION_TTL_SECONDS,
    request.mandate.expiresAt,
  );
  if (expiresAt <= issuedAt) {
    throw new MarketplaceServiceError(
      "ATTESTATION_EXPIRY_INVALID",
      "category attestation cannot outlive the mandate",
    );
  }
  const attestationId = readAttestationId(options.randomUUID);
  try {
    return marketplaceCategoryAttestationUnsignedSchema.parse({
      schema: MARKETPLACE_CATEGORY_ATTESTATION_SCHEMA,
      signatureProfile: MARKETPLACE_CATEGORY_ATTESTATION_SIGNATURE_PROFILE,
      issuer: MARKETPLACE_CATEGORY_ATTESTATION_ISSUER,
      audience: MARKETPLACE_CATEGORY_ATTESTATION_AUDIENCE,
      keyId: options.keyId,
      attestationId,
      scope: "evaluation_only",
      activationAuthorization: "none",
      reservation: "none",
      replayPolicy: "reusable_until_expiry",
      replayScope: "request_id",
      evidenceMode: MARKETPLACE_CATEGORY_ATTESTATION_EVIDENCE_MODE,
      issuedAt,
      expiresAt,
      mandateSha256: canonicalSha256(request.mandate),
      requestSha256: canonicalSha256(request),
      verifierPolicySha256: options.verifierPolicySha256,
      payload: {
        schema: "mandatex.marketplace.category-condition-payload.v1",
        requestId: request.requestId,
        mandateId: request.mandate.mandateId,
        category: request.category,
        candidate: {
          chainId: request.candidate.chainId,
          tokenId: request.candidate.tokenId,
        },
        adapterId: artifact.adapter.adapterId,
        evidenceSchema: artifact.adapter.evidenceSchema,
        protocol: artifact.adapter.protocol,
        subjectSha256: canonicalSha256(request.subject),
        policySha256: canonicalSha256(request.policy),
        deploymentSha256: options.categoryDeploymentSha256,
        artifactSha256: canonicalSha256(artifact),
        evidenceSha256: canonicalSha256(evidence),
        observedAt: evidence.observedAt,
        observedBlock: evidence.observedBlock,
        observedBlockHash: evidence.observedBlockHash,
        status: "pass",
      },
    });
  } catch (cause) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "category issuer could not construct its strict attestation envelope",
      { cause },
    );
  }
}

type ParsedIssuerOptions = Omit<
  MarketplaceCategoryIssuerOptions,
  "privateKeyPkcs8Der" | "verifier"
> & {
  readonly privateKeyPkcs8Der: Uint8Array;
  readonly verifier: MarketplaceCategoryVerifierRuntime;
};

function parseIssuerOptions(
  value: MarketplaceCategoryIssuerOptions,
): ParsedIssuerOptions {
  if (value === null || typeof value !== "object") {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "category issuer options must be an object",
    );
  }
  const allowedKeys = [
    "categoryDeploymentSha256",
    "clock",
    "keyId",
    "privateKeyPkcs8Der",
    "randomUUID",
    "verifier",
    "verifierPolicySha256",
  ] as const;
  let prototype: object | null;
  let keys: readonly PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
  } catch (cause) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "category issuer options contain unsupported fields",
      { cause },
    );
  }
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== allowedKeys.length ||
    keys.some(
      (key) =>
        typeof key !== "string" ||
        !allowedKeys.includes(key as (typeof allowedKeys)[number]),
    )
  ) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "category issuer options contain unsupported fields",
    );
  }
  const snapshot = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch (cause) {
      throw new MarketplaceServiceError(
        "ATTESTATION_SIGNER_INVALID",
        "category issuer options must contain data properties",
        { cause },
      );
    }
    if (
      typeof key !== "string" ||
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new MarketplaceServiceError(
        "ATTESTATION_SIGNER_INVALID",
        "category issuer options must contain data properties",
      );
    }
    Object.defineProperty(snapshot, key, {
      value: descriptor.value,
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
  Object.freeze(snapshot);
  const keyId = snapshot.keyId;
  const verifierPolicySha256 = snapshot.verifierPolicySha256;
  const categoryDeploymentSha256 = snapshot.categoryDeploymentSha256;
  const privateKeyPkcs8Der = snapshot.privateKeyPkcs8Der;
  const clock = snapshot.clock;
  const randomUUID = snapshot.randomUUID;
  const verifier = snapshot.verifier;
  if (
    typeof keyId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(keyId) ||
    typeof verifierPolicySha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(verifierPolicySha256) ||
    typeof categoryDeploymentSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(categoryDeploymentSha256) ||
    !(privateKeyPkcs8Der instanceof Uint8Array) ||
    typeof clock !== "function" ||
    typeof randomUUID !== "function" ||
    verifier === null ||
    typeof verifier !== "object"
  ) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "category issuer options are invalid",
    );
  }
  return Object.freeze({
    verifier: verifier as MarketplaceCategoryVerifierRuntime,
    keyId,
    privateKeyPkcs8Der: Uint8Array.from(privateKeyPkcs8Der),
    verifierPolicySha256,
    categoryDeploymentSha256,
    clock: clock as () => number,
    randomUUID: randomUUID as () => string,
  });
}

function parseRequest(value: unknown): MarketplaceCategoryEvaluationRequest {
  let parsed: ReturnType<
    typeof marketplaceCategoryEvaluationRequestSchema.safeParse
  >;
  try {
    parsed = marketplaceCategoryEvaluationRequestSchema.safeParse(value);
  } catch (cause) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "category issuer request could not be parsed",
      { cause },
    );
  }
  if (!parsed.success) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "category issuer request is invalid",
      { cause: parsed.error },
    );
  }
  return parsed.data;
}

type ParsedPrivateKey = Readonly<{
  privateKey: KeyObject;
  publicKeySpkiDer: Uint8Array;
  publicKeyFingerprintSha256: string;
}>;

function parsePrivateKey(value: Uint8Array): ParsedPrivateKey {
  try {
    const suppliedDer = Buffer.from(value);
    const privateKey = createPrivateKey({
      key: suppliedDer,
      format: "der",
      type: "pkcs8",
    });
    if (
      privateKey.type !== "private" ||
      privateKey.asymmetricKeyType !== "ed25519"
    ) {
      throw new TypeError("private key is not Ed25519");
    }
    const exportedPrivateKey = privateKey.export({
      format: "der",
      type: "pkcs8",
    });
    if (
      !Buffer.isBuffer(exportedPrivateKey) ||
      !exportedPrivateKey.equals(suppliedDer)
    ) {
      throw new TypeError("private key is not canonical PKCS8 DER");
    }
    const publicKey = createPublicKey(privateKey);
    if (
      publicKey.type !== "public" ||
      publicKey.asymmetricKeyType !== "ed25519"
    ) {
      throw new TypeError("derived public key is not Ed25519");
    }
    const publicKeySpkiDer = publicKey.export({
      format: "der",
      type: "spki",
    });
    if (!Buffer.isBuffer(publicKeySpkiDer)) {
      throw new TypeError("derived public key is not canonical SPKI DER");
    }
    return Object.freeze({
      privateKey,
      publicKeySpkiDer: Uint8Array.from(publicKeySpkiDer),
      publicKeyFingerprintSha256: createHash("sha256")
        .update(publicKeySpkiDer)
        .digest("hex"),
    });
  } catch (cause) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "category issuer private key is not canonical Ed25519 PKCS8 DER",
      { cause },
    );
  }
}

function readClock(clock: () => number): number {
  let value: unknown;
  try {
    value = clock();
  } catch (cause) {
    throw new MarketplaceServiceError(
      "CLOCK_INVALID",
      "category issuer clock threw",
      { cause },
    );
  }
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    throw new MarketplaceServiceError(
      "CLOCK_INVALID",
      "category issuer clock must return positive Unix seconds",
    );
  }
  return value;
}

function readAttestationId(randomUUID: () => string): string {
  let attestationId: unknown;
  try {
    attestationId = randomUUID();
  } catch (cause) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "category issuer UUID generation failed",
      { cause },
    );
  }
  if (
    typeof attestationId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      attestationId,
    )
  ) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "category issuer UUID generator returned a noncanonical UUID",
    );
  }
  return attestationId;
}

function assertIssuanceChronology(
  request: MarketplaceCategoryEvaluationRequest,
  artifact: CategoryExecutionPassArtifact,
  issuedAt: number,
): void {
  const mandate = request.mandate;
  const observedAt = artifact.result.evidence.observedAt;
  if (issuedAt < mandate.createdAt || issuedAt >= mandate.expiresAt) {
    throw new MarketplaceServiceError(
      "ATTESTATION_EXPIRY_INVALID",
      "category attestation issuance is outside the mandate lifetime",
    );
  }
  if (
    artifact.evaluatedAt < mandate.createdAt ||
    artifact.evaluatedAt > issuedAt ||
    observedAt > issuedAt ||
    observedAt > artifact.evaluatedAt + mandate.maxClockSkewSeconds
  ) {
    throw new MarketplaceServiceError(
      "CLOCK_INVALID",
      "category verifier chronology is inconsistent with attestation issuance",
    );
  }
  if (
    observedAt < mandate.createdAt ||
    issuedAt - observedAt > mandate.maxEvidenceAgeSeconds
  ) {
    throw new MarketplaceServiceError(
      "ATTESTATION_EXPIRY_INVALID",
      "category evidence is outside the mandate issuance window",
    );
  }
}

function assertArtifactMatchesRequest(
  request: MarketplaceCategoryEvaluationRequest,
  artifact: CategoryExecutionPassArtifact,
  verifier: MarketplaceCategoryVerifierRuntime,
): void {
  if (
    artifact.adapter.adapterId !== request.adapterId ||
    artifact.adapter.category !== request.category ||
    artifact.adapter.evidenceSchema !== request.evidenceSchema ||
    artifact.adapter.protocol !== request.protocol ||
    artifact.deploymentSha256 !== verifier.deploymentSha256 ||
    artifact.verifierPolicySha256 !== verifier.policySha256
  ) {
    throw new MarketplaceServiceError(
      "ARTIFACT_INTEGRITY_INVALID",
      "category verifier artifact does not match the requested adapter or policy",
    );
  }
  const evidence = artifact.result.evidence;
  if (
    canonicalSha256(evidence.subject) !== canonicalSha256(request.subject) ||
    canonicalSha256(evidence.policy) !== canonicalSha256(request.policy)
  ) {
    throw new MarketplaceServiceError(
      "ARTIFACT_INTEGRITY_INVALID",
      "category verifier evidence does not match the requested subject or policy",
    );
  }
  if (
    verifier.policySha256 !== canonicalSha256(verifier.policy) ||
    verifier.deploymentSha256 !== verifier.policy.categoryPolicy.deploymentSha256
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category verifier policy exposure is inconsistent",
    );
  }
  const entry = verifier.policy.categoryPolicy.deployment.adapters.find(
    (candidate) => candidate.adapterId === request.adapterId,
  );
  if (
    entry === undefined ||
    !entry.enabled ||
    (entry.configuration !== undefined &&
      !configurationMatchesRequest(
        request,
        entry.configuration as unknown as Record<string, unknown>,
      ))
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category request does not match the pinned deployment configuration",
    );
  }
}

function assertRequestMatchesDeployment(
  request: MarketplaceCategoryEvaluationRequest,
  verifier: MarketplaceCategoryVerifierRuntime,
): void {
  const entry = verifier.policy.categoryPolicy.deployment.adapters.find(
    (candidate) => candidate.adapterId === request.adapterId,
  );
  if (
    entry === undefined ||
    !entry.enabled ||
    (entry.configuration !== undefined &&
      !configurationMatchesRequest(
        request,
        entry.configuration as unknown as Record<string, unknown>,
      ))
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "category request does not match the pinned deployment configuration",
    );
  }
}

function configurationMatchesRequest(
  request: MarketplaceCategoryEvaluationRequest,
  configuration: Record<string, unknown>,
): boolean {
  const expected = (() => {
    switch (request.adapterId) {
      case "pancakeswap-v3-grid-v1":
        return {
          subject: { poolAddress: configuration.poolAddress },
          policy: {
            lowerTick: configuration.lowerTick,
            upperTick: configuration.upperTick,
          },
        };
      case "erc4626-yield-v1":
        return {
          subject: { vaultAddress: configuration.vaultAddress },
          policy: { minSharePriceScaled: configuration.minSharePriceScaled },
        };
      case "aave-v3-health-v1":
        return {
          subject: {
            poolAddress: configuration.poolAddress,
            accountAddress: configuration.accountAddress,
          },
          policy: { minHealthFactorScaled: configuration.minHealthFactorScaled },
        };
      case "venus-health-v1":
        return {
          subject: {
            comptrollerAddress: configuration.comptrollerAddress,
            accountAddress: configuration.accountAddress,
            borrowMarketAddress: configuration.borrowMarketAddress,
          },
          policy: { minLiquidityUsdScaled: configuration.minLiquidityUsdScaled },
        };
    }
  })();
  return (
    canonicalSha256(expected.subject) === canonicalSha256(request.subject) &&
    canonicalSha256(expected.policy) === canonicalSha256(request.policy)
  );
}

function requestSelection(
  request: MarketplaceCategoryEvaluationRequest,
):
  | { readonly category: "grid"; readonly adapterId: "pancakeswap-v3-grid-v1" }
  | { readonly category: "yield"; readonly adapterId: "erc4626-yield-v1" }
  | {
      readonly category: "health";
      readonly adapterId: "aave-v3-health-v1" | "venus-health-v1";
    } {
  switch (request.adapterId) {
    case "pancakeswap-v3-grid-v1":
      return { category: "grid", adapterId: request.adapterId };
    case "erc4626-yield-v1":
      return { category: "yield", adapterId: request.adapterId };
    case "aave-v3-health-v1":
    case "venus-health-v1":
      return { category: "health", adapterId: request.adapterId };
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
