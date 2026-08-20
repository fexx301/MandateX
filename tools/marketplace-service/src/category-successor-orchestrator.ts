import { createHash } from "node:crypto";

import {
  BSC_MAINNET,
  CATEGORY_CANDIDATE_IDENTITY_PROFILE,
  CategoryBlockCanonicalityError,
  CategoryBlockPinError,
  CategoryReadContractError,
  MAX_CATEGORY_QUOTE_TTL_SECONDS,
  categoryQuoteChallengeSchema,
  createCategoryCandidateIdentityCapability,
  createCategoryQuoteFetchCapability,
  createCategoryQuoteVerificationCapability,
  createCategoryTargetObservationCapability,
  type BoundedHttpResponse,
  type CategoryCandidateIdentitySelector,
  type CategoryQuoteChallenge,
  type CategoryQuoteExpectedRequest,
  type CategoryQuoteErc1271Check,
  type CategoryQuoteFetchCapability,
  type CategoryTargetObservation,
  type CategoryTargetObservationInput,
  type CategoryExecutionPassArtifact,
  type BoundCategoryExecutionSuccess,
  type CategoryCandidateIdentityCapability,
  type CategoryQuoteVerificationCapability,
  type CategoryTargetObservationCapability,
  type CategorySnapshotHandle,
  type VerifiedCategoryCandidateIdentity,
  type TransportRoute,
} from "@mandatex/agent-supply-verifier";
import {
  MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_AUDIENCE,
  MARKETPLACE_CATEGORY_QUOTE_ISSUER,
  MARKETPLACE_CATEGORY_QUOTE_PROJECTION_SCHEMA,
  MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE,
  MAX_MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_TTL_SECONDS,
  canonicalJson,
  canonicalSha256,
  categoryReadArgumentBindingSha256,
  categoryReadCalldataSha256,
  categoryReadCommitmentsSha256,
  categoryStaticReadProfileSha256,
  marketplaceCategoryQuoteProjectionSchema,
  createMarketplaceCategoryQuoteTrustStore,
  marketplaceCategoryQuoteAttestationSigningMessage,
  marketplaceCategoryQuoteAttestationUnsignedSchema,
  marketplaceCategoryQuoteRequestSchema,
  marketplaceMandateV2Schema,
  serializeMarketplaceCategoryQuoteAttestation,
  validateAdapterReadProfile,
  validateCategoryQuoteRequestBinding,
  validateTargetObservationsForScope,
  verifyMarketplaceCategoryQuoteAttestation,
  type CategoryReadProfile,
  type CategoryScope,
  type MarketplaceCategoryQuoteAttestationWire,
  type MarketplaceCategoryQuoteProjection,
  type MarketplaceCategoryQuoteRequest,
  type MarketplaceMandateV2,
} from "@mandatex/marketplace-core";
import type {
  MarketplaceCategoryTrustCommitment,
  MarketplaceCategoryTrustController,
} from "@mandatex/marketplace-core/internal/trust-controller";
import {
  resolveMarketplaceCategoryTrustCommitment,
  resolveMarketplaceCategoryTrustControllerRoot,
} from "@mandatex/marketplace-core/internal/trust-controller";
import {
  MARKETPLACE_CATEGORY_LINKAGE_PROJECTION_SCHEMA,
  buildCategoryLinkageProjection,
  validateCategoryLinkageProjection,
} from "@mandatex/marketplace-core/internal/category-linkage";
import {
  MARKETPLACE_CATEGORY_QUOTE_SIDECARS_SCHEMA,
} from "@mandatex/marketplace-core/internal/successor-contract";
import {
  assertMarketplaceTrustReleaseModeProjection,
} from "@mandatex/marketplace-core/internal/trust-bundle";

import {
  assertManagedEd25519Signer,
  type ManagedEd25519Signer,
} from "./managed-ed25519-signer.js";
import {
  assertPrivateMarketplaceCategorySuccessorVerifierRuntime,
  privateCategorySnapshotCapabilityForRuntime,
  type PrivateMarketplaceCategorySuccessorVerifierRuntime,
} from "./category-runtime.js";
import { MarketplaceServiceError } from "./errors.js";

const ISSUANCE_RECORD_SCHEMA =
  "mandatex.marketplace.category-issuance-record.v1" as const;
const ISSUANCE_KEY_SCHEMA =
  "mandatex.marketplace.category-issuance-key.v1" as const;
const CATEGORY_ATTESTATION_MINIMUM_REMAINING_VALIDITY_SECONDS = 30 as const;

type IssuanceRecord = Readonly<{
  readonly schema: typeof ISSUANCE_RECORD_SCHEMA;
  readonly idempotencyKey: string;
  readonly attestationId: string;
  readonly wire: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly projection: MarketplaceCategoryQuoteProjection;
}>;

type Reservation =
  | Readonly<{ status: "claimed"; token: string }>
  | Readonly<{ status: "existing"; record: IssuanceRecord }>
  | Readonly<{ status: "in_progress" }>;

/**
 * Durable issuance state is intentionally separate from provider quote replay.
 * The backend must make reserve/commit/release atomic for one idempotency key.
 * Commit is a terminal idempotent transition: if its response is lost, retrying
 * the same request must recover the exact stored record rather than replace it.
 * Release is token-conditional and idempotent; after a committed record exists,
 * release must be a no-op so an ambiguous commit can still be reconciled.
 */
export interface PrivateCategoryIssuanceRecordStore {
  readonly reserve: (input: { readonly idempotencyKey: string }) => Promise<Reservation>;
  readonly commit: (input: {
    readonly idempotencyKey: string;
    readonly token: string;
    readonly record: IssuanceRecord;
  }) => Promise<void>;
  readonly release: (input: {
    readonly idempotencyKey: string;
    readonly token: string;
  }) => Promise<void>;
}

export function createPrivateCategoryIssuanceRecordStore(options: {
  readonly reserve: (input: unknown) => Promise<unknown>;
  readonly commit: (input: unknown) => Promise<unknown>;
  readonly release: (input: unknown) => Promise<unknown>;
}): PrivateCategoryIssuanceRecordStore {
  assertPlainDataObject(options, ["commit", "release", "reserve"], "issuance store");
  if (
    typeof options.reserve !== "function" ||
    typeof options.commit !== "function" ||
    typeof options.release !== "function"
  ) {
    throw new MarketplaceServiceError(
      "IDEMPOTENCY_STORE_INVALID",
      "category issuance store callbacks must be functions",
    );
  }
  const reserve = options.reserve;
  const commit = options.commit;
  const release = options.release;
  const store: PrivateCategoryIssuanceRecordStore = Object.freeze({
    async reserve(input: { readonly idempotencyKey: string }) {
      assertPlainDataObject(input, ["idempotencyKey"], "issuance reservation");
      const key = parseSha256(input.idempotencyKey, "idempotency key");
      let result: unknown;
      try {
        result = await reserve({ idempotencyKey: key });
      } catch (cause) {
        throw new MarketplaceServiceError(
          "IDEMPOTENCY_STORE_INVALID",
          "category issuance store could not reserve its key",
          { cause },
        );
      }
      return parseReservation(result);
    },
    async commit(input: {
      readonly idempotencyKey: string;
      readonly token: string;
      readonly record: IssuanceRecord;
    }) {
      assertPlainDataObject(
        input,
        ["idempotencyKey", "record", "token"],
        "issuance commit",
      );
      const key = parseSha256(input.idempotencyKey, "idempotency key");
      const token = parseToken(input.token);
      const record = parseIssuanceRecord(input.record);
      if (record.idempotencyKey !== key) {
        throw new MarketplaceServiceError(
          "IDEMPOTENCY_STORE_INVALID",
          "issuance record key does not match the reservation",
        );
      }
      try {
        await commit({ idempotencyKey: key, token, record });
      } catch (cause) {
        throw new MarketplaceServiceError(
          "IDEMPOTENCY_STORE_INVALID",
          "category issuance store could not commit its record",
          { cause },
        );
      }
    },
    async release(input: { readonly idempotencyKey: string; readonly token: string }) {
      assertPlainDataObject(input, ["idempotencyKey", "token"], "issuance release");
      const key = parseSha256(input.idempotencyKey, "idempotency key");
      const token = parseToken(input.token);
      try {
        await release({ idempotencyKey: key, token });
      } catch (cause) {
        throw new MarketplaceServiceError(
          "IDEMPOTENCY_STORE_INVALID",
          "category issuance store could not release its reservation",
          { cause },
        );
      }
    },
  });
  return store;
}

export type PrivateCategorySuccessorIssueInput = Readonly<{
  readonly mandate: unknown;
  readonly request: unknown;
}>;

export type PrivateCategorySuccessorIssued = Readonly<{
  readonly status: "issued";
  readonly idempotencyKey: string;
  readonly attestationId: string;
  readonly wire: MarketplaceCategoryQuoteAttestationWire;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly projection: MarketplaceCategoryQuoteProjection;
}>;

export type PrivateCategorySuccessorNotAttested = Readonly<{
  readonly status: "not_attested";
  readonly category: "grid" | "yield" | "health";
  readonly adapterId: string;
  readonly code: string;
  readonly message: string;
}>;

export interface PrivateCategorySuccessorOrchestrator {
  readonly issue: (
    input: PrivateCategorySuccessorIssueInput,
  ) => Promise<PrivateCategorySuccessorIssued | PrivateCategorySuccessorNotAttested>;
}

export type PrivateCategorySuccessorOrchestratorOptions = Readonly<{
  readonly verifier: PrivateMarketplaceCategorySuccessorVerifierRuntime;
  readonly transport: {
    readonly request: (route: TransportRoute) => Promise<BoundedHttpResponse>;
  };
  readonly erc1271Check: CategoryQuoteErc1271Check;
  readonly trustController: MarketplaceCategoryTrustController;
  readonly trustBundleWire: string | Uint8Array;
  readonly releaseId: string;
  readonly signer: ManagedEd25519Signer;
  readonly issuanceStore: PrivateCategoryIssuanceRecordStore;
  readonly clock: () => number;
  /** UUID source used only for the final attestation ID. */
  readonly randomUUID: () => string;
  /** Separate UUID source for transport request IDs. */
  readonly rpcRandomUUID: () => string;
}>;

/**
 * Private successor issuer. This module is deliberately absent from the
 * service package entry point; the public service exposes only the signer-free
 * verifier runtime until a deployment has completed the remaining release
 * gates.
 */
export function createPrivateCategorySuccessorOrchestrator(
  options: PrivateCategorySuccessorOrchestratorOptions,
): PrivateCategorySuccessorOrchestrator {
  assertPrivateMarketplaceCategorySuccessorVerifierRuntime(options.verifier);
  assertManagedEd25519Signer(options.signer);
  const controllerRoot = resolveMarketplaceCategoryTrustControllerRoot(
    options.trustController,
  );
  if (
    controllerRoot.keyId !== options.verifier.trustRoot.keyId ||
    controllerRoot.publicKeyFingerprintSha256 !==
      options.verifier.trustRoot.publicKeyFingerprintSha256
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "trust controller root does not match the static successor policy",
    );
  }
  const optionKeys = [
    "clock",
    "erc1271Check",
    "issuanceStore",
    "randomUUID",
    "releaseId",
    "rpcRandomUUID",
    "signer",
    "transport",
    "trustBundleWire",
    "trustController",
    "verifier",
  ];
  assertPlainDataObject(
    options,
    optionKeys,
    "successor orchestrator options",
  );
  if (
    typeof options.clock !== "function" ||
    typeof options.randomUUID !== "function" ||
    typeof options.rpcRandomUUID !== "function" ||
    typeof options.erc1271Check !== "function"
  ) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "successor orchestrator callbacks are invalid",
    );
  }
  if (
    options.transport === null ||
    typeof options.transport !== "object" ||
    typeof options.transport.request !== "function"
  ) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "successor orchestrator transport is invalid",
    );
  }
  const quoteVerifyingContract = parseAddress(
    options.verifier.policy.successorPolicy.quote.domain.verifyingContract,
    "quote verifying contract",
  );
  const quoteEndpoint = options.verifier.policy.successorPolicy.quote.endpoint;
  if (
    options.verifier.policy.successorPolicy.quote.domain.chainId !==
      BSC_MAINNET.chainId
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "successor quote domain chain does not match the verifier chain",
    );
  }
  const releaseId = parseIdentifier(options.releaseId, "trust release ID");
  const trustBundleWire = copyWire(options.trustBundleWire);
  const clock = options.clock;
  const randomUUID = options.randomUUID;
  const rpcRandomUUID = options.rpcRandomUUID;
  const erc1271Check = options.erc1271Check;
  const signer = options.signer;
  const store = options.issuanceStore;
  const trustController: MarketplaceCategoryTrustController = options.trustController;
  const verifier = options.verifier;
  const snapshotCapability = privateCategorySnapshotCapabilityForRuntime(verifier);
  const transportReceiver = options.transport;
  const transportRequest = options.transport.request;
  const transport = Object.freeze({
    request: (route: TransportRoute) => transportRequest.call(transportReceiver, route),
  });
  const identityCapability = createCategoryCandidateIdentityCapability({
    transport,
    registryAddress: verifier.infrastructure.erc8004Registry,
    snapshotCapability,
  });
  let quoteFetcher: CategoryQuoteFetchCapability;
  try {
    quoteFetcher = createCategoryQuoteFetchCapability({
      endpoint: quoteEndpoint,
      transport,
      randomUUID: rpcRandomUUID,
    });
  } catch (cause) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "successor quote endpoint configuration is invalid",
      { cause },
    );
  }
  if (
    quoteFetcher.endpointSha256 !==
    options.verifier.policy.successorPolicy.quote.endpointSha256
  ) {
    throw new MarketplaceServiceError(
      "VERIFIER_CONFIGURATION_INVALID",
      "successor quote endpoint does not match the static policy digest",
    );
  }
  const quoteCapability = createCategoryQuoteVerificationCapability({
    identityCapability,
    verifyingContract: quoteVerifyingContract,
    clock,
    erc1271Check,
  });
  const targetCapability = createCategoryTargetObservationCapability({
    transport,
    randomUUID: rpcRandomUUID,
    provenanceRoots: {
      pancakeV3Factory: verifier.infrastructure.pancakeV3Factory,
      aavePoolAddressesProvider:
        verifier.infrastructure.aavePoolAddressesProvider,
      venusComptroller: verifier.infrastructure.venusComptroller,
    },
    snapshotCapability,
  });
  const assertIdentityVerified: CategoryCandidateIdentityCapability["assertVerified"] =
    identityCapability.assertVerified;
  const assertQuoteVerified: CategoryQuoteVerificationCapability["assertVerified"] =
    quoteCapability.assertVerified;
  const assertTargetVerified: CategoryTargetObservationCapability["assertVerified"] =
    targetCapability.assertVerified;
  const assertExecutionBound: PrivateMarketplaceCategorySuccessorVerifierRuntime["assertCategoryExecutionBound"] =
    verifier.assertCategoryExecutionBound;

  const issue = async (
    input: PrivateCategorySuccessorIssueInput,
  ): Promise<PrivateCategorySuccessorIssued | PrivateCategorySuccessorNotAttested> => {
    const parsed = parseIssueInput(input);
    const mandate = freezeData(
      marketplaceMandateV2Schema.parse(parsed.mandate),
    ) as MarketplaceMandateV2;
    const request = freezeData(
      validateCategoryQuoteRequestBinding({
        request: parsed.request,
        mandate,
      }),
    ) as MarketplaceCategoryQuoteRequest;
    if (request.serviceMode !== "observe_only") {
      throw new MarketplaceServiceError(
        "TRANSACTIONAL_NOT_READY",
        "successor issuance remains observe-only until a typed action profile and preview capability are approved",
      );
    }

    const quoteWindow = deriveCategoryQuoteChallengeWindow(request, clock);
    const expectedRequest = buildExpectedQuoteRequest(
      mandate,
      request,
      quoteFetcher.endpointSha256,
      quoteWindow,
    );
    const selector: CategoryCandidateIdentitySelector = Object.freeze({
      chainId: request.candidate.chainId,
      tokenId: request.candidate.tokenId,
    });
    const scope = request.categoryScope;
    const notAttested = (
      code: string,
      message: string,
    ): PrivateCategorySuccessorNotAttested =>
      Object.freeze({
        status: "not_attested",
        category: request.category,
        adapterId: request.adapterId,
        code,
        message,
      });

    let claimedToken: string | undefined;
    let claimedIdempotencyKey: string | undefined;
    let committed = false;
    try {
      return await snapshotCapability.withOpaqueSnapshot(async (snapshot) => {
        const anchor = snapshotCapability.anchorForOpaque(snapshot);

        const identityResult = await identityCapability.capture(selector, snapshot);
        if (identityResult.outcome !== "verified") {
          return notAttested(identityResult.code, "candidate identity was not verified");
        }
        const identity = identityResult.identity;
        try {
          assertIdentityVerified(identity, selector);
        } catch (cause) {
          throw new MarketplaceServiceError(
            "ARTIFACT_INTEGRITY_INVALID",
            "candidate identity lost verifier-owned provenance",
            { cause },
          );
        }

        let provider: ReturnType<typeof identityCapability.providerFor>;
        try {
          provider = identityCapability.providerFor(identity, selector);
        } catch (cause) {
          throw new MarketplaceServiceError(
            "ARTIFACT_INTEGRITY_INVALID",
            "candidate provider runtime facts lost verifier-owned provenance",
            { cause },
          );
        }

        const quoteChallenge = buildCategoryQuoteChallenge({
          mandate,
          request,
          expectedRequest,
          identity,
          provider,
          issuedAt: expectedRequest.issuedAt,
          expiresAt: expectedRequest.expiresAt,
          permissionsExpiresAt: expectedRequest.permissionsExpiresAt,
          quoteEndpointSha256: quoteFetcher.endpointSha256,
          quoteVerifyingContract,
        });

        let quote;
        try {
          const quoteEnvelope = await quoteFetcher.fetch(quoteChallenge);
          quote = await quoteCapability.verifyAccepted({
            envelope: quoteEnvelope,
            identity,
            expectedProvider: identity.ownerAddress,
            expectedRequest,
          });
        } catch (cause) {
          throw new MarketplaceServiceError(
            "ARTIFACT_MISMATCH",
            "candidate quote is not an authenticated acceptance of this request",
            { cause },
          );
        }
        try {
          assertQuoteVerified(quote, { identity, expectedRequest });
        } catch (cause) {
          throw new MarketplaceServiceError(
            "ARTIFACT_INTEGRITY_INVALID",
            "candidate quote lost verifier-owned provenance",
            { cause },
          );
        }

        const targetInputs = targetInputsForScope(scope, snapshot);
        const targets: CategoryTargetObservation[] = [];
        for (const targetInput of targetInputs) {
          const targetResult = await targetCapability.observe(targetInput);
          if (targetResult.outcome !== "verified") {
            return notAttested(
              targetResult.code,
              "a mandate-selected target could not be observed at the shared snapshot",
            );
          }
          try {
            assertTargetVerified(targetResult.observation, targetInput);
          } catch (cause) {
            throw new MarketplaceServiceError(
              "ARTIFACT_INTEGRITY_INVALID",
              "target observation lost verifier-owned provenance",
              { cause },
            );
          }
          targets.push(targetResult.observation);
        }

        const context = Object.freeze({
          mandate,
          candidate: request.candidate,
        });
        let execution;
        try {
          execution = await verifier.evaluateCategoryScopeAtSnapshotBound(
            scope,
            snapshot,
            context,
          );
        } catch (cause) {
          throw new MarketplaceServiceError(
            "VERIFIER_EVALUATION_FAILED",
            "successor category execution failed",
            { cause },
          );
        }
        if (execution.outcome === "inconclusive") {
          return notAttested(execution.code, execution.message);
        }
        if (execution.artifact.result.status !== "pass") {
          return notAttested(
            execution.artifact.result.code,
            execution.artifact.result.message,
          );
        }
        try {
          assertExecutionBound(execution, context);
          const boundExecution = execution as BoundCategoryExecutionSuccess;
          assertExecutionHashes(boundExecution, anchor);
        } catch (cause) {
          throw new MarketplaceServiceError(
            "ARTIFACT_INTEGRITY_INVALID",
            "successor category evidence is not verifier-authenticated",
            { cause },
          );
        }

        const boundExecution = execution as BoundCategoryExecutionSuccess;
        const readProfile = buildReadProfile(scope, boundExecution.artifact);
        const observation = Object.freeze({
          status: "pass" as const,
          categoryDeploymentSha256: verifier.deploymentSha256,
          verifierPolicySha256: verifier.policySha256,
          targetsSha256: canonicalSha256(targets),
          readProfileId: readProfile.profileId,
          readProfileSha256: categoryStaticReadProfileSha256(readProfile),
          readCommitmentsSha256: categoryReadCommitmentsSha256(readProfile),
          artifactSha256: boundExecution.artifactSha256,
          evidenceSha256: boundExecution.artifact.result.evidenceSha256,
          observedAt: boundExecution.artifact.anchor.timestamp,
          observedBlock: boundExecution.artifact.anchor.number,
          observedBlockHash: boundExecution.artifact.anchor.hash,
        });
        const providerAcceptance = buildProviderAcceptance({
          quote,
          identitySha256: identity.identitySha256,
        });
        let linkage;
        try {
          linkage = buildCategoryLinkageProjection({
            mandate,
            request,
            candidateIdentity: identity,
            providerAcceptance,
            targetObservations: targets,
            readProfile,
            observation,
          });
        } catch (cause) {
          throw new MarketplaceServiceError(
            "MAPPING_FAILED",
            "successor linkage could not be constructed",
            { cause },
          );
        }
        const projection = freezeData({
          schema: MARKETPLACE_CATEGORY_QUOTE_PROJECTION_SCHEMA,
          linkage,
          sidecars: {
            schema: MARKETPLACE_CATEGORY_QUOTE_SIDECARS_SCHEMA,
            candidateIdentity: identity,
            targetObservations: targets,
            readProfile,
            actionProfile: null,
            service: {
              mode: request.serviceMode,
              actionPermissionsSha256: request.actionPermissionsSha256,
              coverage: "not_applicable" as const,
              permissionExpiresAt: request.permissionsExpiresAt,
              assurance:
                targets.every(
                  (target) => target.assurance === "protocol_instance_verified",
                )
                  ? "protocol_instance_verified"
                  : targets.every(
                      (target) => target.assurance === "interface_only_unendorsed",
                    )
                    ? "interface_only_unendorsed"
                    : "mixed",
            },
            observation,
          },
          preview: Object.freeze({ status: "not_applicable" as const }),
        }) as MarketplaceCategoryQuoteProjection;

        const idempotencyKey = buildIdempotencyKey({
          mandate,
          request,
          identitySha256: identity.identitySha256,
          quoteNegotiationKeccak256: quote.negotiationKeccak256,
          verifierPolicySha256: verifier.policySha256,
          categoryDeploymentSha256: verifier.deploymentSha256,
          trustBundleWire,
          releaseId,
        });
        const reservation = await store.reserve({ idempotencyKey });
        if (reservation.status === "existing") {
          const commitment = await trustController.prepare({
            bundleWire: trustBundleWire,
          });
          assertTrustRootBinding(
            commitment,
            verifier.trustRoot,
            quoteVerifyingContract,
            {
              releaseId,
              verifierPolicySha256: verifier.policySha256,
              categoryDeploymentSha256: verifier.deploymentSha256,
              policyModes: verifier.policy.successorPolicy.release.adapterModes,
            },
          );
          return validateExistingIssuanceRecord({
            record: reservation.record,
            idempotencyKey,
            projection,
            mandate,
            request,
            identity,
            targets,
            readProfile,
            commitment,
            quoteVerifyingContract,
            expectedReleaseId: releaseId,
            clock,
          });
        }
        if (reservation.status === "in_progress") {
          throw new MarketplaceServiceError(
            "ISSUANCE_IN_PROGRESS",
            "an issuance for this exact successor request is already in progress",
          );
        }
        claimedToken = reservation.token;
        claimedIdempotencyKey = idempotencyKey;

        try {
          const issuedAt = readClock(clock);
          const commitment = await trustController.prepare({
            bundleWire: trustBundleWire,
          });
          assertTrustRootBinding(
            commitment,
            verifier.trustRoot,
            quoteVerifyingContract,
            {
              releaseId,
              verifierPolicySha256: verifier.policySha256,
              categoryDeploymentSha256: verifier.deploymentSha256,
              policyModes: verifier.policy.successorPolicy.release.adapterModes,
            },
          );
          const permit = await trustController.issuePermit({
            bundleWire: trustBundleWire,
            keyId: signer.keyId,
            releaseId,
            adapterId: request.adapterId,
            serviceMode: request.serviceMode,
            issuedAt,
          });
          trustController.assertPermit(permit);
          if (
            permit.bundleSha256 !== commitment.bundleSha256 ||
            permit.stateSha256 !== commitment.stateSha256 ||
            permit.keyId !== signer.keyId ||
            permit.quoteVerifyingContract !== quoteVerifyingContract
          ) {
            throw new MarketplaceServiceError(
              "ISSUANCE_CONFLICT",
              "trust permit does not match the prepared successor release",
            );
          }

          const result = await trustController.withPermit(
            permit,
            async (tuple): Promise<PrivateCategorySuccessorIssued> => {
              if (
                tuple.keyId !== signer.keyId ||
                tuple.release.attestationSchema !== MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA ||
                tuple.release.signatureProfile !== MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE ||
                tuple.key.record.publicKeyFingerprintSha256 !==
                signer.publicKeyFingerprintSha256
              ) {
                throw new MarketplaceServiceError(
                  "ATTESTATION_SIGNER_INVALID",
                  "managed signer key does not match the authorized trust tuple",
                );
              }
              try {
                validateCategoryLinkageProjection({
                  projection: linkage,
                  mandate,
                  request,
                  identityArtifact: identity,
                  targetObservations: targets,
                  readProfile,
                  expectedQuoteDomain: {
                    chainId: BSC_MAINNET.chainId,
                    verifyingContract: quoteVerifyingContract,
                  },
                  expectedRelease: {
                    categoryDeploymentSha256: tuple.release.categoryDeploymentSha256,
                    verifierPolicySha256: tuple.release.verifierPolicySha256,
                  },
                  evaluatedAt: issuedAt,
                });
              } catch (cause) {
                throw new MarketplaceServiceError(
                  "MAPPING_FAILED",
                  "successor linkage did not validate against the authorized release",
                  { cause },
                );
              }
              const expiresAt = deriveAttestationExpiry({
                issuedAt,
                mandate,
                request,
                quoteExpiresAt: quote.quoteExpiresAt,
                identityObservedAt: identity.observedAt,
                evidenceObservedAt: observation.observedAt,
                tuple,
              });
              // Keep the attestation ID source untouched until every external
              // pre-sign invariant, including the final shared-block fence,
              // has passed. A reorg is not an issuance attempt.
              await snapshotCapability.assertOpaqueCanonical(snapshot);
              let attestationId: string;
              try {
                attestationId = parseIdentifier(
                  randomUUID(),
                  "category attestation ID",
                );
              } catch (cause) {
                throw new MarketplaceServiceError(
                  "ATTESTATION_SIGNER_INVALID",
                  "category attestation ID generation failed",
                  { cause },
                );
              }
              const unsigned = marketplaceCategoryQuoteAttestationUnsignedSchema.parse({
                schema: MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_SCHEMA,
                signatureProfile: MARKETPLACE_CATEGORY_QUOTE_SIGNATURE_PROFILE,
                issuer: MARKETPLACE_CATEGORY_QUOTE_ISSUER,
                audience: MARKETPLACE_CATEGORY_QUOTE_AUDIENCE,
                keyId: tuple.keyId,
                releaseId: tuple.releaseId,
                releaseDefinitionSha256: tuple.release.definitionSha256,
                publicKeyFingerprintSha256:
                  tuple.key.record.publicKeyFingerprintSha256,
                attestationId,
                scope: "evaluation_only",
                activationAuthorization: "none",
                reservation: "none",
                replayPolicy: "reusable_until_expiry",
                replayScope: "request_id",
                issuedAt,
                expiresAt,
                mandateSha256: canonicalSha256(mandate),
                categoryQuoteRequestSha256: canonicalSha256(request),
                projectionSha256: canonicalSha256(projection),
                verifierPolicySha256: tuple.release.verifierPolicySha256,
                categoryDeploymentSha256: tuple.release.categoryDeploymentSha256,
                quoteVerifyingContract,
                projection,
              });
              let signature;
              try {
                signature = await signer.sign(
                  marketplaceCategoryQuoteAttestationSigningMessage(unsigned),
                );
              } catch (cause) {
                throw new MarketplaceServiceError(
                  "SIGNING_FAILED",
                  "managed signer could not sign the successor attestation",
                  { cause },
                );
              }
              await snapshotCapability.assertOpaqueCanonical(snapshot);
              if (
                signature.keyId !== tuple.keyId ||
                signature.publicKeyFingerprintSha256 !==
                tuple.key.record.publicKeyFingerprintSha256
              ) {
                throw new MarketplaceServiceError(
                  "ATTESTATION_SIGNER_INVALID",
                  "managed signer returned a signature from the wrong trust tuple",
                );
              }
              const wire = serializeMarketplaceCategoryQuoteAttestation({
                ...unsigned,
                signature: signature.signatureHex,
              });
              const trustStore = createMarketplaceCategoryQuoteTrustStore({
                commitment,
              });
              try {
                verifyMarketplaceCategoryQuoteAttestation({
                  wire,
                  mandate,
                  request,
                  identityArtifact: identity,
                  targetObservations: targets,
                  readProfile,
                  trustStore,
                  clock,
                });
              } catch (cause) {
                throw new MarketplaceServiceError(
                  "ATTESTATION_SIGNER_INVALID",
                  "the signed successor attestation did not verify locally",
                  { cause },
                );
              }
              const record: IssuanceRecord = freezeData({
                schema: ISSUANCE_RECORD_SCHEMA,
                idempotencyKey,
                attestationId,
                wire,
                issuedAt,
                expiresAt,
                projection,
              });
              // Finalize while the trust revision fence is still held. The
              // snapshot capability checks canonicality immediately before the
              // durable commit and suppresses its trailing wrapper check after
              // a successful commit.
              await snapshotCapability.finalizeOpaqueSnapshot(snapshot, async () => {
                await store.commit({
                  idempotencyKey,
                  token: reservation.token,
                  record,
                });
                committed = true;
              });
              return freezeData({
                status: "issued" as const,
                idempotencyKey,
                attestationId,
                wire,
                issuedAt,
                expiresAt,
                projection,
              });
            },
          );
          return result;
        } catch (cause) {
          if (
            cause instanceof CategoryBlockCanonicalityError ||
            cause instanceof CategoryBlockPinError ||
            cause instanceof CategoryReadContractError
          ) {
            throw cause;
          }
          if (cause instanceof MarketplaceServiceError) throw cause;
          throw new MarketplaceServiceError(
            "ISSUANCE_CONFLICT",
            "successor issuance could not complete",
            { cause },
          );
        }
      });
    } catch (cause) {
      if (claimedToken !== undefined && !committed) {
        try {
          await store.release({
            idempotencyKey: claimedIdempotencyKey!,
            token: claimedToken,
          });
        } catch {
          // Preserve the original failure; a durable backend should surface
          // the unreleased lease on its next reconciliation pass.
        }
      }
      if (cause instanceof CategoryBlockCanonicalityError) {
        return notAttested(
          "CATEGORY_BLOCK_NONCANONICAL",
          "the shared category snapshot changed before issuance completed",
        );
      }
      if (
        cause instanceof CategoryBlockPinError ||
        cause instanceof CategoryReadContractError
      ) {
        return notAttested(
          "CATEGORY_BLOCK_PIN_UNAVAILABLE",
          "a canonical BSC snapshot could not be captured",
        );
      }
      throw cause;
    }
  };

  return Object.freeze({ issue });
}

function buildExpectedQuoteRequest(
  mandate: MarketplaceMandateV2,
  request: MarketplaceCategoryQuoteRequest,
  quoteEndpointSha256: string,
  quoteWindow: Readonly<{
    issuedAt: number;
    expiresAt: number;
    permissionsExpiresAt: number;
  }>,
) {
  return Object.freeze({
    requestId: request.requestId,
    mandateSha256: canonicalSha256(mandate),
    categoryQuoteRequestSha256: canonicalSha256(request),
    candidate: request.candidate,
    category: request.category,
    adapterId: request.adapterId,
    protocol: request.protocol,
    serviceMode: request.serviceMode,
    subjectSha256: canonicalSha256(request.categoryScope.subject),
    conditionPolicySha256: canonicalSha256(request.categoryScope.conditionPolicy),
    actionPermissionsSha256: request.actionPermissionsSha256,
    maxSpendUsdMicros: request.maxSpendUsdMicros,
    permissionsExpiresAt: quoteWindow.permissionsExpiresAt,
    quoteEndpointSha256: parseSha256(quoteEndpointSha256, "quote endpoint digest"),
    nonce: request.nonce,
    issuedAt: quoteWindow.issuedAt,
    expiresAt: quoteWindow.expiresAt,
    maxClockSkewSeconds: mandate.maxClockSkewSeconds,
  });
}

export function deriveCategoryQuoteChallengeWindow(
  request: MarketplaceCategoryQuoteRequest,
  clock: () => number,
): Readonly<{
  issuedAt: number;
  expiresAt: number;
  permissionsExpiresAt: number;
}> {
  const issuedAt = readClock(clock);
  const expiresAt = Math.min(
    request.expiresAt,
    issuedAt + MAX_CATEGORY_QUOTE_TTL_SECONDS,
  );
  const permissionsExpiresAt = Math.min(
    request.permissionsExpiresAt,
    expiresAt,
  );
  if (
    !Number.isSafeInteger(issuedAt) ||
    !Number.isSafeInteger(expiresAt) ||
    !Number.isSafeInteger(permissionsExpiresAt) ||
    expiresAt <= issuedAt ||
    permissionsExpiresAt <= issuedAt
  ) {
    throw new MarketplaceServiceError(
      "ATTESTATION_EXPIRY_INVALID",
      "category quote challenge has no valid bounded lifetime",
    );
  }
  return Object.freeze({ issuedAt, expiresAt, permissionsExpiresAt });
}

function buildCategoryQuoteChallenge(input: {
  readonly mandate: MarketplaceMandateV2;
  readonly request: MarketplaceCategoryQuoteRequest;
  readonly expectedRequest: CategoryQuoteExpectedRequest;
  readonly identity: {
    readonly chainId: 56;
    readonly tokenId: string;
    readonly registryAddress: string;
    readonly registryCodeSha256: string;
    readonly ownerAddress: string;
    readonly identitySha256: string;
  };
  readonly provider: {
    readonly providerKind: "eoa" | "erc1271";
    readonly providerCodeSha256: string;
  };
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly permissionsExpiresAt: number;
  readonly quoteEndpointSha256: string;
  readonly quoteVerifyingContract: string;
}): CategoryQuoteChallenge {
  return categoryQuoteChallengeSchema.parse({
    schema: "mandatex.agent-supply.category-quote-challenge.v1",
    verificationProfile: "mandatex.agent-supply.category-quote-verification.v1",
    audience: "mandatex-category-quote-verifier",
    signingDomain: "MandateX Category Quote v1",
    chainId: 56,
    verifyingContract: input.quoteVerifyingContract,
    scope: "evaluation_only",
    activationAuthorization: "none",
    reservation: "none",
    replayPolicy: "reusable_until_expiry",
    relation: "candidate_accepts_service_for_subject",
    providerAuthority: "erc8004_registered_owner",
    requestId: input.request.requestId,
    mandateSha256: canonicalSha256(input.mandate),
    categoryQuoteRequestSha256: canonicalSha256(input.request),
    candidate: input.request.candidate,
    identityVerificationProfile: CATEGORY_CANDIDATE_IDENTITY_PROFILE,
    candidateIdentitySha256: input.identity.identitySha256,
    registryAddress: input.identity.registryAddress,
    registryCodeSha256: input.identity.registryCodeSha256,
    registeredOwner: input.identity.ownerAddress,
    providerKind: input.provider.providerKind,
    providerCodeSha256: input.provider.providerCodeSha256,
    category: input.request.category,
    adapterId: input.request.adapterId,
    protocol: input.request.protocol,
    serviceMode: input.request.serviceMode,
    subjectSha256: canonicalSha256(input.request.categoryScope.subject),
    conditionPolicySha256: canonicalSha256(input.request.categoryScope.conditionPolicy),
    actionPermissionsSha256: input.request.actionPermissionsSha256,
    maxSpendUsdMicros: input.request.maxSpendUsdMicros,
    permissionsExpiresAt: input.permissionsExpiresAt,
    quoteEndpointSha256: input.quoteEndpointSha256,
    nonce: input.request.nonce,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    maxClockSkewSeconds: input.expectedRequest.maxClockSkewSeconds,
  });
}

function targetInputsForScope(
  scope: CategoryScope,
  snapshot: CategorySnapshotHandle,
): readonly CategoryTargetObservationInput[] {
  switch (scope.adapterId) {
    case "pancakeswap-v3-grid-v1":
      return [
        {
          adapterId: scope.adapterId,
          role: "pool",
          targetAddress: scope.subject.poolAddress,
          snapshot,
        },
      ];
    case "erc4626-yield-v1":
      return [
        {
          adapterId: scope.adapterId,
          role: "vault",
          targetAddress: scope.subject.vaultAddress,
          snapshot,
        },
      ];
    case "aave-v3-health-v1":
      return [
        {
          adapterId: scope.adapterId,
          role: "pool",
          targetAddress: scope.subject.poolAddress,
          accountAddress: scope.subject.accountAddress,
          snapshot,
        },
      ];
    case "venus-health-v1":
      return [
        {
          adapterId: scope.adapterId,
          role: "borrowMarket",
          targetAddress: scope.subject.borrowMarketAddress,
          accountAddress: scope.subject.accountAddress,
          comptrollerAddress: scope.subject.comptrollerAddress,
          snapshot,
        },
        {
          adapterId: scope.adapterId,
          role: "comptroller",
          targetAddress: scope.subject.comptrollerAddress,
          accountAddress: scope.subject.accountAddress,
          comptrollerAddress: scope.subject.comptrollerAddress,
          borrowMarketAddress: scope.subject.borrowMarketAddress,
          snapshot,
        },
      ];
  }
}

function buildReadProfile(
  scope: CategoryScope,
  artifact: CategoryExecutionPassArtifact,
): CategoryReadProfile {
  const descriptors = {
    "pancakeswap-v3-grid-v1": [
      { role: "pool", callId: "slot0()", selector: "0x3850c7bd" },
    ],
    "erc4626-yield-v1": [
      { role: "vault", callId: "totalAssets()", selector: "0x01e1d114" },
      { role: "vault", callId: "totalSupply()", selector: "0x18160ddd" },
    ],
    "aave-v3-health-v1": [
      {
        role: "pool",
        callId: "getUserAccountData(address)",
        selector: "0xbf92857c",
      },
    ],
    "venus-health-v1": [
      {
        role: "borrowMarket",
        callId: "borrowBalanceStored(address)",
        selector: "0x95dd9193",
      },
      {
        role: "comptroller",
        callId: "getAccountLiquidity(address)",
        selector: "0x5ec88c79",
      },
      {
        role: "comptroller",
        callId: "getAssetsIn(address)",
        selector: "0xabfceffc",
      },
    ],
  } as const;
  if (artifact.adapter.adapterId !== scope.adapterId) {
    throw new MarketplaceServiceError(
      "MAPPING_FAILED",
      "category artifact adapter does not match the mandate scope",
    );
  }
  const descriptor = descriptors[scope.adapterId];
  const accountAddress =
    scope.adapterId === "aave-v3-health-v1" ||
    scope.adapterId === "venus-health-v1"
      ? scope.subject.accountAddress
      : undefined;
  const reads = descriptor.map((entry) => {
    const target = targetForRole(scope, entry.role);
    const observed = artifact.reads.find(
      (read) =>
        read.to === target &&
        read.data.slice(0, 10).toLowerCase() === entry.selector,
    );
    if (observed === undefined || observed.responseSha256 === undefined) {
      throw new MarketplaceServiceError(
        "MAPPING_FAILED",
        `category artifact is missing the exact ${entry.callId} read`,
      );
    }
    return {
      role: entry.role,
      callId: entry.callId,
      target,
      selector: entry.selector,
      argumentBindingSha256: categoryReadArgumentBindingSha256(accountAddress),
      calldataSha256: categoryReadCalldataSha256(entry.selector, accountAddress),
      responseSha256: observed.responseSha256,
    };
  });
  try {
    const profile = {
      schema: "mandatex.marketplace.category-read-profile.v1" as const,
      profileId: profileIdForAdapter(scope.adapterId),
      adapterId: scope.adapterId,
      reads,
    };
    return validateAdapterReadProfile({ profile, scope });
  } catch (cause) {
    if (cause instanceof MarketplaceServiceError) throw cause;
    throw new MarketplaceServiceError(
      "MAPPING_FAILED",
      "category artifact reads do not satisfy the exact Core read profile",
      { cause },
    );
  }
}

function profileIdForAdapter(adapterId: CategoryScope["adapterId"]): string {
  switch (adapterId) {
    case "pancakeswap-v3-grid-v1":
      return "pancakeswap-v3-grid-observation-v1";
    case "erc4626-yield-v1":
      return "erc4626-yield-observation-v1";
    case "aave-v3-health-v1":
      return "aave-v3-health-observation-v1";
    case "venus-health-v1":
      return "venus-health-observation-v1";
  }
}

function targetForRole(scope: CategoryScope, role: string): string {
  switch (scope.adapterId) {
    case "pancakeswap-v3-grid-v1":
      if (role === "pool") return scope.subject.poolAddress;
      break;
    case "erc4626-yield-v1":
      if (role === "vault") return scope.subject.vaultAddress;
      break;
    case "aave-v3-health-v1":
      if (role === "pool") return scope.subject.poolAddress;
      break;
    case "venus-health-v1":
      if (role === "borrowMarket") return scope.subject.borrowMarketAddress;
      if (role === "comptroller") return scope.subject.comptrollerAddress;
      break;
  }
  throw new MarketplaceServiceError(
    "MAPPING_FAILED",
    `category scope has no target for role ${role}`,
  );
}

function assertExecutionHashes(
  execution: {
    readonly artifact: {
      readonly anchor: { readonly number: number; readonly hash: string; readonly timestamp: number };
      readonly result: { readonly evidence: unknown; readonly evidenceSha256: string };
    };
    readonly artifactSha256: string;
  },
  anchor: { readonly number: number; readonly hash: string; readonly timestamp: number },
): void {
  if (
    execution.artifact.anchor.number !== anchor.number ||
    execution.artifact.anchor.hash !== anchor.hash ||
    execution.artifact.anchor.timestamp !== anchor.timestamp
  ) {
    throw new Error("category artifact is not bound to the shared anchor");
  }
  if (canonicalSha256(execution.artifact) !== execution.artifactSha256) {
    throw new Error("category artifact hash does not match its content");
  }
  if (
    canonicalSha256(execution.artifact.result.evidence) !==
    execution.artifact.result.evidenceSha256
  ) {
    throw new Error("category evidence hash does not match its content");
  }
}

function buildProviderAcceptance(input: {
  readonly quote: {
    readonly providerKind: "eoa" | "erc1271";
    readonly signatureMethod: "eip191" | "erc1271";
    readonly validatedSigner: string;
    readonly validatedProvider: string;
    readonly providerCodeSha256: string;
    readonly chainId: 56;
    readonly verifyingContract: string;
    readonly mandateSha256: string;
    readonly categoryQuoteRequestSha256: string;
    readonly subjectSha256: string;
    readonly conditionPolicySha256: string;
    readonly actionPermissionsSha256: string;
    readonly nonce: string;
    readonly requestKeccak256: string;
    readonly responseKeccak256: string;
    readonly negotiationKeccak256: string;
    readonly quoteEndpointSha256: string;
    readonly negotiatedAt: number;
    readonly quoteExpiresAt: number;
  };
  readonly identitySha256: string;
}) {
  return {
    relation: "candidate_accepts_service_for_subject" as const,
    verificationProfile: "mandatex-category-quote-verification-v1" as const,
    providerKind: input.quote.providerKind,
    signatureMethod: input.quote.signatureMethod,
    validatedSigner: input.quote.validatedSigner,
    validatedProvider: input.quote.validatedProvider,
    providerCodeSha256: input.quote.providerCodeSha256,
    chainId: input.quote.chainId,
    verifyingContract: input.quote.verifyingContract,
    candidateIdentitySha256: input.identitySha256,
    mandateSha256: input.quote.mandateSha256,
    categoryQuoteRequestSha256: input.quote.categoryQuoteRequestSha256,
    subjectSha256: input.quote.subjectSha256,
    conditionPolicySha256: input.quote.conditionPolicySha256,
    actionPermissionsSha256: input.quote.actionPermissionsSha256,
    quoteNonce: input.quote.nonce,
    quoteRequestKeccak256: input.quote.requestKeccak256,
    quoteResponseKeccak256: input.quote.responseKeccak256,
    negotiationKeccak256: input.quote.negotiationKeccak256,
    quoteEndpointSha256: input.quote.quoteEndpointSha256,
    negotiatedAt: input.quote.negotiatedAt,
    quoteExpiresAt: input.quote.quoteExpiresAt,
  };
}

function buildIdempotencyKey(input: {
  readonly mandate: MarketplaceMandateV2;
  readonly request: MarketplaceCategoryQuoteRequest;
  readonly identitySha256: string;
  readonly quoteNegotiationKeccak256: string;
  readonly verifierPolicySha256: string;
  readonly categoryDeploymentSha256: string;
  readonly trustBundleWire: string | Uint8Array;
  readonly releaseId: string;
}): string {
  const wireBytes =
    typeof input.trustBundleWire === "string"
      ? Buffer.from(input.trustBundleWire, "utf8")
      : Buffer.from(input.trustBundleWire);
  return canonicalSha256({
    schema: ISSUANCE_KEY_SCHEMA,
    requestSha256: canonicalSha256(input.request),
    mandateSha256: canonicalSha256(input.mandate),
    candidate: input.request.candidate,
    category: input.request.category,
    adapterId: input.request.adapterId,
    subjectSha256: canonicalSha256(input.request.categoryScope.subject),
    conditionPolicySha256: canonicalSha256(input.request.categoryScope.conditionPolicy),
    serviceMode: input.request.serviceMode,
    candidateIdentitySha256: input.identitySha256,
    quoteNegotiationKeccak256: input.quoteNegotiationKeccak256,
    verifierPolicySha256: input.verifierPolicySha256,
    categoryDeploymentSha256: input.categoryDeploymentSha256,
    trustBundleSha256: createHash("sha256").update(wireBytes).digest("hex"),
    releaseId: input.releaseId,
  });
}

export function deriveAttestationExpiry(input: {
  readonly issuedAt: number;
  readonly mandate: MarketplaceMandateV2;
  readonly request: MarketplaceCategoryQuoteRequest;
  readonly quoteExpiresAt: number;
  readonly identityObservedAt: number;
  readonly evidenceObservedAt: number;
  readonly tuple: {
    readonly authorization: { readonly notAfter: number };
    readonly key: { readonly record: { readonly notAfter: number } };
    readonly release: { readonly notAfter: number };
  };
}): number {
  const expiresAt = Math.min(
    input.issuedAt + MAX_MARKETPLACE_CATEGORY_QUOTE_ATTESTATION_TTL_SECONDS,
    input.mandate.expiresAt,
    input.request.expiresAt,
    input.request.permissionsExpiresAt,
    input.quoteExpiresAt,
    input.identityObservedAt + 300 + 1,
    input.evidenceObservedAt + input.mandate.maxEvidenceAgeSeconds + 1,
    input.tuple.authorization.notAfter,
    input.tuple.key.record.notAfter,
    input.tuple.release.notAfter,
  );
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= input.issuedAt) {
    throw new MarketplaceServiceError(
      "ATTESTATION_EXPIRY_INVALID",
      "successor evidence has no valid lifetime after issuance",
    );
  }
  if (
    expiresAt - input.issuedAt <
    CATEGORY_ATTESTATION_MINIMUM_REMAINING_VALIDITY_SECONDS
  ) {
    throw new MarketplaceServiceError(
      "ATTESTATION_EXPIRY_INVALID",
      "successor evidence does not retain the minimum remaining validity",
    );
  }
  return expiresAt;
}

async function validateExistingIssuanceRecord(input: {
  readonly record: IssuanceRecord;
  readonly idempotencyKey: string;
  readonly projection: MarketplaceCategoryQuoteProjection;
  readonly mandate: MarketplaceMandateV2;
  readonly request: MarketplaceCategoryQuoteRequest;
  readonly identity: VerifiedCategoryCandidateIdentity;
  readonly targets: readonly CategoryTargetObservation[];
  readonly readProfile: CategoryReadProfile;
  readonly commitment: MarketplaceCategoryTrustCommitment;
  readonly quoteVerifyingContract: string;
  readonly expectedReleaseId: string;
  readonly clock: () => number;
}): Promise<PrivateCategorySuccessorIssued> {
  try {
    if (input.record.idempotencyKey !== input.idempotencyKey) {
      throw new Error("stored issuance record key does not match the request");
    }
    if (
      canonicalJson(input.record.projection) !==
      canonicalJson(input.projection)
    ) {
      throw new Error("stored issuance projection does not match the request");
    }

    const trustStore = createMarketplaceCategoryQuoteTrustStore({
      commitment: input.commitment,
    });
    const verified = verifyMarketplaceCategoryQuoteAttestation({
      wire: input.record.wire,
      mandate: input.mandate,
      request: input.request,
      identityArtifact: input.identity,
      targetObservations: input.targets,
      readProfile: input.readProfile,
      trustStore,
      clock: input.clock,
    });
    const envelope = verified.envelope;
    if (
      envelope.releaseId !== input.expectedReleaseId ||
      envelope.quoteVerifyingContract !== input.quoteVerifyingContract ||
      envelope.attestationId !== input.record.attestationId ||
      envelope.issuedAt !== input.record.issuedAt ||
      envelope.expiresAt !== input.record.expiresAt
    ) {
      throw new Error("stored issuance metadata does not match its attestation");
    }
    if (
      envelope.projectionSha256 !== canonicalSha256(input.record.projection) ||
      canonicalJson(envelope.projection) !== canonicalJson(input.projection)
    ) {
      throw new Error("stored attestation projection does not match the request");
    }
    if (
      serializeMarketplaceCategoryQuoteAttestation(envelope) !==
      input.record.wire
    ) {
      throw new Error("stored issuance wire is not canonical");
    }

    // Re-enter the current clock boundary after Core's verification read. This
    // closes the small window in which a record can expire during validation.
    const evaluatedAt = readClock(input.clock);
    if (input.record.expiresAt <= evaluatedAt) {
      throw new Error("stored issuance record has expired");
    }
    return freezeData({
      status: "issued" as const,
      idempotencyKey: input.idempotencyKey,
      attestationId: input.record.attestationId,
      wire: input.record.wire,
      issuedAt: input.record.issuedAt,
      expiresAt: input.record.expiresAt,
      projection: input.projection,
    });
  } catch (cause) {
    if (
      cause instanceof MarketplaceServiceError &&
      cause.code === "IDEMPOTENCY_STORE_INVALID"
    ) {
      throw cause;
    }
    throw new MarketplaceServiceError(
      "IDEMPOTENCY_STORE_INVALID",
      "stored category issuance record failed current trust validation",
      { cause },
    );
  }
}

function parseIssueInput(input: unknown): PrivateCategorySuccessorIssueInput {
  assertPlainDataObject(
    input,
    ["mandate", "request"],
    "successor issue input",
  );
  return Object.freeze({
    mandate: input.mandate,
    request: input.request,
  });
}

function parseReservation(value: unknown): Reservation {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("issuance store returned an invalid reservation");
    }
    const record = value as Record<string, unknown>;
    if (record.status === "claimed") {
      assertPlainDataObject(value, ["status", "token"], "issuance reservation");
      return Object.freeze({ status: "claimed", token: parseToken(record.token) });
    }
    if (record.status === "in_progress") {
      assertPlainDataObject(value, ["status"], "issuance reservation");
      return Object.freeze({ status: "in_progress" });
    }
    if (record.status === "existing") {
      assertPlainDataObject(value, ["record", "status"], "issuance reservation");
      return Object.freeze({
        status: "existing",
        record: parseIssuanceRecord(record.record),
      });
    }
    throw new Error("issuance store returned an unknown reservation status");
  } catch (cause) {
    if (
      cause instanceof MarketplaceServiceError &&
      cause.code === "IDEMPOTENCY_STORE_INVALID"
    ) {
      throw cause;
    }
    throw new MarketplaceServiceError(
      "IDEMPOTENCY_STORE_INVALID",
      "issuance store returned an invalid reservation",
      { cause },
    );
  }
}

function parseIssuanceRecord(value: unknown): IssuanceRecord {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("issuance store returned an invalid record");
    }
    const record = value as Record<string, unknown>;
    assertPlainDataObject(
      value,
      [
        "attestationId",
        "expiresAt",
        "idempotencyKey",
        "issuedAt",
        "projection",
        "schema",
        "wire",
      ],
      "issuance record",
    );
    if (record.schema !== ISSUANCE_RECORD_SCHEMA) {
      throw new Error("issuance record schema is invalid");
    }
    const parsed = {
      schema: ISSUANCE_RECORD_SCHEMA,
      idempotencyKey: parseSha256(record.idempotencyKey, "issuance record key"),
      attestationId: parseIdentifier(record.attestationId, "issuance attestation ID"),
      wire: parseWireText(record.wire),
      issuedAt: parsePositiveInteger(record.issuedAt, "issuance issuedAt"),
      expiresAt: parsePositiveInteger(record.expiresAt, "issuance expiresAt"),
      projection: marketplaceCategoryQuoteProjectionSchema.parse(record.projection),
    } as const;
    if (parsed.expiresAt <= parsed.issuedAt) {
      throw new Error("issuance record expiry must follow issuance");
    }
    return freezeData(parsed);
  } catch (cause) {
    if (
      cause instanceof MarketplaceServiceError &&
      cause.code === "IDEMPOTENCY_STORE_INVALID"
    ) {
      throw cause;
    }
    throw new MarketplaceServiceError(
      "IDEMPOTENCY_STORE_INVALID",
      "issuance store returned an invalid record",
      { cause },
    );
  }
}

function issuedFromRecord(record: IssuanceRecord): PrivateCategorySuccessorIssued {
  return freezeData({
    status: "issued" as const,
    idempotencyKey: record.idempotencyKey,
    attestationId: record.attestationId,
    wire: record.wire,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
    projection: record.projection,
  });
}

function assertPlainDataObject(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): asserts value is Record<string, any> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new MarketplaceServiceError("REQUEST_INVALID", `${label} must be a plain object`);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new MarketplaceServiceError("REQUEST_INVALID", `${label} must be a plain object`);
  }
  const keys = Object.keys(value).sort();
  const wanted = [...expectedKeys].sort();
  if (keys.length !== wanted.length || keys.some((key, index) => key !== wanted[index])) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      `${label} contains unsupported or missing fields`,
    );
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new MarketplaceServiceError(
        "REQUEST_INVALID",
        `${label} must contain enumerable data properties`,
      );
    }
  }
}

function freezeData<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    freezeData((object as Record<PropertyKey, unknown>)[key], seen);
  }
  return Object.freeze(value);
}

function parseAddress(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-f]{40}$/.test(value)) {
    throw new MarketplaceServiceError("REQUEST_INVALID", `${label} is invalid`);
  }
  return value;
}

function parseSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new MarketplaceServiceError("REQUEST_INVALID", `${label} is invalid`);
  }
  return value;
}

function parseIdentifier(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)
  ) {
    throw new MarketplaceServiceError("REQUEST_INVALID", `${label} is invalid`);
  }
  return value;
}

function parseToken(value: unknown): string {
  return parseIdentifier(value, "issuance reservation token");
}

function parsePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new MarketplaceServiceError("IDEMPOTENCY_STORE_INVALID", `${label} is invalid`);
  }
  return value;
}

function copyWire(value: string | Uint8Array): string | Uint8Array {
  if (typeof value === "string") return value;
  if (!(value instanceof Uint8Array)) {
    throw new MarketplaceServiceError("REQUEST_INVALID", "trust bundle wire is invalid");
  }
  return Uint8Array.from(value);
}

function parseWireText(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new MarketplaceServiceError("IDEMPOTENCY_STORE_INVALID", "issuance wire is invalid");
  }
  return value;
}

function assertTrustRootBinding(
  commitment: MarketplaceCategoryTrustCommitment,
  expected: Readonly<{
    readonly keyId: string;
    readonly publicKeyFingerprintSha256: string;
  }>,
  expectedQuoteVerifyingContract: string,
  expectedRelease: Readonly<{
    readonly releaseId: string;
    readonly verifierPolicySha256: string;
    readonly categoryDeploymentSha256: string;
    readonly policyModes: unknown;
  }>,
): void {
  let resolved;
  try {
    resolved = resolveMarketplaceCategoryTrustCommitment(commitment);
  } catch (cause) {
    throw new MarketplaceServiceError(
      "ISSUANCE_CONFLICT",
      "trust commitment is not from the private successor controller",
      { cause },
    );
  }
  if (
    resolved.verified.envelope.rootKeyId !== expected.keyId ||
    resolved.verified.rootPublicKeyFingerprintSha256 !==
      expected.publicKeyFingerprintSha256 ||
    resolved.quoteVerifyingContract !== expectedQuoteVerifyingContract
  ) {
    throw new MarketplaceServiceError(
      "ISSUANCE_CONFLICT",
      "trust controller root or quote domain does not match the static successor policy",
    );
  }
  const release = resolved.verified.envelope.releases.find(
    (candidate) => candidate.releaseId === expectedRelease.releaseId,
  );
  if (
    release === undefined ||
    release.verifierPolicySha256 !== expectedRelease.verifierPolicySha256 ||
    release.categoryDeploymentSha256 !==
      expectedRelease.categoryDeploymentSha256
  ) {
    throw new MarketplaceServiceError(
      "ISSUANCE_CONFLICT",
      "trust release digests do not match the static successor policy",
    );
  }
  try {
    assertMarketplaceTrustReleaseModeProjection({
      policyModes: expectedRelease.policyModes,
      release,
    });
  } catch (cause) {
    throw new MarketplaceServiceError(
      "ISSUANCE_CONFLICT",
      "trust release adapter modes do not match the static successor policy",
      { cause },
    );
  }
}

function readClock(clock: () => number): number {
  let value: number;
  try {
    value = clock();
  } catch (cause) {
    throw new MarketplaceServiceError("CLOCK_INVALID", "successor clock failed", { cause });
  }
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new MarketplaceServiceError("CLOCK_INVALID", "successor clock returned an invalid time");
  }
  return value;
}
