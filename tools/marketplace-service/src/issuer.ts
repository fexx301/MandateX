import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID as nodeRandomUUID,
  sign as signEd25519,
  type KeyObject,
} from "node:crypto";

import {
  ACTIVE_QUOTE_LIMITS,
  BSC_PANCAKE_V3,
  BSC_PREVIEW_RPC_LIMITS,
  DEFAULT_HTTP_LIMITS,
  MARKETPLACE_PREVIEW_EVALUATION_SCHEMA,
  PREVIEW_FINAL_BUFFER_SECONDS,
  QUOTE_MARKETPLACE_EVALUATION_EVIDENCE_SCHEMA,
  QUOTE_TRUST_SCHEMA,
  assertTrustedMarketplaceEvaluationSuccess,
  canonicalQuoteJson,
  computeQuoteSha256,
  decodeRebalanceTransactionPlan,
  marketplaceDecodedRebalancePlanSchema,
  marketplacePreviewEvaluationArtifactSchema,
  type DecodedRebalancePlan,
  type MarketplaceDecodedRebalancePlan,
  type MarketplacePreviewEvaluationArtifact,
  type TrustedPreviewMarketplaceEvaluationSuccess,
} from "@mandatex/agent-supply-verifier";
import {
  MARKETPLACE_ATTESTATION_AUDIENCE,
  MARKETPLACE_ATTESTATION_ISSUER,
  MARKETPLACE_ATTESTATION_SIGNATURE_PROFILE,
  MARKETPLACE_EVALUATION_ATTESTATION_SCHEMA,
  MAX_MARKETPLACE_ATTESTATION_TTL_SECONDS,
  canonicalSha256,
  displaySafeQuoteProjectionPayloadSchema,
  marketplaceEvaluationAttestationSigningMessage,
  marketplaceEvaluationAttestationUnsignedSchema,
  marketplaceMandateSchema,
  serializeMarketplaceEvaluationAttestation,
  type DisplaySafeQuoteProjectionPayload,
  type MarketplaceAttestationTrust,
  type MarketplaceEvaluationAttestation,
  type MarketplaceMandate,
} from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "./errors.js";
import { usdNumberToMicros } from "./money.js";
import {
  marketplaceEvaluationRequestSchema,
  type MarketplaceEvaluationRequest,
} from "./schema.js";

export interface MarketplaceAttestationSignerOptions {
  readonly keyId: string;
  readonly privateKeyPkcs8Der: Uint8Array;
  readonly verifierPolicySha256: string;
  readonly clock: () => number;
  readonly randomUUID?: () => string;
}

export interface MarketplaceVerifierPolicyIdentity {
  readonly passivePolicyFingerprint: string;
  readonly trustPolicySha256: string;
}

export const MARKETPLACE_VERIFIER_POLICY_SCHEMA =
  "mandatex.marketplace.verifier-policy.v1" as const;

export const MARKETPLACE_VERIFIER_POLICY_PROFILES = Object.freeze({
  activeQuote: "mandatex.agent-supply.trusted-quote-evaluation.v1",
  preview: "mandatex.agent-supply.rebalance-preview-policy.v1",
  canonicalization: "mandatex.agent-supply.canonical-quote-json.v1",
  chainDeployment: "mandatex.bsc-mainnet.pancakeswap-v3-deployment.v1",
  transportSecurity: "mandatex.agent-supply.pinned-https-transport.v1",
  projection: "mandatex.marketplace-service.rebalancing-projection.v1",
});

export interface IssuedMarketplaceEvaluationAttestation {
  readonly mandate: MarketplaceMandate;
  readonly payload: DisplaySafeQuoteProjectionPayload;
  readonly attestation: MarketplaceEvaluationAttestation;
  readonly wire: string;
}

interface MarketplaceAttestationSigner {
  readonly pinnedTrust: MarketplaceAttestationTrust;
  readonly issueVerified: (
    request: MarketplaceEvaluationRequest,
    result: TrustedPreviewMarketplaceEvaluationSuccess,
  ) => IssuedMarketplaceEvaluationAttestation;
}

export function marketplaceVerifierPolicySha256(
  identity: MarketplaceVerifierPolicyIdentity,
): string {
  return canonicalSha256({
    schema: MARKETPLACE_VERIFIER_POLICY_SCHEMA,
    passivePolicyFingerprint: parseSha256(
      identity.passivePolicyFingerprint,
      "passive policy fingerprint",
    ),
    trustPolicySha256: parseSha256(
      identity.trustPolicySha256,
      "quote trust policy",
    ),
    profiles: MARKETPLACE_VERIFIER_POLICY_PROFILES,
    contracts: {
      quoteTrust: QUOTE_TRUST_SCHEMA,
      quoteEvidence: QUOTE_MARKETPLACE_EVALUATION_EVIDENCE_SCHEMA,
      previewEvaluation: MARKETPLACE_PREVIEW_EVALUATION_SCHEMA,
    },
    quotePolicy: {
      limits: ACTIVE_QUOTE_LIMITS,
    },
    previewPolicy: {
      finalBufferSeconds: PREVIEW_FINAL_BUFFER_SECONDS,
      rpcLimits: BSC_PREVIEW_RPC_LIMITS,
    },
    transportPolicy: {
      defaultLimits: DEFAULT_HTTP_LIMITS,
    },
    chainDeployment: BSC_PANCAKE_V3,
  });
}

/** @internal The package entry point exposes only the verifier-owned runtime. */
export function createMarketplaceAttestationSigner(
  options: MarketplaceAttestationSignerOptions,
): MarketplaceAttestationSigner {
  if (options === null || typeof options !== "object") {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "marketplace attestation signer options must be an object",
    );
  }
  const keyId = parseKeyId(options.keyId);
  const verifierPolicySha256 = parseSha256(
    options.verifierPolicySha256,
    "verifier policy",
  );
  const clock = options.clock;
  if (typeof clock !== "function") {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "the verifier-runtime attestation clock must be a function",
    );
  }
  const privateKey = parsePrivateKey(options.privateKeyPkcs8Der);
  const publicKey = createPublicKey(privateKey);
  const publicKeySpkiDer = publicKey.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(publicKeySpkiDer)) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "the verifier-runtime Ed25519 public key could not be exported",
    );
  }
  const publicKeyFingerprintSha256 = createHash("sha256")
    .update(publicKeySpkiDer)
    .digest("hex");
  const randomUUID = options.randomUUID ?? nodeRandomUUID;
  if (typeof randomUUID !== "function") {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "the attestation ID generator must be a function",
    );
  }

  return Object.freeze({
    get pinnedTrust(): MarketplaceAttestationTrust {
      return Object.freeze({
        keyId,
        publicKeySpkiDer: Uint8Array.from(publicKeySpkiDer),
        publicKeyFingerprintSha256,
        verifierPolicySha256,
      });
    },
    issueVerified(
      requestInput: MarketplaceEvaluationRequest,
      result: TrustedPreviewMarketplaceEvaluationSuccess,
    ): IssuedMarketplaceEvaluationAttestation {
      assertTrustedResult(result);
      const request = parseRequest(requestInput);
      const artifact = parseVerifiedResult(request, result);
      const observedPolicySha256 = marketplaceVerifierPolicySha256({
        passivePolicyFingerprint:
          result.context.passiveReport.policyFingerprint,
        trustPolicySha256: result.context.trustPolicySha256,
      });
      if (observedPolicySha256 !== verifierPolicySha256) {
        throw new MarketplaceServiceError(
          "VERIFIER_POLICY_MISMATCH",
          "marketplace verifier result was produced under a different pinned policy",
        );
      }

      const mandate = buildMarketplaceMandate(request);
      const payload = buildDisplaySafeProjectionPayload(request, result);
      const issuedAt = readClock(clock);
      assertObservationChronology(payload, issuedAt);
      const expiresAt = Math.min(
        issuedAt + MAX_MARKETPLACE_ATTESTATION_TTL_SECONDS,
        payload.expiresAt,
      );
      if (expiresAt <= issuedAt) {
        throw new MarketplaceServiceError(
          "ATTESTATION_EXPIRY_INVALID",
          "marketplace evaluation evidence expires before it can be attested",
        );
      }

      let attestationId: string;
      try {
        attestationId = randomUUID();
      } catch (cause) {
        throw new MarketplaceServiceError(
          "ATTESTATION_SIGNER_INVALID",
          "the attestation ID generator failed",
          { cause },
        );
      }

      let unsigned;
      try {
        unsigned = marketplaceEvaluationAttestationUnsignedSchema.parse({
          schema: MARKETPLACE_EVALUATION_ATTESTATION_SCHEMA,
          signatureProfile: MARKETPLACE_ATTESTATION_SIGNATURE_PROFILE,
          issuer: MARKETPLACE_ATTESTATION_ISSUER,
          audience: MARKETPLACE_ATTESTATION_AUDIENCE,
          keyId,
          attestationId,
          scope: "evaluation_only",
          activationAuthorization: "none",
          reservation: "none",
          replayPolicy: "reusable_until_expiry",
          issuedAt,
          expiresAt,
          mandateSha256: canonicalSha256(mandate),
          payloadSha256: canonicalSha256(payload),
          verifierPolicySha256,
          payload,
        });
      } catch (cause) {
        throw new MarketplaceServiceError(
          "ATTESTATION_SIGNER_INVALID",
          "the verifier runtime could not construct a valid attestation envelope",
          { cause },
        );
      }

      let signature: string;
      try {
        signature = signEd25519(
          null,
          marketplaceEvaluationAttestationSigningMessage(unsigned),
          privateKey,
        ).toString("hex");
      } catch (cause) {
        throw new MarketplaceServiceError(
          "SIGNING_FAILED",
          "the verifier runtime could not sign the evaluation attestation",
          { cause },
        );
      }
      const attestation = {
        ...unsigned,
        signature,
      } satisfies MarketplaceEvaluationAttestation;
      const wire = serializeMarketplaceEvaluationAttestation(attestation);
      return deepFreeze({ mandate, payload, attestation, wire });
    },
  });
}

export function buildMarketplaceMandate(
  requestInput: MarketplaceEvaluationRequest,
): MarketplaceMandate {
  const request = parseRequest(requestInput);
  const mandate = request.mandate;
  try {
    return marketplaceMandateSchema.parse({
      schema: "mandatex.marketplace.mandate.v1",
      mandateId: mandate.mandate_id,
      category: "rebalancing",
      chainId: 56,
      createdAt: request.policy.createdAt,
      expiresAt: mandate.expires_at,
      maxClockSkewSeconds: request.policy.maxClockSkewSeconds,
      maxEvidenceAgeSeconds: mandate.max_evidence_age_seconds,
      maxPreviewAgeSeconds: request.policy.maxPreviewAgeSeconds,
      budgets: {
        maxAgentFeeUsdMicros: request.policy.maxAgentFeeUsdMicros,
        maxGasUsdMicros: usdNumberToMicros(mandate.limits.max_gas_usd),
        maxSlippageBps: mandate.limits.max_slippage_bps,
        maxExposureUsdMicros: usdNumberToMicros(
          mandate.limits.max_exposure_usd,
        ),
      },
      permissions: {
        allowedProtocols: ["pancakeswap-v3"],
        allowedContracts: mandate.permissions.allowed_contracts,
        allowedCalls: mandate.permissions.allowed_calls,
        maxSpendUsdMicros: usdNumberToMicros(
          mandate.permissions.spend_cap_usd,
        ),
        expiresAt: mandate.permissions.expires_at,
      },
      rebalancing: {
        position: {
          protocol: "pancakeswap-v3",
          poolAddress: mandate.position.pool_address,
          positionManagerAddress: mandate.position.position_manager_address,
          tokenId: mandate.position.token_id,
        },
        approvedLowerTick: mandate.range_policy.approved_lower_tick,
        approvedUpperTick: mandate.range_policy.approved_upper_tick,
        targetWidthTicks: mandate.range_policy.target_width_ticks,
        triggerMode: mandate.range_policy.trigger_mode,
        triggerDistanceTicks: mandate.range_policy.trigger_distance_ticks,
      },
    });
  } catch (cause) {
    throw new MarketplaceServiceError(
      "MAPPING_FAILED",
      "quote mandate could not be mapped into the Marketplace Core mandate",
      { cause },
    );
  }
}

export function buildDisplaySafeProjectionPayload(
  requestInput: MarketplaceEvaluationRequest,
  result: TrustedPreviewMarketplaceEvaluationSuccess,
): DisplaySafeQuoteProjectionPayload {
  const request = parseRequest(requestInput);
  const artifact = parseVerifiedResult(request, result);
  const quote = artifact.evidence.quote;
  const preview = artifact.evidence.preview;
  const task = result.signedTask;
  const snapshot = result.preview.snapshot;
  const observedAt = decimalToSafePositiveInteger(
    snapshot.pin.observedAt,
    "fresh preview block timestamp",
  );
  const observedBlock = decimalToSafeNonnegativeInteger(
    snapshot.pin.observedBlockNumber,
    "fresh preview block number",
  );
  const expiresAt = Math.min(
    result.verification.quoteExpiresAt,
    task.mandate.expires_at,
    task.mandate.permissions.expires_at,
    task.proposal.permissions.expires_at,
    result.preview.policy.deadline,
  );
  const currentTick = snapshot.pool.currentTick;
  const currentLowerTick = snapshot.position.tickLower;
  const currentUpperTick = snapshot.position.tickUpper;
  const outside =
    currentTick < currentLowerTick || currentTick >= currentUpperTick;
  const distanceToBoundaryTicks = outside
    ? 0
    : Math.min(
        currentTick - currentLowerTick,
        currentUpperTick - currentTick,
      );
  const triggerFired =
    outside ||
    (task.mandate.range_policy.trigger_mode === "boundary_proximity" &&
      distanceToBoundaryTicks <=
        task.mandate.range_policy.trigger_distance_ticks);
  if (!triggerFired) {
    throw new MarketplaceServiceError(
      "MAPPING_FAILED",
      "fresh preview state no longer satisfies the mandate trigger",
    );
  }

  try {
    return displaySafeQuoteProjectionPayloadSchema.parse({
      sourceCommitments: {
        quoteValidationSha256: artifact.commitments.quoteEvidenceSha256,
        previewValidationSha256: artifact.commitments.previewEvidenceSha256,
      },
      quoteId: artifact.prospectiveReplayKey,
      mandateId: task.mandate.mandate_id,
      category: "rebalancing",
      // v2 has no separate publisher or reputation feed; owner is the verified
      // publisher identity and all-zero reputation means unavailable evidence.
      candidate: {
        chainId: 56,
        tokenId: artifact.candidate.tokenId,
        owner: snapshot.identity.currentOwner,
        publisher: snapshot.identity.currentOwner,
        taskInterface: "a2a",
      },
      observedAt,
      observedBlock,
      observedBlockHash: snapshot.pin.observedBlockHash,
      expiresAt,
      proposedAction:
        "Simulate and propose a bounded PancakeSwap V3 position rebalance.",
      price: {
        amountAtomic: result.verification.price,
        currency: result.verification.currency,
      },
      estimates: {
        gasUsdMicros: usdNumberToMicros(task.proposal.estimated_gas_usd),
        slippageBps: task.proposal.estimated_slippage_bps,
        exposureUsdMicros: usdNumberToMicros(
          task.proposal.estimated_exposure_usd,
        ),
        observedAt: task.mandate.execution_estimate.observed_at,
      },
      permissions: {
        contracts: task.proposal.permissions.contracts,
        calls: task.proposal.permissions.calls,
        spendCapUsdMicros: usdNumberToMicros(
          task.proposal.permissions.spend_cap_usd,
        ),
        expiresAt: task.proposal.permissions.expires_at,
      },
      verification: {
        identity: "pass",
        publisher: "pass",
        endpoint: "pass",
        taskInterface: "pass",
        category: "pass",
        quoteCompleteness: "pass",
      },
      preview: {
        status: "passed",
        observedAt,
        observedBlock,
        observedBlockHash: snapshot.pin.observedBlockHash,
      },
      reputation: {
        scoreBps: 0,
        sampleSize: 0,
        evidenceConfidenceBps: 0,
        observedAt: parseIsoUnixSeconds(artifact.observedAt),
      },
      categoryEvidence: {
        category: "rebalancing",
        protocol: "pancakeswap-v3",
        position: {
          poolAddress: snapshot.pool.address,
          positionManagerAddress: snapshot.deployments.positionManager.address,
          tokenId: snapshot.position.tokenId,
        },
        observedAt,
        observedBlock,
        observedBlockHash: snapshot.pin.observedBlockHash,
        currentTick,
        tickSpacing: snapshot.pool.tickSpacing,
        currentLowerTick,
        currentUpperTick,
        proposedLowerTick: result.decodedPlan.mint.tickLower,
        proposedUpperTick: result.decodedPlan.mint.tickUpper,
        trigger: {
          fired: true,
          reason: outside
            ? "outside_current_range"
            : "near_range_boundary",
          distanceToBoundaryTicks,
        },
      },
    });
  } catch (cause) {
    if (cause instanceof MarketplaceServiceError) throw cause;
    throw new MarketplaceServiceError(
      "MAPPING_FAILED",
      "verified marketplace evidence could not be mapped to a display-safe projection",
      { cause },
    );
  }
}

function parseRequest(
  request: MarketplaceEvaluationRequest,
): MarketplaceEvaluationRequest {
  const parsed = marketplaceEvaluationRequestSchema.safeParse(request);
  if (!parsed.success) {
    throw new MarketplaceServiceError(
      "REQUEST_INVALID",
      "marketplace evaluation request is invalid",
      { cause: parsed.error },
    );
  }
  return parsed.data;
}

function parseVerifiedResult(
  request: MarketplaceEvaluationRequest,
  result: TrustedPreviewMarketplaceEvaluationSuccess,
): MarketplacePreviewEvaluationArtifact {
  if (
    result === null ||
    typeof result !== "object" ||
    result.outcome !== "verified_unreserved" ||
    result.scope !== "evaluation_only" ||
    result.actionability !== "unreserved"
  ) {
    throw new MarketplaceServiceError(
      "ARTIFACT_MISMATCH",
      "only an immediate replay-free verifier success may be attested",
    );
  }
  const parsed = marketplacePreviewEvaluationArtifactSchema.safeParse(
    result.artifact,
  );
  if (!parsed.success) {
    throw new MarketplaceServiceError(
      "ARTIFACT_INTEGRITY_INVALID",
      "marketplace verifier success contains an invalid evaluation artifact",
      { cause: parsed.error },
    );
  }
  assertVerifiedResultIntegrity(request, result, parsed.data);
  return parsed.data;
}

function assertVerifiedResultIntegrity(
  request: MarketplaceEvaluationRequest,
  result: TrustedPreviewMarketplaceEvaluationSuccess,
  artifact: MarketplacePreviewEvaluationArtifact,
): void {
  const quote = artifact.evidence.quote;
  const preview = artifact.evidence.preview;
  const decoded = decodeRebalanceTransactionPlan(
    request.candidate.transactionPlan,
  );
  const decodedArtifact = marketplaceDecodedPlan(decoded);
  const mandateSha256 = computeQuoteSha256(
    canonicalQuoteJson(request.mandate),
  );
  const quoteEvidenceSha256 = verifierCanonicalSha256(
    quote,
    "quote evidence",
  );
  const previewEvidenceSha256 = verifierCanonicalSha256(
    preview,
    "preview evidence",
  );
  const signedSnapshotSha256 = verifierCanonicalSha256(
    preview.signedSnapshot.snapshot,
    "signed snapshot",
  );
  const freshSnapshotSha256 = verifierCanonicalSha256(
    preview.freshSnapshot.snapshot,
    "fresh snapshot",
  );

  assertArtifact(
    artifact.commitments.quoteEvidenceSha256 === quoteEvidenceSha256 &&
      artifact.commitments.previewEvidenceSha256 === previewEvidenceSha256 &&
      preview.quoteEvidenceSha256 === artifact.commitments.quoteEvidenceSha256 &&
      preview.signedSnapshot.snapshotSha256 === signedSnapshotSha256 &&
      preview.freshSnapshot.snapshotSha256 === freshSnapshotSha256,
    "marketplace verifier artifact commitments do not match their canonical evidence",
  );

  assertBinding(
    artifact.candidate.chainId === request.candidate.selector.chainId &&
      artifact.candidate.tokenId === request.candidate.selector.tokenId &&
      quote.mandateSha256 === mandateSha256 &&
      preview.mandateSha256 === mandateSha256 &&
      canonicalEqual(quote.signedTask.mandate, request.mandate) &&
      canonicalEqual(result.signedTask.mandate, request.mandate),
    "marketplace verifier result is bound to a different mandate or candidate",
  );

  assertArtifact(
    preview.transactionPlanSha256 === decoded.transactionPlanSha256 &&
      preview.calldataSha256 === decoded.calldataSha256 &&
      preview.decodedPlanSha256 === decoded.decodedPlanSha256 &&
      result.decodedPlan.transactionPlanSha256 ===
        decoded.transactionPlanSha256 &&
      result.decodedPlan.calldataSha256 === decoded.calldataSha256 &&
      result.decodedPlan.decodedPlanSha256 === decoded.decodedPlanSha256 &&
      canonicalEqual(preview.decodedPlan, decodedArtifact),
    "marketplace verifier result does not match the requested transaction plan",
  );

  assertArtifact(
    quote.passivePolicyFingerprint ===
      result.context.passiveReport.policyFingerprint &&
      quote.trustPolicySha256 === result.context.trustPolicySha256 &&
      quote.passiveReportSha256 === result.context.passiveReportSha256 &&
      quote.passiveCandidateSha256 === result.context.passiveCandidateSha256 &&
      quote.quoteEndpoint === result.context.trust.quoteEndpoint &&
      quote.expectedProvider === result.context.trust.expectedProvider &&
      quote.providerKind === result.context.trust.providerKind &&
      canonicalEqual(quote.acceptedEnvelope, result.acceptedEnvelope) &&
      canonicalEqual(quote.verification, result.verification) &&
      canonicalEqual(quote.signedTask, result.signedTask),
    "marketplace verifier quote artifact diverges from its immediate verified result",
  );

  assertArtifact(
    canonicalEqual(preview.decodedPlan, marketplaceDecodedPlan(result.decodedPlan)) &&
      canonicalEqual(preview.signedSnapshot.snapshot, result.signedSnapshot) &&
      canonicalEqual(preview.freshSnapshot.snapshot, result.preview.snapshot) &&
      canonicalEqual(preview.policy, result.preview.policy) &&
      preview.simulationRequestSha256 ===
        result.preview.simulationRequestSha256 &&
      preview.simulationResponseSha256 ===
        result.preview.simulationResponseSha256 &&
      preview.simulationResultSha256 === result.preview.simulationResultSha256 &&
      Object.values(result.preview.gates).every((gate) => gate === "pass"),
    "marketplace verifier preview artifact diverges from its immediate verified result",
  );
}

function marketplaceDecodedPlan(
  decoded: DecodedRebalancePlan,
): MarketplaceDecodedRebalancePlan {
  return marketplaceDecodedRebalancePlanSchema.parse({
    plan: decoded.plan,
    decrease: {
      method: "decreaseLiquidity",
      tokenId: decoded.decrease.tokenId.toString(),
      liquidity: decoded.decrease.liquidity.toString(),
      amount0Min: decoded.decrease.amount0Min.toString(),
      amount1Min: decoded.decrease.amount1Min.toString(),
      deadline: decoded.decrease.deadline.toString(),
    },
    collect: {
      method: "collect",
      tokenId: decoded.collect.tokenId.toString(),
      recipient: decoded.collect.recipient,
      amount0Max: decoded.collect.amount0Max.toString(),
      amount1Max: decoded.collect.amount1Max.toString(),
    },
    mint: {
      method: "mint",
      token0: decoded.mint.token0,
      token1: decoded.mint.token1,
      fee: decoded.mint.fee,
      tickLower: decoded.mint.tickLower,
      tickUpper: decoded.mint.tickUpper,
      amount0Desired: decoded.mint.amount0Desired.toString(),
      amount1Desired: decoded.mint.amount1Desired.toString(),
      amount0Min: decoded.mint.amount0Min.toString(),
      amount1Min: decoded.mint.amount1Min.toString(),
      recipient: decoded.mint.recipient,
      deadline: decoded.mint.deadline.toString(),
    },
    innerCalldata: [...decoded.innerCalldata],
    transactionPlanSha256: decoded.transactionPlanSha256,
    calldataSha256: decoded.calldataSha256,
    decodedPlanSha256: decoded.decodedPlanSha256,
  });
}

function assertArtifact(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new MarketplaceServiceError(
      "ARTIFACT_INTEGRITY_INVALID",
      message,
    );
  }
}

function assertBinding(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new MarketplaceServiceError("ARTIFACT_MISMATCH", message);
  }
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  try {
    return canonicalQuoteJson(left as never) === canonicalQuoteJson(right as never);
  } catch {
    return false;
  }
}

function verifierCanonicalSha256(value: unknown, label: string): string {
  try {
    return computeQuoteSha256(canonicalQuoteJson(value));
  } catch (cause) {
    throw new MarketplaceServiceError(
      "ARTIFACT_INTEGRITY_INVALID",
      `marketplace verifier ${label} is not canonically hashable`,
      { cause },
    );
  }
}

function assertTrustedResult(
  result: unknown,
): asserts result is TrustedPreviewMarketplaceEvaluationSuccess {
  try {
    assertTrustedMarketplaceEvaluationSuccess(result);
  } catch (cause) {
    throw new MarketplaceServiceError(
      "ARTIFACT_INTEGRITY_INVALID",
      "marketplace verifier success lacks trusted in-process provenance",
      { cause },
    );
  }
}

function assertObservationChronology(
  payload: DisplaySafeQuoteProjectionPayload,
  issuedAt: number,
): void {
  const observations = [
    payload.observedAt,
    payload.estimates.observedAt,
    payload.reputation.observedAt,
    payload.categoryEvidence.observedAt,
    ...(payload.preview.status === "passed" ? [payload.preview.observedAt] : []),
  ];
  if (observations.some((observedAt) => observedAt > issuedAt)) {
    throw new MarketplaceServiceError(
      "CLOCK_INVALID",
      "marketplace evaluation evidence must not be observed after attestation issuance",
    );
  }
}

function parsePrivateKey(value: Uint8Array): KeyObject {
  if (!(value instanceof Uint8Array)) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "the verifier-runtime private key must be PKCS8 DER bytes",
    );
  }
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
    const exported = privateKey.export({ format: "der", type: "pkcs8" });
    if (!Buffer.isBuffer(exported) || !exported.equals(suppliedDer)) {
      throw new TypeError("private key is not canonical PKCS8 DER");
    }
    return privateKey;
  } catch (cause) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "the verifier-runtime private key is not canonical Ed25519 PKCS8 DER",
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
      "the verifier-runtime attestation clock threw",
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
      "the verifier-runtime attestation clock must return positive Unix seconds",
    );
  }
  return value;
}

function parseIsoUnixSeconds(value: string): number {
  const milliseconds = Date.parse(value);
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) {
    throw new MarketplaceServiceError(
      "MAPPING_FAILED",
      "verifier observation time is invalid",
    );
  }
  return Math.floor(milliseconds / 1_000);
}

function decimalToSafePositiveInteger(value: string, label: string): number {
  const parsed = decimalToSafeNonnegativeInteger(value, label);
  if (parsed <= 0) {
    throw new MarketplaceServiceError(
      "MAPPING_FAILED",
      `${label} must be positive`,
    );
  }
  return parsed;
}

function decimalToSafeNonnegativeInteger(
  value: string,
  label: string,
): number {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new MarketplaceServiceError(
      "MAPPING_FAILED",
      `${label} is not a canonical decimal integer`,
    );
  }
  const integer = BigInt(value);
  if (integer > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new MarketplaceServiceError(
      "MAPPING_FAILED",
      `${label} exceeds the safe integer range`,
    );
  }
  return Number(integer);
}

function parseKeyId(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      "the verifier-runtime attestation key ID is invalid",
    );
  }
  return value;
}

function parseSha256(value: string, label: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new MarketplaceServiceError(
      "ATTESTATION_SIGNER_INVALID",
      `the ${label} SHA-256 is invalid`,
    );
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
