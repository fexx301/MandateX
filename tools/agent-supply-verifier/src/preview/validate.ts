import { randomUUID as nodeRandomUUID } from "node:crypto";

import type { Hex } from "viem";

import {
  activationPreviewSchema,
  type ActivationPreview,
} from "../activation/schema.js";

import {
  canonicalQuoteJson,
  computeQuoteSha256,
} from "../quotes/protocol.js";
import {
  quoteMarketplaceEvaluationEvidenceSchema,
  quoteMandatexRebalanceMandateSchema,
  type QuoteMarketplaceEvaluationEvidence,
  type QuoteMandatexSignedRebalanceTask,
  type QuoteSidecar,
} from "../quotes/schema.js";
import {
  executeTrustedQuoteAttempt,
  preflightTrustedQuote,
  prepareTrustedQuoteAttempt,
  QuotePreflightError,
  validateTrustedQuote,
  type TrustedQuoteAttemptOptions,
  type TrustedQuotePreReplayGateInput,
  type TrustedQuoteReplayCandidate,
  type TrustedQuoteReplayCommitResult,
  type TrustedQuoteVerifiedCandidate,
  type ValidateTrustedQuoteOptions,
} from "../quotes/validate.js";
import {
  decodeRebalanceSimulationResult,
  decodeRebalanceTransactionPlan,
  PREVIEW_FINAL_BUFFER_SECONDS,
  PreviewPlanError,
  validateRebalancePlanPolicy,
  type DecodedRebalancePlan,
  type RebalancePlanPolicyResult,
} from "./plan.js";
import {
  verifyPancakeV3State,
  type PancakeStateResult,
  type PancakeStateSnapshot,
} from "./pancake.js";
import {
  assertPreviewBlockCanonical,
  PreviewSimulationError,
  simulatePinnedRebalancePlan,
  TransportPancakeStateRpc,
} from "./rpc.js";
import {
  marketplacePreviewEvaluationArtifactSchema,
  marketplacePreviewEvaluationEvidenceSchema,
  pancakeStateSnapshotSchema,
  rebalancePreviewSidecarSchema,
  type MarketplaceDecodedRebalancePlan,
  type MarketplacePreviewEvaluationArtifact,
  type MarketplacePreviewEvaluationEvidence,
  type RebalancePreviewErrorCode,
  type RebalancePreviewGates,
  type RebalancePreviewSidecar,
  type RebalanceTransactionPlan,
} from "./schema.js";

export interface ValidateTrustedPreviewOptions
  extends Omit<
    ValidateTrustedQuoteOptions,
    "preReplayGate" | "replayCommit"
  > {
  readonly transactionPlan: RebalanceTransactionPlan;
  readonly replayCommit?: TrustedPreviewReplayCommit;
}

export type TrustedPreviewReplayCandidate = Readonly<{
  replayKey: TrustedQuoteReplayCandidate["replayKey"];
  replayMetadata: TrustedQuoteReplayCandidate["replayMetadata"];
  previewSidecar: RebalancePreviewSidecar;
  projection: TrustedRebalanceActivationProjection;
}>;

export type TrustedPreviewReplayCommit = (
  candidate: TrustedPreviewReplayCandidate,
) => Promise<TrustedQuoteReplayCommitResult>;

export interface ValidateTrustedPreviewDependencies {
  readonly quoteValidator?: typeof validateTrustedQuote;
  readonly stateVerifier?: typeof verifyPancakeV3State;
  readonly simulate?: typeof simulatePinnedRebalancePlan;
  readonly assertCanonical?: typeof assertPreviewBlockCanonical;
  readonly captureProjection?: (
    projection: TrustedRebalanceActivationProjection,
  ) => void;
}

export type PreviewPass = Readonly<{
  status: "pass";
  gates: RebalancePreviewGates;
  snapshot: PancakeStateSnapshot;
  policy: RebalancePlanPolicyResult;
  simulationRequestSha256: string;
  simulationResponseSha256: string;
  simulationResultSha256: string;
}>;

type PreviewPassWithSignedSnapshot = PreviewPass &
  Readonly<{ signedSnapshot: PancakeStateSnapshot }>;

type PreviewFailure = Readonly<{
  status: "invalid" | "inconclusive";
  errorCode: RebalancePreviewErrorCode;
  gates: RebalancePreviewGates;
  snapshot?: PancakeStateSnapshot;
  policy?: RebalancePlanPolicyResult;
  simulationRequestSha256?: string;
  simulationResponseSha256?: string;
}>;

type PreviewProgress = PreviewPassWithSignedSnapshot | PreviewFailure;

export type TrustedRebalanceActivationProjection = Readonly<{
  mandate: TrustedQuotePreReplayGateInput["mandate"];
  envelope: TrustedQuotePreReplayGateInput["envelope"];
  verification: TrustedQuotePreReplayGateInput["verification"];
  signedTask: TrustedQuotePreReplayGateInput["binding"]["signedTask"];
  decodedPlan: DecodedRebalancePlan;
  preview: PreviewPass;
}>;

export type TrustedPreviewActivationResult = Readonly<{
  sidecar: RebalancePreviewSidecar;
  projection?: TrustedRebalanceActivationProjection;
}>;

export interface ValidateTrustedPreviewForMarketplaceEvaluationOptions
  extends Omit<
    ValidateTrustedPreviewOptions,
    "replayStore" | "replayCommit"
  > {}

export type ValidateTrustedPreviewForMarketplaceEvaluationDependencies = Pick<
  ValidateTrustedPreviewDependencies,
  "stateVerifier" | "simulate" | "assertCanonical"
>;

export type TrustedPreviewMarketplaceEvaluationFailure = Omit<
  RebalancePreviewSidecar,
  "outcome"
> &
  Readonly<{ outcome: "refused" | "invalid" | "inconclusive" }>;

export type TrustedPreviewMarketplaceEvaluationSuccess = Readonly<{
  schema: "mandatex.agent-supply.marketplace-preview-evaluation-result.v1";
  scope: "evaluation_only";
  actionability: "unreserved";
  outcome: "verified_unreserved";
  artifact: MarketplacePreviewEvaluationArtifact;
  context: TrustedQuoteVerifiedCandidate<unknown>["context"];
  acceptedEnvelope: TrustedQuoteVerifiedCandidate<unknown>["envelope"];
  verification: TrustedQuoteVerifiedCandidate<unknown>["verification"];
  signedTask: TrustedQuoteVerifiedCandidate<unknown>["binding"]["signedTask"];
  decodedPlan: DecodedRebalancePlan;
  signedSnapshot: PancakeStateSnapshot;
  preview: PreviewPass;
}>;

export type TrustedPreviewMarketplaceEvaluationResult =
  | TrustedPreviewMarketplaceEvaluationSuccess
  | TrustedPreviewMarketplaceEvaluationFailure;

class PreviewGateFailure extends Error {
  constructor(
    readonly status: "invalid" | "inconclusive",
    readonly code: RebalancePreviewErrorCode,
    readonly evidence: Readonly<{
      gates?: RebalancePreviewGates;
      snapshot?: PancakeStateSnapshot;
      policy?: RebalancePlanPolicyResult;
      simulationRequestSha256?: string;
      simulationResponseSha256?: string;
    }> = {},
  ) {
    super("the transaction preview gate did not pass");
    this.name = "PreviewGateFailure";
  }
}

export async function validateTrustedPreview(
  options: ValidateTrustedPreviewOptions,
  dependencies: ValidateTrustedPreviewDependencies = {},
): Promise<RebalancePreviewSidecar> {
  const decoded = decodeRebalanceTransactionPlan(options.transactionPlan);
  const parsedMandate = quoteMandatexRebalanceMandateSchema.parse(
    options.mandate,
  );
  const mandateSha256 = computeQuoteSha256(canonicalQuoteJson(parsedMandate));
  const localContext = preflightTrustedQuote({
    manifest: options.manifest,
    passiveReport: options.passiveReport,
    trustFile: options.trustFile,
    candidate: options.candidate,
    ...(options.now === undefined ? {} : { now: options.now }),
  });
  if (
    localContext.trust.providerKind !== "eoa" ||
    decoded.plan.from !== localContext.trust.expectedProvider
  ) {
    throw new QuotePreflightError("PREVIEW_INPUT_UNSUPPORTED");
  }

  let progress: PreviewProgress | undefined;
  let projection: TrustedRebalanceActivationProjection | undefined;
  const { replayCommit, ...quoteOptions } = options;
  const quote = await (dependencies.quoteValidator ?? validateTrustedQuote)({
    ...quoteOptions,
    ...(replayCommit === undefined
      ? {}
      : { replayCommit: async (candidate: TrustedQuoteReplayCandidate) => {
            if (progress?.status !== "pass" || projection === undefined) {
              throw new Error("preview replay commit requires a passing projection");
            }
            return await replayCommit({
              replayKey: candidate.replayKey,
              replayMetadata: candidate.replayMetadata,
              previewSidecar: buildPreviewSidecar({
                quote: candidate.claimedSidecar,
                decoded,
                mandateSha256,
                progress,
              }),
              projection,
            });
          } }),
    preReplayGate: async (input) => {
      try {
        progress = await runPreviewGate({
          decoded,
          task: input.binding.signedTask,
          quoteExpiresAt: input.verification.quoteExpiresAt,
          expectedProvider: input.context.trust.expectedProvider,
          agentTokenId: input.context.trust.tokenId,
          transport: input.transport,
          randomUUID: input.randomUUID,
          now: input.validationTime,
          stateVerifier: dependencies.stateVerifier ?? verifyPancakeV3State,
          simulate: dependencies.simulate ?? simulatePinnedRebalancePlan,
          assertCanonical:
            dependencies.assertCanonical ?? assertPreviewBlockCanonical,
        });
      } catch (error) {
        progress = previewFailure(error);
      }
      if (progress.status === "pass") {
        projection = {
          mandate: input.mandate,
          envelope: input.envelope,
          verification: input.verification,
          signedTask: input.binding.signedTask,
          decodedPlan: decoded,
          preview: publicPreviewPass(progress),
        };
        dependencies.captureProjection?.(projection);
      }
      return progress.status === "pass"
        ? {
            outcome: "pass",
            commitConstraint: {
              validUntil: progress.policy.deadline,
              minimumRemainingMilliseconds:
                PREVIEW_FINAL_BUFFER_SECONDS * 1_000,
            },
          }
        : {
            outcome: progress.status,
            errorCode:
              progress.status === "invalid"
                ? "PREVIEW_GATE_REJECTED"
                : "PREVIEW_GATE_UNAVAILABLE",
          };
    },
  });

  return buildPreviewSidecar({
    quote,
    decoded,
    mandateSha256,
    progress,
  });
}

export async function validateTrustedPreviewForActivation(
  options: ValidateTrustedPreviewOptions,
  dependencies: Omit<
    ValidateTrustedPreviewDependencies,
    "captureProjection"
  > = {},
): Promise<TrustedPreviewActivationResult> {
  let projection: TrustedRebalanceActivationProjection | undefined;
  const sidecar = await validateTrustedPreview(options, {
    ...dependencies,
    captureProjection(value) {
      projection = value;
    },
  });
  if (sidecar.outcome !== "preview_simulation_passed" || projection === undefined) {
    return { sidecar };
  }
  return { sidecar, projection };
}

export async function validateTrustedPreviewForMarketplaceEvaluation(
  options: ValidateTrustedPreviewForMarketplaceEvaluationOptions,
  dependencies: ValidateTrustedPreviewForMarketplaceEvaluationDependencies = {},
): Promise<TrustedPreviewMarketplaceEvaluationResult> {
  const decoded = decodeRebalanceTransactionPlan(options.transactionPlan);
  const parsedMandate = quoteMandatexRebalanceMandateSchema.parse(
    options.mandate,
  );
  const mandateSha256 = computeQuoteSha256(canonicalQuoteJson(parsedMandate));
  const localContext = preflightTrustedQuote({
    manifest: options.manifest,
    passiveReport: options.passiveReport,
    trustFile: options.trustFile,
    candidate: options.candidate,
    ...(options.now === undefined ? {} : { now: options.now }),
  });
  if (
    localContext.trust.providerKind !== "eoa" ||
    decoded.plan.from !== localContext.trust.expectedProvider
  ) {
    throw new QuotePreflightError("PREVIEW_INPUT_UNSUPPORTED");
  }

  const { transactionPlan: _transactionPlan, ...quoteOptions } = options;
  const attempt = prepareTrustedQuoteAttempt(
    quoteOptions as TrustedQuoteAttemptOptions,
  );
  const result = await executeTrustedQuoteAttempt(attempt, async (input) => {
    let progress: PreviewProgress;
    try {
      progress = await runPreviewGate({
        decoded,
        task: input.binding.signedTask,
        quoteExpiresAt: input.verification.quoteExpiresAt,
        expectedProvider: input.context.trust.expectedProvider,
        agentTokenId: input.context.trust.tokenId,
        transport: input.transport,
        randomUUID: input.randomUUID,
        now: input.validationTime,
        stateVerifier: dependencies.stateVerifier ?? verifyPancakeV3State,
        simulate: dependencies.simulate ?? simulatePinnedRebalancePlan,
        assertCanonical:
          dependencies.assertCanonical ?? assertPreviewBlockCanonical,
      });
    } catch (error) {
      progress = previewFailure(error);
    }
    return {
      data: progress,
      decision:
        progress.status === "pass"
          ? {
              outcome: "pass" as const,
              commitConstraint: {
                validUntil: progress.policy.deadline,
                minimumRemainingMilliseconds:
                  PREVIEW_FINAL_BUFFER_SECONDS * 1_000,
              },
            }
          : {
              outcome: progress.status,
              errorCode:
                progress.status === "invalid"
                  ? ("PREVIEW_GATE_REJECTED" as const)
                  : ("PREVIEW_GATE_UNAVAILABLE" as const),
            },
    };
  });

  if (result.status === "terminal") {
    return marketplaceEvaluationFailure(
      buildPreviewSidecar({
        quote: result.sidecar,
        decoded,
        mandateSha256,
        progress: result.gateData,
      }),
    );
  }

  const progress = result.candidate.gateData;
  if (progress?.status !== "pass") {
    throw new Error(
      "verified marketplace quote did not retain passing preview evidence",
    );
  }
  return buildMarketplaceEvaluationSuccess({
    candidate: result.candidate,
    decoded,
    progress,
  });
}

export async function revalidateTrustedPreviewForFunding(input: Readonly<{
  signedTask: QuoteMandatexSignedRebalanceTask;
  transactionPlan: RebalanceTransactionPlan;
  quoteExpiresAt: number;
  expectedProvider: string;
  agentTokenId: string;
  transport: ValidateTrustedQuoteOptions["transport"];
  randomUUID?: () => string;
}>, dependencies: Omit<
  ValidateTrustedPreviewDependencies,
  "quoteValidator" | "captureProjection"
> = {}): Promise<ActivationPreview> {
  const decoded = decodeRebalanceTransactionPlan(input.transactionPlan);
  const progress = await runPreviewGate({
    decoded,
    task: input.signedTask,
    quoteExpiresAt: input.quoteExpiresAt,
    expectedProvider: input.expectedProvider,
    agentTokenId: input.agentTokenId,
    transport: input.transport,
    randomUUID: input.randomUUID ?? nodeRandomUUID,
    now: new Date(0),
    timeAuthority: "snapshot",
    stateVerifier: dependencies.stateVerifier ?? verifyPancakeV3State,
    simulate: dependencies.simulate ?? simulatePinnedRebalancePlan,
    assertCanonical: dependencies.assertCanonical ?? assertPreviewBlockCanonical,
  });
  const blockTimestamp = parseSnapshotUnixSeconds(
    progress.snapshot.pin.observedAt,
  );
  const validUntil = Math.min(
    input.quoteExpiresAt,
    progress.policy.deadline,
    input.signedTask.mandate.expires_at,
    input.signedTask.mandate.permissions.expires_at,
  );
  return activationPreviewSchema.parse({
    schema: "mandatex.erc8183.activation-preview.v1",
    observedAt: new Date(blockTimestamp * 1_000).toISOString(),
    blockNumber: progress.snapshot.pin.observedBlockNumber,
    blockHash: progress.snapshot.pin.observedBlockHash,
    blockTimestamp,
    quoteExpiresAt: input.quoteExpiresAt,
    transactionPlanSha256: decoded.transactionPlanSha256,
    signedTaskSha256: computeQuoteSha256(
      canonicalQuoteJson(input.signedTask),
    ),
    allGatesPass: true,
    validUntil,
  });
}

function parseSnapshotUnixSeconds(value: string): number {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error("activation preview returned a non-canonical block timestamp");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error("activation preview returned an invalid block timestamp");
  }
  return parsed;
}

export function serializeRebalancePreviewSidecar(
  sidecar: RebalancePreviewSidecar,
): string {
  return `${canonicalQuoteJson(rebalancePreviewSidecarSchema.parse(sidecar))}\n`;
}

export function serializeMarketplacePreviewEvaluationArtifact(
  artifact: MarketplacePreviewEvaluationArtifact,
): string {
  return `${canonicalQuoteJson(
    marketplacePreviewEvaluationArtifactSchema.parse(artifact),
  )}\n`;
}

function publicPreviewPass(progress: PreviewPassWithSignedSnapshot): PreviewPass {
  return {
    status: "pass",
    gates: progress.gates,
    snapshot: progress.snapshot,
    policy: progress.policy,
    simulationRequestSha256: progress.simulationRequestSha256,
    simulationResponseSha256: progress.simulationResponseSha256,
    simulationResultSha256: progress.simulationResultSha256,
  };
}

function marketplaceEvaluationFailure(
  sidecar: RebalancePreviewSidecar,
): TrustedPreviewMarketplaceEvaluationFailure {
  const parsed = rebalancePreviewSidecarSchema.parse(sidecar);
  if (
    parsed.outcome === "preview_simulation_passed" ||
    parsed.quote.outcome === "valid" ||
    parsed.quote.replayStatus !== "not_attempted"
  ) {
    throw new Error(
      "marketplace evaluation failure must be non-passing and replay-free",
    );
  }
  return parsed as TrustedPreviewMarketplaceEvaluationFailure;
}

function buildMarketplaceEvaluationSuccess(input: Readonly<{
  candidate: TrustedQuoteVerifiedCandidate<PreviewProgress>;
  decoded: DecodedRebalancePlan;
  progress: PreviewPassWithSignedSnapshot;
}>): TrustedPreviewMarketplaceEvaluationSuccess {
  const quoteEvidence = quoteMarketplaceEvaluationEvidenceSchema.parse({
    schema: "mandatex.agent-supply.quote-marketplace-evaluation-evidence.v1",
    observedAt: input.candidate.decisionTime.toISOString(),
    candidate: {
      chainId: input.candidate.context.trust.chainId,
      tokenId: input.candidate.context.trust.tokenId,
    },
    passiveReportSha256: input.candidate.context.passiveReportSha256,
    passiveCandidateSha256: input.candidate.context.passiveCandidateSha256,
    passivePolicyFingerprint:
      input.candidate.context.passiveReport.policyFingerprint,
    trustPolicySha256: input.candidate.context.trustPolicySha256,
    quoteEndpoint: input.candidate.context.trust.quoteEndpoint,
    a2aRequestSha256: input.candidate.requestSha256,
    a2aResponseSha256: input.candidate.responseSha256,
    expectedProvider: input.candidate.context.trust.expectedProvider,
    providerKind: input.candidate.context.trust.providerKind,
    acceptedEnvelope: input.candidate.envelope,
    verification: {
      ...input.candidate.verification,
      chainId: 56,
    },
    signedTask: input.candidate.binding.signedTask,
    mandateSha256: input.candidate.binding.mandateSha256,
    gates: {
      passivePreflight: "pass",
      endpointBinding: "pass",
      quoteSignature: "pass",
      quotePolicy: "pass",
      finalChecks: "pass",
    },
  } satisfies QuoteMarketplaceEvaluationEvidence);
  const quoteEvidenceSha256 = canonicalSha256(quoteEvidence);

  const decodedPlan = marketplaceDecodedPlan(input.decoded);
  const previewEvidence = marketplacePreviewEvaluationEvidenceSchema.parse({
    schema: "mandatex.agent-supply.marketplace-preview-evidence.v1",
    quoteEvidenceSha256,
    mandateSha256: input.candidate.binding.mandateSha256,
    transactionPlanSha256: input.decoded.transactionPlanSha256,
    calldataSha256: input.decoded.calldataSha256,
    decodedPlanSha256: input.decoded.decodedPlanSha256,
    decodedPlan,
    signedSnapshot: marketplaceSnapshotCommitment(
      input.progress.signedSnapshot,
    ),
    freshSnapshot: marketplaceSnapshotCommitment(input.progress.snapshot),
    simulationRequestSha256: input.progress.simulationRequestSha256,
    simulationResponseSha256: input.progress.simulationResponseSha256,
    simulationResultSha256: input.progress.simulationResultSha256,
    policy: {
      authority: input.progress.policy.authority,
      deadline: input.progress.policy.deadline,
      calls: [...input.progress.policy.calls],
    },
    gates: marketplacePassingGates(input.progress.gates),
  } satisfies MarketplacePreviewEvaluationEvidence);
  const previewEvidenceSha256 = canonicalSha256(previewEvidence);

  const artifact = marketplacePreviewEvaluationArtifactSchema.parse({
    schema: "mandatex.agent-supply.marketplace-preview-evaluation.v1",
    scope: "evaluation_only",
    actionability: "unreserved",
    outcome: "verified_unreserved",
    observedAt: input.candidate.decisionTime.toISOString(),
    replayStatus: "not_attempted",
    candidate: {
      chainId: input.candidate.context.trust.chainId,
      tokenId: input.candidate.context.trust.tokenId,
    },
    prospectiveReplayKey: input.candidate.prospectiveReplayKey,
    commitments: {
      quoteEvidenceSha256,
      previewEvidenceSha256,
    },
    evidence: {
      quote: quoteEvidence,
      preview: previewEvidence,
    },
  });

  return {
    schema: "mandatex.agent-supply.marketplace-preview-evaluation-result.v1",
    scope: "evaluation_only",
    actionability: "unreserved",
    outcome: "verified_unreserved",
    artifact,
    context: input.candidate.context,
    acceptedEnvelope: quoteEvidence.acceptedEnvelope,
    verification: input.candidate.verification,
    signedTask: input.candidate.binding.signedTask,
    decodedPlan: input.decoded,
    signedSnapshot: artifact.evidence.preview.signedSnapshot.snapshot,
    preview: publicPreviewPass(input.progress),
  };
}

function marketplaceDecodedPlan(
  decoded: DecodedRebalancePlan,
): MarketplaceDecodedRebalancePlan {
  return {
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
  };
}

function marketplaceSnapshotCommitment(snapshot: PancakeStateSnapshot) {
  const parsed = pancakeStateSnapshotSchema.parse(snapshot);
  return {
    snapshotSha256: canonicalSha256(parsed),
    snapshot: parsed,
  };
}

function marketplacePassingGates(gates: RebalancePreviewGates) {
  if (Object.values(gates).some((state) => state !== "pass")) {
    throw new Error("passing marketplace preview contains a non-passing gate");
  }
  return {
    signedEvidence: "pass" as const,
    freshState: "pass" as const,
    identityOwner: "pass" as const,
    positionAuthority: "pass" as const,
    transactionPolicy: "pass" as const,
    evmSimulation: "pass" as const,
  };
}

function canonicalSha256(value: unknown): string {
  return computeQuoteSha256(canonicalQuoteJson(value));
}

async function runPreviewGate(input: {
  decoded: DecodedRebalancePlan;
  task: QuoteMandatexSignedRebalanceTask;
  quoteExpiresAt: number;
  expectedProvider: string;
  agentTokenId: string;
  transport: ValidateTrustedQuoteOptions["transport"];
  randomUUID: () => string;
  now: Date;
  timeAuthority?: "local" | "snapshot";
  stateVerifier: typeof verifyPancakeV3State;
  simulate: typeof simulatePinnedRebalancePlan;
  assertCanonical: typeof assertPreviewBlockCanonical;
}): Promise<PreviewPassWithSignedSnapshot> {
  let gates = emptyPreviewGates();
  const rpc = new TransportPancakeStateRpc(input.transport, input.randomUUID);
  const stateOptions = {
    rpc,
    chainId: 56,
    poolAddress: input.task.mandate.position.pool_address,
    positionManagerAddress:
      input.task.mandate.position.position_manager_address,
    positionTokenId: input.task.mandate.position.token_id,
    caller: input.decoded.plan.from,
    agentTokenId: input.agentTokenId,
    expectedProvider: input.expectedProvider,
  } as const;

  const signedResult = await input.stateVerifier({
    ...stateOptions,
    target: {
      mode: "exact",
      blockNumber: input.task.evidence.observed_block.toString(),
      blockHash: input.task.evidence.observed_block_hash,
    },
  });
  const signedSnapshot = requireState(
    signedResult,
    "SIGNED_EVIDENCE_INVALID",
    gates,
  );
  assertSignedEvidence(signedSnapshot, input.task);
  gates = { ...gates, signedEvidence: "pass" };

  const freshResult = await input.stateVerifier({
    ...stateOptions,
    target: { mode: "fresh" },
  });
  const freshSnapshot = requireState(
    freshResult,
    "PREVIEW_STATE_INVALID",
    gates,
  );
  gates = {
    ...gates,
    freshState: "pass",
    identityOwner: "pass",
  };
  assertCrossBlockState(signedSnapshot, freshSnapshot);

  const policyNow =
    input.timeAuthority === "snapshot"
      ? new Date(parseSnapshotUnixSeconds(freshSnapshot.pin.observedAt) * 1_000)
      : input.now;
  if (Number.isNaN(policyNow.valueOf())) {
    throw new PreviewGateFailure("inconclusive", "PREVIEW_STATE_UNAVAILABLE");
  }

  let policy: RebalancePlanPolicyResult;
  try {
    policy = validateRebalancePlanPolicy({
      decoded: input.decoded,
      task: input.task,
      state: {
        expectedProvider: input.expectedProvider,
        positionOwner: freshSnapshot.position.owner,
        approvedAddress: freshSnapshot.position.approved,
        operatorApproved: freshSnapshot.position.callerApprovedForAll,
        positionLiquidity: freshSnapshot.position.liquidity,
        positionTickLower: freshSnapshot.position.tickLower,
        positionTickUpper: freshSnapshot.position.tickUpper,
        token0: freshSnapshot.pool.token0,
        token1: freshSnapshot.pool.token1,
        fee: freshSnapshot.pool.fee,
        currentTick: freshSnapshot.pool.currentTick,
      },
      quoteExpiresAt: input.quoteExpiresAt,
      now: policyNow,
    });
    assertTokenAllowances(input.decoded, freshSnapshot);
  } catch (error) {
    if (
      error instanceof PreviewPlanError &&
      error.code === "POSITION_AUTHORITY_REJECTED"
    ) {
      throw new PreviewGateFailure("invalid", "POSITION_AUTHORITY_REJECTED", {
        snapshot: freshSnapshot,
      });
    }
    throw new PreviewGateFailure("invalid", "TRANSACTION_POLICY_REJECTED", {
      snapshot: freshSnapshot,
    });
  }
  gates = {
    ...gates,
    positionAuthority: "pass",
    transactionPolicy: "pass",
  };

  let simulation;
  try {
    simulation = await input.simulate({
      transport: input.transport,
      randomUUID: input.randomUUID,
      caller: input.decoded.plan.from,
      data: input.decoded.plan.data as Hex,
      blockHash: freshSnapshot.pin.observedBlockHash,
    });
  } catch (error) {
    if (error instanceof PreviewSimulationError && error.kind === "reverted") {
      throw new PreviewGateFailure("invalid", "EVM_SIMULATION_REVERTED", {
        gates: { ...gates, evmSimulation: "fail" },
        snapshot: freshSnapshot,
        policy,
        ...(error.evidence.requestSha256 === undefined
          ? {}
          : { simulationRequestSha256: error.evidence.requestSha256 }),
        ...(error.evidence.responseSha256 === undefined
          ? {}
          : { simulationResponseSha256: error.evidence.responseSha256 }),
      });
    }
    throw new PreviewGateFailure("inconclusive", "PREVIEW_STATE_UNAVAILABLE", {
      gates,
      snapshot: freshSnapshot,
      policy,
      ...(error instanceof PreviewSimulationError &&
      error.evidence.requestSha256 !== undefined
        ? { simulationRequestSha256: error.evidence.requestSha256 }
        : {}),
      ...(error instanceof PreviewSimulationError &&
      error.evidence.responseSha256 !== undefined
        ? { simulationResponseSha256: error.evidence.responseSha256 }
        : {}),
    });
  }

  let decodedResult;
  try {
    decodedResult = decodeRebalanceSimulationResult({
      rawResult: simulation.rawResult,
      decoded: input.decoded,
      maxSlippageBps: input.task.mandate.limits.max_slippage_bps,
    });
  } catch {
    throw new PreviewGateFailure("invalid", "EVM_SIMULATION_INVALID", {
      gates: { ...gates, evmSimulation: "fail" },
      snapshot: freshSnapshot,
      policy,
      simulationRequestSha256: simulation.requestSha256,
      simulationResponseSha256: simulation.responseSha256,
    });
  }
  try {
    await input.assertCanonical({
      rpc,
      blockNumber: signedSnapshot.pin.observedBlockNumber,
      blockHash: signedSnapshot.pin.observedBlockHash,
    });
    await input.assertCanonical({
      rpc,
      blockNumber: freshSnapshot.pin.observedBlockNumber,
      blockHash: freshSnapshot.pin.observedBlockHash,
    });
  } catch {
    throw new PreviewGateFailure("inconclusive", "PREVIEW_STATE_UNAVAILABLE", {
      gates,
      snapshot: freshSnapshot,
      policy,
      simulationRequestSha256: simulation.requestSha256,
      simulationResponseSha256: simulation.responseSha256,
    });
  }

  gates = { ...gates, evmSimulation: "pass" };
  return {
    status: "pass",
    gates,
    signedSnapshot,
    snapshot: freshSnapshot,
    policy,
    simulationRequestSha256: simulation.requestSha256,
    simulationResponseSha256: simulation.responseSha256,
    simulationResultSha256: decodedResult.simulationResultSha256,
  };
}

function requireState(
  result: PancakeStateResult,
  invalidCode: RebalancePreviewErrorCode,
  gates: RebalancePreviewGates,
): PancakeStateSnapshot {
  if (result.status === "verified") return result.snapshot;
  if (result.status === "inconclusive") {
    throw new PreviewGateFailure("inconclusive", "PREVIEW_STATE_UNAVAILABLE", {
      gates,
    });
  }
  if (result.code === "AGENT_OWNER_MISMATCH") {
    throw new PreviewGateFailure("invalid", "IDENTITY_OWNER_MISMATCH", {
      gates: { ...gates, identityOwner: "fail" },
    });
  }
  if (result.code === "PROVIDER_NOT_EOA") {
    throw new PreviewGateFailure("invalid", "CALLER_NOT_EOA", {
      gates: { ...gates, identityOwner: "fail" },
    });
  }
  throw new PreviewGateFailure("invalid", invalidCode);
}

function assertSignedEvidence(
  snapshot: PancakeStateSnapshot,
  task: QuoteMandatexSignedRebalanceTask,
): void {
  const evidence = task.evidence;
  if (
    snapshot.pin.observedBlockNumber !== evidence.observed_block.toString() ||
    snapshot.pin.observedBlockHash !== evidence.observed_block_hash ||
    snapshot.pin.observedAt !== evidence.observed_at.toString() ||
    snapshot.pool.address !== evidence.pool_address ||
    snapshot.deployments.positionManager.address !==
      evidence.position_manager_address ||
    snapshot.position.tokenId !== evidence.position_token_id ||
    snapshot.position.owner !== evidence.position_owner ||
    snapshot.pool.token0 !== evidence.token0 ||
    snapshot.pool.token1 !== evidence.token1 ||
    snapshot.tokens.token0.decimals !== evidence.token0_decimals ||
    snapshot.tokens.token1.decimals !== evidence.token1_decimals ||
    snapshot.pool.fee !== evidence.fee ||
    snapshot.pool.tickSpacing !== evidence.tick_spacing ||
    snapshot.pool.currentTick !== evidence.current_tick ||
    snapshot.pool.sqrtPriceX96 !== evidence.sqrt_price_x96 ||
    snapshot.position.tickLower !== evidence.position_tick_lower ||
    snapshot.position.tickUpper !== evidence.position_tick_upper ||
    snapshot.pool.liquidity !== evidence.pool_liquidity ||
    snapshot.position.liquidity !== evidence.position_liquidity
  ) {
    throw new PreviewGateFailure("invalid", "SIGNED_EVIDENCE_INVALID");
  }
}

function assertCrossBlockState(
  signed: PancakeStateSnapshot,
  fresh: PancakeStateSnapshot,
): void {
  if (
    BigInt(fresh.pin.observedBlockNumber) <
      BigInt(signed.pin.observedBlockNumber) ||
    fresh.identity.currentOwner !== signed.identity.currentOwner ||
    fresh.deployments.factory.address !== signed.deployments.factory.address ||
    fresh.deployments.deployer.address !== signed.deployments.deployer.address ||
    fresh.deployments.positionManager.address !==
      signed.deployments.positionManager.address ||
    fresh.pool.address !== signed.pool.address ||
    fresh.pool.factory !== signed.pool.factory ||
    fresh.pool.token0 !== signed.pool.token0 ||
    fresh.pool.token1 !== signed.pool.token1 ||
    fresh.pool.fee !== signed.pool.fee ||
    fresh.pool.tickSpacing !== signed.pool.tickSpacing ||
    fresh.position.owner !== signed.position.owner ||
    fresh.position.token0 !== signed.position.token0 ||
    fresh.position.token1 !== signed.position.token1 ||
    fresh.position.fee !== signed.position.fee ||
    fresh.position.tickLower !== signed.position.tickLower ||
    fresh.position.tickUpper !== signed.position.tickUpper ||
    fresh.position.liquidity !== signed.position.liquidity
  ) {
    throw new PreviewGateFailure("invalid", "PREVIEW_STATE_INVALID");
  }
}

function assertTokenAllowances(
  decoded: DecodedRebalancePlan,
  snapshot: PancakeStateSnapshot,
): void {
  if (
    BigInt(snapshot.tokens.token0.callerAllowanceToPositionManager) <
      decoded.mint.amount0Desired ||
    BigInt(snapshot.tokens.token1.callerAllowanceToPositionManager) <
      decoded.mint.amount1Desired
  ) {
    throw new PreviewPlanError("TRANSACTION_POLICY_REJECTED");
  }
}

function previewFailure(error: unknown): PreviewFailure {
  if (error instanceof PreviewGateFailure) {
    return {
      status: error.status,
      errorCode: error.code,
      gates: error.evidence.gates ?? gatesForFailure(error.code),
      ...(error.evidence.snapshot === undefined
        ? {}
        : { snapshot: error.evidence.snapshot }),
      ...(error.evidence.policy === undefined
        ? {}
        : { policy: error.evidence.policy }),
      ...(error.evidence.simulationRequestSha256 === undefined
        ? {}
        : {
            simulationRequestSha256:
              error.evidence.simulationRequestSha256,
          }),
      ...(error.evidence.simulationResponseSha256 === undefined
        ? {}
        : {
            simulationResponseSha256:
              error.evidence.simulationResponseSha256,
          }),
    };
  }
  return {
    status: "inconclusive",
    errorCode: "PREVIEW_STATE_UNAVAILABLE",
    gates: emptyPreviewGates(),
  };
}

function buildPreviewSidecar(input: {
  quote: Awaited<ReturnType<typeof validateTrustedQuote>>;
  decoded: DecodedRebalancePlan;
  mandateSha256: string;
  progress: PreviewProgress | undefined;
}): RebalancePreviewSidecar {
  const progress = input.progress;
  const previewExpired =
    progress?.status === "pass" &&
    (input.quote.errorCode === "QUOTE_POLICY_REJECTED" ||
      input.quote.errorCode === "PREVIEW_GATE_REJECTED");
  const passed = input.quote.outcome === "valid" && progress?.status === "pass";
  const outcome = passed
    ? "preview_simulation_passed"
    : input.quote.outcome === "refused"
      ? "refused"
      : input.quote.outcome === "inconclusive" ||
          progress?.status === "inconclusive"
        ? "inconclusive"
        : "invalid";
  const errorCode = passed || outcome === "refused"
    ? undefined
    : progress !== undefined && progress.status !== "pass"
      ? progress.errorCode
      : input.quote.outcome === "inconclusive"
        ? "QUOTE_VALIDATION_INCONCLUSIVE"
        : previewExpired
          ? "PREVIEW_EXPIRED"
          : "QUOTE_VALIDATION_FAILED";
  const snapshot = progress?.snapshot;
  const policy = progress?.policy;
  const callerAuthority =
    policy?.authority ??
    (snapshot === undefined ? undefined : snapshotAuthority(snapshot));
  const calls = policy?.calls ?? publicCalls(input.decoded);

  return rebalancePreviewSidecarSchema.parse({
    schema: "mandatex.agent-supply.rebalance-preview.v1",
    observedAt: input.quote.observedAt,
    outcome,
    classification: passed
      ? "PREVIEW_SIMULATION_PASSED"
      : outcome === "inconclusive"
        ? "INCONCLUSIVE"
        : "EXCLUDED",
    operatorSuppliedPlan: true,
    simulationOnly: true,
    candidate: input.quote.candidate,
    quote: input.quote,
    mandateSha256: input.mandateSha256,
    transactionPlanSha256: input.decoded.transactionPlanSha256,
    calldataSha256: input.decoded.calldataSha256,
    decodedPlanSha256: input.decoded.decodedPlanSha256,
    ...(progress?.simulationRequestSha256 === undefined
      ? {}
      : { simulationRequestSha256: progress.simulationRequestSha256 }),
    ...(progress?.simulationResponseSha256 === undefined
      ? {}
      : { simulationResponseSha256: progress.simulationResponseSha256 }),
    ...(progress?.status !== "pass"
      ? {}
      : { simulationResultSha256: progress.simulationResultSha256 }),
    ...(snapshot === undefined || callerAuthority === undefined
      ? {}
      : {
          snapshot: {
            chainId: 56,
            headBlockNumber: snapshot.pin.headBlockNumber,
            blockNumber: snapshot.pin.observedBlockNumber,
            blockHash: snapshot.pin.observedBlockHash,
            blockTimestamp: Number(snapshot.pin.observedAt),
            confirmationDepth: 2,
            positionOwner: snapshot.position.owner,
            callerAuthority,
            currentTick: snapshot.pool.currentTick,
            positionLiquidity: snapshot.position.liquidity,
          },
        }),
    calls,
    gates: previewExpired
      ? { ...progress.gates, transactionPolicy: "fail" }
      : progress?.gates ?? emptyPreviewGates(),
    ...(errorCode === undefined ? {} : { errorCode }),
  });
}

function snapshotAuthority(
  snapshot: PancakeStateSnapshot,
): RebalancePlanPolicyResult["authority"] | undefined {
  if (snapshot.position.owner === snapshot.position.caller) return "owner";
  if (snapshot.position.approved === snapshot.position.caller) {
    return "token_approval";
  }
  if (snapshot.position.callerApprovedForAll) return "operator_approval";
  return undefined;
}

function publicCalls(decoded: DecodedRebalancePlan) {
  const deadline = Number(decoded.mint.deadline);
  return [
    {
      method: "decreaseLiquidity" as const,
      tokenId: decoded.decrease.tokenId.toString(),
      ...(Number.isSafeInteger(deadline) && deadline > 0 ? { deadline } : {}),
    },
    {
      method: "collect" as const,
      tokenId: decoded.collect.tokenId.toString(),
      recipient: decoded.collect.recipient,
    },
    {
      method: "mint" as const,
      lowerTick: decoded.mint.tickLower,
      upperTick: decoded.mint.tickUpper,
      recipient: decoded.mint.recipient,
      ...(Number.isSafeInteger(deadline) && deadline > 0 ? { deadline } : {}),
    },
  ];
}

function emptyPreviewGates(): RebalancePreviewGates {
  return {
    signedEvidence: "unknown",
    freshState: "unknown",
    identityOwner: "unknown",
    positionAuthority: "unknown",
    transactionPolicy: "unknown",
    evmSimulation: "unknown",
  };
}

function gatesForFailure(
  code: RebalancePreviewErrorCode,
): RebalancePreviewGates {
  const gates = emptyPreviewGates();
  if (code === "SIGNED_EVIDENCE_INVALID") {
    return { ...gates, signedEvidence: "fail" };
  }
  if (code === "PREVIEW_STATE_UNAVAILABLE") return gates;
  if (
    code === "PREVIEW_STATE_INVALID" ||
    code === "IDENTITY_OWNER_MISMATCH" ||
    code === "CALLER_NOT_EOA"
  ) {
    return {
      ...gates,
      signedEvidence: "pass",
      freshState: code === "PREVIEW_STATE_INVALID" ? "fail" : "pass",
      identityOwner:
        code === "IDENTITY_OWNER_MISMATCH" || code === "CALLER_NOT_EOA"
          ? "fail"
          : "unknown",
    };
  }
  if (code === "POSITION_AUTHORITY_REJECTED") {
    return {
      ...gates,
      signedEvidence: "pass",
      freshState: "pass",
      identityOwner: "pass",
      positionAuthority: "fail",
    };
  }
  if (code === "TRANSACTION_POLICY_REJECTED") {
    return {
      ...gates,
      signedEvidence: "pass",
      freshState: "pass",
      identityOwner: "pass",
      positionAuthority: "pass",
      transactionPolicy: "fail",
    };
  }
  if (
    code === "EVM_SIMULATION_REVERTED" ||
    code === "EVM_SIMULATION_INVALID"
  ) {
    return {
      ...gates,
      signedEvidence: "pass",
      freshState: "pass",
      identityOwner: "pass",
      positionAuthority: "pass",
      transactionPolicy: "pass",
      evmSimulation: "fail",
    };
  }
  return gates;
}
