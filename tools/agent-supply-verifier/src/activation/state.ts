import { createHash } from "node:crypto";

import { JobDescription } from "@bnbagent/sdk/erc8183";
import { encodeFunctionData, parseAbi, type Address, type Hex } from "viem";

import {
  canonicalQuoteJson,
  computeQuoteSha256,
  decodeQuoteSignedTask,
} from "../quotes/protocol.js";
import { quoteMandatexSignedRebalanceTaskSchema } from "../quotes/schema.js";
import { rebalanceTransactionPlanSchema } from "../preview/schema.js";
import {
  BSC_ACTIVATION_DEPLOYMENT,
  ACTIVATION_CONFIRMATION_DEPTH,
  ACTIVATION_PHASE_ORDER,
  minimumQuoteRemainingSeconds,
  type ActivationPhase,
} from "./deployment.js";
import { captureActivationIntent } from "./capture.js";
import {
  ACTIVATION_REPORT_SCHEMA,
  ACTIVATION_STATE_SCHEMA,
  activationBindingSchema,
  activationDeploymentObservationSchema,
  activationJobObservationSchema,
  activationPreviewSchema,
  activationReconciliationSchema,
  activationReportSchema,
  activationReceiptSchema,
  activationStateSchema,
  activationSubmissionSchema,
  assertZeroBudgetBinding,
  type ActivationDeploymentObservation,
  type ActivationJobObservation,
  type ActivationOperation,
  type ActivationPreview,
  type ActivationReconciliation,
  type ActivationReceipt,
  type ActivationReport,
  type ActivationState,
} from "./schema.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const commerceWriteAbi = parseAbi([
  "function createJob(address provider,address evaluator,uint256 expiredAt,string description,address hook)",
  "function setBudget(uint256 jobId,uint256 amount,bytes optParams)",
  "function fund(uint256 jobId,uint256 expectedBudget,bytes optParams)",
]);
const routerWriteAbi = parseAbi([
  "function registerJob(uint256 jobId,address policy)",
]);

export type PrepareCreateInput = Readonly<{
  binding: ActivationState["binding"];
  signedTask: ActivationState["signedTask"];
  transactionPlan: ActivationState["transactionPlan"];
  initialPreview: ActivationPreview;
  deployment: ActivationDeploymentObservation;
  cleanupOwner: ActivationState["cleanup"]["owner"];
  now?: Date;
}>;

export class ActivationStateError extends Error {
  constructor(
    readonly code:
      | "QUOTE_EXPIRED"
      | "DEPLOYMENT_MISMATCH"
      | "STATE_MISMATCH"
      | "TRANSACTION_MISMATCH"
      | "EVENT_MISMATCH"
      | "JOB_STATE_MISMATCH"
      | "PREVIEW_REQUIRED",
  ) {
    super("activation state transition failed closed");
    this.name = "ActivationStateError";
  }
}

export async function prepareCreateActivation(
  input: PrepareCreateInput,
): Promise<ActivationState> {
  const binding = activationBindingSchema.parse(input.binding);
  const signedTask = quoteMandatexSignedRebalanceTaskSchema.parse(input.signedTask);
  const transactionPlan = rebalanceTransactionPlanSchema.parse(input.transactionPlan);
  const initialPreview = activationPreviewSchema.parse(input.initialPreview);
  const deployment = assertDeployment(input.deployment);
  assertBinding(binding);
  assertArtifactHashes({ binding, signedTask, transactionPlan, initialPreview });
  assertPreviewMatches(binding, initialPreview, true);
  assertQuoteWindow("PREPARED_CREATE", binding, deployment.blockTimestamp);
  assertPreviewWindow("PREPARED_CREATE", initialPreview, deployment.blockTimestamp);
  assertPreviewPrecedesDeployment(initialPreview, deployment);
  assertJobDescription(binding, signedTask);
  assertJobExpiry(binding, deployment, initialPreview);

  const intent = await captureActivationIntent({
    operation: "create_job",
    client: binding.client,
    provider: binding.provider,
    expiredAt: BigInt(binding.jobExpiresAt),
    description: binding.jobDescription,
  });
  const now = (input.now ?? new Date()).toISOString();
  const activationId = computeActivationId(binding);
  return activationStateSchema.parse({
    schema: ACTIVATION_STATE_SCHEMA,
    version: 1,
    activationId,
    sequence: 0,
    phase: "PREPARED_CREATE",
    condition: "ready",
    createdAt: now,
    updatedAt: now,
    binding,
    signedTask,
    transactionPlan,
    initialPreview,
    intent,
    receipts: [],
    cleanup: cleanupForPhase("PREPARED_CREATE", input.cleanupOwner),
  });
}

/**
 * Revalidates a recovered sequence-zero activation against a fresh canonical
 * deployment observation before its unsigned intent is exposed again.
 */
export function assertRecoveredCreateActivation(input: Readonly<{
  state: ActivationState;
  deployment: ActivationDeploymentObservation;
}>): ActivationState {
  const state = activationStateSchema.parse(input.state);
  assertStateIntegrity(state);
  if (
    state.sequence !== 0 ||
    state.parentStateSha256 !== undefined ||
    state.phase !== "PREPARED_CREATE" ||
    state.condition !== "ready" ||
    state.intent === undefined ||
    state.submission !== undefined ||
    state.reconciliation !== undefined ||
    state.receipts.length !== 0
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  const deployment = assertDeployment(input.deployment);
  assertQuoteWindow("PREPARED_CREATE", state.binding, deployment.blockTimestamp);
  assertPreviewWindow(
    "PREPARED_CREATE",
    state.initialPreview,
    deployment.blockTimestamp,
  );
  assertPreviewPrecedesDeployment(state.initialPreview, deployment);
  assertJobExpiry(state.binding, deployment, state.initialPreview);
  return state;
}

export async function prepareNextActivationStep(input: Readonly<{
  state: ActivationState;
  deployment: ActivationDeploymentObservation;
  job: ActivationJobObservation;
  fundingPreview?: ActivationPreview;
  now?: Date;
}>): Promise<ActivationState> {
  const state = activationStateSchema.parse(input.state);
  assertStateIntegrity(state);
  if (state.condition !== "ready" || state.intent !== undefined) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  const deployment = assertDeployment(input.deployment);
  const next = nextPreparedPhase(state.phase);
  if (next === undefined || state.jobId === undefined) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  const job = activationJobObservationSchema.parse(input.job);
  assertJobMatches(state, state.phase, job, state.jobId);
  assertQuoteWindow(next, state.binding, deployment.blockTimestamp);

  if (next === "PREPARED_FUND") {
    if (input.fundingPreview === undefined) {
      throw new ActivationStateError("PREVIEW_REQUIRED");
    }
    const preview = activationPreviewSchema.parse(input.fundingPreview);
    assertPreviewMatches(state.binding, preview, false);
    assertPreviewWindow("PREPARED_FUND", preview, deployment.blockTimestamp);
    assertPreviewPrecedesDeployment(preview, deployment);
  }

  const jobId = BigInt(state.jobId);
  const intent = await captureActivationIntent(
    next === "PREPARED_REGISTER"
      ? { operation: "register_job", client: state.binding.client, jobId }
      : next === "PREPARED_SET_BUDGET"
        ? { operation: "set_budget", client: state.binding.client, jobId }
        : { operation: "fund", client: state.binding.client, jobId },
  );

  return activationStateSchema.parse({
    ...state,
    sequence: state.sequence + 1,
    parentStateSha256: activationStateSha256(state),
    phase: next,
    updatedAt: (input.now ?? new Date()).toISOString(),
    intent,
    ...(next === "PREPARED_FUND"
      ? { fundingPreview: activationPreviewSchema.parse(input.fundingPreview) }
      : {}),
    cleanup: cleanupForPhase(next, state.cleanup.owner),
  });
}

export function recordActivationSubmission(input: Readonly<{
  state: ActivationState;
  transactionHash: string;
  now?: Date;
}>): ActivationState {
  const state = activationStateSchema.parse(input.state);
  assertStateIntegrity(state);
  if (state.intent === undefined || !state.phase.startsWith("PREPARED_")) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  if (
    state.condition !== "ready" &&
    state.condition !== "broadcast_unknown" &&
    state.condition !== "reconcile_required"
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  const submission = activationSubmissionSchema.parse({
    transactionHash: input.transactionHash,
    recordedAt: (input.now ?? new Date()).toISOString(),
  });
  if (state.submission !== undefined) {
    if (state.submission.transactionHash !== submission.transactionHash) {
      throw new ActivationStateError("TRANSACTION_MISMATCH");
    }
    return state;
  }
  return activationStateSchema.parse({
    ...state,
    sequence: state.sequence + 1,
    parentStateSha256: activationStateSha256(state),
    condition: "reconcile_required",
    updatedAt: submission.recordedAt,
    submission,
    reconciliation: undefined,
    errorCode: undefined,
  });
}

export function reconcileActivationStep(input: Readonly<{
  state: ActivationState;
  receipt: ActivationReceipt;
  job: ActivationJobObservation;
  deployment: ActivationDeploymentObservation;
  now?: Date;
}>): ActivationState {
  const state = activationStateSchema.parse(input.state);
  assertStateIntegrity(state);
  const receipt = activationReceiptSchema.parse(input.receipt);
  const job = activationJobObservationSchema.parse(input.job);
  assertDeployment(input.deployment);
  if (
    state.condition !== "reconcile_required" ||
    state.intent === undefined ||
    state.submission === undefined
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  assertReceiptMatches(state, receipt, input.deployment);
  const confirmed = confirmedPhaseFor(state.phase);
  if (confirmed === undefined) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  const jobId = state.jobId ?? eventJobId(receipt, state.phase);
  if (jobId === undefined || job.jobId !== jobId) {
    throw new ActivationStateError("EVENT_MISMATCH");
  }
  assertJobMatches(state, confirmed, job, jobId);

  return activationStateSchema.parse({
    ...state,
    sequence: state.sequence + 1,
    parentStateSha256: activationStateSha256(state),
    phase: confirmed,
    condition: "ready",
    updatedAt: (input.now ?? new Date()).toISOString(),
    jobId,
    intent: undefined,
    submission: undefined,
    reconciliation: undefined,
    receipts: [...state.receipts, receipt],
    cleanup: cleanupForPhase(confirmed, state.cleanup.owner),
    errorCode: undefined,
  });
}

export function recordActivationReconciliation(input: Readonly<{
  state: ActivationState;
  observation: ActivationReconciliation;
  deployment?: ActivationDeploymentObservation;
  job?: ActivationJobObservation;
}>): ActivationState {
  const state = activationStateSchema.parse(input.state);
  assertStateIntegrity(state);
  const observation = activationReconciliationSchema.parse(input.observation);
  if (
    state.condition !== "reconcile_required" ||
    state.intent === undefined ||
    state.submission === undefined ||
    observation.transactionHash !== state.submission.transactionHash ||
    Date.parse(observation.observedAt) < Date.parse(state.updatedAt)
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  if (
    state.reconciliation !== undefined &&
    canonicalQuoteJson(state.reconciliation) === canonicalQuoteJson(observation)
  ) {
    return state;
  }

  if (observation.kind !== "reverted") {
    return activationStateSchema.parse({
      ...state,
      sequence: state.sequence + 1,
      parentStateSha256: activationStateSha256(state),
      updatedAt: observation.observedAt,
      reconciliation: observation,
      errorCode:
        observation.kind === "reorged" ? "CANONICALITY_FAILED" : undefined,
    });
  }

  if (input.deployment === undefined) {
    throw new ActivationStateError("DEPLOYMENT_MISMATCH");
  }
  const deployment = assertDeployment(input.deployment);
  if (
    deployment.blockNumber !== observation.blockNumber ||
    deployment.blockHash !== observation.blockHash ||
    deployment.confirmationDepth !== observation.confirmationDepth
  ) {
    throw new ActivationStateError("DEPLOYMENT_MISMATCH");
  }
  if (state.phase === "PREPARED_CREATE") {
    if (state.jobId !== undefined || input.job !== undefined) {
      throw new ActivationStateError("JOB_STATE_MISMATCH");
    }
  } else {
    const confirmed = priorConfirmedPhase(state.phase);
    if (
      confirmed === undefined ||
      state.jobId === undefined ||
      input.job === undefined
    ) {
      throw new ActivationStateError("JOB_STATE_MISMATCH");
    }
    assertJobMatches(
      state,
      confirmed,
      activationJobObservationSchema.parse(input.job),
      state.jobId,
    );
  }

  const createReverted = state.phase === "PREPARED_CREATE";
  return activationStateSchema.parse({
    ...state,
    sequence: state.sequence + 1,
    parentStateSha256: activationStateSha256(state),
    updatedAt: observation.observedAt,
    condition: createReverted ? "aborted" : "cleanup_required",
    reconciliation: observation,
    errorCode: "RECEIPT_REVERTED",
    cleanup: createReverted
      ? {
          owner: state.cleanup.owner,
          requiredActions: [],
          note: "The exact create transaction reverted canonically; no job was created by it.",
        }
      : cleanupForPhase(state.phase, state.cleanup.owner),
  });
}

export function markActivationBroadcastUnknown(
  input: Readonly<{ state: ActivationState; now?: Date }>,
): ActivationState {
  const state = activationStateSchema.parse(input.state);
  assertStateIntegrity(state);
  if (
    state.intent === undefined ||
    state.submission !== undefined ||
    state.condition !== "ready"
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  return activationStateSchema.parse({
    ...state,
    sequence: state.sequence + 1,
    parentStateSha256: activationStateSha256(state),
    condition: "broadcast_unknown",
    updatedAt: (input.now ?? new Date()).toISOString(),
    errorCode: "BROADCAST_UNKNOWN",
    reconciliation: undefined,
    cleanup: {
      owner: state.cleanup.owner,
      requiredActions: [],
      note: "Do not retry or advance. Recover the transaction hash and reconcile before deriving cleanup actions.",
    },
  });
}

export function activationStateSha256(state: ActivationState): string {
  const parsed = activationStateSchema.parse(state);
  assertStateIntegrity(parsed);
  return computeQuoteSha256(canonicalQuoteJson(parsed));
}

export function serializeActivationState(state: ActivationState): string {
  const parsed = activationStateSchema.parse(state);
  assertStateIntegrity(parsed);
  return `${canonicalQuoteJson(parsed)}\n`;
}

export function buildActivationReport(stateInput: ActivationState): ActivationReport {
  const state = activationStateSchema.parse(stateInput);
  assertStateIntegrity(state);
  const latestReceipt = state.receipts.at(-1);
  const reconciliation = state.reconciliation;
  const classification = classificationFor(state);
  return {
    schema: ACTIVATION_REPORT_SCHEMA,
    activationId: state.activationId,
    stateSha256: activationStateSha256(state),
    observedAt: state.updatedAt,
    phase: state.phase,
    condition: state.condition,
    candidate: { chainId: 56, tokenId: state.binding.tokenId },
    client: state.binding.client,
    provider: state.binding.provider,
    ...(state.jobId === undefined ? {} : { jobId: state.jobId }),
    ...(state.intent === undefined
      ? latestReceipt === undefined
        ? {}
        : {
            operation: latestReceipt.operation,
            transactionHash: latestReceipt.transactionHash,
            calldataSha256: latestReceipt.calldataSha256,
            blockNumber: latestReceipt.blockNumber,
            blockHash: latestReceipt.blockHash,
          }
      : {
          operation: state.intent.operation,
          ...(state.submission === undefined
            ? {}
            : { transactionHash: state.submission.transactionHash }),
          calldataSha256: state.intent.calldataSha256,
          ...(reconciliation === undefined || !("blockNumber" in reconciliation)
            ? {}
            : {
                blockNumber: reconciliation.blockNumber,
                blockHash: reconciliation.blockHash,
              }),
        }),
    ...(state.errorCode === undefined ? {} : { errorCode: state.errorCode }),
    ...(reconciliation === undefined
      ? {}
      : { reconciliationOutcome: reconciliation.kind }),
    quoteExpiresAt: state.binding.quoteExpiresAt,
    cleanup: state.cleanup,
    classification,
  };
}

export function serializeActivationReport(report: ActivationReport): string {
  return `${canonicalQuoteJson(activationReportSchema.parse(report))}\n`;
}

function assertBinding(binding: ActivationState["binding"]): void {
  assertZeroBudgetBinding(binding);
  const deployment = BSC_ACTIVATION_DEPLOYMENT;
  const expected: ReadonlyArray<readonly [string, string]> = [
    [binding.commerceProxy, deployment.commerceProxy],
    [binding.commerceImplementation, deployment.commerceImplementation],
    [binding.commerceImplementationCodeHash, deployment.commerceImplementationCodeHash],
    [binding.routerProxy, deployment.routerProxy],
    [binding.routerImplementation, deployment.routerImplementation],
    [binding.routerImplementationCodeHash, deployment.routerImplementationCodeHash],
    [binding.policy, deployment.policy],
    [binding.paymentToken, deployment.paymentToken],
    [binding.paymentTokenCodeHash, deployment.paymentTokenCodeHash],
  ];
  if (expected.some(([actual, pinned]) => actual !== pinned)) {
    throw new ActivationStateError("DEPLOYMENT_MISMATCH");
  }
}

function assertArtifactHashes(input: Pick<
  PrepareCreateInput,
  "binding" | "signedTask" | "transactionPlan" | "initialPreview"
>): void {
  const { binding } = input;
  if (
    binding.mandateSha256 !== sha256Json(input.signedTask.mandate) ||
    binding.signedTaskSha256 !== sha256Json(input.signedTask) ||
    binding.transactionPlanSha256 !== sha256Json(input.transactionPlan) ||
    binding.initialPreviewSha256 !== sha256Json(input.initialPreview)
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
}

function assertStateIntegrity(state: ActivationState): void {
  assertBinding(state.binding);
  assertArtifactHashes({
    binding: state.binding,
    signedTask: state.signedTask,
    transactionPlan: state.transactionPlan,
    initialPreview: state.initialPreview,
  });
  assertPreviewMatches(state.binding, state.initialPreview, true);
  assertJobDescription(state.binding, state.signedTask);
  if (state.activationId !== computeActivationId(state.binding)) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  if (
    Date.parse(state.updatedAt) < Date.parse(state.createdAt) ||
    state.binding.negotiatedAt >= state.binding.quoteExpiresAt ||
    state.binding.jobExpiresAt <= state.binding.quoteExpiresAt
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  const phaseIndex = ACTIVATION_PHASE_ORDER.indexOf(state.phase);
  const expectedReceipts = Math.floor((phaseIndex + 1) / 2);
  if (
    phaseIndex < 0 ||
    state.receipts.length !== expectedReceipts ||
    (phaseIndex === 0 && state.jobId !== undefined) ||
    (phaseIndex >= 1 && state.jobId === undefined)
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  const expectedOperations = [
    "create_job",
    "register_job",
    "set_budget",
    "fund",
  ] as const;
  if (
    state.receipts.some(
      (receipt, index) => receipt.operation !== expectedOperations[index],
    )
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  assertReceiptHistory(state);
  if (state.intent !== undefined) {
    const expectedOperation = expectedOperations[Math.floor(phaseIndex / 2)];
    const expectedTarget =
      expectedOperation === "register_job"
        ? BSC_ACTIVATION_DEPLOYMENT.routerProxy
        : BSC_ACTIVATION_DEPLOYMENT.commerceProxy;
    if (
      state.intent.operation !== expectedOperation ||
      state.intent.from !== state.binding.client ||
      state.intent.to !== expectedTarget
    ) {
      throw new ActivationStateError("STATE_MISMATCH");
    }
    if (state.intent.data !== expectedActivationCalldata(state, expectedOperation)) {
      throw new ActivationStateError("STATE_MISMATCH");
    }
  }
  if (
    state.submission !== undefined &&
    (state.intent === undefined ||
      state.submission.transactionHash === undefined ||
      state.receipts.some(
        (receipt) => receipt.transactionHash === state.submission!.transactionHash,
      ) ||
      Date.parse(state.submission.recordedAt) > Date.parse(state.updatedAt))
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  if (state.fundingPreview !== undefined) {
    if (phaseIndex < 6) {
      throw new ActivationStateError("STATE_MISMATCH");
    }
    assertPreviewMatches(state.binding, state.fundingPreview, false);
  }
}

function assertPreviewMatches(
  binding: ActivationState["binding"],
  previewInput: ActivationPreview,
  requireInitialBlock: boolean,
): void {
  const preview = activationPreviewSchema.parse(previewInput);
  if (
    preview.transactionPlanSha256 !== binding.transactionPlanSha256 ||
    preview.signedTaskSha256 !== binding.signedTaskSha256 ||
    preview.quoteExpiresAt !== binding.quoteExpiresAt ||
    preview.validUntil > binding.quoteExpiresAt ||
    (requireInitialBlock &&
      (preview.blockNumber !== binding.previewBlockNumber ||
        preview.blockHash !== binding.previewBlockHash)) ||
    (!requireInitialBlock &&
      BigInt(preview.blockNumber) < BigInt(binding.previewBlockNumber))
  ) {
    throw new ActivationStateError("PREVIEW_REQUIRED");
  }
}

function assertPreviewWindow(
  phase: ActivationPhase,
  preview: ActivationPreview,
  canonicalBlockTimestamp: number,
): void {
  if (
    preview.blockTimestamp > canonicalBlockTimestamp ||
    preview.validUntil - canonicalBlockTimestamp < minimumQuoteRemainingSeconds(phase)
  ) {
    throw new ActivationStateError("QUOTE_EXPIRED");
  }
}

function assertPreviewPrecedesDeployment(
  preview: ActivationPreview,
  deployment: ActivationDeploymentObservation,
): void {
  if (
    BigInt(preview.blockNumber) > BigInt(deployment.blockNumber) ||
    preview.blockTimestamp > deployment.blockTimestamp
  ) {
    throw new ActivationStateError("PREVIEW_REQUIRED");
  }
}

function assertQuoteWindow(
  phase: ActivationPhase,
  binding: ActivationState["binding"],
  canonicalBlockTimestamp: number,
): void {
  if (
    canonicalBlockTimestamp < binding.negotiatedAt ||
    binding.quoteExpiresAt - canonicalBlockTimestamp <
      minimumQuoteRemainingSeconds(phase)
  ) {
    throw new ActivationStateError("QUOTE_EXPIRED");
  }
}

function assertJobDescription(
  binding: ActivationState["binding"],
  signedTask: ActivationState["signedTask"],
): void {
  const description = JobDescription.fromStr(binding.jobDescription);
  let embeddedTask: ActivationState["signedTask"] | undefined;
  try {
    embeddedTask =
      description === null
        ? undefined
        : decodeQuoteSignedTask(description.task, "mandatex-rebalance:v1");
  } catch {
    embeddedTask = undefined;
  }
  if (
    description === null ||
    description.price !== "0" ||
    description.currency.toLowerCase() !== binding.paymentToken ||
    description.negotiationHash?.toLowerCase() !== binding.negotiationHash ||
    description.providerSig === null ||
    description.providerSig.length === 0 ||
    description.quoteExpiresAt !== binding.quoteExpiresAt ||
    description.negotiatedAt !== binding.negotiatedAt ||
    embeddedTask === undefined ||
    canonicalQuoteJson(embeddedTask) !== canonicalQuoteJson(signedTask)
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
}

function assertJobExpiry(
  binding: ActivationState["binding"],
  deployment: ActivationDeploymentObservation,
  initialPreview: ActivationPreview,
): void {
  const disputeWindow = BigInt(deployment.disputeWindowSeconds);
  const minimumExpiry =
    BigInt(Math.max(deployment.blockTimestamp, initialPreview.validUntil)) +
    disputeWindow +
    300n;
  if (BigInt(binding.jobExpiresAt) <= minimumExpiry) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
}

function assertDeployment(
  input: ActivationDeploymentObservation,
): ActivationDeploymentObservation {
  const observed = activationDeploymentObservationSchema.parse(input);
  const pinned = BSC_ACTIVATION_DEPLOYMENT;
  if (
    observed.confirmationDepth < ACTIVATION_CONFIRMATION_DEPTH ||
    BigInt(observed.headBlockNumber) - BigInt(observed.blockNumber) !==
      BigInt(observed.confirmationDepth) ||
    observed.commerceImplementation !== pinned.commerceImplementation ||
    observed.commerceProxyCodeHash !== pinned.commerceProxyCodeHash ||
    observed.commerceImplementationCodeHash !==
      pinned.commerceImplementationCodeHash ||
    observed.routerImplementation !== pinned.routerImplementation ||
    observed.routerProxyCodeHash !== pinned.routerProxyCodeHash ||
    observed.routerImplementationCodeHash !== pinned.routerImplementationCodeHash ||
    observed.policyCodeHash !== pinned.policyCodeHash ||
    observed.paymentToken !== pinned.paymentToken ||
    observed.paymentTokenCodeHash !== pinned.paymentTokenCodeHash ||
    observed.routerCommerce !== pinned.commerceProxy ||
    observed.policyCommerce !== pinned.commerceProxy ||
    observed.policyRouter !== pinned.routerProxy ||
    !observed.policyWhitelisted ||
    observed.commercePaused ||
    observed.routerPaused
  ) {
    throw new ActivationStateError("DEPLOYMENT_MISMATCH");
  }
  return observed;
}

function assertReceiptMatches(
  state: ActivationState,
  receipt: ActivationReceipt,
  deployment: ActivationDeploymentObservation,
): void {
  const intent = state.intent!;
  if (
    receipt.operation !== intent.operation ||
    receipt.from !== intent.from ||
    receipt.to !== intent.to ||
    receipt.valueWei !== intent.valueWei ||
    receipt.calldataSha256 !== intent.calldataSha256 ||
    state.submission === undefined ||
    receipt.transactionHash !== state.submission.transactionHash ||
    receipt.blockTimestamp < state.binding.negotiatedAt ||
    receipt.blockTimestamp > state.binding.quoteExpiresAt ||
    BigInt(receipt.blockNumber) < BigInt(state.initialPreview.blockNumber) ||
    (state.phase === "PREPARED_FUND" &&
      (state.fundingPreview === undefined ||
        receipt.blockTimestamp > state.fundingPreview.validUntil ||
        BigInt(receipt.blockNumber) < BigInt(state.fundingPreview.blockNumber))) ||
    receipt.blockHash !== deployment.blockHash ||
    receipt.blockNumber !== deployment.blockNumber
  ) {
    throw new ActivationStateError("TRANSACTION_MISMATCH");
  }
  const requiredEvent =
    state.phase === "PREPARED_CREATE"
      ? "JobCreated"
      : state.phase === "PREPARED_REGISTER"
        ? "JobRegistered"
        : state.phase === "PREPARED_FUND"
          ? "JobFunded"
          : undefined;
  if (requiredEvent !== undefined) {
    const matching = receipt.events.filter((event) => event.name === requiredEvent);
    if (matching.length !== 1) {
      throw new ActivationStateError("EVENT_MISMATCH");
    }
    const event = matching[0]!;
    if (
      (event.name === "JobCreated" &&
        (event.client !== state.binding.client ||
          event.provider !== state.binding.provider ||
          event.evaluator !== BSC_ACTIVATION_DEPLOYMENT.routerProxy ||
          event.expiredAt !== state.binding.jobExpiresAt.toString() ||
          event.hook !== BSC_ACTIVATION_DEPLOYMENT.routerProxy)) ||
      (event.name === "JobRegistered" &&
        (event.jobId !== state.jobId ||
          event.policy !== BSC_ACTIVATION_DEPLOYMENT.policy ||
          event.client !== state.binding.client)) ||
      (event.name === "JobFunded" &&
        (event.jobId !== state.jobId ||
          event.client !== state.binding.client ||
          event.provider !== state.binding.provider ||
          event.amount !== "0"))
    ) {
      throw new ActivationStateError("EVENT_MISMATCH");
    }
  }
}

function assertJobMatches(
  state: ActivationState,
  confirmed: ActivationPhase,
  job: ActivationJobObservation,
  jobId: string,
): void {
  if (
    job.jobId !== jobId ||
    job.client !== state.binding.client ||
    job.provider !== state.binding.provider ||
    job.evaluator !== BSC_ACTIVATION_DEPLOYMENT.routerProxy ||
    job.hook !== BSC_ACTIVATION_DEPLOYMENT.routerProxy ||
    job.descriptionSha256 !== sha256Text(state.binding.jobDescription) ||
    job.budget !== "0" ||
    job.expiredAt !== state.binding.jobExpiresAt.toString()
  ) {
    throw new ActivationStateError("JOB_STATE_MISMATCH");
  }
  const expectedPolicy =
    confirmed === "CREATE_CONFIRMED"
      ? ZERO_ADDRESS
      : BSC_ACTIVATION_DEPLOYMENT.policy;
  const expectedHasBudget =
    confirmed === "BUDGET_CONFIRMED" || confirmed === "FUNDED_CONFIRMED";
  const expectedStatus =
    confirmed === "FUNDED_CONFIRMED" ? "FUNDED" : "OPEN";
  if (
    job.policy !== expectedPolicy ||
    job.hasBudget !== expectedHasBudget ||
    job.status !== expectedStatus
  ) {
    throw new ActivationStateError("JOB_STATE_MISMATCH");
  }
}

function nextPreparedPhase(phase: ActivationPhase): ActivationPhase | undefined {
  switch (phase) {
    case "CREATE_CONFIRMED":
      return "PREPARED_REGISTER";
    case "REGISTER_CONFIRMED":
      return "PREPARED_SET_BUDGET";
    case "BUDGET_CONFIRMED":
      return "PREPARED_FUND";
    default:
      return undefined;
  }
}

function confirmedPhaseFor(phase: ActivationPhase): ActivationPhase | undefined {
  switch (phase) {
    case "PREPARED_CREATE":
      return "CREATE_CONFIRMED";
    case "PREPARED_REGISTER":
      return "REGISTER_CONFIRMED";
    case "PREPARED_SET_BUDGET":
      return "BUDGET_CONFIRMED";
    case "PREPARED_FUND":
      return "FUNDED_CONFIRMED";
    default:
      return undefined;
  }
}

function priorConfirmedPhase(phase: ActivationPhase): ActivationPhase | undefined {
  switch (phase) {
    case "PREPARED_REGISTER":
      return "CREATE_CONFIRMED";
    case "PREPARED_SET_BUDGET":
      return "REGISTER_CONFIRMED";
    case "PREPARED_FUND":
      return "BUDGET_CONFIRMED";
    default:
      return undefined;
  }
}

function eventJobId(
  receipt: ActivationReceipt,
  phase: ActivationPhase,
): string | undefined {
  const expected = phase === "PREPARED_CREATE" ? "JobCreated" : undefined;
  return expected === undefined
    ? undefined
    : receipt.events.find((event) => event.name === expected)?.jobId;
}

function cleanupForPhase(
  phase: ActivationPhase,
  owner: ActivationState["cleanup"]["owner"],
): ActivationState["cleanup"] {
  const funded = phase === "FUNDED_CONFIRMED";
  const created = phase !== "PREPARED_CREATE";
  return {
    owner,
    requiredActions: funded
      ? ["claimRefund", "markExpired"]
      : created
        ? ["reject"]
        : [],
    note: funded
      ? "FUNDED is not delivery; after expiry the owner must claimRefund and then markExpired."
      : created
        ? "An OPEN orphan must be rejected by the assigned cleanup owner."
        : "No on-chain job exists before create confirmation.",
  };
}

function classificationFor(state: ActivationState): ActivationReport["classification"] {
  if (state.condition === "aborted") return "ACTIVATION_ABORTED";
  if (state.condition === "cleanup_required") {
    return "ACTIVATION_CLEANUP_REQUIRED";
  }
  if (
    state.condition === "broadcast_unknown" ||
    state.condition === "reconcile_required"
  ) {
    return "ACTIVATION_RECONCILE_REQUIRED";
  }
  if (state.phase === "FUNDED_CONFIRMED") {
    return "ACTIVATION_FUNDED_NOT_DELIVERED";
  }
  return state.intent === undefined
    ? "ACTIVATION_CONFIRMED"
    : "ACTIVATION_PREPARED";
}

function computeActivationId(binding: ActivationState["binding"]): string {
  return computeQuoteSha256(
    canonicalQuoteJson({
      schema: "mandatex.erc8183.activation-id.v1",
      binding,
    }),
  );
}

function assertReceiptHistory(state: ActivationState): void {
  const seenTransactions = new Set<string>();
  let previousBlock = -1n;
  let previousTimestamp = -1;
  let observedJobId: string | undefined;
  const operations = [
    "create_job",
    "register_job",
    "set_budget",
    "fund",
  ] as const;

  for (const [index, receipt] of state.receipts.entries()) {
    const operation = operations[index];
    if (operation === undefined) {
      throw new ActivationStateError("STATE_MISMATCH");
    }
    const blockNumber = BigInt(receipt.blockNumber);
    if (
      seenTransactions.has(receipt.transactionHash) ||
      blockNumber < previousBlock ||
      receipt.blockTimestamp < previousTimestamp ||
      receipt.blockTimestamp < state.binding.negotiatedAt ||
      receipt.blockTimestamp > state.binding.quoteExpiresAt ||
      receipt.from !== state.binding.client ||
      receipt.to !== targetForOperation(operation) ||
      receipt.valueWei !== "0" ||
      receipt.calldataSha256 !==
        sha256Calldata(expectedActivationCalldata(state, operation))
    ) {
      throw new ActivationStateError("STATE_MISMATCH");
    }
    seenTransactions.add(receipt.transactionHash);
    previousBlock = blockNumber;
    previousTimestamp = receipt.blockTimestamp;

    if (operation === "set_budget") {
      if (receipt.events.length !== 0) {
        throw new ActivationStateError("EVENT_MISMATCH");
      }
      continue;
    }
    if (receipt.events.length !== 1) {
      throw new ActivationStateError("EVENT_MISMATCH");
    }
    const event = receipt.events[0]!;
    if (operation === "create_job") {
      if (
        event.name !== "JobCreated" ||
        event.client !== state.binding.client ||
        event.provider !== state.binding.provider ||
        event.evaluator !== BSC_ACTIVATION_DEPLOYMENT.routerProxy ||
        event.expiredAt !== state.binding.jobExpiresAt.toString() ||
        event.hook !== BSC_ACTIVATION_DEPLOYMENT.routerProxy
      ) {
        throw new ActivationStateError("EVENT_MISMATCH");
      }
      observedJobId = event.jobId;
    } else if (operation === "register_job") {
      if (
        event.name !== "JobRegistered" ||
        event.jobId !== observedJobId ||
        event.policy !== BSC_ACTIVATION_DEPLOYMENT.policy ||
        event.client !== state.binding.client
      ) {
        throw new ActivationStateError("EVENT_MISMATCH");
      }
    } else if (
      event.name !== "JobFunded" ||
      event.jobId !== observedJobId ||
      event.client !== state.binding.client ||
      event.provider !== state.binding.provider ||
      event.amount !== "0"
    ) {
      throw new ActivationStateError("EVENT_MISMATCH");
    }
  }

  if (
    state.receipts.length > 0 &&
    (observedJobId === undefined || state.jobId !== observedJobId)
  ) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
}

function expectedActivationCalldata(
  state: ActivationState,
  operation: ActivationOperation,
): Hex {
  switch (operation) {
    case "create_job":
      return encodeFunctionData({
        abi: commerceWriteAbi,
        functionName: "createJob",
        args: [
          state.binding.provider as Address,
          BSC_ACTIVATION_DEPLOYMENT.routerProxy as Address,
          BigInt(state.binding.jobExpiresAt),
          state.binding.jobDescription,
          BSC_ACTIVATION_DEPLOYMENT.routerProxy as Address,
        ],
      }).toLowerCase() as Hex;
    case "register_job":
      return encodeFunctionData({
        abi: routerWriteAbi,
        functionName: "registerJob",
        args: [requiredJobId(state), BSC_ACTIVATION_DEPLOYMENT.policy as Address],
      }).toLowerCase() as Hex;
    case "set_budget":
      return encodeFunctionData({
        abi: commerceWriteAbi,
        functionName: "setBudget",
        args: [requiredJobId(state), 0n, "0x"],
      }).toLowerCase() as Hex;
    case "fund":
      return encodeFunctionData({
        abi: commerceWriteAbi,
        functionName: "fund",
        args: [requiredJobId(state), 0n, "0x"],
      }).toLowerCase() as Hex;
  }
}

function requiredJobId(state: ActivationState): bigint {
  if (state.jobId === undefined) {
    throw new ActivationStateError("STATE_MISMATCH");
  }
  return BigInt(state.jobId);
}

function targetForOperation(
  operation: ActivationOperation,
): string {
  return operation === "register_job"
    ? BSC_ACTIVATION_DEPLOYMENT.routerProxy
    : BSC_ACTIVATION_DEPLOYMENT.commerceProxy;
}

function sha256Calldata(data: string): string {
  return createHash("sha256")
    .update(Buffer.from(data.slice(2), "hex"))
    .digest("hex");
}

function sha256Json(value: unknown): string {
  return computeQuoteSha256(canonicalQuoteJson(value));
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
