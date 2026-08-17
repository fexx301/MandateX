import {
  activationStateSchema,
  type ActivationIntent,
  type ActivationJobObservation,
  type ActivationReconciliation,
  type ActivationState,
} from "./schema.js";
import type { ActivationReceiptObservation } from "./rpc.js";
import {
  reconcileActivationStep,
  recordActivationReconciliation,
} from "./state.js";

export interface ActivationObservationReader {
  observeReceipt(
    transactionHash: string,
    intent: ActivationIntent,
  ): Promise<ActivationReceiptObservation>;
  observeJob(
    jobId: string,
    blockHash: string,
  ): Promise<ActivationJobObservation>;
}

export async function observeAndReconcileActivation(input: Readonly<{
  state: ActivationState;
  rpc: ActivationObservationReader;
  now?: Date;
}>): Promise<ActivationState> {
  const state = activationStateSchema.parse(input.state);
  if (state.intent === undefined || state.submission === undefined) {
    throw new Error("activation reconciliation requires a recorded submission");
  }
  const observed = await input.rpc.observeReceipt(
    state.submission.transactionHash,
    state.intent,
  );
  if (observed.kind !== "confirmed") {
    if (observed.kind !== "reverted") {
      return recordActivationReconciliation({
        state,
        observation: observed,
      });
    }

    const job =
      state.phase === "PREPARED_CREATE"
        ? undefined
        : await input.rpc.observeJob(requiredJobId(state), observed.blockHash);
    return recordActivationReconciliation({
      state,
      observation: reconciliationObservation(observed),
      deployment: observed.deployment,
      ...(job === undefined ? {} : { job }),
    });
  }

  const jobId = state.jobId ?? createdJobId(observed.receipt);
  const job = await input.rpc.observeJob(jobId, observed.receipt.blockHash);
  return reconcileActivationStep({
    state,
    receipt: observed.receipt,
    job,
    deployment: observed.deployment,
    ...(input.now === undefined ? {} : { now: input.now }),
  });
}

function reconciliationObservation(
  observed: Extract<ActivationReceiptObservation, { kind: "reverted" }>,
): ActivationReconciliation {
  return {
    kind: observed.kind,
    transactionHash: observed.transactionHash,
    observedAt: observed.observedAt,
    blockNumber: observed.blockNumber,
    blockHash: observed.blockHash,
    confirmationDepth: observed.confirmationDepth,
  };
}

function requiredJobId(state: ActivationState): string {
  if (state.jobId === undefined) {
    throw new Error("post-create reconciliation requires a recorded job ID");
  }
  return state.jobId;
}

function createdJobId(
  receipt: Extract<ActivationReceiptObservation, { kind: "confirmed" }>["receipt"],
): string {
  const events = receipt.events.filter((event) => event.name === "JobCreated");
  if (events.length !== 1) {
    throw new Error("create reconciliation requires exactly one JobCreated event");
  }
  return events[0]!.jobId;
}
