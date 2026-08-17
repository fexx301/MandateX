import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  ActivationStateError,
  activationStateSha256,
  markActivationBroadcastUnknown,
  prepareNextActivationStep,
  reconcileActivationStep,
  recordActivationSubmission,
} from "../src/activation/state.js";
import { activationPreviewSchema } from "../src/activation/schema.js";
import {
  ACTIVATION_NOW,
  activationDeployment,
  activationJob,
  activationPreview,
  activationReceipt,
  preparedCreateState,
} from "./activation-fixture.js";

test("state integrity rejects calldata tampering even when its hash is replaced", async () => {
  const state = await preparedCreateState();
  assert.ok(state.intent !== undefined);
  const data = `0x${"00".repeat((state.intent.data.length - 2) / 2)}`;
  const tampered = {
    ...state,
    intent: {
      ...state.intent,
      data,
      calldataSha256: createHash("sha256")
        .update(Buffer.from(data.slice(2), "hex"))
        .digest("hex"),
    },
  };
  assert.throws(
    () => activationStateSha256(tampered),
    hasStateCode("STATE_MISMATCH"),
  );
});

test("state integrity rejects activation identity, job, event, and receipt-order tampering", async () => {
  const created = reconcilePrepared(
    await preparedCreateState(),
    activationDeployment({ blockNumber: "102", blockTimestamp: ACTIVATION_NOW + 10 }),
    "a",
    "CREATE_CONFIRMED",
  );
  assert.throws(
    () => activationStateSha256({ ...created, activationId: "0".repeat(64) }),
    hasStateCode("STATE_MISMATCH"),
  );
  assert.throws(
    () => activationStateSha256({ ...created, jobId: "8" }),
    hasStateCode("STATE_MISMATCH"),
  );
  assert.throws(
    () =>
      activationStateSha256({
        ...created,
        receipts: [
          {
            ...created.receipts[0]!,
            events: [
              ...created.receipts[0]!.events,
              {
                name: "JobFunded" as const,
                jobId: created.jobId!,
                client: created.binding.client,
                provider: created.binding.provider,
                amount: "0",
              },
            ],
          },
        ],
      }),
    hasStateCode("EVENT_MISMATCH"),
  );

  const registerPrepared = await prepareNextActivationStep({
    state: created,
    deployment: activationDeployment({
      blockNumber: "103",
      blockTimestamp: ACTIVATION_NOW + 15,
    }),
    job: activationJob(created, "CREATE_CONFIRMED"),
  });
  const registered = reconcilePrepared(
    registerPrepared,
    activationDeployment({ blockNumber: "104", blockTimestamp: ACTIVATION_NOW + 20 }),
    "b",
    "REGISTER_CONFIRMED",
  );
  assert.throws(
    () =>
      activationStateSha256({
        ...registered,
        receipts: [
          registered.receipts[0]!,
          {
            ...registered.receipts[1]!,
            transactionHash: registered.receipts[0]!.transactionHash,
          },
        ],
      }),
    hasStateCode("STATE_MISMATCH"),
  );
  assert.throws(
    () =>
      activationStateSha256({
        ...registered,
        receipts: [
          registered.receipts[0]!,
          {
            ...registered.receipts[1]!,
            blockNumber: "101",
          },
        ],
      }),
    hasStateCode("STATE_MISMATCH"),
  );
});

test("both Commerce and Router pause observations fail closed", async () => {
  for (const paused of [
    { commercePaused: true },
    { routerPaused: true },
  ]) {
    await assert.rejects(
      preparedCreateState({ deployment: { ...activationDeployment(), ...paused } }),
      hasStateCode("DEPLOYMENT_MISMATCH"),
    );
  }
});

test("broadcast uncertainty is narrow, blocks advancement, and can only recover with a hash", async () => {
  const prepared = await preparedCreateState();
  const unknown = markActivationBroadcastUnknown({ state: prepared });
  assert.equal(unknown.condition, "broadcast_unknown");
  assert.equal(unknown.errorCode, "BROADCAST_UNKNOWN");
  assert.deepEqual(unknown.cleanup.requiredActions, []);
  await assert.rejects(
    prepareNextActivationStep({
      state: unknown,
      deployment: activationDeployment(),
      job: activationJob(unknown, "CREATE_CONFIRMED"),
    }),
    hasStateCode("STATE_MISMATCH"),
  );

  const recovered = recordActivationSubmission({
    state: unknown,
    transactionHash: `0x${"c".repeat(64)}`,
  });
  assert.equal(recovered.condition, "reconcile_required");
  assert.equal(recovered.errorCode, undefined);
});

test("preview timestamps are strict Unix-second observations", () => {
  const preview = activationPreview();
  assert.throws(() =>
    activationPreviewSchema.parse({
      ...preview,
      observedAt: new Date((preview.blockTimestamp + 1) * 1_000).toISOString(),
    }),
  );
});

function reconcilePrepared(
  state: Awaited<ReturnType<typeof preparedCreateState>>,
  deployment: ReturnType<typeof activationDeployment>,
  transactionDigit: string,
  confirmedPhase:
    | "CREATE_CONFIRMED"
    | "REGISTER_CONFIRMED"
    | "BUDGET_CONFIRMED"
    | "FUNDED_CONFIRMED",
) {
  const receipt = activationReceipt(state, deployment, transactionDigit);
  const submitted = recordActivationSubmission({
    state,
    transactionHash: receipt.transactionHash,
  });
  return reconcileActivationStep({
    state: submitted,
    receipt,
    job: activationJob(submitted, confirmedPhase),
    deployment,
  });
}

function hasStateCode(
  code: ActivationStateError["code"],
): (error: unknown) => boolean {
  return (error) => error instanceof ActivationStateError && error.code === code;
}
