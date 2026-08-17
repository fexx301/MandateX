import assert from "node:assert/strict";
import test from "node:test";

import { BSC_ACTIVATION_DEPLOYMENT } from "../src/activation/deployment.js";
import {
  ActivationStateError,
  buildActivationReport,
  prepareNextActivationStep,
  reconcileActivationStep,
  recordActivationSubmission,
  serializeActivationReport,
} from "../src/activation/state.js";
import {
  ACTIVATION_JOB_ID,
  ACTIVATION_NOW,
  activationDeployment,
  activationJob,
  activationPreview,
  activationReceipt,
  preparedCreateState,
} from "./activation-fixture.js";

test("activation advances one captured intent through the zero-budget lifecycle", async () => {
  let state = await preparedCreateState();
  assert.equal(state.phase, "PREPARED_CREATE");
  assert.equal(state.intent?.operation, "create_job");
  assert.equal(state.condition, "ready");

  state = reconcilePrepared(
    state,
    activationDeployment({
      blockNumber: "102",
      blockHash: `0x${"c".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 10,
    }),
    "c",
    "CREATE_CONFIRMED",
  );
  assert.equal(state.phase, "CREATE_CONFIRMED");
  assert.equal(state.jobId, ACTIVATION_JOB_ID);
  assert.equal(state.intent, undefined);

  state = await prepareNextActivationStep({
    state,
    deployment: activationDeployment({
      blockNumber: "103",
      blockHash: `0x${"d".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 15,
    }),
    job: activationJob(state, "CREATE_CONFIRMED"),
  });
  assert.equal(state.phase, "PREPARED_REGISTER");
  assert.equal(state.intent?.operation, "register_job");
  state = reconcilePrepared(
    state,
    activationDeployment({
      blockNumber: "104",
      blockHash: `0x${"e".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 20,
    }),
    "d",
    "REGISTER_CONFIRMED",
  );

  state = await prepareNextActivationStep({
    state,
    deployment: activationDeployment({
      blockNumber: "105",
      blockHash: `0x${"1".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 25,
    }),
    job: activationJob(state, "REGISTER_CONFIRMED"),
  });
  assert.equal(state.phase, "PREPARED_SET_BUDGET");
  assert.equal(state.intent?.operation, "set_budget");
  state = reconcilePrepared(
    state,
    activationDeployment({
      blockNumber: "106",
      blockHash: `0x${"2".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 30,
    }),
    "e",
    "BUDGET_CONFIRMED",
  );

  const fundingPreview = activationPreview({
    blockNumber: "107",
    blockHash: `0x${"3".repeat(64)}`,
    blockTimestamp: ACTIVATION_NOW + 35,
    validUntil: ACTIVATION_NOW + 400,
  });
  state = await prepareNextActivationStep({
    state,
    deployment: activationDeployment({
      blockNumber: "108",
      blockHash: `0x${"4".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 40,
    }),
    job: activationJob(state, "BUDGET_CONFIRMED"),
    fundingPreview,
  });
  assert.equal(state.phase, "PREPARED_FUND");
  assert.equal(state.intent?.operation, "fund");
  assert.deepEqual(state.fundingPreview, fundingPreview);
  state = reconcilePrepared(
    state,
    activationDeployment({
      blockNumber: "109",
      blockHash: `0x${"5".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 45,
    }),
    "f",
    "FUNDED_CONFIRMED",
  );

  assert.equal(state.phase, "FUNDED_CONFIRMED");
  assert.equal(state.condition, "ready");
  assert.equal(state.receipts.length, 4);
  assert.deepEqual(state.cleanup.requiredActions, ["claimRefund", "markExpired"]);
  const serialized = serializeActivationReport(buildActivationReport(state));
  assert.doesNotMatch(serialized, /jobDescription|signedTask|transactionPlan|provider_sig|0x1234/);
});

test("phase-specific job state rejects premature policy and budget flags", async () => {
  const prepared = await preparedCreateState();
  const deployment = activationDeployment({
    blockNumber: "102",
    blockHash: `0x${"c".repeat(64)}`,
    blockTimestamp: ACTIVATION_NOW + 10,
  });
  const receipt = activationReceipt(prepared, deployment, "c");
  const submitted = recordActivationSubmission({
    state: prepared,
    transactionHash: receipt.transactionHash,
  });
  const wrongPolicy = {
    ...activationJob(submitted, "CREATE_CONFIRMED"),
    policy: BSC_ACTIVATION_DEPLOYMENT.policy,
  };
  assert.throws(
    () =>
      reconcileActivationStep({
        state: submitted,
        receipt,
        job: wrongPolicy,
        deployment,
      }),
    hasStateCode("JOB_STATE_MISMATCH"),
  );

  const created = reconcileActivationStep({
    state: submitted,
    receipt,
    job: activationJob(submitted, "CREATE_CONFIRMED"),
    deployment,
  });
  const registerPrepared = await prepareNextActivationStep({
    state: created,
    deployment: activationDeployment({
      blockNumber: "103",
      blockHash: `0x${"d".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 15,
    }),
    job: activationJob(created, "CREATE_CONFIRMED"),
  });
  const registerDeployment = activationDeployment({
    blockNumber: "104",
    blockHash: `0x${"e".repeat(64)}`,
    blockTimestamp: ACTIVATION_NOW + 20,
  });
  const registerReceipt = activationReceipt(registerPrepared, registerDeployment, "d");
  const registerSubmitted = recordActivationSubmission({
    state: registerPrepared,
    transactionHash: registerReceipt.transactionHash,
  });
  assert.throws(
    () =>
      reconcileActivationStep({
        state: registerSubmitted,
        receipt: registerReceipt,
        job: {
          ...activationJob(registerSubmitted, "REGISTER_CONFIRMED"),
          hasBudget: true,
        },
        deployment: registerDeployment,
      }),
    hasStateCode("JOB_STATE_MISMATCH"),
  );
});

test("funding requires a fresh preview and the mined block must remain within it", async () => {
  let state = await preparedCreateState();
  state = reconcilePrepared(
    state,
    activationDeployment({
      blockNumber: "102",
      blockHash: `0x${"c".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 10,
    }),
    "c",
    "CREATE_CONFIRMED",
  );
  state = await prepareNextActivationStep({
    state,
    deployment: activationDeployment({ blockNumber: "103", blockTimestamp: ACTIVATION_NOW + 15 }),
    job: activationJob(state, "CREATE_CONFIRMED"),
  });
  state = reconcilePrepared(
    state,
    activationDeployment({
      blockNumber: "104",
      blockHash: `0x${"d".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 20,
    }),
    "d",
    "REGISTER_CONFIRMED",
  );
  state = await prepareNextActivationStep({
    state,
    deployment: activationDeployment({ blockNumber: "105", blockTimestamp: ACTIVATION_NOW + 25 }),
    job: activationJob(state, "REGISTER_CONFIRMED"),
  });
  state = reconcilePrepared(
    state,
    activationDeployment({
      blockNumber: "106",
      blockHash: `0x${"e".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 30,
    }),
    "e",
    "BUDGET_CONFIRMED",
  );

  await assert.rejects(
    prepareNextActivationStep({
      state,
      deployment: activationDeployment({
        blockNumber: "108",
        blockTimestamp: ACTIVATION_NOW + 40,
      }),
      job: activationJob(state, "BUDGET_CONFIRMED"),
    }),
    hasStateCode("PREVIEW_REQUIRED"),
  );

  const preview = activationPreview({
    blockNumber: "107",
    blockTimestamp: ACTIVATION_NOW + 35,
    validUntil: ACTIVATION_NOW + 150,
  });
  state = await prepareNextActivationStep({
    state,
    deployment: activationDeployment({
      blockNumber: "108",
      blockTimestamp: ACTIVATION_NOW + 40,
    }),
    job: activationJob(state, "BUDGET_CONFIRMED"),
    fundingPreview: preview,
  });
  const lateDeployment = activationDeployment({
    blockNumber: "109",
    blockHash: `0x${"f".repeat(64)}`,
    blockTimestamp: ACTIVATION_NOW + 151,
  });
  const lateReceipt = activationReceipt(state, lateDeployment, "f");
  const submitted = recordActivationSubmission({
    state,
    transactionHash: lateReceipt.transactionHash,
  });
  assert.throws(
    () =>
      reconcileActivationStep({
        state: submitted,
        receipt: lateReceipt,
        job: activationJob(submitted, "FUNDED_CONFIRMED"),
        deployment: lateDeployment,
      }),
    hasStateCode("TRANSACTION_MISMATCH"),
  );
});

test("create preparation applies the full phase lifetime to preview validity", async () => {
  await assert.rejects(
    preparedCreateState({
      preview: activationPreview({ validUntil: ACTIVATION_NOW + 200 }),
      deployment: activationDeployment({ blockTimestamp: ACTIVATION_NOW + 5 }),
    }),
    hasStateCode("QUOTE_EXPIRED"),
  );
});

test("submission journaling is idempotent for one hash and rejects a replacement", async () => {
  const prepared = await preparedCreateState();
  const hash = `0x${"a".repeat(64)}`;
  const submitted = recordActivationSubmission({ state: prepared, transactionHash: hash });
  assert.equal(submitted.condition, "reconcile_required");
  assert.equal(submitted.submission?.transactionHash, hash);
  assert.deepEqual(
    recordActivationSubmission({ state: submitted, transactionHash: hash }),
    submitted,
  );
  assert.throws(
    () =>
      recordActivationSubmission({
        state: submitted,
        transactionHash: `0x${"b".repeat(64)}`,
      }),
    hasStateCode("TRANSACTION_MISMATCH"),
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
