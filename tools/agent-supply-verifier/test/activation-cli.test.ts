import assert from "node:assert/strict";
import test from "node:test";

import { runActivationCli } from "../src/activation-cli.js";
import {
  activationStateSha256,
  buildActivationReport,
  reconcileActivationStep,
  recordActivationSubmission,
} from "../src/activation/state.js";
import type { ActivationState } from "../src/activation/schema.js";
import type { PersistedActivationSnapshot } from "../src/activation/store.js";
import {
  ACTIVATION_NOW,
  activationDeployment,
  activationJob,
  activationReceipt,
  preparedCreateState,
} from "./activation-fixture.js";

const STATE_PATH = "/private/tmp/mandatex-activation-state.json";
const STATE_DIRECTORY = "/private/tmp/mandatex-activation-state";
const REPORT_DIRECTORY = "/private/tmp/mandatex-activation-report";

test("activation acknowledgements are checked before files or network", async () => {
  for (const argv of [
    ["prepare-create"],
    [
      "prepare-next",
      "--state",
      STATE_PATH,
      "--activation-state-dir",
      STATE_DIRECTORY,
      "--report-dir",
      REPORT_DIRECTORY,
    ],
    [
      "reconcile",
      "--state",
      STATE_PATH,
      "--activation-state-dir",
      STATE_DIRECTORY,
      "--report-dir",
      REPORT_DIRECTORY,
    ],
    [
      "broadcast-unknown",
      "--state",
      STATE_PATH,
      "--activation-state-dir",
      STATE_DIRECTORY,
      "--report-dir",
      REPORT_DIRECTORY,
    ],
  ]) {
    let fileReads = 0;
    let rpcFactories = 0;
    const code = await runActivationCli(argv, {
      stdout: sink(),
      stderr: sink(),
      async readState() {
        fileReads += 1;
        throw new Error("must not read");
      },
      activationRpcFactory() {
        rpcFactories += 1;
        throw new Error("must not create RPC");
      },
    });
    assert.equal(code, 1, argv[0]);
    assert.equal(fileReads, 0, argv[0]);
    assert.equal(rpcFactories, 0, argv[0]);
  }
});

test("prepare-next observes deployment and current job at one canonical block", async () => {
  const created = await createdState();
  const deployment = activationDeployment({
    blockNumber: "103",
    blockHash: `0x${"d".repeat(64)}`,
    blockTimestamp: ACTIVATION_NOW + 15,
  });
  let observedJobBlock: string | undefined;
  let persisted: ActivationState | undefined;
  const code = await runActivationCli(
    [
      "prepare-next",
      "--state",
      STATE_PATH,
      "--activation-state-dir",
      STATE_DIRECTORY,
      "--report-dir",
      REPORT_DIRECTORY,
      "--ack-funding-repreview",
    ],
    {
      stdout: sink(),
      stderr: sink(),
      async readState() {
        return created;
      },
      async readCurrent() {
        return persistedSnapshot(created);
      },
      activationRpcFactory() {
        return {
          async observeDeployment() {
            return deployment;
          },
          async observeJob(_jobId, blockHash) {
            observedJobBlock = blockHash;
            return activationJob(created, "CREATE_CONFIRMED");
          },
          async observeReceipt() {
            throw new Error("prepare-next must not read a receipt");
          },
        };
      },
      async persist(input) {
        persisted = input.state;
        return persistedSnapshot(input.state);
      },
    },
  );
  assert.equal(code, 0);
  assert.equal(observedJobBlock, deployment.blockHash);
  assert.equal(persisted?.phase, "PREPARED_REGISTER");
});

test("reconcile writes the external transaction hash before any receipt read", async () => {
  const prepared = await preparedCreateState();
  const transactionHash = `0x${"e".repeat(64)}`;
  const writes: ActivationState[] = [];
  let reconciliationCalls = 0;
  const code = await runActivationCli(
    [
      "reconcile",
      "--state",
      STATE_PATH,
      "--transaction-hash",
      transactionHash,
      "--activation-state-dir",
      STATE_DIRECTORY,
      "--report-dir",
      REPORT_DIRECTORY,
      "--ack-external-transaction-hash",
      "--ack-cli-never-signs-or-broadcasts",
    ],
    {
      stdout: sink(),
      stderr: sink(),
      async readState() {
        return prepared;
      },
      async readCurrent() {
        return persistedSnapshot(prepared);
      },
      async persist(input) {
        writes.push(input.state);
        return persistedSnapshot(input.state);
      },
      async reconcile(input) {
        reconciliationCalls += 1;
        assert.equal(writes.length, 1);
        assert.equal(input.state.condition, "reconcile_required");
        assert.equal(input.state.submission?.transactionHash, transactionHash);
        throw new Error("RPC temporarily unavailable");
      },
    },
  );
  assert.equal(code, 1);
  assert.equal(reconciliationCalls, 1);
  assert.equal(writes.length, 1);
});

test("activation CLI accepts no receipt or job observation JSON and has no generic mark", async () => {
  let reads = 0;
  const dependencies = {
    stdout: sink(),
    stderr: sink(),
    async readState() {
      reads += 1;
      return preparedCreateState();
    },
  };
  const receiptCode = await runActivationCli(
    [
      "reconcile",
      "--state",
      STATE_PATH,
      "--receipt",
      "/private/tmp/receipt.json",
      "--activation-state-dir",
      STATE_DIRECTORY,
      "--report-dir",
      REPORT_DIRECTORY,
      "--ack-external-transaction-hash",
      "--ack-cli-never-signs-or-broadcasts",
    ],
    dependencies,
  );
  const markCode = await runActivationCli(["mark"], dependencies);
  assert.equal(receiptCode, 1);
  assert.equal(markCode, 1);
  assert.equal(reads, 0);
});

test("commands reject a stale state file before persistence or RPC", async () => {
  const stale = await preparedCreateState();
  const current = recordActivationSubmission({
    state: stale,
    transactionHash: `0x${"f".repeat(64)}`,
  });
  let persists = 0;
  let rpcFactories = 0;
  const code = await runActivationCli(
    [
      "broadcast-unknown",
      "--state",
      STATE_PATH,
      "--activation-state-dir",
      STATE_DIRECTORY,
      "--report-dir",
      REPORT_DIRECTORY,
      "--ack-broadcast-attempt-had-no-transaction-hash",
    ],
    {
      stdout: sink(),
      stderr: sink(),
      async readState() {
        return stale;
      },
      async readCurrent() {
        return persistedSnapshot(current);
      },
      async persist(input) {
        persists += 1;
        return persistedSnapshot(input.state);
      },
      activationRpcFactory() {
        rpcFactories += 1;
        throw new Error("stale state must stop before RPC");
      },
    },
  );
  assert.equal(code, 1);
  assert.equal(persists, 0);
  assert.equal(rpcFactories, 0);
});

async function createdState(): Promise<ActivationState> {
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
  return reconcileActivationStep({
    state: submitted,
    receipt,
    job: activationJob(submitted, "CREATE_CONFIRMED"),
    deployment,
  });
}

function persistedSnapshot(state: ActivationState): PersistedActivationSnapshot {
  return {
    state,
    report: buildActivationReport(state),
    stateSha256: activationStateSha256(state),
    reportSha256: "0".repeat(64),
    statePath: STATE_PATH,
    reportPath: "/private/tmp/mandatex-activation-report.json",
  };
}

function sink(): { write(chunk: string): number } {
  return { write: (chunk) => chunk.length };
}
