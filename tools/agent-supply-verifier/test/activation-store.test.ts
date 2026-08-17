import assert from "node:assert/strict";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";

import {
  activationBindingSchema,
  activationHeadSchema,
  activationStateSchema,
  type ActivationDeploymentObservation,
  type ActivationState,
} from "../src/activation/schema.js";
import {
  ActivationStoreError,
  activationHeadFilePath,
  activationLockFilePath,
  bootstrapActivationSnapshot,
  persistActivationSnapshot,
  readActivationState,
  readCurrentActivationSnapshot,
} from "../src/activation/store.js";
import {
  activationStateSha256,
  markActivationBroadcastUnknown,
  prepareNextActivationStep,
  recordActivationReconciliation,
  reconcileActivationStep,
  recordActivationSubmission,
} from "../src/activation/state.js";
import {
  canonicalQuoteJson,
  computeQuoteReplayKey,
  computeQuoteSha256,
} from "../src/quotes/protocol.js";
import type {
  ActivationReplayMetadata,
  ActivationReplayStore,
  ReplayMetadata,
} from "../src/quotes/replay.js";
import {
  ACTIVATION_NOW,
  activationDeployment,
  activationJob,
  activationPreview,
  activationReceipt,
  preparedCreateState as basePreparedCreateState,
} from "./activation-fixture.js";

test("activation persistence installs one canonical private head and is idempotent", async () => {
  const fixture = await activationDirectories();
  try {
    const state = await preparedCreateState();
    await assert.rejects(
      persistActivationSnapshot({ state, ...fixture }),
      hasStoreCode("COMPARE_AND_SWAP_FAILED"),
    );
    const persisted = await bootstrapInitial(state, fixture);
    const headPath = activationHeadFilePath(
      fixture.stateDirectory,
      state.activationId,
    );
    const headRaw = await readFile(headPath, "utf8");
    const head = activationHeadSchema.parse(JSON.parse(headRaw) as unknown);

    assert.equal(headRaw, `${canonicalQuoteJson(head)}\n`);
    assert.equal(head.stateSha256, persisted.stateSha256);
    assert.equal(head.reportSha256, persisted.reportSha256);
    assert.equal(head.stateFile, basename(persisted.statePath));
    assert.equal(head.reportFile, basename(persisted.reportPath));

    for (const path of [
      headPath,
      persisted.statePath,
      persisted.reportPath,
    ]) {
      assert.equal(Number((await lstat(path, { bigint: true })).mode & 0o777n), 0o600);
    }
    assert.equal(
      Number((await lstat(fixture.stateDirectory, { bigint: true })).mode & 0o777n),
      0o700,
    );
    assert.equal(
      Number((await lstat(fixture.reportDirectory, { bigint: true })).mode & 0o777n),
      0o700,
    );

    const current = await readCurrentActivationSnapshot({
      activationId: state.activationId,
      ...fixture,
    });
    assert.equal(current?.stateSha256, persisted.stateSha256);
    assert.deepEqual(await readActivationState(persisted.statePath), state);

    const retried = await bootstrapInitial(state, fixture);
    assert.equal(retried.stateSha256, persisted.stateSha256);
    assert.equal(
      (await readdir(fixture.stateDirectory)).some((name) =>
        name.startsWith(".activation-lock-v1-"),
      ),
      false,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("concurrent sibling generations have exactly one CAS winner", async () => {
  const fixture = await activationDirectories();
  try {
    const parent = await preparedCreateState();
    await bootstrapInitial(parent, fixture);
    const first = markActivationBroadcastUnknown({
      state: parent,
      now: new Date(Date.parse(parent.updatedAt) + 1_000),
    });
    const second = markActivationBroadcastUnknown({
      state: parent,
      now: new Date(Date.parse(parent.updatedAt) + 2_000),
    });

    const results = await Promise.allSettled([
      persistActivationSnapshot({ state: first, ...fixture }),
      persistActivationSnapshot({ state: second, ...fixture }),
    ]);
    const winners = results.filter(
      (result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof persistActivationSnapshot>>> =>
        result.status === "fulfilled",
    );
    const losers = results.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );
    assert.equal(winners.length, 1);
    assert.equal(losers.length, 1);
    assert.equal(hasStoreCode("COMPARE_AND_SWAP_FAILED")(losers[0]!.reason), true);

    const current = await readCurrentActivationSnapshot({
      activationId: parent.activationId,
      ...fixture,
    });
    assert.equal(current?.stateSha256, winners[0]!.value.stateSha256);
    assert.equal(
      (await readdir(fixture.stateDirectory)).some((name) =>
        name.startsWith(".activation-lock-v1-"),
      ),
      false,
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("persistence rejects stale parents and a canonical head that names missing artifacts", async () => {
  const fixture = await activationDirectories();
  try {
    const parent = await preparedCreateState();
    const persisted = await bootstrapInitial(parent, fixture);
    const child = markActivationBroadcastUnknown({
      state: parent,
      now: new Date(Date.parse(parent.updatedAt) + 1_000),
    });
    const wrongParent = activationStateSchema.parse({
      ...child,
      parentStateSha256: "0".repeat(64),
    });
    await assert.rejects(
      persistActivationSnapshot({ state: wrongParent, ...fixture }),
      hasStoreCode("COMPARE_AND_SWAP_FAILED"),
    );

    const headPath = activationHeadFilePath(
      fixture.stateDirectory,
      parent.activationId,
    );
    const head = activationHeadSchema.parse(
      JSON.parse(await readFile(headPath, "utf8")) as unknown,
    );
    const missingReport = activationHeadSchema.parse({
      ...head,
      reportSha256: "0".repeat(64),
      reportFile: `report-v1-${parent.activationId}-${parent.sequence}-${"0".repeat(64)}.json`,
    });
    await writeFile(headPath, `${canonicalQuoteJson(missingReport)}\n`, {
      mode: 0o600,
    });
    await chmod(headPath, 0o600);
    await assert.rejects(
      readCurrentActivationSnapshot({
        activationId: parent.activationId,
        ...fixture,
      }),
    );
    assert.notEqual((await readFile(persisted.reportPath, "utf8")).length, 0);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("a correctly linked child cannot rewrite immutable activation creation data", async () => {
  const fixture = await activationDirectories();
  try {
    const parent = await preparedCreateState();
    await bootstrapInitial(parent, fixture);
    const child = markActivationBroadcastUnknown({
      state: parent,
      now: new Date(Date.parse(parent.updatedAt) + 2_000),
    });
    const forged = activationStateSchema.parse({
      ...child,
      createdAt: new Date(Date.parse(parent.createdAt) + 1_000).toISOString(),
    });
    assert.equal(forged.parentStateSha256, activationStateSha256(parent));
    await assert.rejects(
      persistActivationSnapshot({ state: forged, ...fixture }),
      hasStoreCode("INVALID_TRANSITION"),
    );
    assert.equal(
      (await readCurrentActivationSnapshot({
        activationId: parent.activationId,
        ...fixture,
      }))?.stateSha256,
      activationStateSha256(parent),
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("the CAS transition policy accepts the complete zero-budget lifecycle", async () => {
  const fixture = await activationDirectories();
  try {
    let state = await preparedCreateState();
    await bootstrapInitial(state, fixture);
    state = await submitConfirmAndPersist(
      state,
      activationDeployment({
        blockNumber: "102",
        blockHash: `0x${"c".repeat(64)}`,
        blockTimestamp: ACTIVATION_NOW + 10,
      }),
      "c",
      "CREATE_CONFIRMED",
      fixture,
    );

    state = await prepareNextActivationStep({
      state,
      deployment: activationDeployment({
        blockNumber: "103",
        blockTimestamp: ACTIVATION_NOW + 15,
      }),
      job: activationJob(state, "CREATE_CONFIRMED"),
      now: new Date((ACTIVATION_NOW + 15) * 1_000),
    });
    await persistActivationSnapshot({ state, ...fixture });
    state = await submitConfirmAndPersist(
      state,
      activationDeployment({
        blockNumber: "104",
        blockHash: `0x${"d".repeat(64)}`,
        blockTimestamp: ACTIVATION_NOW + 20,
      }),
      "d",
      "REGISTER_CONFIRMED",
      fixture,
    );

    state = await prepareNextActivationStep({
      state,
      deployment: activationDeployment({
        blockNumber: "105",
        blockTimestamp: ACTIVATION_NOW + 25,
      }),
      job: activationJob(state, "REGISTER_CONFIRMED"),
      now: new Date((ACTIVATION_NOW + 25) * 1_000),
    });
    await persistActivationSnapshot({ state, ...fixture });
    state = await submitConfirmAndPersist(
      state,
      activationDeployment({
        blockNumber: "106",
        blockHash: `0x${"e".repeat(64)}`,
        blockTimestamp: ACTIVATION_NOW + 30,
      }),
      "e",
      "BUDGET_CONFIRMED",
      fixture,
    );

    state = await prepareNextActivationStep({
      state,
      deployment: activationDeployment({
        blockNumber: "108",
        blockTimestamp: ACTIVATION_NOW + 40,
      }),
      job: activationJob(state, "BUDGET_CONFIRMED"),
      fundingPreview: activationPreview({
        blockNumber: "107",
        blockTimestamp: ACTIVATION_NOW + 35,
        validUntil: ACTIVATION_NOW + 400,
      }),
      now: new Date((ACTIVATION_NOW + 40) * 1_000),
    });
    await persistActivationSnapshot({ state, ...fixture });
    state = await submitConfirmAndPersist(
      state,
      activationDeployment({
        blockNumber: "109",
        blockHash: `0x${"f".repeat(64)}`,
        blockTimestamp: ACTIVATION_NOW + 45,
      }),
      "f",
      "FUNDED_CONFIRMED",
      fixture,
    );

    const current = await readCurrentActivationSnapshot({
      activationId: state.activationId,
      ...fixture,
    });
    assert.equal(current?.state.phase, "FUNDED_CONFIRMED");
    assert.equal(current?.state.receipts.length, 4);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("the CAS transition policy preserves unresolved and reverted reconciliation evidence", async () => {
  const fixture = await activationDirectories();
  try {
    const initial = await preparedCreateState();
    await bootstrapInitial(initial, fixture);
    const deployment = activationDeployment({
      blockNumber: "102",
      blockHash: `0x${"c".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 10,
    });
    const receipt = activationReceipt(initial, deployment, "c");
    const submitted = recordActivationSubmission({
      state: initial,
      transactionHash: receipt.transactionHash,
      now: new Date((ACTIVATION_NOW + 1) * 1_000),
    });
    await persistActivationSnapshot({ state: submitted, ...fixture });

    const pending = recordActivationReconciliation({
      state: submitted,
      observation: {
        kind: "pending",
        transactionHash: receipt.transactionHash,
        observedAt: new Date((ACTIVATION_NOW + 2) * 1_000).toISOString(),
      },
    });
    await persistActivationSnapshot({ state: pending, ...fixture });

    const reverted = recordActivationReconciliation({
      state: pending,
      observation: {
        kind: "reverted",
        transactionHash: receipt.transactionHash,
        observedAt: new Date(deployment.blockTimestamp * 1_000).toISOString(),
        blockNumber: deployment.blockNumber,
        blockHash: deployment.blockHash,
        confirmationDepth: deployment.confirmationDepth,
      },
      deployment,
    });
    await persistActivationSnapshot({ state: reverted, ...fixture });
    const current = await readCurrentActivationSnapshot({
      activationId: reverted.activationId,
      ...fixture,
    });
    assert.equal(current?.state.condition, "aborted");
    assert.equal(current?.state.reconciliation?.kind, "reverted");
    assert.equal(current?.state.errorCode, "RECEIPT_REVERTED");
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("head reload rejects broad permissions, hard links, and symbolic links", async () => {
  const fixture = await activationDirectories();
  try {
    const state = await preparedCreateState();
    const persisted = await bootstrapInitial(state, fixture);
    const headPath = activationHeadFilePath(
      fixture.stateDirectory,
      state.activationId,
    );

    await chmod(headPath, 0o644);
    await assert.rejects(
      readCurrentActivationSnapshot({ activationId: state.activationId, ...fixture }),
    );
    await chmod(headPath, 0o600);

    await chmod(fixture.reportDirectory, 0o755);
    await assert.rejects(
      readCurrentActivationSnapshot({ activationId: state.activationId, ...fixture }),
    );
    await chmod(fixture.reportDirectory, 0o700);

    const hardLink = join(fixture.stateDirectory, "state-hard-link.json");
    await link(persisted.statePath, hardLink);
    await assert.rejects(
      readCurrentActivationSnapshot({ activationId: state.activationId, ...fixture }),
    );
    await rm(hardLink);

    const reportBackup = join(fixture.reportDirectory, "report-backup.json");
    await writeFile(
      reportBackup,
      await readFile(persisted.reportPath, "utf8"),
      { mode: 0o600 },
    );
    await rm(persisted.reportPath);
    await symlink(reportBackup, persisted.reportPath);
    await assert.rejects(
      readCurrentActivationSnapshot({ activationId: state.activationId, ...fixture }),
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("a symbolic or hard-linked lock path cannot acquire journal authority", async () => {
  for (const attack of ["symbolic", "hard"] as const) {
    const fixture = await activationDirectories();
    try {
      const state = await preparedCreateState();
      const target = join(fixture.stateDirectory, `attacker-${attack}`);
      await writeFile(target, "attacker\n", { mode: 0o600 });
      const lockPath = activationLockFilePath(
        fixture.stateDirectory,
        state.activationId,
      );
      if (attack === "symbolic") {
        await symlink(target, lockPath);
      } else {
        await link(target, lockPath);
      }
      await assert.rejects(
        bootstrapInitial(state, fixture),
        hasStoreCode("LOCK_INTEGRITY_FAILED"),
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("a canonical lock left by a dead process is recovered before CAS", async () => {
  const fixture = await activationDirectories();
  try {
    const state = await preparedCreateState();
    const lockPath = activationLockFilePath(
      fixture.stateDirectory,
      state.activationId,
    );
    const staleLock = {
      schema: "mandatex.erc8183.activation-lock.v1",
      activationId: state.activationId,
      pid: 2_147_483_647,
      nonce: "a".repeat(64),
      createdAt: "2026-08-17T00:00:00.000Z",
    };
    await writeFile(lockPath, `${canonicalQuoteJson(staleLock)}\n`, {
      mode: 0o600,
    });
    await chmod(lockPath, 0o600);

    const persisted = await bootstrapInitial(state, fixture);
    assert.equal(persisted.stateSha256, activationStateSha256(state));
    await assert.rejects(lstat(lockPath), hasNodeCode("ENOENT"));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("interruptions before and after head replacement remain recoverable", async () => {
  const before = await activationDirectories();
  try {
    const state = await preparedCreateState();
    await assert.rejects(
      bootstrapInitial(state, before, {
        hooks: {
          afterStage(stage) {
            if (stage === "artifacts_verified") throw new Error("injected crash");
          },
        },
      }),
      /injected crash/,
    );
    await assert.rejects(
      lstat(activationHeadFilePath(before.stateDirectory, state.activationId)),
      hasNodeCode("ENOENT"),
    );
    assert.equal(
      (await readdir(before.stateDirectory)).some((name) => name.startsWith("state-v1-")),
      true,
    );
    await bootstrapInitial(state, before);
    assert.equal(
      (await readCurrentActivationSnapshot({ activationId: state.activationId, ...before }))
        ?.stateSha256,
      activationStateSha256(state),
    );
  } finally {
    await rm(before.root, { recursive: true, force: true });
  }

  const after = await activationDirectories();
  try {
    const parent = await preparedCreateState();
    await bootstrapInitial(parent, after);
    const child = markActivationBroadcastUnknown({
      state: parent,
      now: new Date(Date.parse(parent.updatedAt) + 1_000),
    });
    await assert.rejects(
      persistActivationSnapshot({
        state: child,
        ...after,
        hooks: {
          afterStage(stage) {
            if (stage === "head_replaced") throw new Error("injected crash");
          },
        },
      }),
      /injected crash/,
    );
    assert.equal(
      (await readCurrentActivationSnapshot({ activationId: child.activationId, ...after }))
        ?.stateSha256,
      activationStateSha256(child),
    );
    assert.equal(
      (await persistActivationSnapshot({ state: child, ...after })).stateSha256,
      activationStateSha256(child),
    );
  } finally {
    await rm(after.root, { recursive: true, force: true });
  }
});

async function activationDirectories(): Promise<Readonly<{
  root: string;
  stateDirectory: string;
  reportDirectory: string;
  replayStore: MemoryActivationReplayStore;
}>> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "mandatex-activation-store-")),
  );
  await chmod(root, 0o700);
  const stateDirectory = join(root, "state");
  const reportDirectory = join(root, "report");
  await Promise.all([
    mkdir(stateDirectory, { mode: 0o700 }),
    mkdir(reportDirectory, { mode: 0o700 }),
  ]);
  await Promise.all([
    chmod(stateDirectory, 0o700),
    chmod(reportDirectory, 0o700),
  ]);
  const replayStore = new MemoryActivationReplayStore();
  await replayStore.prepare();
  return { root, stateDirectory, reportDirectory, replayStore };
}

async function preparedCreateState(input: Readonly<{
  preview?: ReturnType<typeof activationPreview>;
  deployment?: ActivationDeploymentObservation;
}> = {}): Promise<ActivationState> {
  const base = await basePreparedCreateState(input);
  const replayMetadata = replayMetadataForState(base);
  const replayKey = computeQuoteReplayKey(replayMetadata);
  const binding = activationBindingSchema.parse({
    ...base.binding,
    replayKey,
  });
  return activationStateSchema.parse({
    ...base,
    binding,
    activationId: computeQuoteSha256(
      canonicalQuoteJson({
        schema: "mandatex.erc8183.activation-id.v1",
        binding,
      }),
    ),
  });
}

async function bootstrapInitial(
  state: ActivationState,
  fixture: Readonly<{
    stateDirectory: string;
    reportDirectory: string;
    replayStore: ActivationReplayStore;
  }>,
  options: Readonly<{
    deployment?: ActivationDeploymentObservation;
    hooks?: Parameters<typeof bootstrapActivationSnapshot>[0]["hooks"];
  }> = {},
) {
  const result = await bootstrapActivationSnapshot({
    state,
    deployment: options.deployment ?? activationDeployment(),
    replayKey: state.binding.replayKey,
    replayMetadata: replayMetadataForState(state),
    replayStore: fixture.replayStore,
    stateDirectory: fixture.stateDirectory,
    reportDirectory: fixture.reportDirectory,
    ...(options.hooks === undefined ? {} : { hooks: options.hooks }),
  });
  return result.snapshot;
}

function replayMetadataForState(state: ActivationState): ReplayMetadata {
  return {
    schema: "mandatex.agent-supply.quote-replay.v1",
    claimedAt: state.createdAt,
    chainId: state.binding.chainId,
    tokenId: state.binding.tokenId,
    endpointHash: "7".repeat(64),
    provider: state.binding.provider,
    commerceContract: state.binding.commerceProxy,
    negotiationHash: state.binding.negotiationHash,
  };
}

class MemoryActivationReplayStore implements ActivationReplayStore {
  readonly #markers = new Map<string, ActivationReplayMetadata>();
  #prepared = false;

  async prepare(): Promise<void> {
    this.#prepared = true;
  }

  async inspectActivation(
    key: string,
  ): Promise<ActivationReplayMetadata | undefined> {
    if (!this.#prepared) throw new Error("replay store was not prepared");
    return this.#markers.get(key);
  }

  async claimActivation(
    key: string,
    metadata: ActivationReplayMetadata,
  ): Promise<Readonly<{
    status: "created" | "existing_exact" | "existing_conflict";
    metadata: ActivationReplayMetadata;
  }>> {
    if (!this.#prepared) throw new Error("replay store was not prepared");
    const existing = this.#markers.get(key);
    if (existing === undefined) {
      this.#markers.set(key, metadata);
      return { status: "created", metadata };
    }
    const exact =
      existing.activationHeadSha256 === metadata.activationHeadSha256 &&
      canonicalQuoteJson(existing.activationHead) ===
        canonicalQuoteJson(metadata.activationHead);
    return {
      status: exact ? "existing_exact" : "existing_conflict",
      metadata: existing,
    };
  }
}

async function submitConfirmAndPersist(
  state: Awaited<ReturnType<typeof preparedCreateState>>,
  deployment: ReturnType<typeof activationDeployment>,
  transactionDigit: string,
  confirmedPhase:
    | "CREATE_CONFIRMED"
    | "REGISTER_CONFIRMED"
    | "BUDGET_CONFIRMED"
    | "FUNDED_CONFIRMED",
  fixture: Readonly<{ stateDirectory: string; reportDirectory: string }>,
) {
  const receipt = activationReceipt(state, deployment, transactionDigit);
  const submitted = recordActivationSubmission({
    state,
    transactionHash: receipt.transactionHash,
    now: new Date((deployment.blockTimestamp - 1) * 1_000),
  });
  await persistActivationSnapshot({ state: submitted, ...fixture });
  const confirmed = reconcileActivationStep({
    state: submitted,
    receipt,
    job: activationJob(submitted, confirmedPhase),
    deployment,
    now: new Date(deployment.blockTimestamp * 1_000),
  });
  await persistActivationSnapshot({ state: confirmed, ...fixture });
  return confirmed;
}

function hasStoreCode(
  code: ActivationStoreError["code"],
): (error: unknown) => boolean {
  return (error) => error instanceof ActivationStoreError && error.code === code;
}

function hasNodeCode(code: string): (error: unknown) => boolean {
  return (error) =>
    error instanceof Error && "code" in error && error.code === code;
}
