import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";

import { buildJobDescription } from "@bnbagent/sdk/erc8183";

import {
  activationBindingSchema,
  activationHeadSchema,
  activationPreviewSchema,
  activationStateSchema,
  type ActivationDeploymentObservation,
  type ActivationState,
} from "../src/activation/schema.js";
import {
  activationHeadFilePath,
  bootstrapActivationSnapshot,
  readCurrentActivationSnapshot,
} from "../src/activation/store.js";
import {
  activationStateSha256,
  prepareCreateActivation,
} from "../src/activation/state.js";
import {
  canonicalQuoteJson,
  computeQuoteReplayKey,
  computeQuoteSha256,
} from "../src/quotes/protocol.js";
import {
  FileReplayStore,
  computeActivationHeadSha256,
  type ActivationReplayMetadata,
  type ReplayMetadata,
} from "../src/quotes/replay.js";
import { rebalanceTransactionPlanSchema } from "../src/preview/schema.js";
import {
  ACTIVATION_NOW,
  activationDeployment,
  activationPreview,
  preparedCreateState as basePreparedCreateState,
} from "./activation-fixture.js";

test("bootstrap crash stages are recoverable in replay order", async () => {
  const beforeClaim = await bootstrapFixture();
  try {
    await assert.rejects(
      runBootstrap(beforeClaim, {
        hooks: crashAt("artifacts_verified"),
      }),
      /injected crash/,
    );
    assert.equal(
      (await readdir(beforeClaim.stateDirectory)).some((name) =>
        name.startsWith("state-v1-"),
      ),
      true,
    );
    await assert.rejects(readFile(beforeClaim.markerPath), hasNodeCode("ENOENT"));
    await assert.rejects(
      readFile(
        activationHeadFilePath(
          beforeClaim.stateDirectory,
          beforeClaim.state.activationId,
        ),
      ),
      hasNodeCode("ENOENT"),
    );
    assert.equal((await runBootstrap(beforeClaim)).status, "created");
  } finally {
    await rm(beforeClaim.root, { recursive: true, force: true });
  }

  const afterClaim = await bootstrapFixture();
  try {
    await claimThenCrash(afterClaim);
    const marker = await readMarker(afterClaim.markerPath);
    await assert.rejects(
      readFile(
        activationHeadFilePath(
          afterClaim.stateDirectory,
          marker.activationHead.activationId,
        ),
      ),
      hasNodeCode("ENOENT"),
    );

    const reopened = new FileReplayStore(afterClaim.replayDirectory);
    await reopened.prepare();
    const recovered = await runBootstrap(afterClaim, { replayStore: reopened });
    assert.equal(recovered.status, "recovered");
    assert.equal(recovered.snapshot.stateSha256, marker.activationHead.stateSha256);
    assert.equal(basename(recovered.snapshot.statePath), marker.activationHead.stateFile);
    assert.equal(
      basename(recovered.snapshot.reportPath),
      marker.activationHead.reportFile,
    );
  } finally {
    await rm(afterClaim.root, { recursive: true, force: true });
  }

  const afterHead = await bootstrapFixture();
  try {
    await assert.rejects(
      runBootstrap(afterHead, { hooks: crashAt("head_replaced") }),
      /injected crash/,
    );
    const marker = await readMarker(afterHead.markerPath);
    const headPath = activationHeadFilePath(
      afterHead.stateDirectory,
      marker.activationHead.activationId,
    );
    assert.equal(
      await readFile(headPath, "utf8"),
      `${canonicalQuoteJson(marker.activationHead)}\n`,
    );
    const reopened = new FileReplayStore(afterHead.replayDirectory);
    await reopened.prepare();
    assert.equal(
      (await runBootstrap(afterHead, { replayStore: reopened })).status,
      "recovered",
    );
  } finally {
    await rm(afterHead.root, { recursive: true, force: true });
  }
});

test("bootstrap accepts only invocation-dependent recovery differences", async () => {
  const fixture = await bootstrapFixture();
  try {
    await claimThenCrash(fixture);
    const preview = activationPreview({
      blockNumber: "101",
      blockHash: `0x${"c".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 5,
      validUntil: ACTIVATION_NOW + 650,
    });
    const candidate = await rebuildState(fixture.state, {
      preview,
      deployment: activationDeployment({
        blockNumber: "102",
        blockHash: `0x${"d".repeat(64)}`,
        blockTimestamp: ACTIVATION_NOW + 10,
      }),
      now: new Date((ACTIVATION_NOW + 5) * 1_000),
    });
    const reopened = new FileReplayStore(fixture.replayDirectory);
    await reopened.prepare();
    const recovered = await runBootstrap(fixture, {
      state: candidate,
      deployment: activationDeployment({
        blockNumber: "102",
        blockHash: `0x${"d".repeat(64)}`,
        blockTimestamp: ACTIVATION_NOW + 10,
      }),
      replayStore: reopened,
    });
    assert.equal(recovered.status, "recovered");
    assert.equal(
      recovered.snapshot.stateSha256,
      activationStateSha256(fixture.state),
    );
    assert.notEqual(candidate.activationId, fixture.state.activationId);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("missing or tampered marker-bound artifacts fail closed", async () => {
  for (const attack of [
    "missing_state",
    "tampered_state",
    "missing_report",
    "tampered_report",
  ] as const) {
    const fixture = await bootstrapFixture();
    try {
      await claimThenCrash(fixture);
      const marker = await readMarker(fixture.markerPath);
      if (attack === "missing_state") {
        await rm(join(fixture.stateDirectory, marker.activationHead.stateFile));
      } else if (attack === "tampered_state") {
        const statePath = join(
          fixture.stateDirectory,
          marker.activationHead.stateFile,
        );
        await writeFile(statePath, "{}\n", { mode: 0o600 });
        await chmod(statePath, 0o600);
      } else if (attack === "missing_report") {
        await rm(join(fixture.reportDirectory, marker.activationHead.reportFile));
      } else {
        const reportPath = join(
          fixture.reportDirectory,
          marker.activationHead.reportFile,
        );
        await writeFile(reportPath, "{}\n", { mode: 0o600 });
        await chmod(reportPath, 0o600);
      }
      const reopened = new FileReplayStore(fixture.replayDirectory);
      await reopened.prepare();
      await assert.rejects(runBootstrap(fixture, { replayStore: reopened }));
      const retried = new FileReplayStore(fixture.replayDirectory);
      await retried.prepare();
      await assert.rejects(runBootstrap(fixture, { replayStore: retried }));
      await assert.rejects(
        readFile(
          activationHeadFilePath(
            fixture.stateDirectory,
            marker.activationHead.activationId,
          ),
        ),
        hasNodeCode("ENOENT"),
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("altered marker hashes, filenames, and digests fail closed", async () => {
  for (const attack of ["head_hash", "filename", "digest"] as const) {
    const fixture = await bootstrapFixture();
    try {
      await claimThenCrash(fixture);
      const marker = await readMarker(fixture.markerPath);
      let altered: ActivationReplayMetadata;
      if (attack === "head_hash") {
        altered = { ...marker, activationHeadSha256: "0".repeat(64) };
      } else if (attack === "filename") {
        const activationHead = activationHeadSchema.parse({
          ...marker.activationHead,
          stateFile: `state-v1-${marker.activationHead.activationId}-0-${"0".repeat(64)}.json`,
        });
        altered = {
          ...marker,
          activationHead,
          activationHeadSha256: createHash("sha256")
            .update(canonicalQuoteJson(activationHead), "utf8")
            .digest("hex"),
        };
      } else {
        const stateSha256 = "0".repeat(64);
        const activationHead = activationHeadSchema.parse({
          ...marker.activationHead,
          stateSha256,
          stateFile: `state-v1-${marker.activationHead.activationId}-0-${stateSha256}.json`,
        });
        altered = {
          ...marker,
          activationHead,
          activationHeadSha256: computeActivationHeadSha256(activationHead),
        };
      }
      await writeFile(
        fixture.markerPath,
        `${canonicalQuoteJson(altered)}\n`,
        { mode: 0o600 },
      );
      await chmod(fixture.markerPath, 0o600);
      const reopened = new FileReplayStore(fixture.replayDirectory);
      await reopened.prepare();
      await assert.rejects(runBootstrap(fixture, { replayStore: reopened }));
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("stable activation conflicts cannot resume another replay claim", async () => {
  const variants: ReadonlyArray<readonly [string, (state: ActivationState) => Promise<ActivationState>]> = [
    [
      "client",
      (state) =>
        rebuildState(state, {
          binding: { client: "0x8888888888888888888888888888888888888888" },
        }),
    ],
    [
      "provider",
      (state) =>
        rebuildState(state, {
          binding: { provider: "0x9999999999999999999999999999999999999999" },
        }),
    ],
    [
      "job_expiry",
      (state) =>
        rebuildState(state, {
          binding: { jobExpiresAt: state.binding.jobExpiresAt + 1 },
        }),
    ],
    [
      "cleanup_owner",
      (state) => rebuildState(state, { cleanupOwner: "external_client" }),
    ],
    [
      "transaction_plan",
      (state) =>
        rebuildState(state, {
          transactionPlan: rebalanceTransactionPlanSchema.parse({
            ...state.transactionPlan,
            data: "0x5678",
          }),
        }),
    ],
    [
      "mandate",
      (state) =>
        rebuildState(state, {
          signedTask: {
            ...state.signedTask,
            mandate: {
              ...state.signedTask.mandate,
              mandate_id: "activation-fixture-conflict",
            },
          },
        }),
    ],
  ];

  for (const [name, buildVariant] of variants) {
    const fixture = await bootstrapFixture();
    try {
      await claimThenCrash(fixture);
      const candidate = await buildVariant(fixture.state);
      const reopened = new FileReplayStore(fixture.replayDirectory);
      await reopened.prepare();
      await assert.rejects(
        runBootstrap(fixture, { state: candidate, replayStore: reopened }),
        (error) => error instanceof Error,
        name,
      );
      const marker = await readMarker(fixture.markerPath);
      await assert.rejects(
        readFile(
          activationHeadFilePath(
            fixture.stateDirectory,
            marker.activationHead.activationId,
          ),
        ),
        hasNodeCode("ENOENT"),
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("expired recovered quote or preview state consumes no second head", async () => {
  const fixture = await bootstrapFixture();
  try {
    await claimThenCrash(fixture);
    const deployment = activationDeployment({
      blockNumber: "151",
      blockHash: `0x${"e".repeat(64)}`,
      blockTimestamp: ACTIVATION_NOW + 500,
    });
    const candidate = await rebuildState(fixture.state, {
      preview: activationPreview({
        blockNumber: "150",
        blockHash: `0x${"f".repeat(64)}`,
        blockTimestamp: ACTIVATION_NOW + 490,
        validUntil: ACTIVATION_NOW + 750,
      }),
      deployment,
      now: new Date((ACTIVATION_NOW + 490) * 1_000),
    });
    const reopened = new FileReplayStore(fixture.replayDirectory);
    await reopened.prepare();
    await assert.rejects(
      runBootstrap(fixture, {
        state: candidate,
        deployment,
        replayStore: reopened,
      }),
    );
    assert.equal((await readFile(fixture.markerPath, "utf8")).length > 0, true);
    const marker = await readMarker(fixture.markerPath);
    await assert.rejects(
      readFile(
        activationHeadFilePath(
          fixture.stateDirectory,
          marker.activationHead.activationId,
        ),
      ),
      hasNodeCode("ENOENT"),
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }

  const expiredQuote = await bootstrapFixture();
  try {
    await claimThenCrash(expiredQuote);
    await assert.rejects(
      runBootstrap(expiredQuote, {
        deployment: activationDeployment({
          blockNumber: "161",
          blockHash: `0x${"1".repeat(64)}`,
          blockTimestamp: ACTIVATION_NOW + 650,
        }),
      }),
    );
    const marker = await readMarker(expiredQuote.markerPath);
    await assert.rejects(
      readFile(
        activationHeadFilePath(
          expiredQuote.stateDirectory,
          marker.activationHead.activationId,
        ),
      ),
      hasNodeCode("ENOENT"),
    );
  } finally {
    await rm(expiredQuote.root, { recursive: true, force: true });
  }
});

test("recovery rechecks fresh Commerce and Router deployment safety", async () => {
  for (const paused of ["commercePaused", "routerPaused"] as const) {
    const fixture = await bootstrapFixture();
    try {
      await claimThenCrash(fixture);
      const deployment: ActivationDeploymentObservation = {
        ...activationDeployment(),
        [paused]: true,
      };
      await assert.rejects(runBootstrap(fixture, { deployment }));
      const marker = await readMarker(fixture.markerPath);
      await assert.rejects(
        readFile(
          activationHeadFilePath(
            fixture.stateDirectory,
            marker.activationHead.activationId,
          ),
        ),
        hasNodeCode("ENOENT"),
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  }
});

test("legacy replay markers cannot bootstrap activation", async () => {
  const fixture = await bootstrapFixture();
  try {
    assert.equal(
      await fixture.replayStore.claim(fixture.replayKey, fixture.replayMetadata),
      "claimed",
    );
    await assert.rejects(runBootstrap(fixture));
    await assert.rejects(
      readFile(
        activationHeadFilePath(
          fixture.stateDirectory,
          fixture.state.activationId,
        ),
      ),
      hasNodeCode("ENOENT"),
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("concurrent different sequence-zero candidates authorize exactly one head", async () => {
  const fixture = await bootstrapFixture();
  try {
    const conflicting = await rebuildState(fixture.state, {
      binding: { client: "0x8888888888888888888888888888888888888888" },
    });
    const secondStore = new FileReplayStore(fixture.replayDirectory);
    await secondStore.prepare();
    const results = await Promise.allSettled([
      runBootstrap(fixture),
      runBootstrap(fixture, { state: conflicting, replayStore: secondStore }),
    ]);
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(results.filter((result) => result.status === "rejected").length, 1);

    const marker = await readMarker(fixture.markerPath);
    const heads = (await readdir(fixture.stateDirectory)).filter((name) =>
      name.startsWith("activation-head-v1-"),
    );
    assert.deepEqual(heads, [
      `activation-head-v1-${marker.activationHead.activationId}.json`,
    ]);
    const headRaw = await readFile(
      activationHeadFilePath(
        fixture.stateDirectory,
        marker.activationHead.activationId,
      ),
      "utf8",
    );
    assert.equal(headRaw, `${canonicalQuoteJson(marker.activationHead)}\n`);
    const current = await readCurrentActivationSnapshot({
      activationId: marker.activationHead.activationId,
      stateDirectory: fixture.stateDirectory,
      reportDirectory: fixture.reportDirectory,
    });
    assert.equal(current?.stateSha256, marker.activationHead.stateSha256);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

type BootstrapFixture = Awaited<ReturnType<typeof bootstrapFixture>>;

async function bootstrapFixture(): Promise<Readonly<{
  root: string;
  stateDirectory: string;
  reportDirectory: string;
  replayDirectory: string;
  state: ActivationState;
  deployment: ActivationDeploymentObservation;
  replayKey: string;
  replayMetadata: ReplayMetadata;
  markerPath: string;
  replayStore: FileReplayStore;
}>> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "mandatex-activation-bootstrap-")),
  );
  await chmod(root, 0o700);
  const stateDirectory = join(root, "state");
  const reportDirectory = join(root, "report");
  const replayDirectory = join(root, "replay");
  await Promise.all(
    [stateDirectory, reportDirectory, replayDirectory].map((path) =>
      mkdir(path, { mode: 0o700 }),
    ),
  );
  await Promise.all(
    [stateDirectory, reportDirectory, replayDirectory].map((path) =>
      chmod(path, 0o700),
    ),
  );
  const deployment = activationDeployment();
  const state = await replayBoundState(deployment);
  const replayMetadata = replayMetadataForState(state);
  const replayKey = state.binding.replayKey;
  const replayStore = new FileReplayStore(replayDirectory);
  await replayStore.prepare();
  return {
    root,
    stateDirectory,
    reportDirectory,
    replayDirectory,
    state,
    deployment,
    replayKey,
    replayMetadata,
    markerPath: join(replayDirectory, `${replayKey}.json`),
    replayStore,
  };
}

async function replayBoundState(
  deployment: ActivationDeploymentObservation,
): Promise<ActivationState> {
  const base = await basePreparedCreateState({ deployment });
  const replayMetadata = replayMetadataForState(base);
  const replayKey = computeQuoteReplayKey(replayMetadata);
  const binding = activationBindingSchema.parse({
    ...base.binding,
    replayKey,
  });
  return activationStateSchema.parse({
    ...base,
    binding,
    activationId: activationIdForBinding(binding),
  });
}

async function rebuildState(
  state: ActivationState,
  input: Readonly<{
    binding?: Partial<ActivationState["binding"]>;
    signedTask?: ActivationState["signedTask"];
    transactionPlan?: ActivationState["transactionPlan"];
    preview?: ActivationState["initialPreview"];
    deployment?: ActivationDeploymentObservation;
    cleanupOwner?: ActivationState["cleanup"]["owner"];
    now?: Date;
  }>,
): Promise<ActivationState> {
  const signedTask = input.signedTask ?? state.signedTask;
  const transactionPlan = input.transactionPlan ?? state.transactionPlan;
  const signedTaskSha256 = computeQuoteSha256(canonicalQuoteJson(signedTask));
  const transactionPlanSha256 = computeQuoteSha256(
    canonicalQuoteJson(transactionPlan),
  );
  const preview = activationPreviewSchema.parse({
    ...(input.preview ?? state.initialPreview),
    signedTaskSha256,
    transactionPlanSha256,
  });
  const preliminaryBinding = {
    ...state.binding,
    ...input.binding,
    mandateSha256: computeQuoteSha256(
      canonicalQuoteJson(signedTask.mandate),
    ),
    signedTaskSha256,
    transactionPlanSha256,
    previewSidecarSha256: computeQuoteSha256(canonicalQuoteJson(preview)),
    initialPreviewSha256: computeQuoteSha256(canonicalQuoteJson(preview)),
    previewBlockNumber: preview.blockNumber,
    previewBlockHash: preview.blockHash,
  };
  const binding = activationBindingSchema.parse({
    ...preliminaryBinding,
    jobDescription:
      input.signedTask === undefined
        ? preliminaryBinding.jobDescription
        : jobDescriptionFor(signedTask, preliminaryBinding),
  });
  return prepareCreateActivation({
    binding,
    signedTask,
    transactionPlan,
    initialPreview: preview,
    deployment: input.deployment ?? activationDeployment(),
    cleanupOwner: input.cleanupOwner ?? state.cleanup.owner,
    now: input.now ?? new Date(state.createdAt),
  });
}

function jobDescriptionFor(
  signedTask: ActivationState["signedTask"],
  binding: ActivationState["binding"],
): string {
  const taskDescription = `mandatex-rebalance:v1:${deflateRawSync(
    Buffer.from(canonicalQuoteJson(signedTask), "utf8"),
  ).toString("base64url")}`;
  return buildJobDescription({
    request: {
      task_description: taskDescription,
      terms: {
        deliverables: "rebalance position",
        quality_standards: "match the signed mandate",
        evaluation_required: true,
        evaluator_type: "router",
      },
    },
    response: {
      accepted: true,
      terms: {
        deliverables: "rebalance position",
        quality_standards: "match the signed mandate",
        evaluation_required: true,
        evaluator_type: "router",
        price: "0",
        currency: binding.currency,
      },
      estimated_completion_seconds: 300,
      quote_expires_at: binding.quoteExpiresAt,
      negotiated_at: binding.negotiatedAt,
    },
    negotiation_hash: binding.negotiationHash,
    provider_sig: "0x11",
    chain_id: binding.chainId,
    verifying_contract: binding.commerceProxy,
  });
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

function activationIdForBinding(binding: ActivationState["binding"]): string {
  return computeQuoteSha256(
    canonicalQuoteJson({
      schema: "mandatex.erc8183.activation-id.v1",
      binding,
    }),
  );
}

async function runBootstrap(
  fixture: BootstrapFixture,
  overrides: Readonly<{
    state?: ActivationState;
    deployment?: ActivationDeploymentObservation;
    replayStore?: FileReplayStore;
    hooks?: Parameters<typeof bootstrapActivationSnapshot>[0]["hooks"];
  }> = {},
) {
  return bootstrapActivationSnapshot({
    state: overrides.state ?? fixture.state,
    deployment: overrides.deployment ?? fixture.deployment,
    replayKey: fixture.replayKey,
    replayMetadata: fixture.replayMetadata,
    replayStore: overrides.replayStore ?? fixture.replayStore,
    stateDirectory: fixture.stateDirectory,
    reportDirectory: fixture.reportDirectory,
    ...(overrides.hooks === undefined ? {} : { hooks: overrides.hooks }),
  });
}

async function claimThenCrash(fixture: BootstrapFixture): Promise<void> {
  await assert.rejects(
    runBootstrap(fixture, { hooks: crashAt("replay_claimed") }),
    /injected crash/,
  );
}

function crashAt(
  target: Parameters<
    NonNullable<
      NonNullable<Parameters<typeof bootstrapActivationSnapshot>[0]["hooks"]>["afterStage"]
    >
  >[0],
) {
  return {
    afterStage(stage: typeof target) {
      if (stage === target) throw new Error("injected crash");
    },
  };
}

async function readMarker(path: string): Promise<ActivationReplayMetadata> {
  return JSON.parse(await readFile(path, "utf8")) as ActivationReplayMetadata;
}

function hasNodeCode(code: string): (error: unknown) => boolean {
  return (error) =>
    error instanceof Error && "code" in error && error.code === code;
}
