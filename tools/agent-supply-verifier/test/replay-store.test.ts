import assert from "node:assert/strict";
import {
  chmod,
  link,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  buildActivationReplayMetadata,
  computeActivationHeadSha256,
  FileReplayStore,
  ReplayStoreError,
  type ActivationReplayMetadata,
  type ReplayMetadata,
} from "../src/quotes/replay.js";
import { computeQuoteReplayKey } from "../src/quotes/protocol.js";
import type { ActivationHead } from "../src/activation/schema.js";

const RAW_SECRET = "0xfeed-actionable-provider-signature";
const KEY = computeQuoteReplayKey(metadata());

test("concurrent replay claims have exactly one winner and persist", async () => {
  const directory = await secureTempDirectory();
  try {
    const first = new FileReplayStore(directory);
    const second = new FileReplayStore(directory);
    await Promise.all([first.prepare(), second.prepare()]);

    const results = await Promise.all([
      first.claim(KEY, metadata()),
      second.claim(KEY, metadata()),
    ]);
    assert.deepEqual([...results].sort(), ["claimed", "duplicate"]);

    const reopened = new FileReplayStore(directory);
    await reopened.prepare();
    assert.equal(
      await reopened.claim(
        KEY,
        metadata("2026-08-16T20:00:01.000Z"),
      ),
      "duplicate",
    );

    const files = await readdir(directory);
    assert.deepEqual(files, [`${KEY}.json`]);
    const marker = await readFile(join(directory, files[0]!), "utf8");
    assert.doesNotMatch(marker, /"(?:task_description|provider_sig|mandate)"/i);
    assert.equal(marker.includes(RAW_SECRET), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a truncated temporary marker is cleaned without publishing a partial final marker", async () => {
  const directory = await secureTempDirectory();
  const crash = new Error("simulated crash before publication");
  try {
    const store = new FileReplayStore(directory, {
      hooks: {
        async afterStage(stage, context) {
          if (stage !== "temp_verified") return;
          await writeFile(context.temporaryPath, "{\"partial\":", {
            encoding: "utf8",
          });
          throw crash;
        },
      },
    });
    await store.prepare();
    await assert.rejects(store.claim(KEY, metadata()), crash);
    assert.deepEqual(await readdir(directory), []);

    const reopened = new FileReplayStore(directory);
    await reopened.prepare();
    assert.equal(await reopened.claim(KEY, metadata()), "claimed");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an interrupted hard-link publication is recovered to one canonical marker", async () => {
  const directory = await secureTempDirectory();
  try {
    const temporaryPath = join(
      directory,
      `.quote-replay-${KEY}-${"ab".repeat(32)}.tmp`,
    );
    const markerPath = join(directory, `${KEY}.json`);
    await writeFile(temporaryPath, `${JSON.stringify(metadata())}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await link(temporaryPath, markerPath);
    assert.equal((await stat(markerPath)).nlink, 2);

    const store = new FileReplayStore(directory);
    await store.prepare();
    assert.equal(await store.claim(KEY, metadata()), "duplicate");
    assert.deepEqual(await readdir(directory), [`${KEY}.json`]);
    assert.equal((await stat(markerPath)).nlink, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activation replay exact retry returns verified winner metadata", async () => {
  const directory = await secureTempDirectory();
  try {
    const head = activationHead();
    const firstMetadata = activationMetadata(
      "2026-08-16T20:00:00.000Z",
      head,
    );
    const store = new FileReplayStore(directory);
    await store.prepare();
    assert.equal(await store.inspectActivation(KEY), undefined);
    assert.deepEqual(await store.claimActivation(KEY, firstMetadata), {
      status: "created",
      metadata: firstMetadata,
    });
    assert.deepEqual(await store.inspectActivation(KEY), firstMetadata);

    const retry = activationMetadata(
      "2026-08-16T20:00:05.000Z",
      head,
    );
    assert.deepEqual(await store.claimActivation(KEY, retry), {
      status: "existing_exact",
      metadata: firstMetadata,
    });
    assert.equal(
      computeActivationHeadSha256(head),
      firstMetadata.activationHeadSha256,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activation replay conflict returns only the verified existing v2 winner", async () => {
  const directory = await secureTempDirectory();
  try {
    const firstMetadata = activationMetadata(
      "2026-08-16T20:00:00.000Z",
      activationHead(),
    );
    const conflicting = activationMetadata(
      "2026-08-16T20:00:01.000Z",
      activationHead({
        stateSha256: "44".repeat(32),
        reportSha256: "55".repeat(32),
      }),
    );
    const store = new FileReplayStore(directory);
    await store.prepare();
    assert.equal(
      (await store.claimActivation(KEY, firstMetadata)).status,
      "created",
    );
    assert.deepEqual(await store.claimActivation(KEY, conflicting), {
      status: "existing_conflict",
      metadata: firstMetadata,
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("legacy and activation replay markers fail closed across schema versions", async () => {
  const legacyDirectory = await secureTempDirectory();
  const activationDirectory = await secureTempDirectory();
  try {
    const legacy = new FileReplayStore(legacyDirectory);
    await legacy.prepare();
    assert.equal(await legacy.claim(KEY, metadata()), "claimed");
    await assert.rejects(
      legacy.inspectActivation(KEY),
      replayWriteFailure,
    );
    await assert.rejects(
      legacy.claimActivation(KEY, activationMetadata()),
      replayWriteFailure,
    );

    const activation = new FileReplayStore(activationDirectory);
    await activation.prepare();
    assert.equal(
      (await activation.claimActivation(KEY, activationMetadata())).status,
      "created",
    );
    await assert.rejects(activation.claim(KEY, metadata()), replayWriteFailure);
  } finally {
    await rm(legacyDirectory, { recursive: true, force: true });
    await rm(activationDirectory, { recursive: true, force: true });
  }
});

test("concurrent activation replay claims have exactly one created result", async () => {
  const directory = await secureTempDirectory();
  try {
    const first = new FileReplayStore(directory);
    const second = new FileReplayStore(directory);
    await Promise.all([first.prepare(), second.prepare()]);
    const requested = activationMetadata();
    const results = await Promise.all([
      first.claimActivation(KEY, requested),
      second.claimActivation(KEY, requested),
    ]);
    assert.deepEqual(
      results.map((result) => result.status).sort(),
      ["created", "existing_exact"],
    );
    assert.deepEqual(results[0]!.metadata, requested);
    assert.deepEqual(results[1]!.metadata, requested);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activation replay metadata is strict and binds the canonical head hash", async () => {
  const directory = await secureTempDirectory();
  try {
    const store = new FileReplayStore(directory);
    await store.prepare();
    const valid = activationMetadata();
    await assert.rejects(
      store.claimActivation(KEY, {
        ...valid,
        activationHeadSha256: "00".repeat(32),
      }),
      replayWriteFailure,
    );
    await assert.rejects(
      store.claimActivation(KEY, {
        ...valid,
        unexpected: true,
      } as ActivationReplayMetadata),
      replayWriteFailure,
    );
    assert.deepEqual(await readdir(directory), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("existing replay markers must match the filename and requested domain", async () => {
  const directory = await secureTempDirectory();
  try {
    const tampered = { ...metadata(), tokenId: "265376" };
    await writeFile(
      join(directory, `${KEY}.json`),
      `${JSON.stringify(tampered)}\n`,
      { mode: 0o600 },
    );
    const store = new FileReplayStore(directory);
    await store.prepare();
    await assert.rejects(
      store.claim(KEY, metadata()),
      (error: unknown) =>
        error instanceof ReplayStoreError && error.code === "STATE_WRITE_FAILED",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("unexplained replay marker hard links are rejected", async () => {
  const directory = await secureTempDirectory();
  try {
    const store = new FileReplayStore(directory);
    await store.prepare();
    assert.equal(await store.claim(KEY, metadata()), "claimed");
    await link(
      join(directory, `${KEY}.json`),
      join(directory, "unexpected-hard-link.json"),
    );
    await assert.rejects(store.claim(KEY, metadata()), replayWriteFailure);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("replay store rejects relative, symlinked, and broadly readable state", async () => {
  assert.throws(
    () => new FileReplayStore("relative-state"),
    (error: unknown) =>
      error instanceof ReplayStoreError && error.code === "INVALID_STATE_PATH",
  );

  const directory = await secureTempDirectory();
  const link = `${directory}-link`;
  try {
    await symlink(directory, link);
    await assert.rejects(
      new FileReplayStore(link).prepare(),
      (error: unknown) =>
        error instanceof ReplayStoreError &&
        error.code === "UNSAFE_STATE_DIRECTORY",
    );

    await chmod(directory, 0o755);
    await assert.rejects(
      new FileReplayStore(directory).prepare(),
      (error: unknown) =>
        error instanceof ReplayStoreError &&
        error.code === "UNSAFE_STATE_DIRECTORY",
    );
  } finally {
    await rm(link, { force: true });
    await rm(directory, { recursive: true, force: true });
  }
});

test("claim fails closed when prepare was not completed", async () => {
  const directory = await secureTempDirectory();
  try {
    const store = new FileReplayStore(directory);
    await assert.rejects(
      store.claim(KEY, metadata()),
      (error: unknown) =>
        error instanceof ReplayStoreError && error.code === "STATE_WRITE_FAILED",
    );
    await assert.rejects(
      store.inspectActivation(KEY),
      replayWriteFailure,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

async function secureTempDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "mandatex-quote-replay-"));
  await chmod(directory, 0o700);
  return realpath(directory);
}

function metadata(
  claimedAt = "2026-08-16T20:00:00.000Z",
): ReplayMetadata {
  return {
    schema: "mandatex.agent-supply.quote-replay.v1",
    claimedAt,
    chainId: 56,
    tokenId: "265375",
    endpointHash: "cd".repeat(32),
    provider: "0x20f1ca5d1e5a3ee94c29dbf95e6bf6cea6a8d64b",
    commerceContract: "0xea4daa3100a767e86fded867729ae7446476eba6",
    negotiationHash: `0x${"ef".repeat(32)}`,
  };
}

function activationMetadata(
  claimedAt = "2026-08-16T20:00:00.000Z",
  head = activationHead(),
): ActivationReplayMetadata {
  return buildActivationReplayMetadata(metadata(claimedAt), head);
}

function activationHead(
  overrides: Partial<ActivationHead> = {},
): ActivationHead {
  const activationId = overrides.activationId ?? "11".repeat(32);
  const sequence = overrides.sequence ?? 0;
  const stateSha256 = overrides.stateSha256 ?? "22".repeat(32);
  const reportSha256 = overrides.reportSha256 ?? "33".repeat(32);
  return {
    schema: "mandatex.erc8183.activation-head.v1",
    activationId,
    sequence,
    stateSha256,
    stateFile: `state-v1-${activationId}-${sequence}-${stateSha256}.json`,
    reportSha256,
    reportFile: `report-v1-${activationId}-${sequence}-${reportSha256}.json`,
    updatedAt: "2026-08-16T20:00:00.000Z",
    ...overrides,
  };
}

function replayWriteFailure(error: unknown): boolean {
  return error instanceof ReplayStoreError && error.code === "STATE_WRITE_FAILED";
}
