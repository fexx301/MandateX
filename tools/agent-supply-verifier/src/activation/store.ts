import { createHash, randomBytes } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  type FileHandle,
  lstat,
  open,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import {
  canonicalQuoteJson,
  computeQuoteReplayKey,
} from "../quotes/protocol.js";
import {
  ACTIVATION_REPLAY_MARKER_SCHEMA,
  REPLAY_MARKER_SCHEMA,
  buildActivationReplayMetadata,
  computeActivationHeadSha256,
  type ActivationReplayMetadata,
  type ActivationReplayStore,
  type ReplayMetadata,
} from "../quotes/replay.js";
import {
  assertPrivateDirectory,
  readSecureTextFile,
  SecureFileError,
  writePrivateFileExclusive,
} from "../secure-files.js";
import {
  ACTIVATION_HEAD_SCHEMA,
  activationHeadSchema,
  activationReportSchema,
  activationStateSchema,
  type ActivationHead,
  type ActivationDeploymentObservation,
  type ActivationReport,
  type ActivationState,
} from "./schema.js";
import { ACTIVATION_PHASE_ORDER } from "./deployment.js";
import {
  activationStateSha256,
  assertRecoveredCreateActivation,
  buildActivationReport,
  serializeActivationReport,
  serializeActivationState,
} from "./state.js";

export const ACTIVATION_STATE_MAX_BYTES = 256 * 1024;
export const ACTIVATION_REPORT_MAX_BYTES = 32 * 1024;
export const ACTIVATION_HEAD_MAX_BYTES = 8 * 1024;
export const ACTIVATION_LOCK_MAX_BYTES = 2 * 1024;

const ACTIVATION_ID_PATTERN = /^[a-f0-9]{64}$/;
const LOCK_NONCE_PATTERN = /^[a-f0-9]{64}$/;
const ACTIVATION_LOCK_SCHEMA = "mandatex.erc8183.activation-lock.v1" as const;
const LOCK_WAIT_TIMEOUT_MS = 5_000;
const LOCK_RETRY_MS = 10;
const LOCK_INITIALIZATION_GRACE_MS = 1_000;

export class ActivationStoreError extends Error {
  constructor(
    readonly code:
      | "NON_CANONICAL_STATE"
      | "NON_CANONICAL_REPORT"
      | "NON_CANONICAL_HEAD"
      | "CONTENT_ADDRESS_MISMATCH"
      | "ARTIFACT_COLLISION"
      | "HEAD_INTEGRITY_FAILED"
      | "COMPARE_AND_SWAP_FAILED"
      | "INVALID_TRANSITION"
      | "LOCK_UNAVAILABLE"
      | "LOCK_INTEGRITY_FAILED",
    options?: ErrorOptions,
  ) {
    super("activation artifact persistence failed closed", options);
    this.name = "ActivationStoreError";
  }
}

export type PersistedActivationSnapshot = Readonly<{
  state: ActivationState;
  report: ActivationReport;
  stateSha256: string;
  reportSha256: string;
  statePath: string;
  reportPath: string;
}>;

export type ActivationPersistenceStage =
  | "artifacts_verified"
  | "head_replaced"
  | "head_verified";

export type ActivationBootstrapStage =
  | ActivationPersistenceStage
  | "replay_claimed";

/** Test-only crash injection. Production callers should omit this option. */
export type ActivationPersistenceHooks = Readonly<{
  afterStage?: (
    stage: ActivationPersistenceStage,
  ) => void | Promise<void>;
}>;

/** Test-only crash injection. Production callers should omit this option. */
export type ActivationBootstrapHooks = Readonly<{
  afterStage?: (
    stage: ActivationBootstrapStage,
  ) => void | Promise<void>;
}>;

export type BootstrapActivationSnapshotResult = Readonly<{
  status: "created" | "recovered";
  snapshot: PersistedActivationSnapshot;
}>;

/** The replay store must retain the identity established by its prior prepare(). */
export async function bootstrapActivationSnapshot(input: Readonly<{
  state: ActivationState;
  deployment: ActivationDeploymentObservation;
  replayKey: string;
  replayMetadata: ReplayMetadata;
  replayStore: ActivationReplayStore;
  stateDirectory: string;
  reportDirectory: string;
  hooks?: ActivationBootstrapHooks;
}>): Promise<BootstrapActivationSnapshotResult> {
  const state = assertRecoveredCreateActivation({
    state: input.state,
    deployment: input.deployment,
  });
  const prepared = prepareSnapshot(
    state,
    input.stateDirectory,
    input.reportDirectory,
  );
  const candidateHead = buildActivationHead(prepared);
  const candidateMetadata = buildActivationReplayMetadata(
    input.replayMetadata,
    candidateHead,
  );
  assertReplayBinding(state, input.replayKey, candidateMetadata);

  const directories = await captureDirectories(
    input.stateDirectory,
    input.reportDirectory,
  );
  const inspected = await input.replayStore.inspectActivation(input.replayKey);
  let status: BootstrapActivationSnapshotResult["status"];
  let winnerMetadata: ActivationReplayMetadata;
  if (inspected !== undefined) {
    winnerMetadata = normalizeActivationReplayMetadata(inspected);
    assertReplayDomain(winnerMetadata, candidateMetadata, input.replayKey);
    status = "recovered";
  } else {
    await stagePreparedSnapshot(prepared, directories);
    await input.hooks?.afterStage?.("artifacts_verified");
    await verifyStagedSnapshot(prepared, directories);

    const claim = await input.replayStore.claimActivation(
      input.replayKey,
      candidateMetadata,
    );
    winnerMetadata = normalizeClaimedActivationMetadata({
      claim,
      replayKey: input.replayKey,
      expectedDomain: candidateMetadata,
      candidateMetadata,
    });
    status = claim.status === "created" ? "created" : "recovered";
  }
  await input.hooks?.afterStage?.("replay_claimed");

  const recovered = await readMarkerBoundSnapshot({
    metadata: winnerMetadata,
    stateDirectory: input.stateDirectory,
    reportDirectory: input.reportDirectory,
    directories,
  });
  assertReplayBinding(recovered.state, input.replayKey, winnerMetadata);
  assertBootstrapSemantics(state, recovered.state);
  assertRecoveredCreateActivation({
    state: recovered.state,
    deployment: input.deployment,
  });

  const lock = await acquireActivationLock(
    activationLockFilePath(
      input.stateDirectory,
      winnerMetadata.activationHead.activationId,
    ),
    winnerMetadata.activationHead.activationId,
    directories.state,
  );
  let operationError: unknown;
  try {
    const snapshot = await installReplayAuthorizedHead({
      candidateState: state,
      deployment: input.deployment,
      replayKey: input.replayKey,
      replayStore: input.replayStore,
      winnerMetadata,
      stateDirectory: input.stateDirectory,
      reportDirectory: input.reportDirectory,
      directories,
      lock,
      ...(input.hooks === undefined ? {} : { hooks: input.hooks }),
    });
    return {
      status,
      snapshot,
    };
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      await releaseActivationLock(lock, directories.state);
    } catch (releaseError) {
      if (operationError !== undefined) {
        throw new AggregateError(
          [operationError, releaseError],
          "activation bootstrap and lock release both failed",
        );
      }
      throw releaseError;
    }
  }
}

export async function persistActivationSnapshot(input: Readonly<{
  state: ActivationState;
  stateDirectory: string;
  reportDirectory: string;
  hooks?: ActivationPersistenceHooks;
}>): Promise<PersistedActivationSnapshot> {
  const prepared = prepareSnapshot(
    input.state,
    input.stateDirectory,
    input.reportDirectory,
  );
  if (prepared.state.sequence === 0) {
    throw new ActivationStoreError("COMPARE_AND_SWAP_FAILED");
  }
  const directories = await captureDirectories(
    input.stateDirectory,
    input.reportDirectory,
  );
  const lock = await acquireActivationLock(
    activationLockFilePath(input.stateDirectory, prepared.state.activationId),
    prepared.state.activationId,
    directories.state,
  );

  let operationError: unknown;
  try {
    return await commitSnapshot({
      prepared,
      stateDirectory: input.stateDirectory,
      reportDirectory: input.reportDirectory,
      directories,
      lock,
      ...(input.hooks === undefined ? {} : { hooks: input.hooks }),
    });
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try {
      await releaseActivationLock(lock, directories.state);
    } catch (releaseError) {
      if (operationError !== undefined) {
        throw new AggregateError(
          [operationError, releaseError],
          "activation persistence and lock release both failed",
        );
      }
      throw releaseError;
    }
  }
}

/**
 * Loads the authoritative journal head and verifies both immutable artifacts.
 * A missing head is returned as undefined; an invalid head always fails closed.
 */
export async function readCurrentActivationSnapshot(input: Readonly<{
  activationId: string;
  stateDirectory: string;
  reportDirectory: string;
}>): Promise<PersistedActivationSnapshot | undefined> {
  assertActivationId(input.activationId);
  const directories = await captureDirectories(
    input.stateDirectory,
    input.reportDirectory,
  );
  const current = await readHeadRecord({
    activationId: input.activationId,
    stateDirectory: input.stateDirectory,
    reportDirectory: input.reportDirectory,
  });
  await Promise.all([
    assertDirectoryIdentity(input.stateDirectory, directories.state),
    assertDirectoryIdentity(input.reportDirectory, directories.report),
  ]);
  return current?.snapshot;
}

export async function readActivationState(path: string): Promise<ActivationState> {
  const raw = await readSecureTextFile(path, {
    maxBytes: ACTIVATION_STATE_MAX_BYTES,
    mode: "operator-private",
  });
  let state: ActivationState;
  try {
    state = activationStateSchema.parse(JSON.parse(raw) as unknown);
    if (serializeActivationState(state) !== raw) {
      throw new Error("state serialization is not canonical");
    }
  } catch (error) {
    throw new ActivationStoreError("NON_CANONICAL_STATE", { cause: error });
  }
  const digest = activationStateSha256(state);
  if (basename(path) !== stateFileName(state, digest)) {
    throw new ActivationStoreError("CONTENT_ADDRESS_MISMATCH");
  }
  return state;
}

export function activationHeadFilePath(
  stateDirectory: string,
  activationId: string,
): string {
  assertActivationId(activationId);
  return join(stateDirectory, `activation-head-v1-${activationId}.json`);
}

export function activationLockFilePath(
  stateDirectory: string,
  activationId: string,
): string {
  assertActivationId(activationId);
  return join(stateDirectory, `.activation-lock-v1-${activationId}`);
}

type DirectoryIdentity = Readonly<{ dev: bigint; ino: bigint }>;
type CapturedDirectories = Readonly<{
  state: DirectoryIdentity;
  report: DirectoryIdentity;
}>;
type PreparedSnapshot = PersistedActivationSnapshot;
type ActivationLock = Readonly<{
  path: string;
  handle: FileHandle;
  identity: DirectoryIdentity;
  serialized: string;
}>;
type ActivationLockMetadata = Readonly<{
  schema: typeof ACTIVATION_LOCK_SCHEMA;
  activationId: string;
  pid: number;
  nonce: string;
  createdAt: string;
}>;
type HeadRecord = Readonly<{
  head: ActivationHead;
  identity: DirectoryIdentity;
  snapshot: PersistedActivationSnapshot;
}>;

function buildActivationHead(prepared: PreparedSnapshot): ActivationHead {
  return activationHeadSchema.parse({
    schema: ACTIVATION_HEAD_SCHEMA,
    activationId: prepared.state.activationId,
    sequence: prepared.state.sequence,
    stateSha256: prepared.stateSha256,
    stateFile: basename(prepared.statePath),
    reportSha256: prepared.reportSha256,
    reportFile: basename(prepared.reportPath),
    updatedAt: prepared.state.updatedAt,
  });
}

function prepareSnapshot(
  stateInput: ActivationState,
  stateDirectory: string,
  reportDirectory: string,
): PreparedSnapshot {
  const state = activationStateSchema.parse(stateInput);
  const report = activationReportSchema.parse(buildActivationReport(state));
  const serializedState = serializeActivationState(state);
  const serializedReport = serializeActivationReport(report);
  assertArtifactSize(serializedState, ACTIVATION_STATE_MAX_BYTES);
  assertArtifactSize(serializedReport, ACTIVATION_REPORT_MAX_BYTES);

  const stateSha256 = activationStateSha256(state);
  const reportSha256 = sha256(serializedReport);
  return {
    state,
    report,
    stateSha256,
    reportSha256,
    statePath: join(stateDirectory, stateFileName(state, stateSha256)),
    reportPath: join(reportDirectory, reportFileName(state, reportSha256)),
  };
}

async function stagePreparedSnapshot(
  prepared: PreparedSnapshot,
  directories: CapturedDirectories,
): Promise<void> {
  await Promise.all([
    assertDirectoryIdentity(dirname(prepared.statePath), directories.state),
    assertDirectoryIdentity(dirname(prepared.reportPath), directories.report),
  ]);
  await Promise.all([
    writeCanonicalPrivateFile(
      prepared.statePath,
      serializeActivationState(prepared.state),
      ACTIVATION_STATE_MAX_BYTES,
    ),
    writeCanonicalPrivateFile(
      prepared.reportPath,
      serializeActivationReport(prepared.report),
      ACTIVATION_REPORT_MAX_BYTES,
    ),
  ]);
  await verifyStagedSnapshot(prepared, directories);
}

async function verifyStagedSnapshot(
  prepared: PreparedSnapshot,
  directories: CapturedDirectories,
): Promise<void> {
  await verifyPreparedSnapshot(prepared);
  await Promise.all([
    syncDirectory(dirname(prepared.statePath), directories.state),
    syncDirectory(dirname(prepared.reportPath), directories.report),
  ]);
  await verifyPreparedSnapshot(prepared);
}

function normalizeClaimedActivationMetadata(input: Readonly<{
  claim: Awaited<ReturnType<ActivationReplayStore["claimActivation"]>>;
  replayKey: string;
  expectedDomain: ActivationReplayMetadata;
  candidateMetadata: ActivationReplayMetadata;
}>): ActivationReplayMetadata {
  if (
    input.claim.status !== "created" &&
    input.claim.status !== "existing_exact" &&
    input.claim.status !== "existing_conflict"
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  const metadata = normalizeActivationReplayMetadata(input.claim.metadata);
  assertReplayDomain(metadata, input.expectedDomain, input.replayKey);
  if (
    input.claim.status === "created" &&
    !sameCanonical(metadata, input.candidateMetadata)
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  if (
    input.claim.status === "existing_exact" &&
    !sameActivationHeadBinding(metadata, input.candidateMetadata)
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  if (
    input.claim.status === "existing_conflict" &&
    sameActivationHeadBinding(metadata, input.candidateMetadata)
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  return metadata;
}

function sameActivationHeadBinding(
  left: ActivationReplayMetadata,
  right: ActivationReplayMetadata,
): boolean {
  return (
    left.activationHeadSha256 === right.activationHeadSha256 &&
    sameCanonical(left.activationHead, right.activationHead)
  );
}

function normalizeActivationReplayMetadata(
  metadataInput: ActivationReplayMetadata,
): ActivationReplayMetadata {
  if (metadataInput.schema !== ACTIVATION_REPLAY_MARKER_SCHEMA) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  const replay: ReplayMetadata = {
    schema: REPLAY_MARKER_SCHEMA,
    claimedAt: metadataInput.claimedAt,
    chainId: metadataInput.chainId,
    tokenId: metadataInput.tokenId,
    endpointHash: metadataInput.endpointHash,
    provider: metadataInput.provider,
    commerceContract: metadataInput.commerceContract,
    negotiationHash: metadataInput.negotiationHash,
  };
  let normalized: ActivationReplayMetadata;
  try {
    normalized = buildActivationReplayMetadata(
      replay,
      metadataInput.activationHead,
    );
  } catch (error) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED", { cause: error });
  }
  if (
    metadataInput.activationHeadSha256 !==
      computeActivationHeadSha256(normalized.activationHead) ||
    !sameCanonical(metadataInput, normalized)
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  return normalized;
}

function assertReplayDomain(
  actual: ActivationReplayMetadata,
  expected: ActivationReplayMetadata,
  replayKey: string,
): void {
  const actualKey = computeQuoteReplayKey({
    chainId: actual.chainId,
    tokenId: actual.tokenId,
    endpointHash: actual.endpointHash,
    provider: actual.provider,
    commerceContract: actual.commerceContract,
    negotiationHash: actual.negotiationHash,
  });
  if (
    actualKey !== replayKey ||
    actual.chainId !== expected.chainId ||
    actual.tokenId !== expected.tokenId ||
    actual.endpointHash !== expected.endpointHash ||
    actual.provider !== expected.provider ||
    actual.commerceContract !== expected.commerceContract ||
    actual.negotiationHash !== expected.negotiationHash
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
}

function assertReplayBinding(
  state: ActivationState,
  replayKey: string,
  metadata: ActivationReplayMetadata,
): void {
  if (
    state.binding.replayKey !== replayKey ||
    state.binding.chainId !== metadata.chainId ||
    state.binding.tokenId !== metadata.tokenId ||
    state.binding.provider !== metadata.provider ||
    state.binding.commerceProxy !== metadata.commerceContract ||
    state.binding.negotiationHash !== metadata.negotiationHash
  ) {
    throw new ActivationStoreError("INVALID_TRANSITION");
  }
}

function assertBootstrapSemantics(
  candidate: ActivationState,
  recovered: ActivationState,
): void {
  const stableBinding = (state: ActivationState) => ({
    chainId: state.binding.chainId,
    tokenId: state.binding.tokenId,
    client: state.binding.client,
    provider: state.binding.provider,
    commerceProxy: state.binding.commerceProxy,
    commerceImplementation: state.binding.commerceImplementation,
    commerceImplementationCodeHash:
      state.binding.commerceImplementationCodeHash,
    routerProxy: state.binding.routerProxy,
    routerImplementation: state.binding.routerImplementation,
    routerImplementationCodeHash: state.binding.routerImplementationCodeHash,
    policy: state.binding.policy,
    paymentToken: state.binding.paymentToken,
    paymentTokenCodeHash: state.binding.paymentTokenCodeHash,
    localReplayOnly: state.binding.localReplayOnly,
    replayKey: state.binding.replayKey,
    negotiationHash: state.binding.negotiationHash,
    mandateSha256: state.binding.mandateSha256,
    signedTaskSha256: state.binding.signedTaskSha256,
    transactionPlanSha256: state.binding.transactionPlanSha256,
    negotiatedAt: state.binding.negotiatedAt,
    quoteExpiresAt: state.binding.quoteExpiresAt,
    jobExpiresAt: state.binding.jobExpiresAt,
    price: state.binding.price,
    currency: state.binding.currency,
    jobDescription: state.binding.jobDescription,
  });
  if (
    !sameCanonical(stableBinding(candidate), stableBinding(recovered)) ||
    !sameCanonical(candidate.signedTask.mandate, recovered.signedTask.mandate) ||
    !sameCanonical(candidate.signedTask, recovered.signedTask) ||
    !sameCanonical(candidate.transactionPlan, recovered.transactionPlan) ||
    candidate.cleanup.owner !== recovered.cleanup.owner ||
    !sameCanonical(candidate.intent, recovered.intent)
  ) {
    throw new ActivationStoreError("INVALID_TRANSITION");
  }
}

async function readMarkerBoundSnapshot(input: Readonly<{
  metadata: ActivationReplayMetadata;
  stateDirectory: string;
  reportDirectory: string;
  directories: CapturedDirectories;
}>): Promise<PersistedActivationSnapshot> {
  const metadata = normalizeActivationReplayMetadata(input.metadata);
  if (
    metadata.activationHead.sequence !== 0 ||
    computeActivationHeadSha256(metadata.activationHead) !==
      metadata.activationHeadSha256
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  const snapshot = await readSnapshotForHead(
    metadata.activationHead,
    input.stateDirectory,
    input.reportDirectory,
  );
  await Promise.all([
    assertDirectoryIdentity(input.stateDirectory, input.directories.state),
    assertDirectoryIdentity(input.reportDirectory, input.directories.report),
  ]);
  return snapshot;
}

async function installReplayAuthorizedHead(input: Readonly<{
  candidateState: ActivationState;
  deployment: ActivationDeploymentObservation;
  replayKey: string;
  replayStore: ActivationReplayStore;
  winnerMetadata: ActivationReplayMetadata;
  stateDirectory: string;
  reportDirectory: string;
  directories: CapturedDirectories;
  lock: ActivationLock;
  hooks?: ActivationBootstrapHooks;
}>): Promise<PersistedActivationSnapshot> {
  await assertCommitAuthority(input);
  const recheckedClaim = await input.replayStore.claimActivation(
    input.replayKey,
    input.winnerMetadata,
  );
  if (recheckedClaim.status !== "existing_exact") {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  const recheckedMetadata = normalizeClaimedActivationMetadata({
    claim: recheckedClaim,
    replayKey: input.replayKey,
    expectedDomain: input.winnerMetadata,
    candidateMetadata: input.winnerMetadata,
  });
  if (!sameCanonical(recheckedMetadata, input.winnerMetadata)) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  const recovered = await readMarkerBoundSnapshot({
    metadata: recheckedMetadata,
    stateDirectory: input.stateDirectory,
    reportDirectory: input.reportDirectory,
    directories: input.directories,
  });
  assertReplayBinding(recovered.state, input.replayKey, recheckedMetadata);
  assertBootstrapSemantics(input.candidateState, recovered.state);
  assertRecoveredCreateActivation({
    state: recovered.state,
    deployment: input.deployment,
  });
  await assertCommitAuthority(input);

  const current = await readHeadRecord({
    activationId: recheckedMetadata.activationHead.activationId,
    stateDirectory: input.stateDirectory,
    reportDirectory: input.reportDirectory,
  });
  const serializedHead = serializeActivationHead(
    recheckedMetadata.activationHead,
  );
  if (current !== undefined) {
    if (serializeActivationHead(current.head) !== serializedHead) {
      throw new ActivationStoreError("COMPARE_AND_SWAP_FAILED");
    }
    await input.hooks?.afterStage?.("head_verified");
    return current.snapshot;
  }

  const temporaryHeadPath = await writeTemporaryHead(
    input.stateDirectory,
    recheckedMetadata.activationHead,
    serializedHead,
  );
  await assertCommitAuthority(input);
  await assertHeadUnchanged(
    activationHeadFilePath(
      input.stateDirectory,
      recheckedMetadata.activationHead.activationId,
    ),
    undefined,
  );
  await readMarkerBoundSnapshot({
    metadata: recheckedMetadata,
    stateDirectory: input.stateDirectory,
    reportDirectory: input.reportDirectory,
    directories: input.directories,
  });

  const headPath = activationHeadFilePath(
    input.stateDirectory,
    recheckedMetadata.activationHead.activationId,
  );
  try {
    await rename(temporaryHeadPath, headPath);
  } catch (error) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED", { cause: error });
  }
  await input.hooks?.afterStage?.("head_replaced");
  await syncDirectory(input.stateDirectory, input.directories.state);

  const committed = await readHeadRecord({
    activationId: recheckedMetadata.activationHead.activationId,
    stateDirectory: input.stateDirectory,
    reportDirectory: input.reportDirectory,
  });
  if (
    committed === undefined ||
    serializeActivationHead(committed.head) !== serializedHead
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  await assertCommitAuthority(input);
  await input.hooks?.afterStage?.("head_verified");
  return committed.snapshot;
}

async function commitSnapshot(input: Readonly<{
  prepared: PreparedSnapshot;
  stateDirectory: string;
  reportDirectory: string;
  directories: CapturedDirectories;
  lock: ActivationLock;
  hooks?: ActivationPersistenceHooks;
}>): Promise<PersistedActivationSnapshot> {
  const { prepared } = input;
  await assertCommitAuthority(input);
  const current = await readHeadRecord({
    activationId: prepared.state.activationId,
    stateDirectory: input.stateDirectory,
    reportDirectory: input.reportDirectory,
  });

  if (current?.head.stateSha256 === prepared.stateSha256) {
    assertIdempotentHead(current.head, prepared);
    return current.snapshot;
  }
  assertExpectedHead(prepared.state, current);

  await Promise.all([
    writeCanonicalPrivateFile(
      prepared.statePath,
      serializeActivationState(prepared.state),
      ACTIVATION_STATE_MAX_BYTES,
    ),
    writeCanonicalPrivateFile(
      prepared.reportPath,
      serializeActivationReport(prepared.report),
      ACTIVATION_REPORT_MAX_BYTES,
    ),
  ]);
  await verifyPreparedSnapshot(prepared);
  await input.hooks?.afterStage?.("artifacts_verified");
  await verifyPreparedSnapshot(prepared);
  await assertCommitAuthority(input);
  await assertHeadUnchanged(
    activationHeadFilePath(input.stateDirectory, prepared.state.activationId),
    current,
  );

  const head = buildActivationHead(prepared);
  const serializedHead = serializeActivationHead(head);
  assertArtifactSize(serializedHead, ACTIVATION_HEAD_MAX_BYTES);
  const temporaryHeadPath = await writeTemporaryHead(
    input.stateDirectory,
    head,
    serializedHead,
  );
  await assertCommitAuthority(input);
  await assertHeadUnchanged(
    activationHeadFilePath(input.stateDirectory, prepared.state.activationId),
    current,
  );
  await verifyPreparedSnapshot(prepared);

  const headPath = activationHeadFilePath(
    input.stateDirectory,
    prepared.state.activationId,
  );
  try {
    await rename(temporaryHeadPath, headPath);
  } catch (error) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED", { cause: error });
  }
  await input.hooks?.afterStage?.("head_replaced");
  await syncDirectory(input.stateDirectory, input.directories.state);

  const committed = await readHeadRecord({
    activationId: prepared.state.activationId,
    stateDirectory: input.stateDirectory,
    reportDirectory: input.reportDirectory,
  });
  if (
    committed === undefined ||
    serializeActivationHead(committed.head) !== serializedHead
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  await assertCommitAuthority(input);
  await input.hooks?.afterStage?.("head_verified");
  return committed.snapshot;
}

async function assertCommitAuthority(input: Readonly<{
  stateDirectory: string;
  reportDirectory: string;
  directories: CapturedDirectories;
  lock: ActivationLock;
}>): Promise<void> {
  await Promise.all([
    assertDirectoryIdentity(input.stateDirectory, input.directories.state),
    assertDirectoryIdentity(input.reportDirectory, input.directories.report),
    assertLockIdentity(input.lock, input.directories.state),
  ]);
}

function assertExpectedHead(
  state: ActivationState,
  current: HeadRecord | undefined,
): void {
  if (current === undefined) {
    throw new ActivationStoreError("COMPARE_AND_SWAP_FAILED");
  }
  if (
    state.sequence !== current.head.sequence + 1 ||
    state.parentStateSha256 !== current.head.stateSha256
  ) {
    throw new ActivationStoreError("COMPARE_AND_SWAP_FAILED");
  }
  assertChildTransition(current.snapshot.state, state);
}

function assertChildTransition(
  parent: ActivationState,
  child: ActivationState,
): void {
  if (
    child.activationId !== parent.activationId ||
    child.createdAt !== parent.createdAt ||
    Date.parse(child.updatedAt) < Date.parse(parent.updatedAt) ||
    !sameCanonical(child.binding, parent.binding) ||
    !sameCanonical(child.signedTask, parent.signedTask) ||
    !sameCanonical(child.transactionPlan, parent.transactionPlan) ||
    !sameCanonical(child.initialPreview, parent.initialPreview) ||
    child.cleanup.owner !== parent.cleanup.owner ||
    !receiptsExtend(parent, child) ||
    (parent.jobId !== undefined && child.jobId !== parent.jobId) ||
    (parent.fundingPreview !== undefined &&
      !sameCanonical(child.fundingPreview, parent.fundingPreview))
  ) {
    throw new ActivationStoreError("INVALID_TRANSITION");
  }

  const parentIndex = ACTIVATION_PHASE_ORDER.indexOf(parent.phase);
  const childIndex = ACTIVATION_PHASE_ORDER.indexOf(child.phase);
  if (parentIndex < 0 || childIndex < 0) {
    throw new ActivationStoreError("INVALID_TRANSITION");
  }
  if (parent.phase === child.phase) {
    assertSamePhaseTransition(parent, child);
    return;
  }
  if (childIndex !== parentIndex + 1) {
    throw new ActivationStoreError("INVALID_TRANSITION");
  }
  if (parentIndex % 2 === 0) {
    assertConfirmationTransition(parent, child);
    return;
  }
  assertPreparationTransition(parent, child);
}

function assertSamePhaseTransition(
  parent: ActivationState,
  child: ActivationState,
): void {
  if (
    !parent.phase.startsWith("PREPARED_") ||
    !sameCanonical(child.intent, parent.intent) ||
    child.receipts.length !== parent.receipts.length ||
    child.jobId !== parent.jobId ||
    !sameCanonical(child.fundingPreview, parent.fundingPreview)
  ) {
    throw new ActivationStoreError("INVALID_TRANSITION");
  }

  const broadcastUnknown =
    parent.condition === "ready" &&
    child.condition === "broadcast_unknown" &&
    parent.submission === undefined &&
    child.submission === undefined &&
    child.errorCode === "BROADCAST_UNKNOWN";
  const submissionRecorded =
    (parent.condition === "ready" ||
      parent.condition === "broadcast_unknown") &&
    child.condition === "reconcile_required" &&
    parent.submission === undefined &&
    child.submission !== undefined &&
    child.submission.recordedAt === child.updatedAt &&
    child.reconciliation === undefined &&
    child.errorCode === undefined &&
    sameCanonical(child.cleanup, parent.cleanup);
  const pendingObservation =
    parent.condition === "reconcile_required" &&
    child.condition === "reconcile_required" &&
    sameCanonical(child.submission, parent.submission) &&
    child.reconciliation !== undefined &&
    child.reconciliation.kind !== "reverted" &&
    child.reconciliation.transactionHash === child.submission?.transactionHash &&
    child.reconciliation.observedAt === child.updatedAt &&
    (child.reconciliation.kind === "reorged"
      ? child.errorCode === "CANONICALITY_FAILED"
      : child.errorCode === undefined) &&
    sameCanonical(child.cleanup, parent.cleanup);
  const terminalReconciliation =
    parent.condition === "reconcile_required" &&
    (child.condition === "cleanup_required" || child.condition === "aborted") &&
    sameCanonical(child.submission, parent.submission) &&
    child.reconciliation?.kind === "reverted" &&
    child.reconciliation.transactionHash === child.submission?.transactionHash &&
    child.reconciliation.observedAt === child.updatedAt &&
    child.errorCode === "RECEIPT_REVERTED";
  if (
    !broadcastUnknown &&
    !submissionRecorded &&
    !pendingObservation &&
    !terminalReconciliation
  ) {
    throw new ActivationStoreError("INVALID_TRANSITION");
  }
}

function assertConfirmationTransition(
  parent: ActivationState,
  child: ActivationState,
): void {
  if (
    !parent.phase.startsWith("PREPARED_") ||
    child.phase.startsWith("PREPARED_") ||
    (parent.condition !== "ready" &&
      parent.condition !== "reconcile_required") ||
    child.condition !== "ready" ||
    parent.intent === undefined ||
    child.intent !== undefined ||
    child.submission !== undefined ||
    child.reconciliation !== undefined ||
    child.errorCode !== undefined ||
    child.receipts.length !== parent.receipts.length + 1 ||
    child.receipts.at(-1)?.operation !== parent.intent.operation ||
    (parent.jobId === undefined && child.phase !== "CREATE_CONFIRMED") ||
    (parent.jobId === undefined && child.jobId === undefined) ||
    (parent.jobId !== undefined && child.jobId !== parent.jobId) ||
    !sameCanonical(child.fundingPreview, parent.fundingPreview)
  ) {
    throw new ActivationStoreError("INVALID_TRANSITION");
  }
}

function assertPreparationTransition(
  parent: ActivationState,
  child: ActivationState,
): void {
  const fundingPreviewIntroduced =
    parent.phase === "BUDGET_CONFIRMED" &&
    child.phase === "PREPARED_FUND" &&
    parent.fundingPreview === undefined &&
    child.fundingPreview !== undefined;
  const fundingPreviewUnchanged = sameCanonical(
    child.fundingPreview,
    parent.fundingPreview,
  );
  if (
    parent.phase.startsWith("PREPARED_") ||
    !child.phase.startsWith("PREPARED_") ||
    parent.condition !== "ready" ||
    child.condition !== "ready" ||
    parent.intent !== undefined ||
    parent.submission !== undefined ||
    parent.reconciliation !== undefined ||
    child.intent === undefined ||
    child.submission !== undefined ||
    child.reconciliation !== undefined ||
    child.errorCode !== undefined ||
    child.receipts.length !== parent.receipts.length ||
    child.jobId !== parent.jobId ||
    (!fundingPreviewIntroduced && !fundingPreviewUnchanged)
  ) {
    throw new ActivationStoreError("INVALID_TRANSITION");
  }
}

function receiptsExtend(
  parent: ActivationState,
  child: ActivationState,
): boolean {
  if (child.receipts.length < parent.receipts.length) return false;
  return parent.receipts.every((receipt, index) =>
    sameCanonical(receipt, child.receipts[index]),
  );
}

function sameCanonical(left: unknown, right: unknown): boolean {
  if (left === undefined || right === undefined) return left === right;
  return canonicalQuoteJson(left) === canonicalQuoteJson(right);
}

function assertIdempotentHead(
  head: ActivationHead,
  prepared: PreparedSnapshot,
): void {
  if (
    head.activationId !== prepared.state.activationId ||
    head.sequence !== prepared.state.sequence ||
    head.stateFile !== basename(prepared.statePath) ||
    head.reportSha256 !== prepared.reportSha256 ||
    head.reportFile !== basename(prepared.reportPath) ||
    head.updatedAt !== prepared.state.updatedAt
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
}

async function verifyPreparedSnapshot(
  prepared: PreparedSnapshot,
): Promise<void> {
  const state = await readActivationState(prepared.statePath);
  if (activationStateSha256(state) !== prepared.stateSha256) {
    throw new ActivationStoreError("CONTENT_ADDRESS_MISMATCH");
  }
  const report = await readActivationReport(prepared.reportPath, state);
  const rawReport = serializeActivationReport(report);
  if (sha256(rawReport) !== prepared.reportSha256) {
    throw new ActivationStoreError("CONTENT_ADDRESS_MISMATCH");
  }
}

async function readActivationReport(
  path: string,
  state: ActivationState,
): Promise<ActivationReport> {
  const raw = await readSecureTextFile(path, {
    maxBytes: ACTIVATION_REPORT_MAX_BYTES,
    mode: "operator-private",
  });
  let report: ActivationReport;
  try {
    report = activationReportSchema.parse(JSON.parse(raw) as unknown);
    if (
      serializeActivationReport(report) !== raw ||
      serializeActivationReport(buildActivationReport(state)) !== raw
    ) {
      throw new Error("report serialization is not canonical for its state");
    }
  } catch (error) {
    throw new ActivationStoreError("NON_CANONICAL_REPORT", { cause: error });
  }
  const digest = sha256(raw);
  if (basename(path) !== reportFileName(state, digest)) {
    throw new ActivationStoreError("CONTENT_ADDRESS_MISMATCH");
  }
  return report;
}

async function readHeadRecord(input: Readonly<{
  activationId: string;
  stateDirectory: string;
  reportDirectory: string;
}>): Promise<HeadRecord | undefined> {
  const headPath = activationHeadFilePath(
    input.stateDirectory,
    input.activationId,
  );
  const headFile = await readOptionalCanonicalHead(headPath);
  if (headFile === undefined) return undefined;
  const { head, identity } = headFile;
  if (head.activationId !== input.activationId) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  const snapshot = await readSnapshotForHead(
    head,
    input.stateDirectory,
    input.reportDirectory,
  );
  await assertFileIdentity(headPath, identity, "HEAD_INTEGRITY_FAILED");
  return {
    head,
    identity,
    snapshot,
  };
}

async function readSnapshotForHead(
  headInput: ActivationHead,
  stateDirectory: string,
  reportDirectory: string,
): Promise<PersistedActivationSnapshot> {
  const head = activationHeadSchema.parse(headInput);
  if (
    head.stateFile !==
      `state-v1-${head.activationId}-${head.sequence}-${head.stateSha256}.json` ||
    head.reportFile !==
      `report-v1-${head.activationId}-${head.sequence}-${head.reportSha256}.json`
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  const statePath = join(stateDirectory, head.stateFile);
  const reportPath = join(reportDirectory, head.reportFile);
  const state = await readActivationState(statePath);
  if (
    state.activationId !== head.activationId ||
    state.sequence !== head.sequence ||
    state.updatedAt !== head.updatedAt ||
    activationStateSha256(state) !== head.stateSha256
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  const report = await readActivationReport(reportPath, state);
  const reportSha256 = sha256(serializeActivationReport(report));
  if (reportSha256 !== head.reportSha256) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  return {
    state,
    report,
    stateSha256: head.stateSha256,
    reportSha256,
    statePath,
    reportPath,
  };
}

async function readOptionalCanonicalHead(
  path: string,
): Promise<Readonly<{ head: ActivationHead; identity: DirectoryIdentity }> | undefined> {
  let before: BigIntStats;
  try {
    before = await lstat(path, { bigint: true });
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED", { cause: error });
  }
  assertPrivateFileStat(before, "HEAD_INTEGRITY_FAILED");
  const identity = { dev: before.dev, ino: before.ino };
  const raw = await readSecureTextFile(path, {
    maxBytes: ACTIVATION_HEAD_MAX_BYTES,
    mode: "operator-private",
  });
  let head: ActivationHead;
  try {
    head = activationHeadSchema.parse(JSON.parse(raw) as unknown);
    if (serializeActivationHead(head) !== raw) {
      throw new Error("head serialization is not canonical");
    }
  } catch (error) {
    throw new ActivationStoreError("NON_CANONICAL_HEAD", { cause: error });
  }
  await assertFileIdentity(path, identity, "HEAD_INTEGRITY_FAILED");
  return { head, identity };
}

async function writeTemporaryHead(
  stateDirectory: string,
  head: ActivationHead,
  serialized: string,
): Promise<string> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const path = join(
      stateDirectory,
      `.activation-head-v1-${head.activationId}-${randomBytes(16).toString("hex")}.tmp`,
    );
    try {
      await writePrivateFileExclusive(path, serialized);
      const persisted = await readOptionalCanonicalHead(path);
      if (
        persisted === undefined ||
        serializeActivationHead(persisted.head) !== serialized
      ) {
        throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
      }
      return path;
    } catch (error) {
      if (error instanceof SecureFileError && error.code === "FILE_EXISTS") {
        continue;
      }
      throw error;
    }
  }
  throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
}

async function assertHeadUnchanged(
  path: string,
  current: HeadRecord | undefined,
): Promise<void> {
  if (current === undefined) {
    try {
      await lstat(path);
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return;
      throw new ActivationStoreError("HEAD_INTEGRITY_FAILED", { cause: error });
    }
    throw new ActivationStoreError("COMPARE_AND_SWAP_FAILED");
  }
  await assertFileIdentity(path, current.identity, "COMPARE_AND_SWAP_FAILED");
}

async function writeCanonicalPrivateFile(
  path: string,
  contents: string,
  maxBytes: number,
): Promise<void> {
  try {
    await writePrivateFileExclusive(path, contents);
    return;
  } catch (error) {
    if (!(error instanceof SecureFileError) || error.code !== "FILE_EXISTS") {
      throw error;
    }
  }
  const existing = await readSecureTextFile(path, {
    maxBytes,
    mode: "operator-private",
  });
  if (existing !== contents) {
    throw new ActivationStoreError("ARTIFACT_COLLISION");
  }
}

async function captureDirectories(
  stateDirectory: string,
  reportDirectory: string,
): Promise<CapturedDirectories> {
  const [state, report] = await Promise.all([
    captureDirectoryIdentity(stateDirectory),
    captureDirectoryIdentity(reportDirectory),
  ]);
  return { state, report };
}

async function captureDirectoryIdentity(path: string): Promise<DirectoryIdentity> {
  await assertPrivateDirectory(path);
  let canonical: string;
  let stats: BigIntStats;
  try {
    [canonical, stats] = await Promise.all([
      realpath(path),
      lstat(path, { bigint: true }),
    ]);
  } catch (error) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED", { cause: error });
  }
  if (
    canonical !== path ||
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    Number(stats.mode & 0o777n) !== 0o700 ||
    !isOwnedByCurrentUser(stats.uid)
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
  return { dev: stats.dev, ino: stats.ino };
}

async function assertDirectoryIdentity(
  path: string,
  expected: DirectoryIdentity,
): Promise<void> {
  await assertPrivateDirectory(path);
  let stats: BigIntStats;
  try {
    stats = await lstat(path, { bigint: true });
  } catch (error) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED", { cause: error });
  }
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    stats.dev !== expected.dev ||
    stats.ino !== expected.ino ||
    Number(stats.mode & 0o777n) !== 0o700 ||
    !isOwnedByCurrentUser(stats.uid)
  ) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
}

async function acquireActivationLock(
  path: string,
  activationId: string,
  directory: DirectoryIdentity,
): Promise<ActivationLock> {
  const deadline = Date.now() + LOCK_WAIT_TIMEOUT_MS;
  for (;;) {
    await assertDirectoryIdentity(dirname(path), directory);
    const metadata: ActivationLockMetadata = {
      schema: ACTIVATION_LOCK_SCHEMA,
      activationId,
      pid: process.pid,
      nonce: randomBytes(32).toString("hex"),
      createdAt: new Date().toISOString(),
    };
    const serialized = serializeActivationLock(metadata);
    let handle: FileHandle;
    try {
      handle = await open(
        path,
        constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_EXCL |
          constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (!isNodeError(error) || error.code !== "EEXIST") {
        throw new ActivationStoreError("LOCK_UNAVAILABLE", { cause: error });
      }
      const lockStillExists = await inspectExistingLockPath(
        path,
        activationId,
        directory,
      );
      if (!lockStillExists) continue;
      if (Date.now() >= deadline) {
        throw new ActivationStoreError("LOCK_UNAVAILABLE");
      }
      await delay(LOCK_RETRY_MS);
      continue;
    }

    try {
      const created = await handle.stat({ bigint: true });
      assertPrivateFileStat(created, "LOCK_INTEGRITY_FAILED");
      const identity = { dev: created.dev, ino: created.ino };
      await handle.writeFile(serialized, { encoding: "utf8" });
      await handle.sync();
      await assertFileIdentity(path, identity, "LOCK_INTEGRITY_FAILED");
      await syncDirectory(dirname(path), directory);
      const persisted = await readSecureTextFile(path, {
        maxBytes: ACTIVATION_LOCK_MAX_BYTES,
        mode: "operator-private",
      });
      if (persisted !== serialized) {
        throw new ActivationStoreError("LOCK_INTEGRITY_FAILED");
      }
      return { path, handle, identity, serialized };
    } catch (error) {
      await handle.close().catch(() => undefined);
      throw error;
    }
  }
}

async function inspectExistingLockPath(
  path: string,
  activationId: string,
  directory: DirectoryIdentity,
): Promise<boolean> {
  let stats: BigIntStats;
  try {
    stats = await lstat(path, { bigint: true });
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return false;
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED", { cause: error });
  }
  assertPrivateFileStat(stats, "LOCK_INTEGRITY_FAILED");
  const identity = { dev: stats.dev, ino: stats.ino };
  let metadata: ActivationLockMetadata;
  try {
    const raw = await readSecureTextFile(path, {
      maxBytes: ACTIVATION_LOCK_MAX_BYTES,
      mode: "operator-private",
    });
    metadata = parseActivationLock(raw, activationId);
  } catch (error) {
    if (Date.now() - Number(stats.ctimeMs) <= LOCK_INITIALIZATION_GRACE_MS) {
      return true;
    }
    if (error instanceof ActivationStoreError) throw error;
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED", { cause: error });
  }
  await assertFileIdentity(path, identity, "LOCK_INTEGRITY_FAILED");
  if (isProcessAlive(metadata.pid)) return true;
  await quarantineDeadLock(path, identity, directory);
  return false;
}

async function assertLockIdentity(
  lock: ActivationLock,
  directory: DirectoryIdentity,
): Promise<void> {
  await assertDirectoryIdentity(dirname(lock.path), directory);
  let handleStats: BigIntStats;
  try {
    handleStats = await lock.handle.stat({ bigint: true });
  } catch (error) {
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED", { cause: error });
  }
  assertPrivateFileStat(handleStats, "LOCK_INTEGRITY_FAILED");
  if (
    handleStats.dev !== lock.identity.dev ||
    handleStats.ino !== lock.identity.ino
  ) {
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED");
  }
  await assertFileIdentity(lock.path, lock.identity, "LOCK_INTEGRITY_FAILED");
  const persisted = await readSecureTextFile(lock.path, {
    maxBytes: ACTIVATION_LOCK_MAX_BYTES,
    mode: "operator-private",
  });
  if (persisted !== lock.serialized) {
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED");
  }
}

async function quarantineDeadLock(
  path: string,
  identity: DirectoryIdentity,
  directory: DirectoryIdentity,
): Promise<void> {
  const quarantinePath = join(
    dirname(path),
    `.activation-dead-lock-${randomBytes(32).toString("hex")}.tmp`,
  );
  await assertFileIdentity(path, identity, "LOCK_INTEGRITY_FAILED");
  try {
    await rename(path, quarantinePath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return;
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED", { cause: error });
  }
  await assertFileIdentity(
    quarantinePath,
    identity,
    "LOCK_INTEGRITY_FAILED",
  );
  try {
    await unlink(quarantinePath);
    await syncDirectory(dirname(path), directory);
  } catch (error) {
    if (error instanceof ActivationStoreError) throw error;
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED", { cause: error });
  }
}

async function releaseActivationLock(
  lock: ActivationLock,
  directory: DirectoryIdentity,
): Promise<void> {
  try {
    await assertLockIdentity(lock, directory);
    await unlink(lock.path);
    await syncDirectory(dirname(lock.path), directory);
  } catch (error) {
    if (error instanceof ActivationStoreError) throw error;
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED", { cause: error });
  } finally {
    await lock.handle.close().catch(() => undefined);
  }
}

async function assertFileIdentity(
  path: string,
  expected: DirectoryIdentity,
  code:
    | "HEAD_INTEGRITY_FAILED"
    | "COMPARE_AND_SWAP_FAILED"
    | "LOCK_INTEGRITY_FAILED",
): Promise<void> {
  let stats: BigIntStats;
  try {
    stats = await lstat(path, { bigint: true });
  } catch (error) {
    throw new ActivationStoreError(code, { cause: error });
  }
  assertPrivateFileStat(stats, code);
  if (stats.dev !== expected.dev || stats.ino !== expected.ino) {
    throw new ActivationStoreError(code);
  }
}

function assertPrivateFileStat(
  stats: BigIntStats,
  code:
    | "HEAD_INTEGRITY_FAILED"
    | "COMPARE_AND_SWAP_FAILED"
    | "LOCK_INTEGRITY_FAILED",
): void {
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1n ||
    Number(stats.mode & 0o777n) !== 0o600 ||
    !isOwnedByCurrentUser(stats.uid)
  ) {
    throw new ActivationStoreError(code);
  }
}

async function syncDirectory(
  path: string,
  expected: DirectoryIdentity,
): Promise<void> {
  await assertDirectoryIdentity(path, expected);
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const stats = await handle.stat({ bigint: true });
    if (
      !stats.isDirectory() ||
      stats.dev !== expected.dev ||
      stats.ino !== expected.ino
    ) {
      throw new Error("directory identity changed");
    }
    await handle.sync();
  } catch (error) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED", { cause: error });
  } finally {
    await handle?.close().catch(() => undefined);
  }
  await assertDirectoryIdentity(path, expected);
}

function serializeActivationHead(head: ActivationHead): string {
  return `${canonicalQuoteJson(activationHeadSchema.parse(head))}\n`;
}

function serializeActivationLock(lock: ActivationLockMetadata): string {
  return `${canonicalQuoteJson(lock)}\n`;
}

function parseActivationLock(
  raw: string,
  activationId: string,
): ActivationLockMetadata {
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch (error) {
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED", { cause: error });
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED");
  }
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).sort();
  if (
    keys.length !== 5 ||
    keys[0] !== "activationId" ||
    keys[1] !== "createdAt" ||
    keys[2] !== "nonce" ||
    keys[3] !== "pid" ||
    keys[4] !== "schema" ||
    object.schema !== ACTIVATION_LOCK_SCHEMA ||
    object.activationId !== activationId ||
    typeof object.pid !== "number" ||
    !Number.isSafeInteger(object.pid) ||
    object.pid <= 0 ||
    typeof object.nonce !== "string" ||
    !LOCK_NONCE_PATTERN.test(object.nonce) ||
    typeof object.createdAt !== "string"
  ) {
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED");
  }
  const createdAt = new Date(object.createdAt);
  if (
    Number.isNaN(createdAt.valueOf()) ||
    createdAt.toISOString() !== object.createdAt
  ) {
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED");
  }
  const metadata: ActivationLockMetadata = {
    schema: ACTIVATION_LOCK_SCHEMA,
    activationId,
    pid: object.pid,
    nonce: object.nonce,
    createdAt: object.createdAt,
  };
  if (serializeActivationLock(metadata) !== raw) {
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED");
  }
  return metadata;
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (isNodeError(error) && error.code === "ESRCH") return false;
    if (isNodeError(error) && error.code === "EPERM") return true;
    throw new ActivationStoreError("LOCK_INTEGRITY_FAILED", { cause: error });
  }
}

function stateFileName(state: ActivationState, digest: string): string {
  return `state-v1-${state.activationId}-${state.sequence}-${digest}.json`;
}

function reportFileName(state: ActivationState, digest: string): string {
  return `report-v1-${state.activationId}-${state.sequence}-${digest}.json`;
}

function assertArtifactSize(contents: string, maxBytes: number): void {
  if (Buffer.byteLength(contents, "utf8") > maxBytes) {
    throw new ActivationStoreError("NON_CANONICAL_STATE");
  }
}

function assertActivationId(activationId: string): void {
  if (!ACTIVATION_ID_PATTERN.test(activationId)) {
    throw new ActivationStoreError("HEAD_INTEGRITY_FAILED");
  }
}

function isOwnedByCurrentUser(uid: bigint): boolean {
  return typeof process.getuid !== "function" || Number(uid) === process.getuid();
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
