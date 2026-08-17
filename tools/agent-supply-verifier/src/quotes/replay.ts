import { createHash, randomBytes } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import {
  type FileHandle,
  link,
  lstat,
  open,
  readdir,
  realpath,
  unlink,
} from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

import {
  activationHeadSchema,
  type ActivationHead,
} from "../activation/schema.js";
import {
  canonicalQuoteJson,
  computeQuoteReplayKey,
} from "./protocol.js";

const REPLAY_KEY_PATTERN = /^[a-f0-9]{64}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
export const REPLAY_MARKER_SCHEMA =
  "mandatex.agent-supply.quote-replay.v1" as const;
export const ACTIVATION_REPLAY_MARKER_SCHEMA =
  "mandatex.agent-supply.quote-replay.v2" as const;
const MARKER_MAX_BYTES = 16 * 1024;
const TEMP_NONCE_PATTERN = /^[a-f0-9]{64}$/;

const V1_KEYS = [
  "schema",
  "claimedAt",
  "chainId",
  "tokenId",
  "endpointHash",
  "provider",
  "commerceContract",
  "negotiationHash",
] as const;
const V2_KEYS = [
  ...V1_KEYS,
  "activationHead",
  "activationHeadSha256",
] as const;

export type ReplayMetadata = Readonly<{
  schema: typeof REPLAY_MARKER_SCHEMA;
  claimedAt: string;
  chainId: number;
  tokenId: string;
  endpointHash: string;
  provider: string;
  commerceContract: string;
  negotiationHash: string;
}>;

export type ActivationReplayMetadata = Readonly<{
  schema: typeof ACTIVATION_REPLAY_MARKER_SCHEMA;
  claimedAt: string;
  chainId: number;
  tokenId: string;
  endpointHash: string;
  provider: string;
  commerceContract: string;
  negotiationHash: string;
  activationHead: ActivationHead;
  activationHeadSha256: string;
}>;

export type ActivationReplayClaimResult = Readonly<{
  status: "created" | "existing_exact" | "existing_conflict";
  metadata: ActivationReplayMetadata;
}>;

export interface ReplayStore {
  prepare(): Promise<void>;
  claim(
    key: string,
    metadata: ReplayMetadata,
  ): Promise<"claimed" | "duplicate">;
}

export interface ActivationReplayStore {
  prepare(): Promise<void>;
  inspectActivation(
    key: string,
  ): Promise<ActivationReplayMetadata | undefined>;
  claimActivation(
    key: string,
    metadata: ActivationReplayMetadata,
  ): Promise<ActivationReplayClaimResult>;
}

export type ReplayPersistenceStage =
  | "temp_verified"
  | "marker_published"
  | "marker_verified";

export type ReplayPersistenceHookContext = Readonly<{
  key: string;
  markerPath: string;
  temporaryPath: string;
}>;

/** Test-only crash injection. Production callers should omit this option. */
export type ReplayPersistenceHooks = Readonly<{
  afterStage?: (
    stage: ReplayPersistenceStage,
    context: ReplayPersistenceHookContext,
  ) => void | Promise<void>;
}>;

export type FileReplayStoreOptions = Readonly<{
  hooks?: ReplayPersistenceHooks;
}>;

export class ReplayStoreError extends Error {
  readonly code:
    | "INVALID_STATE_PATH"
    | "UNSAFE_STATE_DIRECTORY"
    | "STATE_DIRECTORY_UNAVAILABLE"
    | "STATE_WRITE_FAILED";

  constructor(
    code: ReplayStoreError["code"],
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ReplayStoreError";
    this.code = code;
  }
}

export function computeActivationHeadSha256(head: ActivationHead): string {
  const normalized = normalizeActivationHead(head);
  return createHash("sha256")
    .update(canonicalQuoteJson(normalized), "utf8")
    .digest("hex");
}

export function buildActivationReplayMetadata(
  replay: ReplayMetadata,
  activationHead: ActivationHead,
): ActivationReplayMetadata {
  const normalizedReplay = normalizeReplayMetadata(replay);
  const normalizedHead = normalizeActivationHead(activationHead);
  return normalizeActivationReplayMetadata({
    schema: ACTIVATION_REPLAY_MARKER_SCHEMA,
    claimedAt: normalizedReplay.claimedAt,
    chainId: normalizedReplay.chainId,
    tokenId: normalizedReplay.tokenId,
    endpointHash: normalizedReplay.endpointHash,
    provider: normalizedReplay.provider,
    commerceContract: normalizedReplay.commerceContract,
    negotiationHash: normalizedReplay.negotiationHash,
    activationHead: normalizedHead,
    activationHeadSha256: computeActivationHeadSha256(normalizedHead),
  });
}

type DirectoryIdentity = Readonly<{ dev: bigint; ino: bigint }>;
type FileIdentity = Readonly<{ dev: bigint; ino: bigint }>;
type TemporaryMarker = Readonly<{
  path: string;
  handle: FileHandle;
  identity: FileIdentity;
}>;
type StoredMarker =
  | Readonly<{ version: 1; metadata: ReplayMetadata }>
  | Readonly<{ version: 2; metadata: ActivationReplayMetadata }>;
type PublicationResult = Readonly<{
  status: "created" | "existing";
  marker: StoredMarker;
}>;

export class FileReplayStore implements ReplayStore, ActivationReplayStore {
  readonly #directory: string;
  readonly #hooks: ReplayPersistenceHooks | undefined;
  #preparedIdentity: DirectoryIdentity | null = null;

  constructor(directory: string, options: FileReplayStoreOptions = {}) {
    if (!isAbsolute(directory) || resolve(directory) !== directory) {
      throw new ReplayStoreError(
        "INVALID_STATE_PATH",
        "replay store must be an absolute canonical path",
      );
    }
    this.#directory = directory;
    this.#hooks = options.hooks;
  }

  async prepare(): Promise<void> {
    let linkStats: BigIntStats;
    let canonicalPath: string;
    try {
      [linkStats, canonicalPath] = await Promise.all([
        lstat(this.#directory, { bigint: true }),
        realpath(this.#directory),
      ]);
    } catch (error) {
      throw new ReplayStoreError(
        "STATE_DIRECTORY_UNAVAILABLE",
        "replay state directory is unavailable",
        { cause: error },
      );
    }

    assertSafeDirectory(linkStats, canonicalPath, this.#directory);
    this.#preparedIdentity = { dev: linkStats.dev, ino: linkStats.ino };
  }

  async claim(
    key: string,
    metadata: ReplayMetadata,
  ): Promise<"claimed" | "duplicate"> {
    this.#assertClaimReady(key);
    const safeMetadata = normalizeReplayMetadata(metadata);
    if (replayKeyForMetadata(safeMetadata) !== key) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay key does not match its metadata domain",
      );
    }

    const publication = await this.#publishMarker(
      key,
      serializeReplayMetadata(safeMetadata),
    );
    if (publication.marker.version !== 1) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "activation replay markers are not resumable as legacy quote claims",
      );
    }
    if (!sameReplayDomain(publication.marker.metadata, safeMetadata)) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "existing replay marker domain mismatch",
      );
    }
    return publication.status === "created" ? "claimed" : "duplicate";
  }

  async inspectActivation(
    key: string,
  ): Promise<ActivationReplayMetadata | undefined> {
    this.#assertClaimReady(key);
    await this.#assertDirectoryIdentity();
    const markerPath = join(this.#directory, `${key}.json`);
    try {
      await lstat(markerPath, { bigint: true });
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        await this.#assertDirectoryIdentity();
        return undefined;
      }
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "activation replay marker could not be inspected",
        { cause: error },
      );
    }

    const marker = await this.#readVerifiedMarker(markerPath, key);
    if (marker.version !== 2) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "legacy replay markers cannot resume activation bootstrap",
      );
    }
    return marker.metadata;
  }

  async claimActivation(
    key: string,
    metadata: ActivationReplayMetadata,
  ): Promise<ActivationReplayClaimResult> {
    this.#assertClaimReady(key);
    const safeMetadata = normalizeActivationReplayMetadata(metadata);
    if (replayKeyForMetadata(safeMetadata) !== key) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay key does not match its metadata domain",
      );
    }

    const publication = await this.#publishMarker(
      key,
      serializeActivationReplayMetadata(safeMetadata),
    );
    if (publication.marker.version !== 2) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "legacy replay markers cannot resume activation bootstrap",
      );
    }
    const existing = publication.marker.metadata;
    if (!sameReplayDomain(existing, safeMetadata)) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "existing activation replay marker domain mismatch",
      );
    }
    if (publication.status === "created") {
      return { status: "created", metadata: existing };
    }
    return {
      status: sameActivationBinding(existing, safeMetadata)
        ? "existing_exact"
        : "existing_conflict",
      metadata: existing,
    };
  }

  #assertClaimReady(key: string): void {
    if (!REPLAY_KEY_PATTERN.test(key)) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay key must be a lowercase SHA-256 digest",
      );
    }
    if (this.#preparedIdentity === null) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay store was not prepared",
      );
    }
  }

  async #publishMarker(
    key: string,
    serialized: string,
  ): Promise<PublicationResult> {
    if (Buffer.byteLength(serialized, "utf8") > MARKER_MAX_BYTES) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay marker exceeds the persistence limit",
      );
    }
    await this.#assertDirectoryIdentity();
    const markerPath = join(this.#directory, `${key}.json`);
    const temporary = await this.#createTemporaryMarker(key);
    const context: ReplayPersistenceHookContext = {
      key,
      markerPath,
      temporaryPath: temporary.path,
    };
    let publicationStatus: "created" | "existing" | undefined;
    let operationError: unknown;

    try {
      await temporary.handle.writeFile(serialized, { encoding: "utf8" });
      await temporary.handle.sync();
      const verifiedTemporary = await this.#readSecureFile(
        temporary.path,
        new Set([1n]),
      );
      if (
        verifiedTemporary.raw !== serialized ||
        !sameIdentity(verifiedTemporary.identity, temporary.identity)
      ) {
        throw new ReplayStoreError(
          "STATE_WRITE_FAILED",
          "temporary replay marker failed integrity validation",
        );
      }
      await this.#hooks?.afterStage?.("temp_verified", context);
      await this.#assertDirectoryIdentity();

      try {
        await link(temporary.path, markerPath);
        publicationStatus = "created";
      } catch (error) {
        if (isNodeError(error) && error.code === "EEXIST") {
          publicationStatus = "existing";
        } else {
          throw new ReplayStoreError(
            "STATE_WRITE_FAILED",
            "replay marker could not be atomically published",
            { cause: error },
          );
        }
      }

      if (publicationStatus === "created") {
        await this.#assertPublishedLink(markerPath, temporary.identity);
        await this.#hooks?.afterStage?.("marker_published", context);
        await temporary.handle.sync();
      }
    } catch (error) {
      operationError = error;
    }

    operationError = await collectFailure(
      operationError,
      () => temporary.handle.close(),
      "replay publication and handle close both failed",
    );
    operationError = await collectFailure(
      operationError,
      () =>
        this.#removeTemporaryMarker(
          temporary,
          publicationStatus === "created",
        ),
      "replay publication and temporary cleanup both failed",
    );
    operationError = await collectFailure(
      operationError,
      () => this.#syncDirectory(),
      "replay publication and directory persistence both failed",
    );
    if (operationError !== undefined) throw operationError;
    if (publicationStatus === undefined) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay marker publication did not reach a terminal state",
      );
    }

    const marker = await this.#readVerifiedMarker(markerPath, key);
    if (publicationStatus === "created") {
      if (serializeStoredMarker(marker) !== serialized) {
        throw new ReplayStoreError(
          "STATE_WRITE_FAILED",
          "published replay marker does not match the requested claim",
        );
      }
      await this.#hooks?.afterStage?.("marker_verified", context);
    }
    await this.#assertDirectoryIdentity();
    return { status: publicationStatus, marker };
  }

  async #createTemporaryMarker(key: string): Promise<TemporaryMarker> {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      await this.#assertDirectoryIdentity();
      const nonce = randomBytes(32).toString("hex");
      const path = join(this.#directory, temporaryMarkerName(key, nonce));
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
        if (isNodeError(error) && error.code === "EEXIST") continue;
        throw new ReplayStoreError(
          "STATE_WRITE_FAILED",
          "temporary replay marker could not be created",
          { cause: error },
        );
      }

      try {
        const stats = await handle.stat({ bigint: true });
        assertSafePrivateFile(stats, new Set([1n]), true);
        await this.#assertDirectoryIdentity();
        return {
          path,
          handle,
          identity: { dev: stats.dev, ino: stats.ino },
        };
      } catch (error) {
        const identity = await handle
          .stat({ bigint: true })
          .then((stats) => ({ dev: stats.dev, ino: stats.ino }))
          .catch(() => undefined);
        await handle.close().catch(() => undefined);
        if (identity !== undefined) {
          await this.#removeTemporaryMarker(
            { path, handle, identity },
            false,
          ).catch(() => undefined);
        }
        throw error;
      }
    }
    throw new ReplayStoreError(
      "STATE_WRITE_FAILED",
      "temporary replay marker name allocation failed",
    );
  }

  async #removeTemporaryMarker(
    temporary: TemporaryMarker,
    published: boolean,
  ): Promise<void> {
    await this.#assertDirectoryIdentity();
    let stats: BigIntStats;
    try {
      stats = await lstat(temporary.path, { bigint: true });
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return;
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "temporary replay marker could not be inspected for cleanup",
        { cause: error },
      );
    }
    const allowedLinks = published ? new Set([1n, 2n]) : new Set([1n]);
    assertSafePrivateFile(stats, allowedLinks, true);
    if (!sameIdentity(stats, temporary.identity)) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "temporary replay marker identity changed before cleanup",
      );
    }
    try {
      await unlink(temporary.path);
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return;
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "temporary replay marker could not be removed",
        { cause: error },
      );
    }
    try {
      await lstat(temporary.path, { bigint: true });
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return;
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "temporary replay marker cleanup could not be verified",
        { cause: error },
      );
    }
    throw new ReplayStoreError(
      "STATE_WRITE_FAILED",
      "temporary replay marker path was replaced during cleanup",
    );
  }

  async #assertPublishedLink(
    markerPath: string,
    expected: FileIdentity,
  ): Promise<void> {
    let stats: BigIntStats;
    try {
      stats = await lstat(markerPath, { bigint: true });
    } catch (error) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "published replay marker could not be inspected",
        { cause: error },
      );
    }
    assertSafePrivateFile(stats, new Set([1n, 2n]), false);
    if (!sameIdentity(stats, expected)) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "published replay marker identity does not match its temporary inode",
      );
    }
  }

  async #readVerifiedMarker(
    markerPath: string,
    key: string,
  ): Promise<StoredMarker> {
    await this.#assertDirectoryIdentity();
    await this.#recoverInterruptedPublication(markerPath, key);
    try {
      const file = await this.#readSecureFile(markerPath, new Set([1n]));
      const marker = parseStoredMarker(file.raw);
      if (replayKeyForMetadata(marker.metadata) !== key) {
        throw new Error("replay marker filename does not match its domain");
      }
      await this.#assertDirectoryIdentity();
      return marker;
    } catch (error) {
      if (error instanceof ReplayStoreError) throw error;
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "existing replay marker failed integrity validation",
        { cause: error },
      );
    }
  }

  async #recoverInterruptedPublication(
    markerPath: string,
    key: string,
  ): Promise<void> {
    let marker: BigIntStats;
    try {
      marker = await lstat(markerPath, { bigint: true });
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return;
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay marker could not be inspected",
        { cause: error },
      );
    }
    if (marker.nlink === 1n) return;
    assertSafePrivateFile(marker, new Set([2n]), false);

    const names = await readdir(this.#directory);
    const matchingPaths: string[] = [];
    for (const name of names) {
      if (!isTemporaryMarkerName(name, key)) continue;
      const candidatePath = join(this.#directory, name);
      let candidate: BigIntStats;
      try {
        candidate = await lstat(candidatePath, { bigint: true });
      } catch (error) {
        if (isNodeError(error) && error.code === "ENOENT") continue;
        throw error;
      }
      if (sameIdentity(candidate, marker)) matchingPaths.push(candidatePath);
    }

    if (matchingPaths.length !== 1) {
      const current = await lstat(markerPath, { bigint: true }).catch(
        () => undefined,
      );
      if (
        current !== undefined &&
        current.nlink === 1n &&
        sameIdentity(current, marker)
      ) {
        return;
      }
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay marker has an unexplained hard-link topology",
      );
    }

    const temporaryPath = matchingPaths[0]!;
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        temporaryPath,
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      const temporary = await handle.stat({ bigint: true });
      assertSafePrivateFile(temporary, new Set([2n]), false);
      if (!sameIdentity(temporary, marker)) {
        throw new Error("temporary hard link identity changed");
      }
      await unlink(temporaryPath);
      const remaining = await handle.stat({ bigint: true });
      if (remaining.nlink !== 1n || !sameIdentity(remaining, marker)) {
        throw new Error("published replay marker did not become singly linked");
      }
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        const current = await lstat(markerPath, { bigint: true }).catch(
          () => undefined,
        );
        if (
          current !== undefined &&
          current.nlink === 1n &&
          sameIdentity(current, marker)
        ) {
          return;
        }
      }
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "interrupted replay publication could not be recovered safely",
        { cause: error },
      );
    } finally {
      await handle?.close().catch(() => undefined);
    }

    await this.#syncDirectory();
    const recovered = await lstat(markerPath, { bigint: true });
    assertSafePrivateFile(recovered, new Set([1n]), false);
    if (!sameIdentity(recovered, marker)) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "recovered replay marker identity changed",
      );
    }
  }

  async #readSecureFile(
    path: string,
    allowedLinks: ReadonlySet<bigint>,
  ): Promise<Readonly<{ raw: string; identity: FileIdentity }>> {
    let handle: FileHandle | undefined;
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const before = await handle.stat({ bigint: true });
      assertSafePrivateFile(before, allowedLinks, false);
      const raw = await readBoundedUtf8(handle, MARKER_MAX_BYTES);
      const after = await handle.stat({ bigint: true });
      if (
        !sameStableFile(before, after) ||
        BigInt(Buffer.byteLength(raw, "utf8")) !== after.size
      ) {
        throw new Error("replay marker changed while it was read");
      }
      const linked = await lstat(path, { bigint: true });
      assertSafePrivateFile(linked, allowedLinks, false);
      if (!sameIdentity(linked, after)) {
        throw new Error("replay marker path identity changed while it was read");
      }
      return { raw, identity: { dev: after.dev, ino: after.ino } };
    } catch (error) {
      if (error instanceof ReplayStoreError) throw error;
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay marker could not be read safely",
        { cause: error },
      );
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  async #assertDirectoryIdentity(): Promise<void> {
    const expected = this.#preparedIdentity;
    if (expected === null) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay store was not prepared",
      );
    }
    let current: BigIntStats;
    let canonicalPath: string;
    try {
      [current, canonicalPath] = await Promise.all([
        lstat(this.#directory, { bigint: true }),
        realpath(this.#directory),
      ]);
    } catch (error) {
      throw new ReplayStoreError(
        "STATE_DIRECTORY_UNAVAILABLE",
        "replay state directory is unavailable",
        { cause: error },
      );
    }
    assertSafeDirectory(current, canonicalPath, this.#directory);
    if (current.dev !== expected.dev || current.ino !== expected.ino) {
      throw new ReplayStoreError(
        "UNSAFE_STATE_DIRECTORY",
        "replay state directory changed after validation",
      );
    }
  }

  async #syncDirectory(): Promise<void> {
    await this.#assertDirectoryIdentity();
    const expected = this.#preparedIdentity!;
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        this.#directory,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      const stats = await handle.stat({ bigint: true });
      if (
        !stats.isDirectory() ||
        stats.dev !== expected.dev ||
        stats.ino !== expected.ino ||
        Number(stats.mode & 0o777n) !== 0o700 ||
        !isOwnedByCurrentUser(stats.uid)
      ) {
        throw new Error("replay directory identity changed before fsync");
      }
      await handle.sync();
    } catch (error) {
      throw new ReplayStoreError(
        "STATE_WRITE_FAILED",
        "replay state directory could not be persisted",
        { cause: error },
      );
    } finally {
      await handle?.close().catch(() => undefined);
    }
    await this.#assertDirectoryIdentity();
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

async function collectFailure(
  existing: unknown,
  operation: () => Promise<unknown>,
  message: string,
): Promise<unknown> {
  try {
    await operation();
    return existing;
  } catch (error) {
    return existing === undefined
      ? error
      : new AggregateError([existing, error], message);
  }
}

function assertSafeDirectory(
  stats: BigIntStats,
  canonicalPath: string,
  expectedPath: string,
): void {
  if (
    stats.isSymbolicLink() ||
    !stats.isDirectory() ||
    canonicalPath !== expectedPath
  ) {
    throw new ReplayStoreError(
      "UNSAFE_STATE_DIRECTORY",
      "replay state directory must be a real, non-symlink directory",
    );
  }
  if (Number(stats.mode & 0o777n) !== 0o700) {
    throw new ReplayStoreError(
      "UNSAFE_STATE_DIRECTORY",
      "replay state directory permissions must be 0700",
    );
  }
  if (!isOwnedByCurrentUser(stats.uid)) {
    throw new ReplayStoreError(
      "UNSAFE_STATE_DIRECTORY",
      "replay state directory must be owned by the current user",
    );
  }
}

function assertSafePrivateFile(
  stats: BigIntStats,
  allowedLinks: ReadonlySet<bigint>,
  allowEmpty: boolean,
): void {
  if (
    stats.isSymbolicLink() ||
    !stats.isFile() ||
    !allowedLinks.has(stats.nlink) ||
    Number(stats.mode & 0o777n) !== 0o600 ||
    !isOwnedByCurrentUser(stats.uid) ||
    stats.size > BigInt(MARKER_MAX_BYTES) ||
    (!allowEmpty && stats.size <= 0n)
  ) {
    throw new ReplayStoreError(
      "STATE_WRITE_FAILED",
      "replay marker file metadata is unsafe",
    );
  }
}

function isOwnedByCurrentUser(uid: bigint): boolean {
  return typeof process.getuid !== "function" || Number(uid) === process.getuid();
}

function sameIdentity(
  left: Pick<BigIntStats, "dev" | "ino"> | FileIdentity,
  right: Pick<BigIntStats, "dev" | "ino"> | FileIdentity,
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameStableFile(left: BigIntStats, right: BigIntStats): boolean {
  return (
    sameIdentity(left, right) &&
    left.size === right.size &&
    left.nlink === right.nlink &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function readBoundedUtf8(
  handle: FileHandle,
  maxBytes: number,
): Promise<string> {
  const buffer = Buffer.alloc(maxBytes + 1);
  let offset = 0;
  while (offset <= maxBytes) {
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      buffer.length - offset,
      offset,
    );
    if (bytesRead === 0) break;
    offset += bytesRead;
    if (offset > maxBytes) {
      throw new Error("replay marker exceeds the persistence limit");
    }
  }
  return buffer.subarray(0, offset).toString("utf8");
}

function normalizeReplayMetadata(metadata: unknown): ReplayMetadata {
  const object = assertExactRecord(metadata, V1_KEYS);
  const claimedAt = object.claimedAt;
  const timestamp = typeof claimedAt === "string" ? new Date(claimedAt) : null;
  if (
    object.schema !== REPLAY_MARKER_SCHEMA ||
    timestamp === null ||
    Number.isNaN(timestamp.valueOf()) ||
    timestamp.toISOString() !== claimedAt ||
    !Number.isSafeInteger(object.chainId) ||
    (object.chainId as number) <= 0 ||
    typeof object.tokenId !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/.test(object.tokenId) ||
    typeof object.endpointHash !== "string" ||
    !SHA256_PATTERN.test(object.endpointHash) ||
    typeof object.provider !== "string" ||
    !/^0x[a-f0-9]{40}$/.test(object.provider) ||
    typeof object.commerceContract !== "string" ||
    !/^0x[a-f0-9]{40}$/.test(object.commerceContract) ||
    typeof object.negotiationHash !== "string" ||
    !/^0x[a-f0-9]{64}$/.test(object.negotiationHash)
  ) {
    throw invalidMetadata();
  }

  return Object.freeze({
    schema: REPLAY_MARKER_SCHEMA,
    claimedAt,
    chainId: object.chainId as number,
    tokenId: object.tokenId,
    endpointHash: object.endpointHash,
    provider: object.provider,
    commerceContract: object.commerceContract,
    negotiationHash: object.negotiationHash,
  });
}

function normalizeActivationReplayMetadata(
  metadata: unknown,
): ActivationReplayMetadata {
  const object = assertExactRecord(metadata, V2_KEYS);
  const replay = normalizeReplayMetadata({
    schema: REPLAY_MARKER_SCHEMA,
    claimedAt: object.claimedAt,
    chainId: object.chainId,
    tokenId: object.tokenId,
    endpointHash: object.endpointHash,
    provider: object.provider,
    commerceContract: object.commerceContract,
    negotiationHash: object.negotiationHash,
  });
  if (
    object.schema !== ACTIVATION_REPLAY_MARKER_SCHEMA ||
    typeof object.activationHeadSha256 !== "string" ||
    !SHA256_PATTERN.test(object.activationHeadSha256)
  ) {
    throw invalidMetadata();
  }
  const activationHead = normalizeActivationHead(object.activationHead);
  const activationHeadSha256 = computeActivationHeadSha256(activationHead);
  if (activationHeadSha256 !== object.activationHeadSha256) {
    throw invalidMetadata();
  }
  return Object.freeze({
    schema: ACTIVATION_REPLAY_MARKER_SCHEMA,
    claimedAt: replay.claimedAt,
    chainId: replay.chainId,
    tokenId: replay.tokenId,
    endpointHash: replay.endpointHash,
    provider: replay.provider,
    commerceContract: replay.commerceContract,
    negotiationHash: replay.negotiationHash,
    activationHead,
    activationHeadSha256,
  });
}

function normalizeActivationHead(head: unknown): ActivationHead {
  let parsed: ActivationHead;
  try {
    parsed = activationHeadSchema.parse(head);
  } catch (error) {
    throw new ReplayStoreError(
      "STATE_WRITE_FAILED",
      "activation replay head is invalid",
      { cause: error },
    );
  }
  if (
    parsed.stateFile !==
      `state-v1-${parsed.activationId}-${parsed.sequence}-${parsed.stateSha256}.json` ||
    parsed.reportFile !==
      `report-v1-${parsed.activationId}-${parsed.sequence}-${parsed.reportSha256}.json`
  ) {
    throw new ReplayStoreError(
      "STATE_WRITE_FAILED",
      "activation replay head filenames do not match their content addresses",
    );
  }
  return Object.freeze({ ...parsed });
}

function assertExactRecord(
  value: unknown,
  expectedKeys: readonly string[],
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    throw invalidMetadata();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== expectedKeys.length ||
    ownKeys.some(
      (key) => typeof key !== "string" || !expectedKeys.includes(key),
    )
  ) {
    throw invalidMetadata();
  }
  return value as Record<string, unknown>;
}

function invalidMetadata(): ReplayStoreError {
  return new ReplayStoreError(
    "STATE_WRITE_FAILED",
    "replay metadata is invalid",
  );
}

function parseStoredMarker(raw: string): StoredMarker {
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch (error) {
    throw new ReplayStoreError(
      "STATE_WRITE_FAILED",
      "replay marker is not valid JSON",
      { cause: error },
    );
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalidMetadata();
  }
  const schema = (value as Record<string, unknown>).schema;
  if (schema === REPLAY_MARKER_SCHEMA) {
    const metadata = normalizeReplayMetadata(value);
    if (raw !== serializeReplayMetadata(metadata)) throw invalidMetadata();
    return { version: 1, metadata };
  }
  if (schema === ACTIVATION_REPLAY_MARKER_SCHEMA) {
    const metadata = normalizeActivationReplayMetadata(value);
    if (raw !== serializeActivationReplayMetadata(metadata)) {
      throw invalidMetadata();
    }
    return { version: 2, metadata };
  }
  throw invalidMetadata();
}

function serializeReplayMetadata(metadata: ReplayMetadata): string {
  return `${JSON.stringify(normalizeReplayMetadata(metadata))}\n`;
}

function serializeActivationReplayMetadata(
  metadata: ActivationReplayMetadata,
): string {
  return `${canonicalQuoteJson(normalizeActivationReplayMetadata(metadata))}\n`;
}

function serializeStoredMarker(marker: StoredMarker): string {
  return marker.version === 1
    ? serializeReplayMetadata(marker.metadata)
    : serializeActivationReplayMetadata(marker.metadata);
}

function replayKeyForMetadata(
  metadata: ReplayMetadata | ActivationReplayMetadata,
): string {
  return computeQuoteReplayKey({
    chainId: metadata.chainId,
    tokenId: metadata.tokenId,
    endpointHash: metadata.endpointHash,
    provider: metadata.provider,
    commerceContract: metadata.commerceContract,
    negotiationHash: metadata.negotiationHash,
  });
}

function sameReplayDomain(
  left: ReplayMetadata | ActivationReplayMetadata,
  right: ReplayMetadata | ActivationReplayMetadata,
): boolean {
  return (
    left.chainId === right.chainId &&
    left.tokenId === right.tokenId &&
    left.endpointHash === right.endpointHash &&
    left.provider === right.provider &&
    left.commerceContract === right.commerceContract &&
    left.negotiationHash === right.negotiationHash
  );
}

function sameActivationBinding(
  left: ActivationReplayMetadata,
  right: ActivationReplayMetadata,
): boolean {
  return (
    left.activationHeadSha256 === right.activationHeadSha256 &&
    canonicalQuoteJson(left.activationHead) ===
      canonicalQuoteJson(right.activationHead)
  );
}

function temporaryMarkerName(key: string, nonce: string): string {
  return `.quote-replay-${key}-${nonce}.tmp`;
}

function isTemporaryMarkerName(name: string, key: string): boolean {
  const prefix = `.quote-replay-${key}-`;
  if (!name.startsWith(prefix) || !name.endsWith(".tmp")) return false;
  const nonce = name.slice(prefix.length, -".tmp".length);
  return TEMP_NONCE_PATTERN.test(nonce);
}
