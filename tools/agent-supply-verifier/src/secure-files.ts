import { constants, type BigIntStats } from "node:fs";
import {
  type FileHandle,
  lstat,
  open,
  realpath,
} from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

export type SecureFileMode = "owned-input" | "operator-private";

export class SecureFileError extends Error {
  readonly code:
    | "INVALID_PATH"
    | "UNSAFE_FILE"
    | "UNSAFE_DIRECTORY"
    | "FILE_TOO_LARGE"
    | "FILE_EXISTS"
    | "READ_FAILED"
    | "WRITE_FAILED";

  constructor(
    code: SecureFileError["code"],
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "SecureFileError";
    this.code = code;
  }
}

export async function readSecureJsonFile(
  path: string,
  options: Readonly<{
    maxBytes: number;
    mode: SecureFileMode;
  }>,
): Promise<unknown> {
  try {
    return JSON.parse(await readSecureTextFile(path, options)) as unknown;
  } catch (error) {
    if (error instanceof SecureFileError) throw error;
    throw new SecureFileError("READ_FAILED", "input file could not be read", {
      cause: error,
    });
  }
}

export async function readSecureTextFile(
  path: string,
  options: Readonly<{
    maxBytes: number;
    mode: SecureFileMode;
  }>,
): Promise<string> {
  assertCanonicalAbsolutePath(path);
  const parent = dirname(path);
  let directoryHandle: FileHandle | undefined;
  let directoryIdentity: FileIdentity | undefined;
  let handle: FileHandle | undefined;
  try {
    ({ handle: directoryHandle, identity: directoryIdentity } =
      await openSafeInputDirectory(parent, options.mode));
    await assertDirectoryPathIdentity(
      parent,
      directoryIdentity,
      options.mode,
    );

    const canonicalPath = await realpath(path);
    if (canonicalPath !== path) {
      throw new SecureFileError(
        "UNSAFE_FILE",
        "input file path must not contain symbolic links",
      );
    }
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    assertSafeFileStat(before, options.mode);
    await assertFilePathIdentity(path, before);
    await assertDirectoryPathIdentity(
      parent,
      directoryIdentity,
      options.mode,
    );
    if (before.size > BigInt(options.maxBytes)) {
      throw new SecureFileError(
        "FILE_TOO_LARGE",
        "input file exceeds its size limit",
      );
    }
    const raw = await handle.readFile({ encoding: "utf8" });
    const after = await handle.stat({ bigint: true });
    assertSafeFileStat(after, options.mode);
    if (
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size ||
      after.ctimeNs !== before.ctimeNs ||
      after.mtimeNs !== before.mtimeNs ||
      Buffer.byteLength(raw, "utf8") > options.maxBytes
    ) {
      throw new SecureFileError(
        "UNSAFE_FILE",
        "input file changed while it was being read",
      );
    }
    await assertFilePathIdentity(path, after);
    await assertDirectoryPathIdentity(
      parent,
      directoryIdentity,
      options.mode,
    );
    return raw;
  } catch (error) {
    if (error instanceof SecureFileError) throw error;
    throw new SecureFileError("READ_FAILED", "input file could not be read", {
      cause: error,
    });
  } finally {
    await handle?.close().catch(() => undefined);
    await directoryHandle?.close().catch(() => undefined);
  }
}

export async function writePrivateFileExclusive(
  path: string,
  contents: string,
): Promise<void> {
  assertCanonicalAbsolutePath(path);
  const parent = dirname(path);
  await assertPrivateDirectory(parent);

  let handle;
  let identity: { dev: bigint; ino: bigint } | undefined;
  try {
    handle = await open(
      path,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    const created = await handle.stat({ bigint: true });
    assertSafeFileStat(created, "operator-private");
    identity = { dev: created.dev, ino: created.ino };
    await handle.writeFile(contents, { encoding: "utf8" });
    await handle.sync();
  } catch (error) {
    if (isNodeError(error) && error.code === "EEXIST") {
      throw new SecureFileError(
        "FILE_EXISTS",
        "output file already exists",
        { cause: error },
      );
    }
    if (error instanceof SecureFileError) throw error;
    throw new SecureFileError("WRITE_FAILED", "output file could not be written", {
      cause: error,
    });
  } finally {
    await handle?.close().catch(() => undefined);
  }

  try {
    const written = await lstat(path, { bigint: true });
    assertSafeFileStat(written, "operator-private");
    if (
      identity === undefined ||
      written.dev !== identity.dev ||
      written.ino !== identity.ino
    ) {
      throw new Error("output identity changed");
    }
    await syncDirectory(parent);
    await assertPrivateDirectory(parent);
  } catch (error) {
    if (error instanceof SecureFileError) throw error;
    throw new SecureFileError(
      "WRITE_FAILED",
      "output file could not be verified",
      { cause: error },
    );
  }
}

export async function assertPrivateOutputAvailable(path: string): Promise<void> {
  assertCanonicalAbsolutePath(path);
  await assertPrivateDirectory(dirname(path));
  try {
    await lstat(path);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return;
    throw new SecureFileError(
      "WRITE_FAILED",
      "output path could not be inspected",
      { cause: error },
    );
  }
  throw new SecureFileError("FILE_EXISTS", "output file already exists");
}

export async function assertPrivateDirectory(path: string): Promise<void> {
  assertCanonicalAbsolutePath(path);
  let canonicalPath: string;
  let stats;
  try {
    [canonicalPath, stats] = await Promise.all([
      realpath(path),
      lstat(path, { bigint: true }),
    ]);
  } catch (error) {
    throw new SecureFileError(
      "UNSAFE_DIRECTORY",
      "private directory is unavailable",
      { cause: error },
    );
  }
  if (
    canonicalPath !== path ||
    stats.isSymbolicLink() ||
    !stats.isDirectory() ||
    Number(stats.mode & 0o777n) !== 0o700 ||
    !isOwnedByCurrentUser(stats.uid)
  ) {
    throw new SecureFileError(
      "UNSAFE_DIRECTORY",
      "private directory must be canonical, owner-only, and mode 0700",
    );
  }
}

interface FileIdentity {
  readonly dev: bigint;
  readonly ino: bigint;
}

async function openSafeInputDirectory(
  path: string,
  mode: SecureFileMode,
): Promise<{ handle: FileHandle; identity: FileIdentity }> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const stats = await handle.stat({ bigint: true });
    assertSafeDirectoryStat(stats, mode);
    return {
      handle,
      identity: { dev: stats.dev, ino: stats.ino },
    };
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error instanceof SecureFileError) throw error;
    throw new SecureFileError(
      "UNSAFE_DIRECTORY",
      "input directory is unavailable",
      { cause: error },
    );
  }
}

async function assertDirectoryPathIdentity(
  path: string,
  expected: FileIdentity,
  mode: SecureFileMode,
): Promise<void> {
  let canonicalPath: string;
  let stats: BigIntStats;
  try {
    [canonicalPath, stats] = await Promise.all([
      realpath(path),
      lstat(path, { bigint: true }),
    ]);
  } catch (error) {
    throw new SecureFileError(
      "UNSAFE_DIRECTORY",
      "input directory identity could not be verified",
      { cause: error },
    );
  }
  assertSafeDirectoryStat(stats, mode);
  if (
    canonicalPath !== path ||
    stats.dev !== expected.dev ||
    stats.ino !== expected.ino
  ) {
    throw new SecureFileError(
      "UNSAFE_DIRECTORY",
      "input directory changed while the file was being read",
    );
  }
}

async function assertFilePathIdentity(
  path: string,
  expected: FileIdentity,
): Promise<void> {
  let stats: BigIntStats;
  try {
    stats = await lstat(path, { bigint: true });
  } catch (error) {
    throw new SecureFileError(
      "UNSAFE_FILE",
      "input file identity could not be verified",
      { cause: error },
    );
  }
  if (
    stats.isSymbolicLink() ||
    stats.dev !== expected.dev ||
    stats.ino !== expected.ino
  ) {
    throw new SecureFileError(
      "UNSAFE_FILE",
      "input file path changed while it was being read",
    );
  }
}

function assertSafeDirectoryStat(
  stats: BigIntStats,
  mode: SecureFileMode,
): void {
  const permissions = Number(stats.mode & 0o777n);
  const safePermissions =
    mode === "operator-private"
      ? permissions === 0o700
      : (permissions & 0o022) === 0;
  if (
    !stats.isDirectory() ||
    !safePermissions ||
    !isOwnedByCurrentUser(stats.uid)
  ) {
    throw new SecureFileError(
      "UNSAFE_DIRECTORY",
      mode === "operator-private"
        ? "operator input directory must be owner-only and mode 0700"
        : "input directory must be owned by the current user and not group/world writable",
    );
  }
}

function assertSafeFileStat(
  stats: BigIntStats,
  mode: SecureFileMode,
): void {
  const permissions = Number(stats.mode & 0o777n);
  const safePermissions =
    mode === "operator-private"
      ? permissions === 0o600
      : (permissions & 0o022) === 0;
  if (
    !stats.isFile() ||
    stats.nlink !== 1n ||
    !safePermissions ||
    !isOwnedByCurrentUser(stats.uid)
  ) {
    throw new SecureFileError(
      "UNSAFE_FILE",
      mode === "operator-private"
        ? "operator file must be owner-only and mode 0600"
        : "input file must be owned by the current user and not group/world writable",
    );
  }
}

function assertCanonicalAbsolutePath(path: string): void {
  if (!isAbsolute(path) || resolve(path) !== path) {
    throw new SecureFileError(
      "INVALID_PATH",
      "file path must be absolute and canonical",
    );
  }
}

function isOwnedByCurrentUser(uid: bigint): boolean {
  return typeof process.getuid !== "function" || Number(uid) === process.getuid();
}

async function syncDirectory(path: string): Promise<void> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY);
    await handle.sync();
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
