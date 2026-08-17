import assert from "node:assert/strict";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  readSecureJsonFile,
  SecureFileError,
} from "../src/secure-files.js";

test("secure input loading accepts the intended directory and file modes", async () => {
  const root = await privateTemporaryDirectory();
  try {
    const privatePath = join(root, "private.json");
    await writeFile(privatePath, '{"kind":"private"}\n', { mode: 0o600 });
    await chmod(privatePath, 0o600);

    assert.deepEqual(
      await readSecureJsonFile(privatePath, {
        maxBytes: 1_024,
        mode: "operator-private",
      }),
      { kind: "private" },
    );

    const publicDirectory = join(root, "config");
    await mkdir(publicDirectory, { mode: 0o755 });
    await chmod(publicDirectory, 0o755);
    const publicPath = join(publicDirectory, "owned.json");
    await writeFile(publicPath, '{"kind":"owned"}\n', { mode: 0o644 });
    await chmod(publicPath, 0o644);

    assert.deepEqual(
      await readSecureJsonFile(publicPath, {
        maxBytes: 1_024,
        mode: "owned-input",
      }),
      { kind: "owned" },
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("operator-private inputs require an owner-only parent directory", async () => {
  const root = await privateTemporaryDirectory();
  try {
    const path = join(root, "private.json");
    await writeFile(path, "{}\n", { mode: 0o600 });
    await chmod(path, 0o600);
    await chmod(root, 0o755);

    await assert.rejects(
      readSecureJsonFile(path, {
        maxBytes: 1_024,
        mode: "operator-private",
      }),
      hasSecureFileCode("UNSAFE_DIRECTORY"),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("owned inputs reject a group-writable parent directory", async () => {
  const root = await privateTemporaryDirectory();
  try {
    const path = join(root, "owned.json");
    await writeFile(path, "{}\n", { mode: 0o644 });
    await chmod(path, 0o644);
    await chmod(root, 0o770);

    await assert.rejects(
      readSecureJsonFile(path, {
        maxBytes: 1_024,
        mode: "owned-input",
      }),
      hasSecureFileCode("UNSAFE_DIRECTORY"),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("secure input loading rejects a symlinked parent directory", async () => {
  const root = await privateTemporaryDirectory();
  try {
    const target = join(root, "target");
    const alias = join(root, "alias");
    await mkdir(target, { mode: 0o700 });
    await chmod(target, 0o700);
    await symlink(target, alias, "dir");
    const targetPath = join(target, "private.json");
    await writeFile(targetPath, "{}\n", { mode: 0o600 });
    await chmod(targetPath, 0o600);

    await assert.rejects(
      readSecureJsonFile(join(alias, "private.json"), {
        maxBytes: 1_024,
        mode: "operator-private",
      }),
      hasSecureFileCode("UNSAFE_DIRECTORY"),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("secure input loading rejects hard-linked authority files", async () => {
  const root = await privateTemporaryDirectory();
  try {
    const original = join(root, "original.json");
    const hardLink = join(root, "hard-link.json");
    await writeFile(original, "{}\n", { mode: 0o600 });
    await chmod(original, 0o600);
    await link(original, hardLink);

    await assert.rejects(
      readSecureJsonFile(hardLink, {
        maxBytes: 1_024,
        mode: "operator-private",
      }),
      hasSecureFileCode("UNSAFE_FILE"),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

async function privateTemporaryDirectory(): Promise<string> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "mandatex-secure-files-")),
  );
  await chmod(root, 0o700);
  return root;
}

function hasSecureFileCode(
  code: SecureFileError["code"],
): (error: unknown) => boolean {
  return (error) => error instanceof SecureFileError && error.code === code;
}
