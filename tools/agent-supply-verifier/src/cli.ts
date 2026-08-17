import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { redactErrorMessage, serializeReport } from "./report.js";
import { manifestFileSchema } from "./schema.js";
import { PinnedHttpsTransport } from "./transport/http.js";
import { verifyManifest } from "./verify.js";

export async function runCli(argv: readonly string[]): Promise<number> {
  const normalizedArgv = argv[0] === "--" ? argv.slice(1) : argv;
  const parsed = parseArgs({
    args: [...normalizedArgv],
    strict: true,
    allowPositionals: false,
    options: {
      candidates: { type: "string", short: "c" },
      out: { type: "string", short: "o" },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (parsed.values.help) {
    process.stdout.write(
      [
        "MandateX passive Agent Supply Verifier",
        "",
        "Usage:",
        "  pnpm run verify -- --candidates ./config/candidates.json [--out ./reports/report.json]",
        "",
        "Exit codes: 0 complete, 2 inconclusive, 1 invalid input/internal error.",
        "",
      ].join("\n"),
    );
    return 0;
  }

  try {
    const candidatesPath = resolve(
      parsed.values.candidates ?? "./config/candidates.json",
    );
    const rawManifest = await readFile(candidatesPath, "utf8");
    const manifest = manifestFileSchema.parse(JSON.parse(rawManifest));
    const report = await verifyManifest({
      manifest,
      transport: new PinnedHttpsTransport(),
    });
    const serialized = serializeReport(report);

    if (parsed.values.out !== undefined) {
      await writeFile(resolve(parsed.values.out), serialized, {
        encoding: "utf8",
        mode: 0o600,
      });
    }
    process.stdout.write(serialized);
    return report.runStatus === "inconclusive" ? 2 : 0;
  } catch (error) {
    process.stderr.write(
      `${JSON.stringify({ error: "VERIFIER_FAILED", message: redactErrorMessage(error) })}\n`,
    );
    return 1;
  }
}

const entrypoint = process.argv[1];
if (
  entrypoint !== undefined &&
  import.meta.url === pathToFileURL(resolve(entrypoint)).href
) {
  process.exitCode = await runCli(process.argv.slice(2));
}
