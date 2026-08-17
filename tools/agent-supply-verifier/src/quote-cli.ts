import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { redactErrorMessage } from "./report.js";
import { manifestFileSchema, runReportSchema } from "./schema.js";
import {
  assertPrivateDirectory,
  assertPrivateOutputAvailable,
  readSecureJsonFile,
  writePrivateFileExclusive,
} from "./secure-files.js";
import { PinnedHttpsTransport } from "./transport/http.js";
import { serializeQuoteSidecar } from "./quotes/protocol.js";
import { FileReplayStore, type ReplayStore } from "./quotes/replay.js";
import {
  MIN_QUOTE_REMAINING_SECONDS,
  quoteMandatexRebalanceMandateSchema,
  quoteTrustFileSchema,
  type QuoteSidecar,
} from "./quotes/schema.js";
import {
  validateTrustedQuote,
  type ValidateTrustedQuoteOptions,
} from "./quotes/validate.js";

const INPUT_LIMITS = Object.freeze({
  manifest: 128 * 1024,
  passiveReport: 4 * 1024 * 1024,
  trust: 128 * 1024,
  mandate: 64 * 1024,
});

type TextWriter = Readonly<{ write(chunk: string): unknown }>;

export interface QuoteCliDependencies {
  readonly stdout?: TextWriter;
  readonly stderr?: TextWriter;
  readonly transport?: ValidateTrustedQuoteOptions["transport"];
  readonly replayStoreFactory?: (directory: string) => ReplayStore;
  readonly validate?: (
    options: ValidateTrustedQuoteOptions,
  ) => Promise<QuoteSidecar>;
}

export async function runQuoteCli(
  argv: readonly string[],
  dependencies: QuoteCliDependencies = {},
): Promise<number> {
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;

  try {
    const normalizedArgv = argv[0] === "--" ? argv.slice(1) : argv;
    const parsed = parseArgs({
      args: [...normalizedArgv],
      strict: true,
      allowPositionals: false,
      options: {
        candidates: { type: "string" },
        "passive-report": { type: "string" },
        trust: { type: "string" },
        mandate: { type: "string" },
        "state-dir": { type: "string" },
        out: { type: "string", short: "o" },
        "chain-id": { type: "string" },
        "token-id": { type: "string" },
        "ack-actionable-quote": { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });

    if (parsed.values.help) {
      stdout.write(quoteHelp());
      return 0;
    }
    if (!parsed.values["ack-actionable-quote"]) {
      throw new Error(
        "active quote validation requires --ack-actionable-quote in this invocation",
      );
    }

    const candidatesPath = resolve(
      requiredString(parsed.values.candidates, "--candidates"),
    );
    const passiveReportPath = resolve(
      requiredString(parsed.values["passive-report"], "--passive-report"),
    );
    const trustPath = resolve(requiredString(parsed.values.trust, "--trust"));
    const mandatePath = resolve(
      requiredString(parsed.values.mandate, "--mandate"),
    );
    const stateDirectory = resolve(
      requiredString(parsed.values["state-dir"], "--state-dir"),
    );
    const outputPath = resolve(requiredString(parsed.values.out, "--out"));
    const chainId = parseChainId(
      requiredString(parsed.values["chain-id"], "--chain-id"),
    );
    const tokenId = parseTokenId(
      requiredString(parsed.values["token-id"], "--token-id"),
    );

    await Promise.all([
      assertPrivateDirectory(stateDirectory),
      assertPrivateDirectory(dirname(outputPath)),
      assertPrivateOutputAvailable(outputPath),
    ]);

    const [rawManifest, rawPassiveReport, rawTrust, rawMandate] =
      await Promise.all([
        readSecureJsonFile(candidatesPath, {
          maxBytes: INPUT_LIMITS.manifest,
          mode: "owned-input",
        }),
        readSecureJsonFile(passiveReportPath, {
          maxBytes: INPUT_LIMITS.passiveReport,
          mode: "owned-input",
        }),
        readSecureJsonFile(trustPath, {
          maxBytes: INPUT_LIMITS.trust,
          mode: "operator-private",
        }),
        readSecureJsonFile(mandatePath, {
          maxBytes: INPUT_LIMITS.mandate,
          mode: "operator-private",
        }),
      ]);

    const manifest = manifestFileSchema.parse(rawManifest);
    const passiveReport = runReportSchema.parse(rawPassiveReport);
    const trustFile = quoteTrustFileSchema.parse(rawTrust);
    const mandate = quoteMandatexRebalanceMandateSchema.parse(rawMandate);
    const replayStore = (
      dependencies.replayStoreFactory ??
      ((directory: string) => new FileReplayStore(directory))
    )(stateDirectory);
    const sidecar = await (dependencies.validate ?? validateTrustedQuote)({
      manifest,
      passiveReport,
      trustFile,
      mandate,
      candidate: { chainId, tokenId },
      transport: dependencies.transport ?? new PinnedHttpsTransport(),
      replayStore,
    });
    const serialized = serializeQuoteSidecar(sidecar);
    await writePrivateFileExclusive(outputPath, serialized);
    stdout.write(serialized);
    return exitCodeForOutcome(sidecar.outcome);
  } catch (error) {
    stderr.write(
      `${JSON.stringify({
        error: "QUOTE_VERIFIER_FAILED",
        message: redactErrorMessage(error),
      })}\n`,
    );
    return 1;
  }
}

function requiredString(
  value: string | boolean | undefined,
  option: string,
): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${option} is required for active quote validation`);
  }
  return value;
}

function parseChainId(value: string): 56 {
  if (value !== "56") {
    throw new Error("active quote validation currently supports chain id 56 only");
  }
  return 56;
}

function parseTokenId(value: string): string {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error("--token-id must be a canonical unsigned decimal integer");
  }
  return value;
}

function exitCodeForOutcome(outcome: QuoteSidecar["outcome"]): number {
  switch (outcome) {
    case "valid":
      return 0;
    case "inconclusive":
      return 2;
    case "refused":
      return 3;
    case "invalid":
      return 4;
  }
}

function quoteHelp(): string {
  return [
    "MandateX trusted active quote validator",
    "",
    "This command sends one actionable negotiate request. It never creates, funds,",
    "settles, or delivers a job.",
    "",
    "Usage:",
    "  corepack pnpm run verify:quote -- \\",
    "    --ack-actionable-quote \\",
    "    --candidates /absolute/path/candidates.json \\",
    "    --passive-report /absolute/path/passive-report.json \\",
    "    --trust /absolute/path/quote-trust.json \\",
    "    --mandate /absolute/path/mandate.json \\",
    "    --state-dir /absolute/path/replay-state \\",
    "    --out /absolute/path/quote-sidecar.json \\",
    "    --chain-id 56 --token-id 265375",
    "",
    "Trust and mandate files must be mode 0600 inside owner-only 0700 directories.",
    "State and output directories must also be owned by the current user and 0700.",
    "The output file must not already exist.",
    `Valid output requires at least ${MIN_QUOTE_REMAINING_SECONDS} seconds of quote lifetime at decision time.`,
    "",
    "Exit codes: 0 valid, 2 inconclusive, 3 refused, 4 invalid, 1 input/internal error.",
    "",
  ].join("\n");
}

const entrypoint = process.argv[1];
if (
  entrypoint !== undefined &&
  import.meta.url === pathToFileURL(resolve(entrypoint)).href
) {
  process.exitCode = await runQuoteCli(process.argv.slice(2));
}
