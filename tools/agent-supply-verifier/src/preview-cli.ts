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
import { FileReplayStore, type ReplayStore } from "./quotes/replay.js";
import {
  MIN_QUOTE_REMAINING_SECONDS,
  quoteMandatexRebalanceMandateSchema,
  quoteTrustFileSchema,
} from "./quotes/schema.js";
import { PinnedHttpsTransport } from "./transport/http.js";
import {
  rebalanceTransactionPlanSchema,
  type RebalancePreviewSidecar,
} from "./preview/schema.js";
import {
  serializeRebalancePreviewSidecar,
  validateTrustedPreview,
  type ValidateTrustedPreviewOptions,
} from "./preview/validate.js";

const INPUT_LIMITS = Object.freeze({
  manifest: 128 * 1024,
  passiveReport: 4 * 1024 * 1024,
  trust: 128 * 1024,
  mandate: 64 * 1024,
  transactionPlan: 64 * 1024,
});

type TextWriter = Readonly<{ write(chunk: string): unknown }>;

export interface PreviewCliDependencies {
  readonly stdout?: TextWriter;
  readonly stderr?: TextWriter;
  readonly transport?: ValidateTrustedPreviewOptions["transport"];
  readonly replayStoreFactory?: (directory: string) => ReplayStore;
  readonly validate?: (
    options: ValidateTrustedPreviewOptions,
  ) => Promise<RebalancePreviewSidecar>;
}

export async function runPreviewCli(
  argv: readonly string[],
  dependencies: PreviewCliDependencies = {},
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
        "transaction-plan": { type: "string" },
        "state-dir": { type: "string" },
        out: { type: "string", short: "o" },
        "chain-id": { type: "string" },
        "token-id": { type: "string" },
        "ack-actionable-quote": { type: "boolean", default: false },
        "ack-operator-calldata-preview": {
          type: "boolean",
          default: false,
        },
        help: { type: "boolean", short: "h", default: false },
      },
    });

    if (parsed.values.help) {
      stdout.write(previewHelp());
      return 0;
    }
    if (!parsed.values["ack-actionable-quote"]) {
      throw new Error(
        "transaction preview requires --ack-actionable-quote in this invocation",
      );
    }
    if (!parsed.values["ack-operator-calldata-preview"]) {
      throw new Error(
        "transaction preview requires --ack-operator-calldata-preview in this invocation",
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
    const transactionPlanPath = resolve(
      requiredString(parsed.values["transaction-plan"], "--transaction-plan"),
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

    const [
      rawManifest,
      rawPassiveReport,
      rawTrust,
      rawMandate,
      rawTransactionPlan,
    ] = await Promise.all([
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
      readSecureJsonFile(transactionPlanPath, {
        maxBytes: INPUT_LIMITS.transactionPlan,
        mode: "operator-private",
      }),
    ]);

    const manifest = manifestFileSchema.parse(rawManifest);
    const passiveReport = runReportSchema.parse(rawPassiveReport);
    const trustFile = quoteTrustFileSchema.parse(rawTrust);
    const mandate = quoteMandatexRebalanceMandateSchema.parse(rawMandate);
    const transactionPlan = rebalanceTransactionPlanSchema.parse(
      rawTransactionPlan,
    );
    const replayStore = (
      dependencies.replayStoreFactory ??
      ((directory: string) => new FileReplayStore(directory))
    )(stateDirectory);
    const sidecar = await (dependencies.validate ?? validateTrustedPreview)({
      manifest,
      passiveReport,
      trustFile,
      mandate,
      transactionPlan,
      candidate: { chainId, tokenId },
      transport: dependencies.transport ?? new PinnedHttpsTransport(),
      replayStore,
    });
    const serialized = serializeRebalancePreviewSidecar(sidecar);
    await writePrivateFileExclusive(outputPath, serialized);
    stdout.write(serialized);
    return exitCodeForOutcome(sidecar.outcome);
  } catch (error) {
    stderr.write(
      `${JSON.stringify({
        error: "PREVIEW_VERIFIER_FAILED",
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
    throw new Error(`${option} is required for transaction preview`);
  }
  return value;
}

function parseChainId(value: string): 56 {
  if (value !== "56") {
    throw new Error("transaction preview currently supports chain id 56 only");
  }
  return 56;
}

function parseTokenId(value: string): string {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error("--token-id must be a canonical unsigned decimal integer");
  }
  return value;
}

function exitCodeForOutcome(
  outcome: RebalancePreviewSidecar["outcome"],
): number {
  switch (outcome) {
    case "preview_simulation_passed":
      return 0;
    case "inconclusive":
      return 2;
    case "refused":
      return 3;
    case "invalid":
      return 4;
  }
}

function previewHelp(): string {
  return [
    "MandateX trusted rebalance transaction preview",
    "",
    "This command sends one actionable quote request and simulates one exact",
    "operator-supplied calldata plan. It never signs, submits, funds, creates,",
    "settles, or delivers a job or transaction.",
    "",
    "Usage:",
    "  corepack pnpm run verify:preview -- \\",
    "    --ack-actionable-quote \\",
    "    --ack-operator-calldata-preview \\",
    "    --candidates /absolute/path/candidates.json \\",
    "    --passive-report /absolute/path/passive-report.json \\",
    "    --trust /absolute/path/quote-trust.json \\",
    "    --mandate /absolute/path/mandate.json \\",
    "    --transaction-plan /absolute/path/transaction-plan.json \\",
    "    --state-dir /absolute/path/replay-state \\",
    "    --out /absolute/path/preview-sidecar.json \\",
    "    --chain-id 56 --token-id 265375",
    "",
    "Trust, mandate, and transaction-plan files must be mode 0600 inside",
    "owner-only 0700 directories. State/output directories must also be 0700.",
    "The output file must not already exist.",
    `A pass still requires at least ${MIN_QUOTE_REMAINING_SECONDS} seconds of quote, mandate, permission, and transaction deadline life at decision time.`,
    "PREVIEW_SIMULATION_PASSED is historical structural evidence only. It does",
    "not declare hireability or prove profitability or future execution.",
    "",
    "Exit codes: 0 preview passed, 2 inconclusive, 3 refused, 4 invalid, 1 input/internal error.",
    "",
  ].join("\n");
}

const entrypoint = process.argv[1];
if (
  entrypoint !== undefined &&
  import.meta.url === pathToFileURL(resolve(entrypoint)).href
) {
  process.exitCode = await runPreviewCli(process.argv.slice(2));
}
