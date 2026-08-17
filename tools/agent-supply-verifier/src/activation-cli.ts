import { randomUUID as nodeRandomUUID } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { redactErrorMessage } from "./report.js";
import { manifestFileSchema, runReportSchema } from "./schema.js";
import { assertPrivateDirectory, readSecureJsonFile } from "./secure-files.js";
import { PinnedHttpsTransport } from "./transport/http.js";
import { FileReplayStore } from "./quotes/replay.js";
import {
  quoteMandatexRebalanceMandateSchema,
  quoteTrustFileSchema,
} from "./quotes/schema.js";
import {
  revalidateTrustedPreviewForFunding,
  serializeRebalancePreviewSidecar,
} from "./preview/validate.js";
import { rebalanceTransactionPlanSchema } from "./preview/schema.js";
import { prepareTrustedActivation } from "./activation/offer.js";
import { observeAndReconcileActivation } from "./activation/reconcile.js";
import { TransportActivationRpc } from "./activation/rpc.js";
import {
  activationStateSha256,
  markActivationBroadcastUnknown,
  prepareNextActivationStep,
  recordActivationSubmission,
  serializeActivationReport,
} from "./activation/state.js";
import {
  persistActivationSnapshot,
  readActivationState,
  readCurrentActivationSnapshot,
} from "./activation/store.js";
import type { ActivationState } from "./activation/schema.js";

const INPUT_LIMITS = Object.freeze({
  manifest: 128 * 1024,
  passiveReport: 4 * 1024 * 1024,
  trust: 128 * 1024,
  mandate: 64 * 1024,
  transactionPlan: 64 * 1024,
});

type TextWriter = Readonly<{ write(chunk: string): unknown }>;
type ActivationRpc = Pick<
  TransportActivationRpc,
  "observeDeployment" | "observeReceipt" | "observeJob"
>;

export interface ActivationCliDependencies {
  readonly stdout?: TextWriter;
  readonly stderr?: TextWriter;
  readonly transport?: Pick<PinnedHttpsTransport, "request">;
  readonly randomUUID?: () => string;
  readonly now?: () => Date;
  readonly activationRpcFactory?: (
    transport: Pick<PinnedHttpsTransport, "request">,
    randomUUID: () => string,
  ) => ActivationRpc;
  readonly prepareTrusted?: typeof prepareTrustedActivation;
  readonly prepareNext?: typeof prepareNextActivationStep;
  readonly revalidateFunding?: typeof revalidateTrustedPreviewForFunding;
  readonly reconcile?: typeof observeAndReconcileActivation;
  readonly persist?: typeof persistActivationSnapshot;
  readonly readState?: typeof readActivationState;
  readonly readCurrent?: typeof readCurrentActivationSnapshot;
}

export async function runActivationCli(
  argv: readonly string[],
  dependencies: ActivationCliDependencies = {},
): Promise<number> {
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  const normalizedArgv = argv[0] === "--" ? argv.slice(1) : argv;
  const command = normalizedArgv[0];

  try {
    if (command === undefined || command === "help" || command === "--help") {
      stdout.write(activationHelp());
      return 0;
    }
    const args = normalizedArgv.slice(1);
    switch (command) {
      case "prepare-create":
        return await prepareCreateCommand(args, dependencies, stdout);
      case "prepare-next":
        return await prepareNextCommand(args, dependencies, stdout);
      case "reconcile":
        return await reconcileCommand(args, dependencies, stdout);
      case "broadcast-unknown":
        return await broadcastUnknownCommand(args, dependencies, stdout);
      default:
        throw new Error("unknown activation command");
    }
  } catch (error) {
    stderr.write(
      `${JSON.stringify({
        error: "ACTIVATION_VERIFIER_FAILED",
        message: redactErrorMessage(error),
      })}\n`,
    );
    return 1;
  }
}

async function prepareCreateCommand(
  argv: readonly string[],
  dependencies: ActivationCliDependencies,
  stdout: TextWriter,
): Promise<number> {
  const parsed = parseArgs({
    args: [...argv],
    strict: true,
    allowPositionals: false,
    options: {
      candidates: { type: "string" },
      "passive-report": { type: "string" },
      trust: { type: "string" },
      mandate: { type: "string" },
      "transaction-plan": { type: "string" },
      "quote-state-dir": { type: "string" },
      "activation-state-dir": { type: "string" },
      "report-dir": { type: "string" },
      "chain-id": { type: "string" },
      "token-id": { type: "string" },
      client: { type: "string" },
      "job-expires-at": { type: "string" },
      "cleanup-owner": { type: "string" },
      "ack-actionable-quote": { type: "boolean", default: false },
      "ack-operator-calldata-preview": { type: "boolean", default: false },
      "ack-public-job-description": { type: "boolean", default: false },
      "ack-buyer-address-not-provider-signed": {
        type: "boolean",
        default: false,
      },
    },
  });
  requireAcknowledgement(
    parsed.values["ack-actionable-quote"],
    "--ack-actionable-quote",
  );
  requireAcknowledgement(
    parsed.values["ack-operator-calldata-preview"],
    "--ack-operator-calldata-preview",
  );
  requireAcknowledgement(
    parsed.values["ack-public-job-description"],
    "--ack-public-job-description",
  );
  requireAcknowledgement(
    parsed.values["ack-buyer-address-not-provider-signed"],
    "--ack-buyer-address-not-provider-signed",
  );

  const paths = {
    candidates: requiredPath(parsed.values.candidates, "--candidates"),
    passiveReport: requiredPath(
      parsed.values["passive-report"],
      "--passive-report",
    ),
    trust: requiredPath(parsed.values.trust, "--trust"),
    mandate: requiredPath(parsed.values.mandate, "--mandate"),
    transactionPlan: requiredPath(
      parsed.values["transaction-plan"],
      "--transaction-plan",
    ),
    quoteStateDirectory: requiredPath(
      parsed.values["quote-state-dir"],
      "--quote-state-dir",
    ),
    activationStateDirectory: requiredPath(
      parsed.values["activation-state-dir"],
      "--activation-state-dir",
    ),
    reportDirectory: requiredPath(parsed.values["report-dir"], "--report-dir"),
  };
  await Promise.all([
    assertPrivateDirectory(paths.quoteStateDirectory),
    assertPrivateDirectory(paths.activationStateDirectory),
    assertPrivateDirectory(paths.reportDirectory),
  ]);
  const [manifestRaw, passiveReportRaw, trustRaw, mandateRaw, planRaw] =
    await Promise.all([
      readSecureJsonFile(paths.candidates, {
        maxBytes: INPUT_LIMITS.manifest,
        mode: "owned-input",
      }),
      readSecureJsonFile(paths.passiveReport, {
        maxBytes: INPUT_LIMITS.passiveReport,
        mode: "owned-input",
      }),
      readSecureJsonFile(paths.trust, {
        maxBytes: INPUT_LIMITS.trust,
        mode: "operator-private",
      }),
      readSecureJsonFile(paths.mandate, {
        maxBytes: INPUT_LIMITS.mandate,
        mode: "operator-private",
      }),
      readSecureJsonFile(paths.transactionPlan, {
        maxBytes: INPUT_LIMITS.transactionPlan,
        mode: "operator-private",
      }),
    ]);

  const transport = activationTransport(dependencies);
  const randomUUID = dependencies.randomUUID ?? nodeRandomUUID;
  const rpc = activationRpc(dependencies, transport, randomUUID);
  const result = await (dependencies.prepareTrusted ?? prepareTrustedActivation)(
    {
      manifest: manifestFileSchema.parse(manifestRaw),
      passiveReport: runReportSchema.parse(passiveReportRaw),
      trustFile: quoteTrustFileSchema.parse(trustRaw),
      mandate: quoteMandatexRebalanceMandateSchema.parse(mandateRaw),
      transactionPlan: rebalanceTransactionPlanSchema.parse(planRaw),
      candidate: {
        chainId: parseChainId(requiredString(parsed.values["chain-id"], "--chain-id")),
        tokenId: parseUint(requiredString(parsed.values["token-id"], "--token-id")),
      },
      transport,
      replayStore: new FileReplayStore(paths.quoteStateDirectory),
      activationStateDirectory: paths.activationStateDirectory,
      reportDirectory: paths.reportDirectory,
      randomUUID,
      ...(dependencies.now === undefined ? {} : { now: dependencies.now }),
      client: requiredString(parsed.values.client, "--client"),
      jobExpiresAt: parseSafeUnixSeconds(
        requiredString(parsed.values["job-expires-at"], "--job-expires-at"),
      ),
      cleanupOwner: parseCleanupOwner(
        requiredString(parsed.values["cleanup-owner"], "--cleanup-owner"),
      ),
      acknowledgePublicJobDescription: true,
      acknowledgeBuyerAddressNotProviderSigned: true,
    },
    { activationRpc: rpc },
  );
  if (result.bootstrap === undefined) {
    stdout.write(serializeRebalancePreviewSidecar(result.previewSidecar));
    return previewExitCode(result.previewSidecar.outcome);
  }
  stdout.write(serializeActivationReport(result.bootstrap.snapshot.report));
  return 0;
}

async function prepareNextCommand(
  argv: readonly string[],
  dependencies: ActivationCliDependencies,
  stdout: TextWriter,
): Promise<number> {
  const parsed = parseArgs({
    args: [...argv],
    strict: true,
    allowPositionals: false,
    options: {
      state: { type: "string" },
      "activation-state-dir": { type: "string" },
      "report-dir": { type: "string" },
      "ack-funding-repreview": { type: "boolean", default: false },
    },
  });
  requireAcknowledgement(
    parsed.values["ack-funding-repreview"],
    "--ack-funding-repreview",
  );
  const directories = outputDirectories(parsed.values);
  const state = await readCurrentStateForCommand(
    parsed.values,
    directories,
    dependencies,
  );
  const transport = activationTransport(dependencies);
  const randomUUID = dependencies.randomUUID ?? nodeRandomUUID;
  let fundingPreview;
  if (state.phase === "BUDGET_CONFIRMED") {
    fundingPreview = await (
      dependencies.revalidateFunding ?? revalidateTrustedPreviewForFunding
    )({
      signedTask: state.signedTask,
      transactionPlan: state.transactionPlan,
      quoteExpiresAt: state.binding.quoteExpiresAt,
      expectedProvider: state.binding.provider,
      agentTokenId: state.binding.tokenId,
      transport,
      randomUUID,
    });
  }
  const rpc = activationRpc(dependencies, transport, randomUUID);
  const deployment = await rpc.observeDeployment();
  if (state.jobId === undefined) {
    throw new Error("prepare-next requires a confirmed activation job");
  }
  const job = await rpc.observeJob(state.jobId, deployment.blockHash);
  const next = await (dependencies.prepareNext ?? prepareNextActivationStep)({
    state,
    deployment,
    job,
    ...(fundingPreview === undefined ? {} : { fundingPreview }),
    ...(dependencies.now === undefined ? {} : { now: dependencies.now() }),
  });
  const persisted = await (dependencies.persist ?? persistActivationSnapshot)({
    state: next,
    ...directories,
  });
  stdout.write(serializeActivationReport(persisted.report));
  return 0;
}

async function reconcileCommand(
  argv: readonly string[],
  dependencies: ActivationCliDependencies,
  stdout: TextWriter,
): Promise<number> {
  const parsed = parseArgs({
    args: [...argv],
    strict: true,
    allowPositionals: false,
    options: {
      state: { type: "string" },
      "transaction-hash": { type: "string" },
      "activation-state-dir": { type: "string" },
      "report-dir": { type: "string" },
      "ack-external-transaction-hash": { type: "boolean", default: false },
      "ack-cli-never-signs-or-broadcasts": { type: "boolean", default: false },
    },
  });
  requireAcknowledgement(
    parsed.values["ack-external-transaction-hash"],
    "--ack-external-transaction-hash",
  );
  requireAcknowledgement(
    parsed.values["ack-cli-never-signs-or-broadcasts"],
    "--ack-cli-never-signs-or-broadcasts",
  );
  const directories = outputDirectories(parsed.values);
  let state = await readCurrentStateForCommand(
    parsed.values,
    directories,
    dependencies,
  );
  const transactionHash =
    typeof parsed.values["transaction-hash"] === "string"
      ? parsed.values["transaction-hash"]
      : state.submission?.transactionHash;
  if (transactionHash === undefined) {
    throw new Error("--transaction-hash is required for a new reconciliation");
  }
  state = recordActivationSubmission({
    state,
    transactionHash,
    ...(dependencies.now === undefined ? {} : { now: dependencies.now() }),
  });
  await (dependencies.persist ?? persistActivationSnapshot)({
    state,
    ...directories,
  });

  const transport = activationTransport(dependencies);
  const randomUUID = dependencies.randomUUID ?? nodeRandomUUID;
  const confirmed = await (
    dependencies.reconcile ?? observeAndReconcileActivation
  )({
    state,
    rpc: activationRpc(dependencies, transport, randomUUID),
    ...(dependencies.now === undefined ? {} : { now: dependencies.now() }),
  });
  const persisted = await (dependencies.persist ?? persistActivationSnapshot)({
    state: confirmed,
    ...directories,
  });
  stdout.write(serializeActivationReport(persisted.report));
  return 0;
}

async function broadcastUnknownCommand(
  argv: readonly string[],
  dependencies: ActivationCliDependencies,
  stdout: TextWriter,
): Promise<number> {
  const parsed = parseArgs({
    args: [...argv],
    strict: true,
    allowPositionals: false,
    options: {
      state: { type: "string" },
      "activation-state-dir": { type: "string" },
      "report-dir": { type: "string" },
      "ack-broadcast-attempt-had-no-transaction-hash": {
        type: "boolean",
        default: false,
      },
    },
  });
  requireAcknowledgement(
    parsed.values["ack-broadcast-attempt-had-no-transaction-hash"],
    "--ack-broadcast-attempt-had-no-transaction-hash",
  );
  const directories = outputDirectories(parsed.values);
  const state = await readCurrentStateForCommand(
    parsed.values,
    directories,
    dependencies,
  );
  const marked = markActivationBroadcastUnknown({
    state,
    ...(dependencies.now === undefined ? {} : { now: dependencies.now() }),
  });
  const persisted = await (dependencies.persist ?? persistActivationSnapshot)({
    state: marked,
    ...directories,
  });
  stdout.write(serializeActivationReport(persisted.report));
  return 0;
}

async function readCurrentStateForCommand(
  values: Readonly<Record<string, string | boolean | undefined>>,
  directories: ReturnType<typeof outputDirectories>,
  dependencies: ActivationCliDependencies,
): Promise<ActivationState> {
  const state = await (dependencies.readState ?? readActivationState)(
    requiredPath(values.state, "--state"),
  );
  const current = await (
    dependencies.readCurrent ?? readCurrentActivationSnapshot
  )({
    activationId: state.activationId,
    ...directories,
  });
  if (
    current === undefined ||
    current.stateSha256 !== activationStateSha256(state)
  ) {
    throw new Error("activation state is not the current journal head");
  }
  return current.state;
}

function activationTransport(
  dependencies: ActivationCliDependencies,
): Pick<PinnedHttpsTransport, "request"> {
  return dependencies.transport ?? new PinnedHttpsTransport();
}

function activationRpc(
  dependencies: ActivationCliDependencies,
  transport: Pick<PinnedHttpsTransport, "request">,
  randomUUID: () => string,
): ActivationRpc {
  return (
    dependencies.activationRpcFactory?.(transport, randomUUID) ??
    new TransportActivationRpc(transport, randomUUID)
  );
}

function outputDirectories(values: Readonly<Record<string, string | boolean | undefined>>) {
  return {
    stateDirectory: requiredPath(
      values["activation-state-dir"],
      "--activation-state-dir",
    ),
    reportDirectory: requiredPath(values["report-dir"], "--report-dir"),
  };
}

function requiredPath(
  value: string | boolean | undefined,
  option: string,
): string {
  return resolve(requiredString(value, option));
}

function requiredString(
  value: string | boolean | undefined,
  option: string,
): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${option} is required for activation`);
  }
  return value;
}

function requireAcknowledgement(
  value: string | boolean | undefined,
  option: string,
): void {
  if (value !== true) {
    throw new Error(`activation requires ${option} in this invocation`);
  }
}

function parseChainId(value: string): 56 {
  if (value !== "56") throw new Error("activation currently supports chain id 56 only");
  return 56;
}

function parseUint(value: string): string {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error("activation requires a canonical unsigned decimal integer");
  }
  return value;
}

function parseSafeUnixSeconds(value: string): number {
  const parsed = Number(parseUint(value));
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error("activation timestamp is outside the safe integer range");
  }
  return parsed;
}

function parseCleanupOwner(
  value: string,
): ActivationState["cleanup"]["owner"] {
  if (value !== "mandatex_operator" && value !== "external_client") {
    throw new Error("--cleanup-owner is invalid");
  }
  return value;
}

function previewExitCode(
  outcome: "preview_simulation_passed" | "inconclusive" | "refused" | "invalid",
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

function activationHelp(): string {
  return [
    "MandateX ERC-8183 activation journal",
    "",
    "Commands:",
    "  prepare-create  Validate a fresh quote/preview and persist one create intent",
    "  prepare-next    Persist the next register, set-budget, or zero-fund intent",
    "  reconcile       Journal a transaction hash, then verify receipt and job state",
    "  broadcast-unknown  Freeze an intent after an external broadcast returned no hash",
    "",
    "This command never connects a wallet, signs, broadcasts, approves tokens,",
    "notifies a provider, submits delivery, settles, or executes the LP plan.",
    "Private state files are immutable and content addressed. Stdout contains only",
    "the redacted activation report (or a failed preview sidecar).",
    "",
    "Run a command with its required absolute file and directory options. All",
    "activation state/report directories must already exist with mode 0700.",
    "",
  ].join("\n");
}

const entrypoint = process.argv[1];
if (
  entrypoint !== undefined &&
  import.meta.url === pathToFileURL(resolve(entrypoint)).href
) {
  process.exitCode = await runActivationCli(process.argv.slice(2));
}
