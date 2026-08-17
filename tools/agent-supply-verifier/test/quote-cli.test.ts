import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { DEFAULT_CHAIN_PROFILE, POLICY_FINGERPRINT } from "../src/policy.js";
import { runPreviewCli } from "../src/preview-cli.js";
import { rebalancePreviewSidecarSchema } from "../src/preview/schema.js";
import { runQuoteCli } from "../src/quote-cli.js";
import { buildReport } from "../src/report.js";
import { buildQuoteSidecar } from "../src/quotes/protocol.js";

const PROVIDER = `0x${"1".repeat(40)}`;
const COMMERCE = `0x${"2".repeat(40)}`;
const MANAGER = "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364";
const POOL = `0x${"3".repeat(40)}`;
const REQUIRED_CALLS = [
  "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
  "collect((uint256,address,uint128,uint128))",
  "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
] as const;

test("active quote CLI checks acknowledgement before files or network", async () => {
  let validateCalls = 0;
  const stderr = captureWriter();
  const code = await runQuoteCli([], {
    stderr,
    validate: async () => {
      validateCalls += 1;
      return inconclusiveSidecar();
    },
  });

  assert.equal(code, 1);
  assert.equal(validateCalls, 0);
  assert.match(stderr.text(), /ack-actionable-quote/);
});

test("preview CLI requires both actionable-quote and calldata acknowledgements", async () => {
  let validateCalls = 0;
  const firstError = captureWriter();
  const first = await runPreviewCli([], {
    stderr: firstError,
    validate: async () => {
      validateCalls += 1;
      return inconclusivePreviewSidecar();
    },
  });
  assert.equal(first, 1);
  assert.match(firstError.text(), /ack-actionable-quote/);

  const secondError = captureWriter();
  const second = await runPreviewCli(["--ack-actionable-quote"], {
    stderr: secondError,
    validate: async () => {
      validateCalls += 1;
      return inconclusivePreviewSidecar();
    },
  });
  assert.equal(second, 1);
  assert.match(secondError.text(), /ack-operator-calldata-preview/);
  assert.equal(validateCalls, 0);
});

test("armed quote CLI reads private inputs and writes one exclusive sidecar", async () => {
  const fixture = await cliFixture();
  try {
    let validateCalls = 0;
    const stdout = captureWriter();
    const stderr = captureWriter();
    const code = await runQuoteCli(fixture.args, {
      stdout,
      stderr,
      replayStoreFactory: () => memoryReplayStore(),
      transport: unreachableTransport(),
      validate: async (options) => {
        validateCalls += 1;
        assert.equal(options.candidate.chainId, 56);
        assert.equal(options.candidate.tokenId, "265375");
        return inconclusiveSidecar();
      },
    });

    assert.equal(code, 2, stderr.text());
    assert.equal(validateCalls, 1);
    assert.equal(stderr.text(), "");
    const persisted = await readFile(fixture.outputPath, "utf8");
    assert.equal(persisted, stdout.text());
    assert.equal(Number((await stat(fixture.outputPath)).mode & 0o777), 0o600);
    assert.doesNotMatch(persisted, /provider_sig|task_description|mandate_id/i);
  } finally {
    await fixture.cleanup();
  }
});

test("armed preview CLI reads a private plan and writes one redacted sidecar", async () => {
  const fixture = await cliFixture();
  try {
    let validateCalls = 0;
    const stdout = captureWriter();
    const stderr = captureWriter();
    const code = await runPreviewCli(fixture.previewArgs, {
      stdout,
      stderr,
      replayStoreFactory: () => memoryReplayStore(),
      transport: unreachableTransport(),
      validate: async (options) => {
        validateCalls += 1;
        assert.equal(options.transactionPlan.from, PROVIDER);
        assert.equal(options.transactionPlan.valueWei, "0");
        return inconclusivePreviewSidecar();
      },
    });

    assert.equal(code, 2, stderr.text());
    assert.equal(validateCalls, 1);
    const persisted = await readFile(fixture.previewOutputPath, "utf8");
    assert.equal(persisted, stdout.text());
    assert.equal(
      Number((await stat(fixture.previewOutputPath)).mode & 0o777),
      0o600,
    );
    assert.equal(persisted.includes("0xac9650d8"), false);
    assert.equal(persisted.includes("VERIFIED_HIREABLE"), false);
  } finally {
    await fixture.cleanup();
  }
});

test("preview CLI rejects a broadly readable transaction plan before validation", async () => {
  const fixture = await cliFixture();
  try {
    await chmod(fixture.transactionPlanPath, 0o644);
    let validateCalls = 0;
    const code = await runPreviewCli(fixture.previewArgs, {
      stderr: captureWriter(),
      validate: async () => {
        validateCalls += 1;
        return inconclusivePreviewSidecar();
      },
    });
    assert.equal(code, 1);
    assert.equal(validateCalls, 0);
  } finally {
    await fixture.cleanup();
  }
});

test("preview CLI refuses an existing sidecar before validation", async () => {
  const fixture = await cliFixture();
  try {
    await writeFile(fixture.previewOutputPath, "existing\n", { mode: 0o600 });
    let validateCalls = 0;
    const code = await runPreviewCli(fixture.previewArgs, {
      stderr: captureWriter(),
      validate: async () => {
        validateCalls += 1;
        return inconclusivePreviewSidecar();
      },
    });
    assert.equal(code, 1);
    assert.equal(validateCalls, 0);
    assert.equal(await readFile(fixture.previewOutputPath, "utf8"), "existing\n");
  } finally {
    await fixture.cleanup();
  }
});

test("active quote CLI rejects broad trust permissions before validation", async () => {
  const fixture = await cliFixture();
  try {
    await chmod(fixture.trustPath, 0o644);
    let validateCalls = 0;
    const code = await runQuoteCli(fixture.args, {
      stderr: captureWriter(),
      validate: async () => {
        validateCalls += 1;
        return inconclusiveSidecar();
      },
    });
    assert.equal(code, 1);
    assert.equal(validateCalls, 0);
  } finally {
    await fixture.cleanup();
  }
});

test("active quote CLI refuses an existing sidecar before validation", async () => {
  const fixture = await cliFixture();
  try {
    await writeFile(fixture.outputPath, "existing\n", { mode: 0o600 });
    let validateCalls = 0;
    const code = await runQuoteCli(fixture.args, {
      stderr: captureWriter(),
      validate: async () => {
        validateCalls += 1;
        return inconclusiveSidecar();
      },
    });
    assert.equal(code, 1);
    assert.equal(validateCalls, 0);
    assert.equal(await readFile(fixture.outputPath, "utf8"), "existing\n");
  } finally {
    await fixture.cleanup();
  }
});

async function cliFixture(): Promise<{
  args: string[];
  outputPath: string;
  previewOutputPath: string;
  trustPath: string;
  transactionPlanPath: string;
  previewArgs: string[];
  cleanup: () => Promise<void>;
}> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "mandatex-quote-cli-")),
  );
  await chmod(root, 0o700);
  const stateDirectory = join(root, "state");
  const outputDirectory = join(root, "sidecars");
  await Promise.all([
    mkdir(stateDirectory, { mode: 0o700 }),
    mkdir(outputDirectory, { mode: 0o700 }),
  ]);

  const candidatesPath = join(root, "candidates.json");
  const passiveReportPath = join(root, "passive-report.json");
  const trustPath = join(root, "quote-trust.json");
  const mandatePath = join(root, "mandate.json");
  const transactionPlanPath = join(root, "transaction-plan.json");
  const outputPath = join(outputDirectory, "quote-sidecar.json");
  const previewOutputPath = join(outputDirectory, "preview-sidecar.json");
  const candidate = {
    chainId: 56,
    tokenId: "265375",
    expectedName: "BNB LP Range Rebalancer",
    expectedEndpoint: "https://agent.example/.well-known/agent-card.json",
    expectedOrigin: "https://agent.example",
    categories: ["rebalancing"],
    source: "8004scan",
  } as const;
  const report = buildReport({
    generatedAt: "2026-08-16T12:00:00.000Z",
    chainProfile: DEFAULT_CHAIN_PROFILE,
    policyFingerprint: POLICY_FINGERPRINT,
    candidates: [{ ...candidate, status: "REGISTERED_ONLY" }],
  });
  const trust = {
    schema: "mandatex.agent-supply.quote-trust.v1",
    candidates: [
      {
        chainId: 56,
        registryAddress: DEFAULT_CHAIN_PROFILE.registryAddress,
        tokenId: "265375",
        category: "rebalancing",
        cardUrl: candidate.expectedEndpoint,
        quoteEndpoint: "https://agent.example/",
        expectedProvider: PROVIDER,
        providerKind: "eoa",
        commerceContract: COMMERCE,
        protocol: {
          a2a: "0.3.x",
          method: "message/send",
          skill: "negotiate",
          signature: "eip191-negotiation-hash-string",
          signedTaskCodec: "mandatex-rebalance:v1",
        },
        maxPassiveAgeSeconds: 300,
        maxQuoteTtlSeconds: 900,
        maxClockSkewSeconds: 30,
        allowedCurrencies: [COMMERCE],
        maxPrice: "0",
      },
    ],
  };
  const mandate = {
    version: "1",
    mandate_id: "cli-test-1",
    category: "rebalancing",
    chain_id: 56,
    protocol: "pancakeswap-v3",
    expires_at: 1_800_003_600,
    max_evidence_age_seconds: 120,
    position: {
      pool_address: POOL,
      position_manager_address: MANAGER,
      token_id: "42",
    },
    range_policy: {
      approved_lower_tick: -600,
      approved_upper_tick: 600,
      target_width_ticks: 240,
      trigger_mode: "boundary_proximity",
      trigger_distance_ticks: 30,
      max_delivery_tick_drift: 30,
    },
    limits: {
      max_gas_usd: 3,
      max_slippage_bps: 50,
      max_exposure_usd: 1_000,
    },
    execution_estimate: {
      gas_usd: 1.25,
      slippage_bps: 30,
      exposure_usd: 500,
      observed_at: 1_800_000_000,
      source_url: "https://evidence.example/estimate",
    },
    permissions: {
      allowed_contracts: [MANAGER],
      allowed_calls: REQUIRED_CALLS,
      spend_cap_usd: 750,
      expires_at: 1_800_001_800,
    },
  };
  const transactionPlan = {
    schema: "mandatex.rebalance.transaction-plan.v1",
    chainId: 56,
    from: PROVIDER,
    to: MANAGER,
    valueWei: "0",
    data: "0xac9650d8",
  };

  await Promise.all([
    writeJson(candidatesPath, { version: 1, candidates: [candidate] }, 0o644),
    writeJson(passiveReportPath, report, 0o644),
    writeJson(trustPath, trust, 0o600),
    writeJson(mandatePath, mandate, 0o600),
    writeJson(transactionPlanPath, transactionPlan, 0o600),
  ]);

  const commonArgs = [
    "--candidates",
    candidatesPath,
    "--passive-report",
    passiveReportPath,
    "--trust",
    trustPath,
    "--mandate",
    mandatePath,
    "--state-dir",
    stateDirectory,
    "--chain-id",
    "56",
    "--token-id",
    "265375",
  ];

  return {
    args: [
      "--ack-actionable-quote",
      ...commonArgs,
      "--out",
      outputPath,
    ],
    outputPath,
    previewOutputPath,
    trustPath,
    transactionPlanPath,
    previewArgs: [
      "--ack-actionable-quote",
      "--ack-operator-calldata-preview",
      ...commonArgs,
      "--transaction-plan",
      transactionPlanPath,
      "--out",
      previewOutputPath,
    ],
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

async function writeJson(
  path: string,
  value: unknown,
  mode: number,
): Promise<void> {
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode });
  await chmod(path, mode);
}

function captureWriter(): { write(chunk: string): void; text(): string } {
  const chunks: string[] = [];
  return {
    write(chunk) {
      chunks.push(chunk);
    },
    text() {
      return chunks.join("");
    },
  };
}

function memoryReplayStore() {
  return {
    async prepare() {},
    async claim() {
      return "claimed" as const;
    },
  };
}

function unreachableTransport() {
  return {
    async request(): Promise<never> {
      throw new Error("transport must not be used by the CLI unit test");
    },
  };
}

function inconclusiveSidecar() {
  return buildQuoteSidecar({
    observedAt: "2026-08-16T12:00:00.000Z",
    outcome: "inconclusive",
    candidate: { chainId: 56, tokenId: "265375" },
    passiveReportSha256: "1".repeat(64),
    passiveCandidateSha256: "2".repeat(64),
    passivePolicyFingerprint: "3".repeat(64),
    trustPolicySha256: "4".repeat(64),
    quoteEndpoint: "https://agent.example/",
    a2aRequestSha256: "5".repeat(64),
    expectedProvider: PROVIDER,
    providerKind: "eoa",
    replayStatus: "not_attempted",
    gates: {
      passivePreflight: "pass",
      endpointBinding: "pass",
      quoteSignature: "unknown",
      quotePolicy: "unknown",
      replay: "unknown",
    },
    errorCode: "TRANSPORT_FAILED",
  });
}

function inconclusivePreviewSidecar() {
  return rebalancePreviewSidecarSchema.parse({
    schema: "mandatex.agent-supply.rebalance-preview.v1",
    observedAt: "2026-08-16T12:00:00.000Z",
    outcome: "inconclusive",
    classification: "INCONCLUSIVE",
    operatorSuppliedPlan: true,
    simulationOnly: true,
    candidate: { chainId: 56, tokenId: "265375" },
    quote: inconclusiveSidecar(),
    mandateSha256: "6".repeat(64),
    transactionPlanSha256: "7".repeat(64),
    calldataSha256: "8".repeat(64),
    calls: [],
    gates: {
      signedEvidence: "unknown",
      freshState: "unknown",
      identityOwner: "unknown",
      positionAuthority: "unknown",
      transactionPolicy: "unknown",
      evmSimulation: "unknown",
    },
    errorCode: "PREVIEW_STATE_UNAVAILABLE",
  });
}
