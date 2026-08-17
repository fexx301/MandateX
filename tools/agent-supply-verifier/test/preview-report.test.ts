import assert from "node:assert/strict";
import test from "node:test";

import {
  rebalancePreviewSidecarSchema,
  type RebalancePreviewSidecar,
} from "../src/preview/schema.js";
import { serializeRebalancePreviewSidecar } from "../src/preview/validate.js";

const HASH = "a".repeat(64);
const ADDRESS = "0x1111111111111111111111111111111111111111";
const MANAGER = "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364";
const OBSERVED_AT = "2026-08-16T12:00:00.000Z";

test("passing preview artifacts are deterministic, redacted, and non-promoting", () => {
  const sidecar = passingSidecar();
  const serialized = serializeRebalancePreviewSidecar(sidecar);

  assert.equal(serialized, serializeRebalancePreviewSidecar(sidecar));
  assert.equal(sidecar.classification, "PREVIEW_SIMULATION_PASSED");
  assert.equal(serialized.includes("VERIFIED_HIREABLE"), false);
  assert.equal(serialized.includes("provider_sig"), false);
  assert.equal(serialized.includes("task_description"), false);
  assert.equal(serialized.includes("amount0Desired"), false);
  assert.equal(serialized.includes("0xac9650d8"), false);
  assert.equal(serialized.includes("private plan"), false);
});

test("a passing preview requires all gates, one valid replay-claimed quote, and hashes", () => {
  const sidecar = passingSidecar();
  assert.throws(() =>
    rebalancePreviewSidecarSchema.parse({
      ...sidecar,
      gates: { ...sidecar.gates, evmSimulation: "unknown" },
    }),
  );
  assert.throws(() =>
    rebalancePreviewSidecarSchema.parse({
      ...sidecar,
      quote: { ...sidecar.quote, outcome: "invalid" },
    }),
  );
  assert.throws(() =>
    rebalancePreviewSidecarSchema.parse({
      ...sidecar,
      simulationResultSha256: undefined,
    }),
  );
});

test("passing preview call summaries require exact order and a live common deadline", () => {
  const sidecar = passingSidecar();
  assert.throws(() =>
    rebalancePreviewSidecarSchema.parse({
      ...sidecar,
      calls: [sidecar.calls[2], sidecar.calls[1], sidecar.calls[0]],
    }),
  );
  const staleDeadline = Math.floor(new Date(OBSERVED_AT).valueOf() / 1_000) + 29;
  assert.throws(() =>
    rebalancePreviewSidecarSchema.parse({
      ...sidecar,
      calls: sidecar.calls.map((call) =>
        call.method === "collect" ? call : { ...call, deadline: staleDeadline },
      ),
    }),
  );
});

test("preview error codes require consistent failure gates", () => {
  const sidecar = passingSidecar();
  assert.throws(() =>
    rebalancePreviewSidecarSchema.parse({
      ...sidecar,
      outcome: "invalid",
      classification: "EXCLUDED",
      errorCode: "EVM_SIMULATION_REVERTED",
      gates: { ...sidecar.gates, evmSimulation: "unknown" },
    }),
  );
  assert.throws(() =>
    rebalancePreviewSidecarSchema.parse({
      ...sidecar,
      outcome: "invalid",
      classification: "EXCLUDED",
      errorCode: "PREVIEW_EXPIRED",
      gates: { ...sidecar.gates, transactionPolicy: "fail", evmSimulation: "unknown" },
    }),
  );
});

test("inconclusive previews require an explicit stable error code", () => {
  const sidecar = passingSidecar();
  const inconclusive = rebalancePreviewSidecarSchema.parse({
    ...sidecar,
    outcome: "inconclusive",
    classification: "INCONCLUSIVE",
    quote: {
      ...sidecar.quote,
      outcome: "inconclusive",
      replayStatus: "not_attempted",
      gates: { ...sidecar.quote.gates, replay: "unknown" },
      errorCode: "PREVIEW_GATE_UNAVAILABLE",
    },
    gates: {
      signedEvidence: "pass",
      freshState: "unknown",
      identityOwner: "unknown",
      positionAuthority: "unknown",
      transactionPolicy: "unknown",
      evmSimulation: "unknown",
    },
    errorCode: "PREVIEW_STATE_UNAVAILABLE",
  });
  assert.equal(inconclusive.classification, "INCONCLUSIVE");

  assert.throws(() =>
    rebalancePreviewSidecarSchema.parse({
      ...inconclusive,
      errorCode: undefined,
    }),
  );
});

function passingSidecar(): RebalancePreviewSidecar {
  return rebalancePreviewSidecarSchema.parse({
    schema: "mandatex.agent-supply.rebalance-preview.v1",
    observedAt: OBSERVED_AT,
    outcome: "preview_simulation_passed",
    classification: "PREVIEW_SIMULATION_PASSED",
    operatorSuppliedPlan: true,
    simulationOnly: true,
    candidate: { chainId: 56, tokenId: "265375" },
    quote: {
      schema: "mandatex.agent-supply.quote-validation.v1",
      observedAt: OBSERVED_AT,
      outcome: "valid",
      candidate: { chainId: 56, tokenId: "265375" },
      passiveReportSha256: HASH,
      passiveCandidateSha256: HASH,
      passivePolicyFingerprint: HASH,
      trustPolicySha256: HASH,
      quoteEndpoint: "https://agent.example/",
      a2aRequestSha256: HASH,
      a2aResponseSha256: HASH,
      expectedProvider: ADDRESS,
      validatedProvider: ADDRESS,
      providerKind: "eoa",
      signatureMethod: "eip191",
      verifyingContract: MANAGER,
      requestHash: `0x${HASH}`,
      responseHash: `0x${HASH}`,
      negotiationHash: `0x${HASH}`,
      negotiatedAt: 1_786_881_600,
      quoteExpiresAt: 1_786_882_200,
      replayKey: HASH,
      replayStatus: "claimed",
      gates: {
        passivePreflight: "pass",
        endpointBinding: "pass",
        quoteSignature: "pass",
        quotePolicy: "pass",
        replay: "pass",
      },
    },
    mandateSha256: HASH,
    transactionPlanSha256: HASH,
    calldataSha256: HASH,
    decodedPlanSha256: HASH,
    simulationRequestSha256: HASH,
    simulationResponseSha256: HASH,
    simulationResultSha256: HASH,
    snapshot: {
      chainId: 56,
      headBlockNumber: "102",
      blockNumber: "100",
      blockHash: `0x${HASH}`,
      blockTimestamp: 1_786_881_600,
      confirmationDepth: 2,
      positionOwner: ADDRESS,
      callerAuthority: "owner",
      currentTick: 120,
      positionLiquidity: "1000",
    },
    calls: [
      { method: "decreaseLiquidity", tokenId: "783", deadline: 1_786_882_100 },
      { method: "collect", tokenId: "783", recipient: ADDRESS },
      {
        method: "mint",
        lowerTick: 60,
        upperTick: 180,
        recipient: ADDRESS,
        deadline: 1_786_882_100,
      },
    ],
    gates: {
      signedEvidence: "pass",
      freshState: "pass",
      identityOwner: "pass",
      positionAuthority: "pass",
      transactionPolicy: "pass",
      evmSimulation: "pass",
    },
  });
}
