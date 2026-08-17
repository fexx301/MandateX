import assert from "node:assert/strict";
import test from "node:test";
import { deflateRawSync } from "node:zlib";

import {
  prepareTrustedActivation,
  type PrepareTrustedActivationOptions,
} from "../src/activation/offer.js";
import type { PersistedActivationSnapshot } from "../src/activation/store.js";
import {
  activationStateSha256,
  buildActivationReport,
} from "../src/activation/state.js";
import { BSC_ACTIVATION_DEPLOYMENT } from "../src/activation/deployment.js";
import {
  canonicalQuoteJson,
  computeQuoteReplayKey,
  computeQuoteSha256,
} from "../src/quotes/protocol.js";
import type { ReplayMetadata } from "../src/quotes/replay.js";
import {
  ACTIVATION_CLIENT,
  ACTIVATION_NOW,
  ACTIVATION_PROVIDER,
  activationDeployment,
  activationPreview,
  activationSignedTask,
  activationTransactionPlan,
  preparedCreateState,
} from "./activation-fixture.js";

test("trusted activation bootstraps the exact replay candidate before returning valid", async () => {
  const state = await preparedCreateState();
  const deployment = activationDeployment();
  const signedTask = activationSignedTask();
  const transactionPlan = activationTransactionPlan();
  const initialPreview = activationPreview();
  const endpointHash = "a".repeat(64);
  const negotiationHash = `0x${"6".repeat(64)}`;
  const replayMetadata: ReplayMetadata = {
    schema: "mandatex.agent-supply.quote-replay.v1",
    claimedAt: new Date(ACTIVATION_NOW * 1_000).toISOString(),
    chainId: 56,
    tokenId: "265375",
    endpointHash,
    provider: ACTIVATION_PROVIDER,
    commerceContract: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
    negotiationHash,
  };
  const replayKey = computeQuoteReplayKey(replayMetadata);
  const previewSidecar = {
    schema: "mandatex.agent-supply.rebalance-preview.v1",
    outcome: "preview_simulation_passed",
    replayKey,
  };
  const projection = {
    mandate: signedTask.mandate,
    signedTask,
    envelope: acceptedEnvelope(signedTask, negotiationHash),
    verification: {
      price: "0",
      currency: BSC_ACTIVATION_DEPLOYMENT.paymentToken,
      validatedProvider: ACTIVATION_PROVIDER,
      negotiationHash,
      negotiatedAt: ACTIVATION_NOW,
      quoteExpiresAt: ACTIVATION_NOW + 800,
    },
    decodedPlan: {
      plan: transactionPlan,
      transactionPlanSha256: computeQuoteSha256(
        canonicalQuoteJson(transactionPlan),
      ),
    },
    preview: {
      snapshot: {
        pin: {
          observedAt: String(ACTIVATION_NOW),
          observedBlockNumber: initialPreview.blockNumber,
          observedBlockHash: initialPreview.blockHash,
        },
      },
      policy: { deadline: ACTIVATION_NOW + 600 },
    },
  };
  const snapshot = persistedSnapshot(state);
  const stages: string[] = [];
  let preparedInput: Readonly<Record<string, unknown>> | undefined;
  let bootstrapInput: Readonly<Record<string, unknown>> | undefined;

  const result = await prepareTrustedActivation(baseOptions(), {
    async previewValidator(options) {
      stages.push("preview_commit");
      assert.ok(options.replayCommit);
      const status = await options.replayCommit({
        replayKey,
        replayMetadata,
        previewSidecar: previewSidecar as never,
        projection: projection as never,
      });
      assert.equal(status, "created");
      stages.push("preview_return");
      return {
        sidecar: previewSidecar as never,
        projection: projection as never,
      };
    },
    activationRpc: {
      async observeDeployment() {
        stages.push("deployment");
        return deployment;
      },
    },
    async prepareCreate(input) {
      stages.push("prepare");
      preparedInput = input;
      return state;
    },
    async bootstrap(input) {
      stages.push("bootstrap");
      bootstrapInput = input;
      return { status: "created", snapshot };
    },
  });

  assert.deepEqual(stages, [
    "preview_commit",
    "deployment",
    "prepare",
    "bootstrap",
    "preview_return",
  ]);
  assert.equal(result.bootstrap?.snapshot.stateSha256, snapshot.stateSha256);
  assert.equal(preparedInput?.deployment, deployment);
  assert.equal(
    (preparedInput?.binding as { replayKey?: string } | undefined)?.replayKey,
    replayKey,
  );
  assert.equal(
    (preparedInput?.binding as { previewSidecarSha256?: string } | undefined)
      ?.previewSidecarSha256,
    computeQuoteSha256(canonicalQuoteJson(previewSidecar)),
  );
  assert.equal(bootstrapInput?.replayKey, replayKey);
  assert.equal(bootstrapInput?.replayMetadata, replayMetadata);
  assert.equal(bootstrapInput?.state, state);
  assert.equal(bootstrapInput?.deployment, deployment);
  assert.equal(bootstrapInput?.stateDirectory, "/private/tmp/activation-state");
  assert.equal(bootstrapInput?.reportDirectory, "/private/tmp/activation-report");
});

test("a passing preview cannot escape without completing bootstrap", async () => {
  await assert.rejects(
    prepareTrustedActivation(baseOptions(), {
      async previewValidator() {
        return {
          sidecar: { outcome: "preview_simulation_passed" } as never,
          projection: {} as never,
        };
      },
    }),
    /not durably bootstrapped/,
  );
});

function baseOptions(): PrepareTrustedActivationOptions {
  return {
    manifest: {} as never,
    passiveReport: {} as never,
    trustFile: {} as never,
    mandate: {} as never,
    transactionPlan: {} as never,
    candidate: { chainId: 56, tokenId: "265375" },
    transport: {} as never,
    replayStore: {} as never,
    activationStateDirectory: "/private/tmp/activation-state",
    reportDirectory: "/private/tmp/activation-report",
    client: ACTIVATION_CLIENT,
    jobExpiresAt: ACTIVATION_NOW + 3_600,
    cleanupOwner: "mandatex_operator",
    acknowledgePublicJobDescription: true,
    acknowledgeBuyerAddressNotProviderSigned: true,
  };
}

function acceptedEnvelope(
  signedTask: ReturnType<typeof activationSignedTask>,
  negotiationHash: string,
) {
  const taskDescription = `mandatex-rebalance:v1:${deflateRawSync(
    Buffer.from(canonicalQuoteJson(signedTask), "utf8"),
  ).toString("base64url")}`;
  return {
    request: {
      task_description: taskDescription,
      terms: {
        deliverables: "rebalance position",
        quality_standards: "match the signed mandate",
        evaluation_required: true,
        evaluator_type: "router",
      },
    },
    response: {
      accepted: true,
      terms: {
        deliverables: "rebalance position",
        quality_standards: "match the signed mandate",
        evaluation_required: true,
        evaluator_type: "router",
        price: "0",
        currency: BSC_ACTIVATION_DEPLOYMENT.paymentToken,
      },
      estimated_completion_seconds: 300,
      quote_expires_at: ACTIVATION_NOW + 800,
      negotiated_at: ACTIVATION_NOW,
    },
    negotiation_hash: negotiationHash,
    provider_sig: "0x11",
    chain_id: 56,
    verifying_contract: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
  };
}

function persistedSnapshot(
  state: Awaited<ReturnType<typeof preparedCreateState>>,
): PersistedActivationSnapshot {
  return {
    state,
    report: buildActivationReport(state),
    stateSha256: activationStateSha256(state),
    reportSha256: "0".repeat(64),
    statePath: "/private/tmp/activation-state.json",
    reportPath: "/private/tmp/activation-report.json",
  };
}
