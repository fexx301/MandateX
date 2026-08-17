import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  encodeAbiParameters,
  toFunctionSelector,
  type Address,
} from "viem";

import { BSC_ACTIVATION_DEPLOYMENT } from "../src/activation/deployment.js";
import { observeAndReconcileActivation } from "../src/activation/reconcile.js";
import {
  ActivationRpcError,
  TransportActivationRpc,
  type ActivationReceiptObservation,
} from "../src/activation/rpc.js";
import { activationIntentSchema } from "../src/activation/schema.js";
import {
  prepareNextActivationStep,
  reconcileActivationStep,
  recordActivationSubmission,
} from "../src/activation/state.js";
import type {
  BoundedHttpResponse,
  BscActivationRpcRoute,
  TransportRoute,
} from "../src/transport/http.js";
import {
  activationDeployment,
  activationJob,
  activationReceipt,
  preparedCreateState,
} from "./activation-fixture.js";

const TRANSACTION_HASH = `0x${"a".repeat(64)}`;
const BLOCK_HASH = `0x${"b".repeat(64)}`;
const REORGED_BLOCK_HASH = `0x${"c".repeat(64)}`;
const BLOCK_NUMBER = "0x64";
const OBSERVED_AT = "2033-05-18T03:33:20.000Z";
const CALLDATA = "0x1234";
const FROM = "0x1111111111111111111111111111111111111111";

const INTENT = activationIntentSchema.parse({
  operation: "create_job",
  from: FROM,
  to: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
  valueWei: "0",
  data: CALLDATA,
  calldataSha256: createHash("sha256")
    .update(Buffer.from(CALLDATA.slice(2), "hex"))
    .digest("hex"),
});

const SELECTORS = Object.freeze({
  paymentToken: toFunctionSelector("paymentToken()"),
  commerce: toFunctionSelector("commerce()"),
  router: toFunctionSelector("router()"),
  policyWhitelist: toFunctionSelector("policyWhitelist(address)"),
  paused: toFunctionSelector("paused()"),
  disputeWindow: toFunctionSelector("disputeWindow()"),
});

test("receipt observation uses only bounded activation routes and confirms one canonical transaction", async () => {
  const routes: BscActivationRpcRoute[] = [];
  const rpc = scenarioRpc({}, routes);

  const observed = await rpc.observeReceipt(TRANSACTION_HASH, INTENT);

  assert.equal(observed.kind, "confirmed");
  if (observed.kind !== "confirmed") return;
  assert.equal(observed.receipt.transactionHash, TRANSACTION_HASH);
  assert.equal(observed.receipt.from, INTENT.from);
  assert.equal(observed.receipt.to, INTENT.to);
  assert.equal(observed.receipt.valueWei, INTENT.valueWei);
  assert.equal(observed.receipt.calldataSha256, INTENT.calldataSha256);
  assert.equal(observed.deployment.blockNumber, "100");
  assert.equal(observed.deployment.blockHash, BLOCK_HASH);
  assert.equal(observed.deployment.commercePaused, false);
  assert.equal(observed.deployment.routerPaused, false);

  assert.deepEqual(routes.slice(0, 2).map((route) => route.purpose), [
    "transaction",
    "receipt",
  ]);
  assert.equal(routes.every((route) => route.kind === "bsc-activation-rpc"), true);
  assert.equal(
    routes.some((route) =>
      /eth_send|eth_sign|personal_|wallet_|debug_|trace_/i.test(route.body),
    ),
    false,
  );
  const pausedTargets = routes
    .filter(
      (route): route is Extract<BscActivationRpcRoute, { purpose: "state-read" }> =>
        route.purpose === "state-read" && rpcSelector(route) === SELECTORS.paused,
    )
    .map((route) => route.approvedTargets[0])
    .sort();
  assert.deepEqual(pausedTargets, [
    BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
    BSC_ACTIVATION_DEPLOYMENT.routerProxy,
  ].sort());
});

test("receipt observation distinguishes not-found, mempool, unconfirmed, and reorged states", async () => {
  const notFound = await scenarioRpc({ transaction: null, receipt: null }).observeReceipt(
    TRANSACTION_HASH,
    INTENT,
  );
  assert.deepEqual(notFound, {
    kind: "not_found",
    transactionHash: TRANSACTION_HASH,
    observedAt: OBSERVED_AT,
  });

  const pending = await scenarioRpc({
    transaction: transaction({ blockNumber: null, blockHash: null }),
    receipt: null,
  }).observeReceipt(TRANSACTION_HASH, INTENT);
  assert.deepEqual(pending, {
    kind: "pending",
    transactionHash: TRANSACTION_HASH,
    observedAt: OBSERVED_AT,
  });

  const unconfirmed = await scenarioRpc({ head: "0x65" }).observeReceipt(
    TRANSACTION_HASH,
    INTENT,
  );
  assert.deepEqual(unconfirmed, {
    kind: "unconfirmed",
    transactionHash: TRANSACTION_HASH,
    observedAt: OBSERVED_AT,
    blockNumber: "100",
    blockHash: BLOCK_HASH,
    confirmationDepth: 1,
    requiredConfirmationDepth: 2,
  });

  const reorged = await scenarioRpc({ canonicalBlockHash: REORGED_BLOCK_HASH })
    .observeReceipt(TRANSACTION_HASH, INTENT);
  assert.deepEqual(reorged, {
    kind: "reorged",
    transactionHash: TRANSACTION_HASH,
    observedAt: OBSERVED_AT,
  });
});

test("an exact matching canonical revert is an outcome, but identity drift fails first", async () => {
  const reverted = await scenarioRpc({
    receipt: receipt({ status: "0x0" }),
  }).observeReceipt(TRANSACTION_HASH, INTENT);
  assert.equal(reverted.kind, "reverted");
  if (reverted.kind !== "reverted") return;
  assert.equal(reverted.transactionHash, TRANSACTION_HASH);
  assert.equal(reverted.observedAt, OBSERVED_AT);
  assert.equal(reverted.blockNumber, "100");
  assert.equal(reverted.blockHash, BLOCK_HASH);
  assert.equal(reverted.confirmationDepth, 2);
  assert.equal(reverted.deployment.blockHash, BLOCK_HASH);
  assert.equal(reverted.deployment.commercePaused, false);

  const routes: BscActivationRpcRoute[] = [];
  await assert.rejects(
    scenarioRpc(
      {
        transaction: transaction({
          from: "0x2222222222222222222222222222222222222222",
        }),
        receipt: receipt({ status: "0x0" }),
      },
      routes,
    ).observeReceipt(TRANSACTION_HASH, INTENT),
    (error: unknown) =>
      error instanceof ActivationRpcError && error.kind === "invalid-response",
  );
  assert.deepEqual(routes.map((route) => route.purpose), ["transaction", "receipt"]);
});

test("activation transport dependency failures remain stable unavailable errors", async () => {
  const rpc = new TransportActivationRpc(
    {
      async request() {
        throw new Error("private provider detail");
      },
    },
    sequentialId(),
    fixedNow,
  );

  await assert.rejects(
    rpc.observeReceipt(TRANSACTION_HASH, INTENT),
    (error: unknown) =>
      error instanceof ActivationRpcError &&
      error.kind === "unavailable" &&
      error.message === "activation RPC verification failed closed",
  );
});

test("reconciliation records unresolved outcomes and advances only confirmed receipts", async () => {
  const prepared = await preparedCreateState();
  const submitted = recordActivationSubmission({
    state: prepared,
    transactionHash: TRANSACTION_HASH,
    now: new Date(OBSERVED_AT),
  });
  const unresolved: Exclude<
    ActivationReceiptObservation,
    { kind: "confirmed" | "reverted" }
  >[] = [
    { kind: "pending", transactionHash: TRANSACTION_HASH, observedAt: OBSERVED_AT },
    { kind: "not_found", transactionHash: TRANSACTION_HASH, observedAt: OBSERVED_AT },
    {
      kind: "unconfirmed",
      transactionHash: TRANSACTION_HASH,
      observedAt: OBSERVED_AT,
      blockNumber: "100",
      blockHash: BLOCK_HASH,
      confirmationDepth: 1,
      requiredConfirmationDepth: 2,
    },
    { kind: "reorged", transactionHash: TRANSACTION_HASH, observedAt: OBSERVED_AT },
  ];

  for (const observation of unresolved) {
    let jobReads = 0;
    const reconciled = await observeAndReconcileActivation({
      state: submitted,
      rpc: {
        async observeReceipt() {
          return observation;
        },
        async observeJob() {
          jobReads += 1;
          throw new Error("unresolved observations must not read job state");
        },
      },
    });
    assert.equal(reconciled.phase, submitted.phase);
    assert.deepEqual(reconciled.intent, submitted.intent);
    assert.deepEqual(reconciled.submission, submitted.submission);
    assert.deepEqual(reconciled.reconciliation, observation);
    assert.equal(reconciled.sequence, submitted.sequence + 1);
    assert.equal(jobReads, 0);
  }

  const deployment = activationDeployment({
    blockNumber: "102",
    blockHash: `0x${"d".repeat(64)}`,
  });
  const confirmedReceipt = activationReceipt(submitted, deployment, "a");
  const confirmed = await observeAndReconcileActivation({
    state: submitted,
    rpc: {
      async observeReceipt() {
        return {
          kind: "confirmed" as const,
          receipt: confirmedReceipt,
          deployment,
        };
      },
      async observeJob() {
        return activationJob(submitted, "CREATE_CONFIRMED");
      },
    },
    now: new Date(OBSERVED_AT),
  });
  assert.equal(confirmed.phase, "CREATE_CONFIRMED");
  assert.equal(confirmed.condition, "ready");
  assert.equal(confirmed.submission, undefined);
});

test("canonical reverts persist deployment evidence and inspect prior job state after create", async () => {
  const createPrepared = await preparedCreateState();
  const createDeployment = activationDeployment({
    blockNumber: "102",
    blockHash: `0x${"d".repeat(64)}`,
  });
  const createReceipt = activationReceipt(createPrepared, createDeployment, "a");
  const createSubmitted = recordActivationSubmission({
    state: createPrepared,
    transactionHash: createReceipt.transactionHash,
    now: new Date(OBSERVED_AT),
  });
  const created = reconcileActivationStep({
    state: createSubmitted,
    receipt: createReceipt,
    job: activationJob(createSubmitted, "CREATE_CONFIRMED"),
    deployment: createDeployment,
    now: new Date(OBSERVED_AT),
  });
  const registerPrepared = await prepareNextActivationStep({
    state: created,
    deployment: activationDeployment({
      blockNumber: "103",
      blockHash: `0x${"e".repeat(64)}`,
    }),
    job: activationJob(created, "CREATE_CONFIRMED"),
    now: new Date(OBSERVED_AT),
  });
  const revertDeployment = activationDeployment({
    blockNumber: "104",
    blockHash: `0x${"f".repeat(64)}`,
  });
  const revertedHash = `0x${"b".repeat(64)}`;
  const registerSubmitted = recordActivationSubmission({
    state: registerPrepared,
    transactionHash: revertedHash,
    now: new Date(OBSERVED_AT),
  });
  let observedJob: { jobId: string; blockHash: string } | undefined;
  const reconciled = await observeAndReconcileActivation({
    state: registerSubmitted,
    rpc: {
      async observeReceipt() {
        return {
          kind: "reverted" as const,
          transactionHash: revertedHash,
          observedAt: OBSERVED_AT,
          blockNumber: revertDeployment.blockNumber,
          blockHash: revertDeployment.blockHash,
          confirmationDepth: revertDeployment.confirmationDepth,
          deployment: revertDeployment,
        };
      },
      async observeJob(jobId, blockHash) {
        observedJob = { jobId, blockHash };
        return activationJob(registerSubmitted, "CREATE_CONFIRMED");
      },
    },
  });

  assert.deepEqual(observedJob, {
    jobId: registerSubmitted.jobId,
    blockHash: revertDeployment.blockHash,
  });
  assert.equal(reconciled.phase, "PREPARED_REGISTER");
  assert.equal(reconciled.condition, "cleanup_required");
  assert.equal(reconciled.errorCode, "RECEIPT_REVERTED");
  assert.equal(reconciled.reconciliation?.kind, "reverted");
  assert.deepEqual(reconciled.submission, registerSubmitted.submission);
});

type Scenario = Readonly<{
  transaction?: unknown;
  receipt?: unknown;
  head?: string;
  canonicalBlockHash?: string | null;
}>;

function scenarioRpc(
  scenario: Scenario = {},
  routes: BscActivationRpcRoute[] = [],
): TransportActivationRpc {
  return new TransportActivationRpc(
    {
      async request(route: TransportRoute): Promise<BoundedHttpResponse> {
        assert.equal(route.kind, "bsc-activation-rpc");
        if (route.kind !== "bsc-activation-rpc") {
          throw new Error("expected the dedicated activation RPC route");
        }
        routes.push(route);
        const request = JSON.parse(route.body) as {
          id: string;
          params: readonly unknown[];
        };
        return response({
          jsonrpc: "2.0",
          id: request.id,
          result: scenarioResult(route, request.params, scenario),
        });
      },
    },
    sequentialId(),
    fixedNow,
  );
}

function scenarioResult(
  route: BscActivationRpcRoute,
  params: readonly unknown[],
  scenario: Scenario,
): unknown {
  switch (route.purpose) {
    case "transaction":
      return scenario.transaction === undefined
        ? transaction()
        : scenario.transaction;
    case "receipt":
      return scenario.receipt === undefined ? receipt() : scenario.receipt;
    case "chain-id":
      return "0x38";
    case "head-block-number":
      return scenario.head ?? "0x66";
    case "block-header":
      if (scenario.canonicalBlockHash === null) return null;
      return {
        number: route.approvedBlockNumber,
        hash: scenario.canonicalBlockHash ?? BLOCK_HASH,
        timestamp: "0x77359405",
      };
    case "contract-code":
      return "0x6000";
    case "proxy-implementation":
      return implementationWord(
        route.approvedTargets[0] === BSC_ACTIVATION_DEPLOYMENT.commerceProxy
          ? BSC_ACTIVATION_DEPLOYMENT.commerceImplementation
          : BSC_ACTIVATION_DEPLOYMENT.routerImplementation,
      );
    case "state-read":
      return stateReadResult(route, params);
  }
}

function stateReadResult(
  route: Extract<BscActivationRpcRoute, { purpose: "state-read" }>,
  params: readonly unknown[],
): string {
  const selector = rpcSelector(route);
  const target = route.approvedTargets[0];
  switch (selector) {
    case SELECTORS.paymentToken:
      return encodeAddress(BSC_ACTIVATION_DEPLOYMENT.paymentToken);
    case SELECTORS.commerce:
      return encodeAddress(BSC_ACTIVATION_DEPLOYMENT.commerceProxy);
    case SELECTORS.router:
      return encodeAddress(BSC_ACTIVATION_DEPLOYMENT.routerProxy);
    case SELECTORS.policyWhitelist:
      return encodeBool(true);
    case SELECTORS.paused:
      assert.equal(
        target === BSC_ACTIVATION_DEPLOYMENT.commerceProxy ||
          target === BSC_ACTIVATION_DEPLOYMENT.routerProxy,
        true,
      );
      return encodeBool(false);
    case SELECTORS.disputeWindow:
      return encodeUint(600n);
    default:
      throw new Error(`unexpected activation state selector ${selector} ${JSON.stringify(params)}`);
  }
}

function rpcSelector(
  route: Extract<BscActivationRpcRoute, { purpose: "state-read" }>,
): string {
  const request = JSON.parse(route.body) as {
    params: readonly [{ readonly data: string }];
  };
  return request.params[0].data.slice(0, 10);
}

function transaction(
  overrides: Partial<{
    hash: string;
    from: string;
    to: string | null;
    input: string;
    value: string;
    blockNumber: string | null;
    blockHash: string | null;
  }> = {},
) {
  return {
    hash: TRANSACTION_HASH,
    from: INTENT.from,
    to: INTENT.to,
    input: INTENT.data,
    value: "0x0",
    blockNumber: BLOCK_NUMBER,
    blockHash: BLOCK_HASH,
    ...overrides,
  };
}

function receipt(
  overrides: Partial<{
    transactionHash: string;
    status: string;
    blockNumber: string;
    blockHash: string;
    logs: readonly unknown[];
  }> = {},
) {
  return {
    transactionHash: TRANSACTION_HASH,
    status: "0x1",
    blockNumber: BLOCK_NUMBER,
    blockHash: BLOCK_HASH,
    logs: [],
    ...overrides,
  };
}

function implementationWord(address: string): string {
  return `0x${"0".repeat(24)}${address.slice(2)}`;
}

function encodeAddress(address: string): string {
  return encodeAbiParameters(
    [{ type: "address" }],
    [address as Address],
  );
}

function encodeBool(value: boolean): string {
  return encodeAbiParameters([{ type: "bool" }], [value]);
}

function encodeUint(value: bigint): string {
  return encodeAbiParameters([{ type: "uint256" }], [value]);
}

function response(value: unknown): BoundedHttpResponse {
  const body = Buffer.from(JSON.stringify(value));
  return {
    status: 200,
    contentType: "application/json",
    retryAfter: null,
    rateLimitRemaining: null,
    body,
    responseSha256: createHash("sha256").update(body).digest("hex"),
    resolvedAddress: "93.184.216.34",
    startedAt: OBSERVED_AT,
    finishedAt: OBSERVED_AT,
    latencyMs: 0,
  };
}

function sequentialId(): () => string {
  let value = 0;
  return () => `id-${++value}`;
}

function fixedNow(): Date {
  return new Date(OBSERVED_AT);
}
