import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  CATEGORY_ADAPTER_REGISTRY,
  GRID_ADAPTER_ID,
  GRID_EVIDENCE_SCHEMA,
  HEALTH_ADAPTER_ID,
  HEALTH_EVIDENCE_SCHEMA,
  SELECTOR_BORROW_BALANCE_STORED,
  SELECTOR_GET_ACCOUNT_LIQUIDITY,
  SELECTOR_GET_ASSETS_IN,
  SELECTOR_GET_USER_ACCOUNT_DATA,
  SELECTOR_SLOT0,
  SELECTOR_TOTAL_ASSETS,
  SELECTOR_TOTAL_SUPPLY,
  VENUS_HEALTH_ADAPTER_ID,
  VENUS_HEALTH_EVIDENCE_SCHEMA,
  YIELD_ADAPTER_ID,
  YIELD_EVIDENCE_SCHEMA,
  addressCalldata,
  type VenusHealthEvidence,
} from "@mandatex/category-adapters";

import {
  assertTrustedCategoryExecution,
  assertTrustedCategoryExecutionSuccess,
  assertBoundCategoryExecutionSuccess,
  bindTrustedCategoryExecutionSuccess,
  createCategoryExecutionBindingCapability,
  createCategoryAdapterExecutor,
  type CategoryAdapterExecutionInput,
  type CategoryExecutionBindingCapability,
} from "../src/category/execute.js";
import {
  CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
  CATEGORY_ADAPTER_VALIDATION_PROFILES,
  parseCategoryAdapterDeploymentManifest,
} from "../src/category/policy.js";
import {
  CATEGORY_EXECUTION_ARTIFACT_SCHEMA,
  categoryExecutionArtifactSchema,
  type CategoryReadAttempt,
} from "../src/category/schema.js";
import { canonicalQuoteJson, computeQuoteSha256 } from "../src/quotes/protocol.js";
import {
  BSC_MAINNET_RPC_ORIGIN,
  type BoundedHttpResponse,
  type BscCategoryRpcRoute,
  type TransportRoute,
} from "../src/transport/http.js";

const POLICY_SHA256 = "a".repeat(64);
const BLOCK_HASH = `0x${"b".repeat(64)}`;
const GRID_POOL = "0x1111111111111111111111111111111111111111";
const YIELD_VAULT = "0x2222222222222222222222222222222222222222";
const AAVE_POOL = "0x3333333333333333333333333333333333333333";
const ACCOUNT = "0x4444444444444444444444444444444444444444";
const VENUS_COMPTROLLER = "0x5555555555555555555555555555555555555555";
const VENUS_MARKET = "0x6666666666666666666666666666666666666666";

test("Venus is the enabled health default, performs three exact reads, and accepts live multiword borrow data", async () => {
  const routes: BscCategoryRpcRoute[] = [];
  const responseBodies = new Map<string, Uint8Array>();
  const deployment = venusDeployment();
  const executor = createCategoryAdapterExecutor({
    deployment,
    verifierPolicySha256: POLICY_SHA256,
    transport: scenarioTransport("pass", routes, responseBodies),
    clock: () => 1_700_000_000,
    randomUUID: sequentialId(),
  });

  const result = await executor.evaluate({ category: "health" });
  assert.equal(result.outcome, "executed");
  if (result.outcome !== "executed") return;
  assert.equal(result.artifact.result.status, "pass");
  if (result.artifact.result.status !== "pass") return;

  const expectedReads = [
    {
      label: "getAccountLiquidity",
      to: VENUS_COMPTROLLER,
      data: addressCalldata(SELECTOR_GET_ACCOUNT_LIQUIDITY, ACCOUNT),
    },
    {
      label: "getAssetsIn",
      to: VENUS_COMPTROLLER,
      data: addressCalldata(SELECTOR_GET_ASSETS_IN, ACCOUNT),
    },
    {
      label: "borrowBalanceStored",
      to: VENUS_MARKET,
      data: addressCalldata(SELECTOR_BORROW_BALANCE_STORED, ACCOUNT),
    },
  ];
  const stateRoutes = routes.filter(
    (route): route is Extract<BscCategoryRpcRoute, { purpose: "state-read" }> =>
      route.purpose === "state-read",
  );
  assert.deepEqual(
    stateRoutes.map((route) => ({
      target: route.approvedTargets[0],
      calldata: route.approvedCalldata,
    })),
    expectedReads.map((read) => ({ target: read.to, calldata: read.data })),
  );
  assert.deepEqual(
    result.artifact.reads.map((read) => ({
      label: read.label,
      to: read.to,
      data: read.data,
      outcome: read.outcome,
    })),
    expectedReads.map((read) => ({ ...read, outcome: "success" })),
  );
  assert.equal(result.artifact.reads.length, 3);
  const venusEvidence = result.artifact.result.evidence as VenusHealthEvidence;
  assert.equal(venusEvidence.metric.borrowBalanceStored, "50");
  assert.equal(venusEvidence.metric.marketsEntered, 1);

  assert.deepEqual(routes.map((route) => route.purpose), [
    "chain-id",
    "head-block-number",
    "block-header",
    "state-read",
    "state-read",
    "state-read",
    "block-header",
  ]);
  assert.equal(
    routes.filter((route) => route.purpose === "block-header").every(
      (route) => route.approvedBlockNumber === "0x62",
    ),
    true,
  );

  for (const [index, route] of stateRoutes.entries()) {
    const attempt: CategoryReadAttempt = result.artifact.reads[index]!;
    const request = JSON.parse(route.body) as { id: string };
    assert.equal(attempt.requestSha256, sha256(route.body));
    assert.equal(
      attempt.responseSha256,
      sha256(responseBodies.get(route.body)!),
    );
    assert.equal(request.id.length > 0, true);
  }

  assert.equal(
    result.artifact.result.evidenceSha256,
    sha256(canonicalQuoteJson(result.artifact.result.evidence)),
  );
  assert.equal(
    result.artifactSha256,
    sha256(canonicalQuoteJson(result.artifact)),
  );
  assertTrustedCategoryExecution(result, executor);
  assertTrustedCategoryExecutionSuccess(result, executor);

  const unsupportedGrid = await executor.evaluate({ category: "grid" });
  assert.deepEqual(unsupportedGrid, {
    schema: "mandatex.agent-supply.category-execution-result.v1",
    outcome: "inconclusive",
    category: "grid",
    code: "CATEGORY_ADAPTER_NOT_CONFIGURED",
    message: "no adapter is enabled for this category in the pinned deployment",
  });
});

test("static-only deployment evaluates mandate-owned scope without dynamic configuration", async () => {
  const deployment = structuredClone(venusDeployment()) as {
    adapters: Array<{ adapterId: string; configuration?: unknown }>;
  };
  for (const entry of deployment.adapters) delete entry.configuration;
  const executor = createCategoryAdapterExecutor({
    deployment,
    verifierPolicySha256: POLICY_SHA256,
    transport: scenarioTransport("pass", [], new Map()),
    clock: () => 1_700_000_000,
    randomUUID: sequentialId(),
  });

  const scope = {
    adapterId: VENUS_HEALTH_ADAPTER_ID,
    category: "health",
    evidenceSchema: VENUS_HEALTH_EVIDENCE_SCHEMA,
    protocol: "venus",
    subject: {
      comptrollerAddress: VENUS_COMPTROLLER,
      accountAddress: ACCOUNT,
      borrowMarketAddress: VENUS_MARKET,
    },
    conditionPolicy: {
      unit: "1e18-usd",
      minLiquidityUsdScaled: "100",
    },
  } as const;
  const result = await executor.evaluateScope(scope);
  assert.equal(result.outcome, "executed", JSON.stringify(result));
  if (result.outcome !== "executed") return;
  assert.equal(result.artifact.result.status, "pass");
  if (result.artifact.result.status !== "pass") return;
  assert.equal(result.artifact.result.evidence.schema, VENUS_HEALTH_EVIDENCE_SCHEMA);
  if (result.artifact.result.evidence.schema !== VENUS_HEALTH_EVIDENCE_SCHEMA) return;
  assert.equal(result.artifact.result.evidence.subject.accountAddress, ACCOUNT);
  assert.equal("configuration" in executor.deployment.adapters.find(
    (entry) => entry.adapterId === VENUS_HEALTH_ADAPTER_ID,
  )!, false);
  assert.equal(
    (await executor.evaluate({ category: "health" })).outcome,
    "inconclusive",
  );
});

test("explicit adapterId selects either enabled health adapter and category-only calls fail closed when ambiguous", async () => {
  const routes: BscCategoryRpcRoute[] = [];
  const deployment = deploymentWithBothHealthAdapters();
  let clockCalls = 0;
  let uuidCalls = 0;
  const nextId = sequentialId();
  const executor = createCategoryAdapterExecutor({
    deployment,
    verifierPolicySha256: POLICY_SHA256,
    transport: mappedStateTransport(
      new Map([
        [
          SELECTOR_GET_USER_ACCOUNT_DATA,
          returndata(1_000n, 500n, 0n, 0n, 0n, 2_000_000_000_000_000_000n),
        ],
        [SELECTOR_GET_ACCOUNT_LIQUIDITY, returndata(0n, 200n, 0n)],
        [SELECTOR_GET_ASSETS_IN, returndata(32n, 1n, BigInt(ACCOUNT))],
        [SELECTOR_BORROW_BALANCE_STORED, returndata(50n, 0n, 0n)],
      ]),
      routes,
    ),
    clock: () => {
      clockCalls += 1;
      return 1_700_000_000;
    },
    randomUUID: () => {
      uuidCalls += 1;
      return nextId();
    },
  });

  const aave = await executor.evaluate({
    category: "health",
    adapterId: HEALTH_ADAPTER_ID,
  });
  assert.equal(aave.outcome, "executed", JSON.stringify(aave));
  if (aave.outcome !== "executed") return;
  assert.equal(aave.artifact.adapter.adapterId, HEALTH_ADAPTER_ID);
  assert.equal(aave.artifact.result.status, "pass");
  assert.deepEqual(
    routes
      .filter(
        (route): route is Extract<
          BscCategoryRpcRoute,
          { purpose: "state-read" }
        > => route.purpose === "state-read",
      )
      .map((route) => ({
        to: route.approvedTargets[0],
        data: route.approvedCalldata,
      })),
    [
      {
        to: AAVE_POOL,
        data: addressCalldata(SELECTOR_GET_USER_ACCOUNT_DATA, ACCOUNT),
      },
    ],
  );

  routes.length = 0;
  const venus = await executor.evaluate({
    category: "health",
    adapterId: VENUS_HEALTH_ADAPTER_ID,
  });
  assert.equal(venus.outcome, "executed", JSON.stringify(venus));
  if (venus.outcome !== "executed") return;
  assert.equal(venus.artifact.adapter.adapterId, VENUS_HEALTH_ADAPTER_ID);
  assert.equal(venus.artifact.result.status, "pass");
  assert.deepEqual(
    routes
      .filter(
        (route): route is Extract<
          BscCategoryRpcRoute,
          { purpose: "state-read" }
        > => route.purpose === "state-read",
      )
      .map((route) => ({
        to: route.approvedTargets[0],
        data: route.approvedCalldata,
      })),
    [
      {
        to: VENUS_COMPTROLLER,
        data: addressCalldata(SELECTOR_GET_ACCOUNT_LIQUIDITY, ACCOUNT),
      },
      {
        to: VENUS_COMPTROLLER,
        data: addressCalldata(SELECTOR_GET_ASSETS_IN, ACCOUNT),
      },
      {
        to: VENUS_MARKET,
        data: addressCalldata(SELECTOR_BORROW_BALANCE_STORED, ACCOUNT),
      },
    ],
  );

  const routesBeforeAmbiguity = routes.length;
  const clockCallsBeforeAmbiguity = clockCalls;
  const uuidCallsBeforeAmbiguity = uuidCalls;
  assert.deepEqual(await executor.evaluate({ category: "health" }), {
    schema: "mandatex.agent-supply.category-execution-result.v1",
    outcome: "inconclusive",
    category: "health",
    code: "CATEGORY_ADAPTER_SELECTION_REQUIRED",
    message: "multiple adapters are enabled for this category; adapterId is required",
  });
  assert.equal(routes.length, routesBeforeAmbiguity);
  assert.equal(clockCalls, clockCallsBeforeAmbiguity);
  assert.equal(uuidCalls, uuidCallsBeforeAmbiguity);

  await assert.rejects(
    executor.evaluate({
      category: "yield",
      adapterId: HEALTH_ADAPTER_ID,
    } as unknown as CategoryAdapterExecutionInput),
    TypeError,
  );
  assert.equal(routes.length, routesBeforeAmbiguity);
  assert.equal(clockCalls, clockCallsBeforeAmbiguity);
  assert.equal(uuidCalls, uuidCallsBeforeAmbiguity);

  const disabledRoutes: BscCategoryRpcRoute[] = [];
  let disabledClockCalls = 0;
  let disabledUuidCalls = 0;
  const disabledExecutor = createCategoryAdapterExecutor({
    deployment: venusDeployment(),
    verifierPolicySha256: POLICY_SHA256,
    transport: scenarioTransport("pass", disabledRoutes, new Map()),
    clock: () => {
      disabledClockCalls += 1;
      return 1_700_000_000;
    },
    randomUUID: () => {
      disabledUuidCalls += 1;
      return "disabled-adapter";
    },
  });
  assert.deepEqual(
    await disabledExecutor.evaluate({
      category: "health",
      adapterId: HEALTH_ADAPTER_ID,
    }),
    {
      schema: "mandatex.agent-supply.category-execution-result.v1",
      outcome: "inconclusive",
      category: "health",
      code: "CATEGORY_ADAPTER_NOT_CONFIGURED",
      message:
        "the requested adapter is not enabled for this category in the pinned deployment",
    },
  );
  assert.equal(disabledRoutes.length, 0);
  assert.equal(disabledClockCalls, 0);
  assert.equal(disabledUuidCalls, 0);
});

test("grid, yield, and Aave runtime branches execute their exact pass reads", async () => {
  const scenarios = [
    {
      adapterId: GRID_ADAPTER_ID,
      category: "grid" as const,
      configuration: {
        poolAddress: GRID_POOL,
        lowerTick: -10,
        upperTick: 10,
      },
      responses: new Map([[SELECTOR_SLOT0, returndata(2n ** 96n, 0n)]]),
      expected: [{ to: GRID_POOL, data: SELECTOR_SLOT0 }],
    },
    {
      adapterId: YIELD_ADAPTER_ID,
      category: "yield" as const,
      configuration: {
        vaultAddress: YIELD_VAULT,
        minSharePriceScaled: "1000000000000000000",
      },
      responses: new Map([
        [SELECTOR_TOTAL_ASSETS, returndata(200n)],
        [SELECTOR_TOTAL_SUPPLY, returndata(100n)],
      ]),
      expected: [
        { to: YIELD_VAULT, data: SELECTOR_TOTAL_ASSETS },
        { to: YIELD_VAULT, data: SELECTOR_TOTAL_SUPPLY },
      ],
    },
    {
      adapterId: HEALTH_ADAPTER_ID,
      category: "health" as const,
      configuration: {
        poolAddress: AAVE_POOL,
        accountAddress: ACCOUNT,
        minHealthFactorScaled: "1100000000000000000",
      },
      responses: new Map([
        [
          SELECTOR_GET_USER_ACCOUNT_DATA,
          returndata(1_000n, 500n, 0n, 0n, 0n, 2_000_000_000_000_000_000n),
        ],
      ]),
      expected: [
        {
          to: AAVE_POOL,
          data: addressCalldata(SELECTOR_GET_USER_ACCOUNT_DATA, ACCOUNT),
        },
      ],
    },
  ];

  for (const scenario of scenarios) {
    const routes: BscCategoryRpcRoute[] = [];
    const executor = createCategoryAdapterExecutor({
      deployment: deploymentWithEnabledAdapter(
        scenario.adapterId,
        scenario.configuration,
      ),
      verifierPolicySha256: POLICY_SHA256,
      transport: mappedStateTransport(scenario.responses, routes),
      clock: () => 1_700_000_000,
      randomUUID: sequentialId(),
    });
    const result = await executor.evaluate({ category: scenario.category });
    assert.equal(result.outcome, "executed", scenario.adapterId);
    if (result.outcome !== "executed") continue;
    assert.equal(result.artifact.result.status, "pass", scenario.adapterId);
    assertTrustedCategoryExecutionSuccess(result, executor);
    assert.deepEqual(
      routes
        .filter(
          (route): route is Extract<
            BscCategoryRpcRoute,
            { purpose: "state-read" }
          > => route.purpose === "state-read",
        )
        .map((route) => ({
          to: route.approvedTargets[0],
          data: route.approvedCalldata,
        })),
      scenario.expected,
    );
  }
});

test("category execution provenance rejects clones, proxies, tampering, and wrong executor bindings", async () => {
  const routes: BscCategoryRpcRoute[] = [];
  const executor = createCategoryAdapterExecutor({
    deployment: venusDeployment(),
    verifierPolicySha256: POLICY_SHA256,
    transport: scenarioTransport("pass", routes, new Map()),
    clock: () => 1_700_000_000,
    randomUUID: sequentialId(),
  });
  const result = await executor.evaluate({ category: "health" });
  assert.equal(result.outcome, "executed");
  if (result.outcome !== "executed") return;

  assert.throws(() =>
    assertTrustedCategoryExecution(structuredClone(result), executor),
  );
  assert.throws(() =>
    assertTrustedCategoryExecution(new Proxy(result, {}), executor),
  );
  const otherExecutor = createCategoryAdapterExecutor({
    deployment: venusDeployment(),
    verifierPolicySha256: POLICY_SHA256,
    transport: scenarioTransport("pass", [], new Map()),
    clock: () => 1_700_000_000,
    randomUUID: sequentialId(),
  });
  assert.throws(() =>
    assertTrustedCategoryExecutionSuccess(result, otherExecutor),
  );
  const unboundSuccessAssertion = assertTrustedCategoryExecutionSuccess as unknown as (
    value: unknown,
  ) => void;
  assert.throws(() => unboundSuccessAssertion(result));

  const tampered = structuredClone(result) as {
    artifact: {
      result: {
        evidence?: { metric: { borrowBalanceStored: string } };
      };
    };
  };
  tampered.artifact.result.evidence!.metric.borrowBalanceStored = "51";
  assert.throws(() => assertTrustedCategoryExecution(tampered, executor));

  await assert.rejects(
    executor.evaluate({
      category: new String("health"),
    } as unknown as { category: "health" }),
    TypeError,
  );
  await assert.rejects(
    executor.evaluate({
      category: "health",
      adapterId: undefined,
    } as unknown as CategoryAdapterExecutionInput),
    TypeError,
  );
  await assert.rejects(
    executor.evaluate({
      category: "health",
      adapterId: new String(VENUS_HEALTH_ADAPTER_ID),
    } as unknown as CategoryAdapterExecutionInput),
    TypeError,
  );
  await assert.rejects(
    executor.evaluate({
      category: "health",
      adapterId: "unknown-adapter-v1",
    } as unknown as CategoryAdapterExecutionInput),
    TypeError,
  );
  const accessorAdapter = { category: "health" as const };
  Object.defineProperty(accessorAdapter, "adapterId", {
    enumerable: true,
    get: () => VENUS_HEALTH_ADAPTER_ID,
  });
  await assert.rejects(
    executor.evaluate(accessorAdapter as CategoryAdapterExecutionInput),
    TypeError,
  );
  const symbolAdapter = {
    category: "health" as const,
    adapterId: VENUS_HEALTH_ADAPTER_ID,
  };
  Object.defineProperty(symbolAdapter, Symbol("unexpected"), {
    enumerable: true,
    value: true,
  });
  await assert.rejects(
    executor.evaluate(symbolAdapter as CategoryAdapterExecutionInput),
    TypeError,
  );

  let categoryReads = 0;
  const changingCategory = new Proxy(
    { category: "health" as const },
    {
      get(target, key, receiver) {
        if (key === "category") {
          categoryReads += 1;
          return categoryReads <= 2 ? "health" : "grid";
        }
        return Reflect.get(target, key, receiver);
      },
    },
  );
  const proxyResult = await executor.evaluate(changingCategory);
  assert.equal(categoryReads, 0);
  assert.equal(proxyResult.outcome, "executed");
  if (proxyResult.outcome === "executed") {
    assert.equal(proxyResult.artifact.adapter.category, "health");
  }

  let adapterReads = 0;
  const changingAdapter = new Proxy(
    {
      category: "health" as const,
      adapterId: VENUS_HEALTH_ADAPTER_ID,
    },
    {
      get(target, key, receiver) {
        if (key === "adapterId") {
          adapterReads += 1;
          return adapterReads === 1
            ? VENUS_HEALTH_ADAPTER_ID
            : HEALTH_ADAPTER_ID;
        }
        return Reflect.get(target, key, receiver);
      },
    },
  );
  const selectedProxyResult = await executor.evaluate(changingAdapter);
  assert.equal(adapterReads, 0);
  assert.equal(selectedProxyResult.outcome, "executed");
  if (selectedProxyResult.outcome === "executed") {
    assert.equal(
      selectedProxyResult.artifact.adapter.adapterId,
      VENUS_HEALTH_ADAPTER_ID,
    );
  }

  assert.throws(() =>
    Object.assign(result.artifact, {
      artifactSha256: "d".repeat(64),
    }),
  );
});

test("trusted pass results bind an explicit adapter and private mandate/candidate context", async () => {
  const { executor, result } = await evaluateMode("pass");
  assert.equal(result.outcome, "executed");
  if (result.outcome !== "executed") return;

  const selection = {
    category: "health" as const,
    adapterId: VENUS_HEALTH_ADAPTER_ID,
  };
  const context = {
    mandate: {
      mandateId: "mandate-1",
      category: "health",
      policy: { minLiquidityUsdScaled: "100" },
    },
    candidate: {
      chainId: 56,
      tokenId: "42",
      owner: ACCOUNT,
    },
  };

  const bound = bindTrustedCategoryExecutionSuccess(
    result,
    executor,
    selection,
    context,
  );
  assert.equal(bound, result);
  assertBoundCategoryExecutionSuccess(result, executor, selection, context);

  assert.throws(() =>
    assertBoundCategoryExecutionSuccess(
      result,
      executor,
      { category: "health", adapterId: HEALTH_ADAPTER_ID },
      context,
    ),
  );
  assert.throws(() =>
    assertBoundCategoryExecutionSuccess(result, executor, selection, {
      ...context,
      candidate: { ...context.candidate, tokenId: "43" },
    }),
  );
  assert.throws(() =>
    bindTrustedCategoryExecutionSuccess(result, executor, selection, {
      ...context,
      mandate: { ...context.mandate, mandateId: "mandate-2" },
    }),
  );

  const requestBound = bindTrustedCategoryExecutionSuccess(
    result,
    executor,
    {
      selection,
      mandate: context.mandate,
      candidate: context.candidate,
    },
  );
  assert.equal(requestBound, result);
});

test("category binding rejects missing or forged selection/context capabilities", async () => {
  const { executor, result } = await evaluateMode("pass");
  assert.equal(result.outcome, "executed");
  if (result.outcome !== "executed") return;

  const context = {
    mandate: { mandateId: "mandate-1" },
    candidate: { chainId: 56, tokenId: "42" },
  };
  assert.throws(() =>
    bindTrustedCategoryExecutionSuccess(result, executor, {
      category: "health",
    } as never, context),
  );
  assert.throws(() =>
    bindTrustedCategoryExecutionSuccess(
      result,
      executor,
      { category: "health", adapterId: VENUS_HEALTH_ADAPTER_ID },
      {
        mandate: { mandateId: "mandate-1" },
        candidate: { chainId: 56, tokenId: "42", extra: undefined },
      },
    ),
  );

  const accessorContext = {
    mandate: { mandateId: "mandate-1" },
    candidate: { chainId: 56, tokenId: "42" },
  } as { mandate: unknown; candidate: unknown };
  Object.defineProperty(accessorContext, "candidate", {
    enumerable: true,
    get: () => ({ chainId: 56, tokenId: "42" }),
  });
  assert.throws(() =>
    bindTrustedCategoryExecutionSuccess(
      result,
      executor,
      { category: "health", adapterId: VENUS_HEALTH_ADAPTER_ID },
      accessorContext,
    ),
  );

  const proxyContext = new Proxy(context, {});
  assert.throws(() =>
    bindTrustedCategoryExecutionSuccess(
      result,
      executor,
      { category: "health", adapterId: VENUS_HEALTH_ADAPTER_ID },
      proxyContext,
    ),
  );
});

test("category binding accepts only a trusted pass result from the originating executor", async () => {
  const pass = await evaluateMode("pass");
  const inconclusive = await evaluateMode("unknown");
  const selection = {
    category: "health" as const,
    adapterId: VENUS_HEALTH_ADAPTER_ID,
  };
  const context = {
    mandate: { mandateId: "mandate-1" },
    candidate: { chainId: 56, tokenId: "42" },
  };
  assert.equal(pass.result.outcome, "executed");
  if (pass.result.outcome !== "executed") return;
  assert.throws(() =>
    bindTrustedCategoryExecutionSuccess(
      structuredClone(pass.result),
      pass.executor,
      selection,
      context,
    ),
  );
  assert.throws(() =>
    bindTrustedCategoryExecutionSuccess(
      new Proxy(pass.result, {}),
      pass.executor,
      selection,
      context,
    ),
  );
  assert.throws(() =>
    bindTrustedCategoryExecutionSuccess(
      pass.result,
      inconclusive.executor,
      selection,
      context,
    ),
  );
  assert.throws(() =>
    bindTrustedCategoryExecutionSuccess(
      inconclusive.result,
      inconclusive.executor,
      selection,
      context,
    ),
  );
});

test("bound capability snapshots the request before adapter I/O", async () => {
  const routes: BscCategoryRpcRoute[] = [];
  const responseBodies = new Map<string, Uint8Array>();
  const baseTransport = scenarioTransport("pass", routes, responseBodies);
  let request: {
    selection: { category: "health"; adapterId: typeof VENUS_HEALTH_ADAPTER_ID };
    mandate: { mandateId: string };
    candidate: { chainId: number; tokenId: string };
  };
  const executor = createCategoryAdapterExecutor({
    deployment: venusDeployment(),
    verifierPolicySha256: POLICY_SHA256,
    transport: {
      async request(route) {
        // Mutate the caller-owned object at the first I/O boundary. A correct
        // bound evaluator has already captured the original request by then.
        request.selection.adapterId = HEALTH_ADAPTER_ID as never;
        request.mandate.mandateId = "mutated-after-snapshot";
        request.candidate.tokenId = "mutated-after-snapshot";
        return baseTransport.request(route);
      },
    },
    clock: () => 1_700_000_000,
    randomUUID: sequentialId(),
  });
  const capability: CategoryExecutionBindingCapability =
    createCategoryExecutionBindingCapability(executor);
  request = {
    selection: {
      category: "health",
      adapterId: VENUS_HEALTH_ADAPTER_ID,
    },
    mandate: { mandateId: "mandate-before-io" },
    candidate: { chainId: 56, tokenId: "candidate-before-io" },
  };
  const originalRequest = structuredClone(request);
  const result = await capability.evaluateBound(request);
  assert.equal(result.outcome, "executed");
  if (result.outcome !== "executed") return;
  assert.equal(result.artifact.adapter.adapterId, VENUS_HEALTH_ADAPTER_ID);

  capability.assertBound(result, originalRequest);
  assert.throws(() => capability.assertBound(result, request));
  assert.equal(
    routes.filter((route) => route.purpose === "state-read").length,
    3,
  );
});

test("fail and unknown executions are trusted artifacts but cannot pass the success assertion", async () => {
  const { executor: failExecutor, result: failResult } =
    await evaluateMode("fail");
  assert.equal(failResult.outcome, "executed");
  if (failResult.outcome !== "executed") return;
  assert.equal(failResult.artifact.result.status, "fail");
  if (failResult.artifact.result.status !== "fail") return;
  assert.equal(failResult.artifact.result.code, "VENUS_ACCOUNT_SHORTFALL");
  assertTrustedCategoryExecution(failResult, failExecutor);
  assert.throws(() =>
    assertTrustedCategoryExecutionSuccess(failResult, failExecutor),
  );

  const { executor: unknownExecutor, result: unknownResult } =
    await evaluateMode("unknown");
  assert.equal(unknownResult.outcome, "executed");
  if (unknownResult.outcome !== "executed") return;
  assert.equal(unknownResult.artifact.result.status, "unknown");
  if (unknownResult.artifact.result.status !== "unknown") return;
  assert.equal(unknownResult.artifact.result.code, "READ_UNAVAILABLE");
  assertTrustedCategoryExecution(unknownResult, unknownExecutor);
  assert.throws(() =>
    assertTrustedCategoryExecutionSuccess(unknownResult, unknownExecutor),
  );
});

test("artifact schema rejects a cross-adapter result code even when the outer shape is valid", async () => {
  const { result } = await evaluateMode("pass");
  assert.equal(result.outcome, "executed");
  if (result.outcome !== "executed") return;
  const tampered = structuredClone(result.artifact) as Record<string, unknown>;
  tampered.result = {
    status: "fail",
    code: "GRID_SPOT_OUTSIDE_BAND",
    message: "wrong adapter code",
  };
  const parsed = categoryExecutionArtifactSchema.safeParse(tampered);
  assert.equal(parsed.success, false);
  assert.equal(CATEGORY_EXECUTION_ARTIFACT_SCHEMA, "mandatex.agent-supply.category-execution-artifact.v1");
});

test("Aave deployment policy requires an explicit health-factor threshold", () => {
  const deployment = deploymentWithEnabledAdapter(HEALTH_ADAPTER_ID, {
    poolAddress: AAVE_POOL,
    accountAddress: ACCOUNT,
  });
  assert.throws(() => parseCategoryAdapterDeploymentManifest(deployment));
});

function venusDeployment(): unknown {
  const registry = new Map(
    CATEGORY_ADAPTER_REGISTRY.map((entry) => [entry.adapterId, entry]),
  );
  return {
    schema: CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
    chainId: 56,
    adapters: [
      {
        adapterId: GRID_ADAPTER_ID,
        category: "grid",
        enabled: false,
        evidenceSchema: GRID_EVIDENCE_SCHEMA,
        validationProfile: CATEGORY_ADAPTER_VALIDATION_PROFILES.grid,
        protocol: "pancakeswap-v3",
        metric: registry.get(GRID_ADAPTER_ID)!.metric,
        reads: [{ label: "slot0", selector: SELECTOR_SLOT0, target: "pool" }],
      },
      {
        adapterId: YIELD_ADAPTER_ID,
        category: "yield",
        enabled: false,
        evidenceSchema: YIELD_EVIDENCE_SCHEMA,
        validationProfile: CATEGORY_ADAPTER_VALIDATION_PROFILES.yield,
        protocol: "erc4626",
        metric: registry.get(YIELD_ADAPTER_ID)!.metric,
        reads: [
          { label: "totalAssets", selector: SELECTOR_TOTAL_ASSETS, target: "vault" },
          { label: "totalSupply", selector: SELECTOR_TOTAL_SUPPLY, target: "vault" },
        ],
      },
      {
        adapterId: HEALTH_ADAPTER_ID,
        category: "health",
        enabled: false,
        evidenceSchema: HEALTH_EVIDENCE_SCHEMA,
        validationProfile: CATEGORY_ADAPTER_VALIDATION_PROFILES.aaveHealth,
        protocol: "aave-v3",
        metric: registry.get(HEALTH_ADAPTER_ID)!.metric,
        reads: [
          {
            label: "getUserAccountData",
            selector: SELECTOR_GET_USER_ACCOUNT_DATA,
            target: "pool",
          },
        ],
      },
      {
        adapterId: VENUS_HEALTH_ADAPTER_ID,
        category: "health",
        enabled: true,
        evidenceSchema: VENUS_HEALTH_EVIDENCE_SCHEMA,
        validationProfile: CATEGORY_ADAPTER_VALIDATION_PROFILES.venusHealth,
        protocol: "venus",
        metric: registry.get(VENUS_HEALTH_ADAPTER_ID)!.metric,
        reads: [
          {
            label: "getAccountLiquidity",
            selector: SELECTOR_GET_ACCOUNT_LIQUIDITY,
            target: "comptroller",
          },
          {
            label: "getAssetsIn",
            selector: SELECTOR_GET_ASSETS_IN,
            target: "comptroller",
          },
          {
            label: "borrowBalanceStored",
            selector: SELECTOR_BORROW_BALANCE_STORED,
            target: "borrowMarket",
          },
        ],
        configuration: {
          comptrollerAddress: VENUS_COMPTROLLER,
          accountAddress: ACCOUNT,
          borrowMarketAddress: VENUS_MARKET,
          minLiquidityUsdScaled: "100",
        },
      },
    ],
  };
}

function deploymentWithEnabledAdapter(
  adapterId: string,
  configuration: Readonly<Record<string, unknown>>,
): unknown {
  return deploymentWithEnabledAdapters(
    new Map([[adapterId, configuration]]),
  );
}

function deploymentWithBothHealthAdapters(): unknown {
  return deploymentWithEnabledAdapters(
    new Map([
      [HEALTH_ADAPTER_ID, {
        poolAddress: AAVE_POOL,
        accountAddress: ACCOUNT,
        minHealthFactorScaled: "1100000000000000000",
      }],
      [VENUS_HEALTH_ADAPTER_ID, {
        comptrollerAddress: VENUS_COMPTROLLER,
        accountAddress: ACCOUNT,
        borrowMarketAddress: VENUS_MARKET,
        minLiquidityUsdScaled: "100",
      }],
    ]),
  );
}

function deploymentWithEnabledAdapters(
  configurations: ReadonlyMap<string, Readonly<Record<string, unknown>>>,
): unknown {
  const deployment = structuredClone(venusDeployment()) as {
    adapters: Array<{
      adapterId: string;
      enabled: boolean;
      configuration?: Record<string, unknown>;
    }>;
  };
  for (const entry of deployment.adapters) {
    entry.enabled = configurations.has(entry.adapterId);
    delete entry.configuration;
    const configuration = configurations.get(entry.adapterId);
    if (configuration !== undefined) entry.configuration = { ...configuration };
  }
  return deployment;
}

async function evaluateMode(
  mode: "pass" | "fail" | "unknown",
): Promise<Readonly<{
  executor: ReturnType<typeof createCategoryAdapterExecutor>;
  result: Awaited<ReturnType<ReturnType<typeof createCategoryAdapterExecutor>["evaluate"]>>;
}>> {
  const executor = createCategoryAdapterExecutor({
    deployment: venusDeployment(),
    verifierPolicySha256: POLICY_SHA256,
    transport: scenarioTransport(mode, [], new Map()),
    clock: () => 1_700_000_000,
    randomUUID: sequentialId(),
  });
  return Object.freeze({
    executor,
    result: await executor.evaluate({ category: "health" }),
  });
}

function scenarioTransport(
  mode: "pass" | "fail" | "unknown",
  routes: BscCategoryRpcRoute[],
  responseBodies: Map<string, Uint8Array>,
): Readonly<{ request: (route: TransportRoute) => Promise<BoundedHttpResponse> }> {
  let headerReads = 0;
  let stateReads = 0;
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      assert.equal(route.kind, "bsc-category-rpc");
      if (route.kind !== "bsc-category-rpc") {
        throw new Error("expected a category route");
      }
      routes.push(route);
      const request = JSON.parse(route.body) as { id: string };
      let result: unknown;
      switch (route.purpose) {
        case "chain-id":
          result = "0x38";
          break;
        case "head-block-number":
          result = "0x64";
          break;
        case "block-header":
          result = {
            number: route.approvedBlockNumber,
            hash: BLOCK_HASH,
            timestamp: "0x64",
          };
          headerReads += 1;
          break;
        case "state-read":
          stateReads += 1;
          if (mode === "unknown" && stateReads === 1) {
            throw new Error("simulated unavailable state read");
          }
          result = venusStateResult(route.approvedCalldata, mode);
          break;
      }
      const value = { jsonrpc: "2.0", id: request.id, result };
      const body = Buffer.from(JSON.stringify(value));
      responseBodies.set(route.body, body);
      return {
        status: 200,
        contentType: "application/json",
        retryAfter: null,
        rateLimitRemaining: null,
        body,
        responseSha256: sha256(body),
        resolvedAddress: "93.184.216.34",
        startedAt: "2026-08-18T12:00:00.000Z",
        finishedAt: "2026-08-18T12:00:00.001Z",
        latencyMs: headerReads,
      };
    },
  };
}

function mappedStateTransport(
  responses: ReadonlyMap<string, string>,
  routes: BscCategoryRpcRoute[],
): Readonly<{ request: (route: TransportRoute) => Promise<BoundedHttpResponse> }> {
  let headerReads = 0;
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      assert.equal(route.kind, "bsc-category-rpc");
      if (route.kind !== "bsc-category-rpc") {
        throw new Error("expected a category route");
      }
      routes.push(route);
      const request = JSON.parse(route.body) as { id: string };
      let result: unknown;
      switch (route.purpose) {
        case "chain-id":
          result = "0x38";
          break;
        case "head-block-number":
          result = "0x64";
          break;
        case "block-header":
          result = {
            number: route.approvedBlockNumber,
            hash: BLOCK_HASH,
            timestamp: "0x64",
          };
          headerReads += 1;
          break;
        case "state-read": {
          const selector = route.approvedCalldata.slice(0, 10);
          result = responses.get(selector);
          if (result === undefined) {
            throw new Error(`unexpected mapped selector ${selector}`);
          }
          break;
        }
      }
      const body = Buffer.from(
        JSON.stringify({ jsonrpc: "2.0", id: request.id, result }),
      );
      return {
        status: 200,
        contentType: "application/json",
        retryAfter: null,
        rateLimitRemaining: null,
        body,
        responseSha256: sha256(body),
        resolvedAddress: "93.184.216.34",
        startedAt: "2026-08-18T12:00:00.000Z",
        finishedAt: "2026-08-18T12:00:00.001Z",
        latencyMs: headerReads,
      };
    },
  };
}

function venusStateResult(data: string, mode: "pass" | "fail" | "unknown"): string {
  const selector = data.slice(0, 10);
  if (selector === SELECTOR_GET_ACCOUNT_LIQUIDITY) {
    return returndata(
      0n,
      mode === "fail" ? 0n : 200n,
      mode === "fail" ? 1n : 0n,
    );
  }
  if (selector === SELECTOR_GET_ASSETS_IN) {
    return returndata(32n, 1n, BigInt(ACCOUNT));
  }
  if (selector === SELECTOR_BORROW_BALANCE_STORED) {
    // Live Venus vTokens return three words; only word zero is the balance.
    return returndata(50n, 0n, 0n);
  }
  throw new Error(`unexpected Venus selector ${selector}`);
}

function sequentialId(): () => string {
  let value = 0;
  return () => `runtime-${++value}`;
}

function returndata(...values: bigint[]): string {
  return `0x${values
    .map((value) => value.toString(16).padStart(64, "0"))
    .join("")}`;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
