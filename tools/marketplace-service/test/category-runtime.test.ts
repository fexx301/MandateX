import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  canonicalQuoteJson,
  computeQuoteSha256,
  validateTransportRoute,
  type BoundedHttpResponse,
  type TransportRoute,
} from "@mandatex/agent-supply-verifier";
import { canonicalSha256 } from "@mandatex/marketplace-core";
import { encodeAbiParameters, parseAbiParameters, type Hex } from "viem";

import {
  createMarketplaceCategoryVerifierRuntime,
  marketplaceVerifierPolicyV2Manifest,
  marketplaceVerifierPolicyV2Sha256,
} from "../src/index.js";
import { createPrivateMarketplaceCategorySuccessorVerifierRuntime } from "../src/category-runtime.js";
import { marketplaceCategorySuccessorPolicySha256 } from "../src/category-verifier-policy.js";
import * as publicServiceApi from "../src/index.js";
import { MarketplaceServiceError } from "../src/errors.js";
import {
  CATEGORY_ACCOUNT,
  CATEGORY_BORROW_MARKET,
  CATEGORY_COMPTROLLER,
  categoryDeployment,
  categorySuccessorDeployment,
  categorySuccessorQuotePolicy,
} from "./category-fixture.js";

const POLICY_IDENTITY = Object.freeze({
  passivePolicyFingerprint: "aa".repeat(32),
  trustPolicySha256: "bb".repeat(32),
});
const ANCHOR_HASH = `0x${"c".repeat(64)}`;
const EVALUATED_AT = 1_725_000_000;

test("the public service API exposes only the signer-free category boundary", () => {
  assert.equal(
    "createMarketplaceCategoryAttestationRuntime" in publicServiceApi,
    false,
  );
  assert.equal(
    "createPrivateMarketplaceCategorySuccessorVerifierRuntime" in publicServiceApi,
    false,
  );
});

test("successor runtime derives execution and infrastructure only from its static policy", () => {
  const deployment = categorySuccessorDeployment();
  const policyIdentity = {
    ...POLICY_IDENTITY,
    categorySuccessorDeployment: deployment,
    quotePolicy: categorySuccessorQuotePolicy(),
  };
  const verifierPolicySha256 =
    marketplaceCategorySuccessorPolicySha256(policyIdentity);
  const runtime = createPrivateMarketplaceCategorySuccessorVerifierRuntime({
    policyIdentity,
    verifierPolicySha256,
    transport: categoryTransport([]),
    clock: () => EVALUATED_AT,
    randomUUID: () => "successor-runtime-rpc-id",
  });

  assert.equal(
    runtime.policy.schema,
    "mandatex.marketplace.category-successor-policy.v1",
  );
  assert.equal(runtime.policySha256, verifierPolicySha256);
  assert.equal(
    runtime.deploymentSha256,
    runtime.policy.categoryPolicy.deploymentSha256,
  );
  assert.deepEqual(runtime.infrastructure, deployment.infrastructure);
  assert.equal(
    runtime.policy.categoryPolicy.deployment.adapters.every(
      (entry) => !Object.hasOwn(entry, "configuration"),
    ),
    true,
  );

  assert.throws(
    () =>
      createPrivateMarketplaceCategorySuccessorVerifierRuntime({
        policyIdentity,
        verifierPolicySha256,
        transport: categoryTransport([]),
        clock: () => EVALUATED_AT,
        randomUUID: () => "successor-runtime-rpc-id",
        deployment: categoryDeployment(),
      } as never),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "VERIFIER_CONFIGURATION_INVALID",
  );
});

test("the signer-free runtime completes the default three-read Venus path", async () => {
  const deployment = categoryDeployment();
  const routes: TransportRoute[] = [];
  const runtime = createRuntime(deployment, categoryTransport(routes));
  const mutableDeployment = deployment as unknown as {
    adapters: Array<{
      configuration?: { comptrollerAddress?: string; borrowMarketAddress?: string };
    }>;
  };
  if (mutableDeployment.adapters[0]?.configuration !== undefined) {
    mutableDeployment.adapters[0].configuration.comptrollerAddress =
      "0x9999999999999999999999999999999999999999";
    mutableDeployment.adapters[0].configuration.borrowMarketAddress =
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  }

  assert.equal("issue" in runtime, false);
  assert.equal("wire" in runtime, false);
  assert.equal("pinnedTrust" in runtime, false);
  assert.equal("evaluateAndAttest" in runtime, false);

  const result = await runtime.evaluateCategory({ category: "health" });
  assert.equal(result.outcome, "executed", JSON.stringify(result));
  if (result.outcome !== "executed") return;
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.artifact), true);
  assert.equal(result.artifact.adapter.adapterId, "venus-health-v1");
  assert.equal(
    result.artifact.verifierPolicyProfile,
    "mandatex.marketplace.verifier-policy.v2",
  );
  assert.equal(result.artifact.result.status, "pass");
  if (result.artifact.result.status !== "pass") return;
  assert.equal(
    result.artifact.result.evidence.schema,
    "mandatex.category.venus-health-evidence.v1",
  );
  if (
    result.artifact.result.evidence.schema !==
    "mandatex.category.venus-health-evidence.v1"
  ) {
    return;
  }
  assert.equal(
    result.artifact.result.evidenceSha256,
    computeQuoteSha256(canonicalQuoteJson(result.artifact.result.evidence)),
  );
  assert.equal(
    result.artifact.result.evidence.subject.borrowMarketAddress,
    CATEGORY_BORROW_MARKET,
  );
  assert.equal(
    result.artifact.result.evidence.metric.borrowBalanceStored,
    "4200000000000000000000",
  );

  assert.deepEqual(
    routes.map((route) =>
      route.kind === "bsc-category-rpc" ? route.purpose : route.kind,
    ),
    [
      "chain-id",
      "head-block-number",
      "block-header",
      "state-read",
      "state-read",
      "state-read",
      "block-header",
    ],
  );
  const stateReads = routes.filter(
    (route): route is Extract<TransportRoute, { kind: "bsc-category-rpc" }> =>
      route.kind === "bsc-category-rpc" && route.purpose === "state-read",
  );
  assert.deepEqual(
    stateReads.map((route) => {
      const body = JSON.parse(route.body) as {
        params: readonly [{ readonly to: string; readonly data: string }, unknown];
      };
      return [body.params[0].to, body.params[0].data.slice(0, 10)];
    }),
    [
      [CATEGORY_COMPTROLLER, "0x5ec88c79"],
      [CATEGORY_COMPTROLLER, "0xabfceffc"],
      [CATEGORY_BORROW_MARKET, "0x95dd9193"],
    ],
  );
  for (const route of stateReads) {
    const body = JSON.parse(route.body) as {
      params: readonly [unknown, { readonly blockHash: string; readonly requireCanonical: boolean }];
    };
    assert.deepEqual(body.params[1], {
      blockHash: ANCHOR_HASH,
      requireCanonical: true,
    });
  }
});

test("category runtime seals fail and unknown adapter outcomes without signing them", async () => {
  const deployment = categoryDeployment();
  const belowFloor = createRuntime(
    deployment,
    categoryTransport([], { liquidity: 500n * 10n ** 18n }),
  );
  const failed = await belowFloor.evaluateCategory({ category: "health" });
  assert.equal(failed.outcome, "executed", JSON.stringify(failed));
  if (failed.outcome === "executed") {
    assert.equal(failed.artifact.result.status, "fail");
    if (failed.artifact.result.status === "fail") {
      assert.equal(failed.artifact.result.code, "VENUS_LIQUIDITY_BELOW_FLOOR");
    }
  }

  const noDebt = createRuntime(
    deployment,
    categoryTransport([], { borrowBalance: 0n }),
  );
  const unknown = await noDebt.evaluateCategory({ category: "health" });
  assert.equal(unknown.outcome, "executed", JSON.stringify(unknown));
  if (unknown.outcome === "executed") {
    assert.equal(unknown.artifact.result.status, "unknown");
    if (unknown.artifact.result.status === "unknown") {
      assert.equal(unknown.artifact.result.code, "VENUS_NO_DEBT_POSITION");
    }
  }
});

test("bound category runtime snapshots request context before adapter I/O", async () => {
  const deployment = categoryDeployment();
  const context = {
    mandate: { mandateId: "mandate-before-io", category: "health" },
    candidate: { chainId: 56, tokenId: "candidate-before-io" },
  };
  const originalContext = structuredClone(context);
  const baseTransport = categoryTransport([]);
  let firstRpc = true;
  const runtime = createRuntime(deployment, {
    async request(route) {
      if (firstRpc) {
        firstRpc = false;
        context.mandate.mandateId = "mutated-after-io";
        context.candidate.tokenId = "mutated-after-io";
      }
      return baseTransport.request(route);
    },
  });

  const result = await runtime.evaluateCategoryBound(
    { category: "health" },
    context,
  );
  assert.equal(result.outcome, "executed", JSON.stringify(result));
  if (result.outcome !== "executed") return;
  assert.equal(result.artifact.result.status, "pass");

  const assertBound: typeof runtime.assertCategoryExecutionBound =
    runtime.assertCategoryExecutionBound;
  assertBound(result, originalContext);
  assert.throws(() => assertBound(result, context));
});

test("category runtime fails closed before anchoring, on reorg, and on policy mismatch", async () => {
  const deployment = categoryDeployment();
  const wrongChain = createRuntime(
    deployment,
    categoryTransport([], { chainId: "0x1" }),
  );
  const unavailable = await wrongChain.evaluateCategory({ category: "health" });
  assert.equal(unavailable.outcome, "inconclusive");
  if (unavailable.outcome === "inconclusive") {
    assert.equal(unavailable.code, "CATEGORY_BLOCK_PIN_UNAVAILABLE");
  }

  const reorged = createRuntime(
    deployment,
    categoryTransport([], { reorgOnFinalCheck: true }),
  );
  const noncanonical = await reorged.evaluateCategory({ category: "health" });
  assert.equal(noncanonical.outcome, "inconclusive");
  if (noncanonical.outcome === "inconclusive") {
    assert.equal(
      noncanonical.code,
      "CATEGORY_BLOCK_NONCANONICAL",
      JSON.stringify(noncanonical),
    );
  }

  assert.throws(
    () =>
      createMarketplaceCategoryVerifierRuntime({
        policyIdentity: {
          ...POLICY_IDENTITY,
          categoryAdapterDeployment: deployment,
        },
        deployment,
        verifierPolicySha256: "00".repeat(32),
        transport: categoryTransport([]),
        clock: () => EVALUATED_AT,
        randomUUID: () => "category-test-id",
      }),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "VERIFIER_CONFIGURATION_INVALID",
  );
});

test("category input rejects an explicitly undefined adapter ID", async () => {
  const deployment = categoryDeployment();
  const runtime = createRuntime(deployment, categoryTransport([]));
  await assert.rejects(
    runtime.evaluateCategory({ category: "health", adapterId: undefined } as never),
    (error: unknown) =>
      error instanceof MarketplaceServiceError && error.code === "REQUEST_INVALID",
  );
  await assert.rejects(
    runtime.evaluateCategoryBound(
      { category: "health", adapterId: undefined } as never,
      { mandate: { mandateId: "m", category: "health" }, candidate: { chainId: 56, tokenId: "c" } },
    ),
    (error: unknown) =>
      error instanceof MarketplaceServiceError && error.code === "REQUEST_INVALID",
  );
});

test("category runtime snapshots proxy options and hashes the exact exposed policy", async () => {
  const deployment = categoryDeployment();
  const policyIdentity = {
    ...POLICY_IDENTITY,
    categoryAdapterDeployment: deployment,
  };
  const expectedPolicy = marketplaceVerifierPolicyV2Manifest(policyIdentity);
  const expectedPolicySha256 = canonicalSha256(expectedPolicy);
  const alternateDeployment = categoryDeployment({
    minLiquidityUsdScaled: "2000000000000000000000",
  });
  let optionGets = 0;
  let identityGets = 0;
  const identityProxy = new Proxy(policyIdentity, {
    get(target, property, receiver) {
      identityGets += 1;
      if (property === "categoryAdapterDeployment") {
        return alternateDeployment;
      }
      return Reflect.get(target, property, receiver);
    },
  });
  const alternateIdentity = {
    ...POLICY_IDENTITY,
    categoryAdapterDeployment: alternateDeployment,
  };
  const options = {
    policyIdentity: identityProxy,
    deployment,
    verifierPolicySha256: expectedPolicySha256,
    transport: categoryTransport([]),
    clock: () => EVALUATED_AT,
    randomUUID: () => "category-proxy-test-id",
  };
  const runtime = createMarketplaceCategoryVerifierRuntime(
    new Proxy(options, {
      get(target, property, receiver) {
        optionGets += 1;
        if (property === "policyIdentity") return alternateIdentity;
        return Reflect.get(target, property, receiver);
      },
    }),
  );

  assert.equal(optionGets, 0);
  assert.equal(identityGets, 0);
  assert.equal(runtime.policySha256, expectedPolicySha256);
  assert.equal(
    canonicalSha256(runtime.policy),
    runtime.policySha256,
  );
  const result = await runtime.evaluateCategory({ category: "health" });
  assert.equal(result.outcome, "executed", JSON.stringify(result));
  if (result.outcome === "executed") {
    assert.equal(
      result.artifact.verifierPolicySha256,
      runtime.policySha256,
    );
  }
});

function createRuntime(
  deployment: ReturnType<typeof categoryDeployment>,
  transport: { readonly request: (route: TransportRoute) => Promise<BoundedHttpResponse> },
) {
  const policyIdentity = {
    ...POLICY_IDENTITY,
    categoryAdapterDeployment: deployment,
  };
  return createMarketplaceCategoryVerifierRuntime({
    policyIdentity,
    deployment,
    verifierPolicySha256: marketplaceVerifierPolicyV2Sha256(policyIdentity),
    transport,
    clock: () => EVALUATED_AT,
    randomUUID: () => "category-test-id",
  });
}

function categoryTransport(
  routes: TransportRoute[],
  options: {
    readonly borrowBalance?: bigint;
    readonly chainId?: string;
    readonly liquidity?: bigint;
    readonly reorgOnFinalCheck?: boolean;
  } = {},
) {
  let blockHeaderReads = 0;
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      validateTransportRoute(route);
      routes.push(route);
      if (route.kind !== "bsc-category-rpc") {
        throw new Error(`unexpected category route ${route.kind}`);
      }
      const request = JSON.parse(route.body) as {
        id: string;
        method: string;
        params: readonly unknown[];
      };
      let result: unknown;
      switch (route.purpose) {
        case "chain-id":
          result = options.chainId ?? "0x38";
          break;
        case "head-block-number":
          result = "0x66";
          break;
        case "block-header":
          blockHeaderReads += 1;
          result = {
            number: "0x64",
            hash:
              options.reorgOnFinalCheck && blockHeaderReads === 2
                ? `0x${"d".repeat(64)}`
                : ANCHOR_HASH,
            timestamp: `0x${(EVALUATED_AT - 10).toString(16)}`,
          };
          break;
        case "state-read": {
          const call = request.params[0] as { readonly data: string };
          switch (call.data.slice(0, 10)) {
            case "0x5ec88c79":
              result = encode(
                "uint256,uint256,uint256",
                [0n, options.liquidity ?? 5_000n * 10n ** 18n, 0n],
              );
              break;
            case "0xabfceffc":
              result = encode("address[]", [
                [
                  "0x7777777777777777777777777777777777777777",
                  "0x8888888888888888888888888888888888888888",
                ],
              ]);
              break;
            case "0x95dd9193":
              result = encode("uint256,uint256,uint256", [
                options.borrowBalance ?? 4_200n * 10n ** 18n,
                0n,
                0n,
              ]);
              break;
            default:
              throw new Error(`unexpected category selector ${call.data.slice(0, 10)}`);
          }
          break;
        }
      }
      return boundedJsonResponse({ jsonrpc: "2.0", id: request.id, result });
    },
  };
}

function encode(types: string, values: readonly unknown[]): Hex {
  return encodeAbiParameters(parseAbiParameters(types), values as never);
}

function boundedJsonResponse(value: unknown): BoundedHttpResponse {
  const body = Buffer.from(JSON.stringify(value));
  return {
    status: 200,
    contentType: "application/json",
    retryAfter: null,
    rateLimitRemaining: null,
    body,
    responseSha256: createHash("sha256").update(body).digest("hex"),
    resolvedAddress: "93.184.216.34",
    startedAt: new Date(EVALUATED_AT * 1_000).toISOString(),
    finishedAt: new Date(EVALUATED_AT * 1_000 + 10).toISOString(),
    latencyMs: 10,
  };
}
