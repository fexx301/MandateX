import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import type { IncomingHttpHeaders } from "node:http";
import { request as nodeHttpsRequest } from "node:https";
import test from "node:test";

import {
  SELECTOR_GET_ACCOUNT_LIQUIDITY,
  SELECTOR_TOTAL_ASSETS,
  SELECTOR_TOTAL_SUPPLY,
  addressCalldata,
} from "@mandatex/category-adapters";

import {
  CategoryBlockCanonicalityError,
  CategoryBlockPinError,
  CategoryReadContractError,
  TransportPinnedCategoryReader,
  type ExpectedCategoryRead,
} from "../src/category/rpc.js";
import {
  BSC_MAINNET_RPC_ORIGIN,
  PinnedHttpsTransport,
  TransportError,
  validateTransportRoute,
  type BoundedHttpResponse,
  type BscCategoryRpcRoute,
  type TransportRoute,
} from "../src/transport/http.js";

const BLOCK_HASH = `0x${"b".repeat(64)}`;
const REORGED_BLOCK_HASH = `0x${"c".repeat(64)}`;
const VAULT = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";
const ACCOUNT = "0x3333333333333333333333333333333333333333";

const YIELD_READS = Object.freeze([
  Object.freeze({
    label: "totalAssets",
    to: VAULT,
    data: SELECTOR_TOTAL_ASSETS,
  }),
  Object.freeze({
    label: "totalSupply",
    to: VAULT,
    data: SELECTOR_TOTAL_SUPPLY,
  }),
] satisfies readonly ExpectedCategoryRead[]);

test("category transport binds one exact target, calldata, selector, and canonical block", () => {
  const calldata = addressCalldata(SELECTOR_GET_ACCOUNT_LIQUIDITY, ACCOUNT);
  const valid = stateRoute(VAULT, calldata);

  assert.equal(validateTransportRoute(valid).origin, BSC_MAINNET_RPC_ORIGIN);

  const parsed = JSON.parse(valid.body) as {
    params: readonly [
      Readonly<{ to: string; data: string }>,
      Readonly<{ blockHash: string; requireCanonical: boolean }>,
    ];
  };
  const changedArgument = `${calldata.slice(0, -2)}44`;
  const invalid: unknown[] = [
    { ...valid, body: stateBody(OTHER, calldata) },
    { ...valid, body: stateBody(VAULT, changedArgument) },
    {
      ...valid,
      approvedCalldata: "0x70a08231",
      body: stateBody(VAULT, "0x70a08231"),
    },
    {
      ...valid,
      approvedCalldata: `${SELECTOR_TOTAL_ASSETS}${"00".repeat(32)}`,
      body: stateBody(
        VAULT,
        `${SELECTOR_TOTAL_ASSETS}${"00".repeat(32)}`,
      ),
    },
    {
      ...valid,
      approvedCalldata: SELECTOR_GET_ACCOUNT_LIQUIDITY,
      body: stateBody(VAULT, SELECTOR_GET_ACCOUNT_LIQUIDITY),
    },
    {
      ...valid,
      approvedCalldata: `${SELECTOR_GET_ACCOUNT_LIQUIDITY}${"1".repeat(24)}${ACCOUNT.slice(2)}`,
      body: stateBody(
        VAULT,
        `${SELECTOR_GET_ACCOUNT_LIQUIDITY}${"1".repeat(24)}${ACCOUNT.slice(2)}`,
      ),
    },
    { ...valid, approvedTargets: [] },
    { ...valid, approvedTargets: [VAULT, OTHER] },
    { ...valid, extra: true },
    {
      ...valid,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "category-test",
        method: "eth_call",
        params: [
          parsed.params[0],
          { blockHash: BLOCK_HASH, requireCanonical: false },
        ],
      }),
    },
  ];

  for (const route of invalid) {
    assert.throws(
      () => validateTransportRoute(route as TransportRoute),
      (error: unknown) =>
        error instanceof TransportError &&
        error.code === "RPC_METHOD_NOT_ALLOWED",
    );
  }
});

test("category transport rejects accessor routes before validation or DNS", async () => {
  let bodyReads = 0;
  let resolverCalls = 0;
  const calldata = addressCalldata(SELECTOR_GET_ACCOUNT_LIQUIDITY, ACCOUNT);
  const route = stateRoute(VAULT, calldata);
  Object.defineProperty(route, "body", {
    enumerable: true,
    configurable: true,
    get() {
      bodyReads += 1;
      return bodyReads === 1
        ? stateBody(VAULT, calldata)
        : JSON.stringify({
            jsonrpc: "2.0",
            id: "category-test",
            method: "eth_sendRawTransaction",
            params: ["0x00"],
          });
    },
  });
  const transport = new PinnedHttpsTransport({
    resolver: async () => {
      resolverCalls += 1;
      return [{ address: "93.184.216.34", family: 4 }];
    },
  });

  await assert.rejects(
    transport.request(route),
    (error: unknown) =>
      error instanceof TransportError && error.code === "METHOD_NOT_ALLOWED",
  );
  assert.equal(bodyReads, 0);
  assert.equal(resolverCalls, 0);
});

test("category transport transmits the body captured before asynchronous DNS", async () => {
  let markResolverStarted!: () => void;
  let releaseResolver!: () => void;
  const resolverStarted = new Promise<void>((resolve) => {
    markResolverStarted = resolve;
  });
  const resolverRelease = new Promise<void>((resolve) => {
    releaseResolver = resolve;
  });
  let transmittedBody = "";
  const route = stateRoute(VAULT, SELECTOR_TOTAL_ASSETS);
  const originalBody = route.body;
  const mutableRoute = route as unknown as {
    body: string;
    approvedTargets: string[];
  };
  const transport = new PinnedHttpsTransport({
    resolver: async () => {
      markResolverStarted();
      await resolverRelease;
      return [{ address: "93.184.216.34", family: 4 }];
    },
    requestFactory: capturingRequestFactory((body) => {
      transmittedBody = body;
    }),
  });

  const pending = transport.request(route);
  await resolverStarted;
  mutableRoute.body = JSON.stringify({
    jsonrpc: "2.0",
    id: "category-test",
    method: "eth_sendRawTransaction",
    params: ["0x00"],
  });
  mutableRoute.approvedTargets[0] = OTHER;
  releaseResolver();

  const result = await pending;
  assert.equal(result.status, 200);
  assert.equal(transmittedBody, originalBody);
});

test("category reader verifies chain 56, pins head minus two, and records raw hashes", async () => {
  const routes: BscCategoryRpcRoute[] = [];
  const reader = await TransportPinnedCategoryReader.create({
    transport: scenarioTransport({}, routes),
    randomUUID: sequentialId(),
    expectedReads: YIELD_READS,
  });

  assert.deepEqual(reader.anchor, {
    number: 98,
    hash: BLOCK_HASH,
    timestamp: 100,
  });
  assert.equal(Object.isFrozen(reader), true);
  assert.equal(Object.isFrozen(reader.anchor), true);
  assert.throws(() => Object.assign(reader.anchor, { hash: REORGED_BLOCK_HASH }));
  assert.throws(() =>
    Object.defineProperty(reader, "anchor", {
      value: { number: 1, hash: REORGED_BLOCK_HASH, timestamp: 1 },
    }),
  );

  const outcomes = await Promise.all(YIELD_READS.map((read) => reader.call(read)));
  assert.equal(outcomes.every((outcome) => outcome !== undefined), true);
  const attempts = reader.attempts();
  await reader.assertCanonical();

  assert.deepEqual(routes.map((route) => route.purpose), [
    "chain-id",
    "head-block-number",
    "block-header",
    "state-read",
    "state-read",
    "block-header",
  ]);
  const headers = routes.filter(
    (route): route is Extract<BscCategoryRpcRoute, { purpose: "block-header" }> =>
      route.purpose === "block-header",
  );
  assert.deepEqual(
    headers.map((route) => route.approvedBlockNumber),
    ["0x62", "0x62"],
  );

  const stateRoutes = routes.filter(
    (route): route is Extract<BscCategoryRpcRoute, { purpose: "state-read" }> =>
      route.purpose === "state-read",
  );
  assert.equal(stateRoutes.length, 2);
  for (const [index, route] of stateRoutes.entries()) {
    const expected = YIELD_READS[index]!;
    assert.deepEqual(route.approvedTargets, [expected.to]);
    assert.equal(route.approvedCalldata, expected.data);
    const request = JSON.parse(route.body) as {
      id: string;
      params: readonly unknown[];
    };
    assert.deepEqual(request.params, [
      { to: expected.to, data: expected.data },
      { blockHash: BLOCK_HASH, requireCanonical: true },
    ]);
    assert.equal(attempts[index]!.data, expected.data);
    assert.equal(attempts[index]!.requestSha256, sha256(route.body));
    assert.equal(
      attempts[index]!.responseSha256,
      sha256(
        JSON.stringify({
          jsonrpc: "2.0",
          id: request.id,
          result: stateResult(expected.data),
        }),
      ),
    );
  }
});

test("category block pinning rejects every chain other than BSC mainnet", async () => {
  const routes: BscCategoryRpcRoute[] = [];
  await assert.rejects(
    TransportPinnedCategoryReader.create({
      transport: scenarioTransport({ chainId: "0x39" }, routes),
      randomUUID: sequentialId(),
      expectedReads: [YIELD_READS[0]!],
    }),
    CategoryBlockPinError,
  );
  assert.deepEqual(routes.map((route) => route.purpose), ["chain-id"]);
});

test("category reader rejects out-of-order, duplicate, missing, and extra reads", async () => {
  {
    const routes: BscCategoryRpcRoute[] = [];
    const reader = await createYieldReader(routes);
    assert.equal(await reader.call(YIELD_READS[1]!), undefined);
    assert.throws(() => reader.attempts(), CategoryReadContractError);
    assert.equal(routes.filter((route) => route.purpose === "state-read").length, 0);
  }

  {
    const routes: BscCategoryRpcRoute[] = [];
    const reader = await createYieldReader(routes);
    assert.notEqual(await reader.call(YIELD_READS[0]!), undefined);
    assert.equal(await reader.call(YIELD_READS[0]!), undefined);
    assert.throws(() => reader.attempts(), CategoryReadContractError);
    assert.equal(routes.filter((route) => route.purpose === "state-read").length, 1);
  }

  {
    const reader = await createYieldReader([]);
    assert.notEqual(await reader.call(YIELD_READS[0]!), undefined);
    assert.throws(() => reader.attempts(), CategoryReadContractError);
  }

  {
    const reader = await createYieldReader([]);
    await Promise.all(YIELD_READS.map((read) => reader.call(read)));
    assert.equal(
      await reader.call({
        label: "extra",
        to: VAULT,
        data: SELECTOR_TOTAL_ASSETS,
      }),
      undefined,
    );
    assert.throws(() => reader.attempts(), CategoryReadContractError);
  }
});

test("tampered response digests resolve fail-closed and retain the actual body hash", async () => {
  const routes: BscCategoryRpcRoute[] = [];
  const reader = await TransportPinnedCategoryReader.create({
    transport: scenarioTransport({ tamperStateDigest: true }, routes),
    randomUUID: sequentialId(),
    expectedReads: [YIELD_READS[0]!],
  });

  assert.equal(await reader.call(YIELD_READS[0]!), undefined);
  const [attempt] = reader.attempts();
  assert.equal(attempt!.outcome, "invalid_response");
  const route = routes.find(
    (candidate): candidate is Extract<
      BscCategoryRpcRoute,
      { purpose: "state-read" }
    > => candidate.purpose === "state-read",
  )!;
  const request = JSON.parse(route.body) as { id: string };
  assert.equal(
    attempt!.responseSha256,
    sha256(
      JSON.stringify({
        jsonrpc: "2.0",
        id: request.id,
        result: stateResult(route.approvedCalldata),
      }),
    ),
  );
});

test("local category transport policy rejection is a contract error, not read unavailability", async () => {
  const baseTransport = scenarioTransport({}, []);
  const originalReader = await TransportPinnedCategoryReader.create({
    transport: {
      async request(route: TransportRoute): Promise<BoundedHttpResponse> {
        if (route.kind === "bsc-category-rpc" && route.purpose === "state-read") {
          throw new TransportError("RPC_METHOD_NOT_ALLOWED");
        }
        return baseTransport.request(route);
      },
    },
    randomUUID: sequentialId(),
    expectedReads: [YIELD_READS[0]!],
  });

  await assert.rejects(
    originalReader.call(YIELD_READS[0]!),
    CategoryReadContractError,
  );
  assert.throws(() => originalReader.attempts(), CategoryReadContractError);
});

test("final category canonicality recheck rejects number, hash, or timestamp drift", async () => {
  for (const scenario of [
    { finalBlockNumber: "0x63" },
    { finalBlockHash: REORGED_BLOCK_HASH },
    { finalTimestamp: "0x65" },
  ] as const) {
    const reader = await TransportPinnedCategoryReader.create({
      transport: scenarioTransport(scenario, []),
      randomUUID: sequentialId(),
      expectedReads: [YIELD_READS[0]!],
    });
    assert.notEqual(await reader.call(YIELD_READS[0]!), undefined);
    reader.attempts();
    await assert.rejects(
      reader.assertCanonical(),
      CategoryBlockCanonicalityError,
    );
  }
});

type Scenario = Readonly<{
  chainId?: string;
  head?: string;
  finalBlockNumber?: string;
  finalBlockHash?: string;
  finalTimestamp?: string;
  tamperStateDigest?: boolean;
}>;

function scenarioTransport(
  scenario: Scenario,
  routes: BscCategoryRpcRoute[],
): Readonly<{ request: (route: TransportRoute) => Promise<BoundedHttpResponse> }> {
  let headerReads = 0;
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      assert.equal(route.kind, "bsc-category-rpc");
      if (route.kind !== "bsc-category-rpc") {
        throw new Error("expected the dedicated category RPC route");
      }
      routes.push(route);
      const request = JSON.parse(route.body) as { id: string };
      let result: unknown;
      switch (route.purpose) {
        case "chain-id":
          result = scenario.chainId ?? "0x38";
          break;
        case "head-block-number":
          result = scenario.head ?? "0x64";
          break;
        case "block-header": {
          const final = headerReads > 0;
          headerReads += 1;
          result = {
            number: final
              ? (scenario.finalBlockNumber ?? route.approvedBlockNumber)
              : route.approvedBlockNumber,
            hash: final ? (scenario.finalBlockHash ?? BLOCK_HASH) : BLOCK_HASH,
            timestamp: final ? (scenario.finalTimestamp ?? "0x64") : "0x64",
          };
          break;
        }
        case "state-read":
          result = stateResult(route.approvedCalldata);
          break;
      }
      const responseValue = { jsonrpc: "2.0", id: request.id, result };
      return response(
        responseValue,
        route.purpose === "state-read" && scenario.tamperStateDigest
          ? "0".repeat(64)
          : undefined,
      );
    },
  };
}

async function createYieldReader(
  routes: BscCategoryRpcRoute[],
): Promise<TransportPinnedCategoryReader> {
  return TransportPinnedCategoryReader.create({
    transport: scenarioTransport({}, routes),
    randomUUID: sequentialId(),
    expectedReads: YIELD_READS,
  });
}

function stateResult(data: string): string {
  return data === SELECTOR_TOTAL_SUPPLY ? word(10n) : word(20n);
}

function stateRoute(to: string, data: string): BscCategoryRpcRoute {
  return {
    kind: "bsc-category-rpc",
    purpose: "state-read",
    method: "POST",
    url: BSC_MAINNET_RPC_ORIGIN,
    rpcMethod: "eth_call",
    approvedTargets: [to],
    approvedCalldata: data,
    approvedBlockHash: BLOCK_HASH,
    body: stateBody(to, data),
  };
}

function stateBody(to: string, data: string): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: "category-test",
    method: "eth_call",
    params: [
      { to, data },
      { blockHash: BLOCK_HASH, requireCanonical: true },
    ],
  });
}

function response(value: unknown, digest?: string): BoundedHttpResponse {
  const body = Buffer.from(JSON.stringify(value));
  return {
    status: 200,
    contentType: "application/json",
    retryAfter: null,
    rateLimitRemaining: null,
    body,
    responseSha256: digest ?? sha256(body),
    resolvedAddress: "93.184.216.34",
    startedAt: "2026-08-18T12:00:00.000Z",
    finishedAt: "2026-08-18T12:00:00.001Z",
    latencyMs: 1,
  };
}

function sequentialId(): () => string {
  let value = 0;
  return () => `id-${++value}`;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function word(value: bigint): string {
  return `0x${value.toString(16).padStart(64, "0")}`;
}

function capturingRequestFactory(
  capture: (body: string) => void,
): typeof nodeHttpsRequest {
  return ((_options: unknown, callback: (response: unknown) => void) => {
    let writtenBody = "";
    const request = new EventEmitter() as EventEmitter & {
      write: (chunk: string) => void;
      end: () => void;
      destroy: (error?: Error) => void;
    };
    request.write = (chunk: string) => {
      writtenBody += chunk;
    };
    request.destroy = (error?: Error) => {
      if (error !== undefined) request.emit("error", error);
    };
    request.end = () => {
      capture(writtenBody);
      const socket = new EventEmitter() as EventEmitter & {
        remoteAddress: string;
      };
      socket.remoteAddress = "93.184.216.34";
      request.emit("socket", socket);
      socket.emit("secureConnect");

      const response = new EventEmitter() as EventEmitter & {
        statusCode: number;
        headers: IncomingHttpHeaders;
        destroy: () => void;
      };
      response.statusCode = 200;
      response.headers = { "content-type": "application/json" };
      response.destroy = () => undefined;
      callback(response);
      response.emit("data", Buffer.from("{}"));
      response.emit("end");
    };
    return request;
  }) as unknown as typeof nodeHttpsRequest;
}
