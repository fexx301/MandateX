import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import type { Hex } from "viem";

import {
  assertPreviewBlockCanonical,
  PreviewSimulationError,
  simulatePinnedRebalancePlan,
  TransportPancakeStateRpc,
} from "../src/preview/rpc.js";
import type {
  BoundedHttpResponse,
  TransportRoute,
} from "../src/transport/http.js";

const BLOCK_HASH = `0x${"a".repeat(64)}`;
const TARGET = "0x1111111111111111111111111111111111111111";
const CALLER = "0x2222222222222222222222222222222222222222";
const MULTICALL = `0xac9650d8${"00".repeat(32)}` as Hex;

test("state RPC maps every reader method onto the dedicated preview route", async () => {
  const routes: TransportRoute[] = [];
  const rpc = new TransportPancakeStateRpc(
    transport(routes, (body) => {
      const request = JSON.parse(body) as { id: string; method: string };
      const result = request.method === "eth_chainId" ? "0x38" : "0x1";
      return { jsonrpc: "2.0", id: request.id, result };
    }),
    sequentialId(),
  );

  await rpc.request({ method: "eth_chainId", params: [] });
  await rpc.request({ method: "eth_blockNumber", params: [] });
  await rpc.request({
    method: "eth_getBlockByNumber",
    params: ["0x62", false],
  });
  await rpc.request({
    method: "eth_getCode",
    params: [TARGET, { blockHash: BLOCK_HASH, requireCanonical: true }],
  });
  await rpc.request({
    method: "eth_call",
    params: [
      { to: TARGET, data: "0x6352211e" },
      { blockHash: BLOCK_HASH, requireCanonical: true },
    ],
  });

  assert.deepEqual(
    routes.map((route) =>
      route.kind === "bsc-preview-rpc" ? route.purpose : route.kind,
    ),
    [
      "chain-id",
      "head-block-number",
      "block-header",
      "contract-code",
      "state-read",
    ],
  );
});

test("simulation returns only bounded request, response, and result evidence", async () => {
  const routes: TransportRoute[] = [];
  const rawResult = `0x${"01".repeat(32)}` as Hex;
  const observation = await simulatePinnedRebalancePlan({
    transport: transport(routes, (body) => {
      const request = JSON.parse(body) as { id: string };
      return { jsonrpc: "2.0", id: request.id, result: rawResult };
    }),
    randomUUID: sequentialId(),
    caller: CALLER,
    data: MULTICALL,
    blockHash: BLOCK_HASH,
  });

  assert.equal(observation.rawResult, rawResult);
  assert.equal(observation.requestSha256.length, 64);
  assert.equal(observation.responseSha256.length, 64);
  assert.equal(routes.length, 1);
  const route = routes[0]!;
  assert.equal(route.kind, "bsc-preview-rpc");
  if (route.kind !== "bsc-preview-rpc") return;
  assert.equal(route.purpose, "simulation");
  assert.equal(JSON.stringify(route).includes("eth_send"), false);
});

test("simulation RPC errors are classified as deterministic reverts", async () => {
  await assert.rejects(
    simulatePinnedRebalancePlan({
      transport: transport([], (body) => {
        const request = JSON.parse(body) as { id: string };
        return {
          jsonrpc: "2.0",
          id: request.id,
          error: { code: 3, message: "execution reverted: private detail" },
        };
      }),
      randomUUID: sequentialId(),
      caller: CALLER,
      data: MULTICALL,
      blockHash: BLOCK_HASH,
    }),
    (error: unknown) =>
      error instanceof PreviewSimulationError &&
      error.kind === "reverted" &&
      error.evidence.requestSha256?.length === 64 &&
      error.evidence.responseSha256?.length === 64,
  );
});

test("non-revert simulation RPC failures remain inconclusive dependencies", async () => {
  await assert.rejects(
    simulatePinnedRebalancePlan({
      transport: transport([], (body) => {
        const request = JSON.parse(body) as { id: string };
        return {
          jsonrpc: "2.0",
          id: request.id,
          error: { code: -32000, message: "header not found" },
        };
      }),
      randomUUID: sequentialId(),
      caller: CALLER,
      data: MULTICALL,
      blockHash: BLOCK_HASH,
    }),
    (error: unknown) =>
      error instanceof PreviewSimulationError && error.kind === "unavailable",
  );
});

test("code 3 without a revert message is not treated as a deterministic revert", async () => {
  await assert.rejects(
    simulatePinnedRebalancePlan({
      transport: transport([], (body) => {
        const request = JSON.parse(body) as { id: string };
        return {
          jsonrpc: "2.0",
          id: request.id,
          error: { code: 3 },
        };
      }),
      randomUUID: sequentialId(),
      caller: CALLER,
      data: MULTICALL,
      blockHash: BLOCK_HASH,
    }),
    (error: unknown) =>
      error instanceof PreviewSimulationError &&
      error.kind === "invalid-response",
  );
});

test("post-simulation canonicality rejects a changed block hash", async () => {
  await assert.rejects(
    assertPreviewBlockCanonical({
      rpc: {
        async request<T>() {
          return {
            number: "0x62",
            hash: `0x${"b".repeat(64)}`,
            timestamp: "0x1",
          } as T;
        },
      },
      blockNumber: "98",
      blockHash: BLOCK_HASH,
    }),
  );
});

test("post-simulation canonicality rejects a missing or changed block number", async () => {
  for (const number of [undefined, "0x63"] as const) {
    await assert.rejects(
      assertPreviewBlockCanonical({
        rpc: {
          async request<T>() {
            return {
              ...(number === undefined ? {} : { number }),
              hash: BLOCK_HASH,
              timestamp: "0x1",
            } as T;
          },
        },
        blockNumber: "98",
        blockHash: BLOCK_HASH,
      }),
    );
  }
});

function transport(
  routes: TransportRoute[],
  responseFor: (body: string) => unknown,
) {
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      routes.push(route);
      if (!("body" in route)) throw new Error("expected a JSON-RPC route");
      return response(responseFor(route.body));
    },
  };
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
    startedAt: "2026-08-16T12:00:00.000Z",
    finishedAt: "2026-08-16T12:00:00.001Z",
    latencyMs: 1,
  };
}

function sequentialId(): () => string {
  let value = 0;
  return () => `id-${++value}`;
}
