import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  verifyErc8004Ownership,
  type Erc8004Result,
} from "../src/sources/erc8004.js";
import type {
  BoundedHttpResponse,
  TransportRoute,
} from "../src/transport/http.js";

const OWNER = "0x20f1ca5d1e5a3ee94c29dbf95e6bf6cea6a8d64b";
const BLOCK_A = `0x${"ab".repeat(32)}`;
const BLOCK_B = `0x${"cd".repeat(32)}`;
const BLOCK_C = `0x${"ef".repeat(32)}`;

test("ERC-8004 ownership uses one canonical N-2 EIP-1898 snapshot", async () => {
  const requests: Array<Record<string, unknown>> = [];
  const transport = rpcTransport((request) => {
    requests.push(request);
    return successfulRpcResult(request, BLOCK_A);
  });

  const result = await verifyErc8004Ownership({
    transport,
    chainId: 56,
    tokenId: "265375",
  });

  assert.equal(result.status, "verified");
  if (result.status !== "verified") return;
  assert.equal(result.snapshot.ownerAddress, OWNER);
  assert.equal(result.snapshot.headBlockNumber, "100");
  assert.equal(result.snapshot.observedBlockNumber, "98");
  assert.equal(result.snapshot.observedBlockHash, BLOCK_A);
  assert.equal(result.snapshot.confirmationDepth, 2);
  assert.equal(result.snapshot.requireCanonical, true);
  assert.equal(result.snapshot.attempts, 1);
  assert.ok(result.snapshot.registryCodeBytes > 0);

  const getCode = requests.find((request) => request.method === "eth_getCode");
  const ownerCall = requests.find((request) => request.method === "eth_call");
  assert.deepEqual((getCode?.params as unknown[])[1], {
    blockHash: BLOCK_A,
    requireCanonical: true,
  });
  assert.deepEqual((ownerCall?.params as unknown[])[1], {
    blockHash: BLOCK_A,
    requireCanonical: true,
  });
  assert.equal(JSON.stringify(requests).includes("latest"), false);
  assert.deepEqual(
    requests.map((request) => request.method),
    [
      "eth_chainId",
      "eth_blockNumber",
      "eth_getBlockByNumber",
      "eth_getCode",
      "eth_call",
      "eth_getBlockByNumber",
    ],
  );
});

test("canonical hash mismatch retries the whole snapshot once without mixing attempts", async () => {
  let attempt = 0;
  const blockCalls = new Map<number, number>();
  const requests: Array<{ attempt: number; request: Record<string, unknown> }> = [];
  const transport = rpcTransport((request) => {
    if (request.method === "eth_chainId") attempt += 1;
    requests.push({ attempt, request });
    if (request.method === "eth_getBlockByNumber") {
      const count = (blockCalls.get(attempt) ?? 0) + 1;
      blockCalls.set(attempt, count);
      const hash = attempt === 1 && count === 2 ? BLOCK_B : attempt === 2 ? BLOCK_C : BLOCK_A;
      return { number: "0x62", hash };
    }
    return successfulRpcResult(request, attempt === 2 ? BLOCK_C : BLOCK_A);
  });

  const result = await verifyErc8004Ownership({
    transport,
    chainId: 56,
    tokenId: "265375",
  });
  assert.equal(result.status, "verified");
  if (result.status !== "verified") return;
  assert.equal(result.snapshot.attempts, 2);
  assert.equal(result.snapshot.observedBlockHash, BLOCK_C);
  assert.equal(
    requests.filter(({ request }) => request.method === "eth_chainId").length,
    2,
  );

  const secondAttemptSelectors = requests
    .filter(({ attempt: requestAttempt, request }) =>
      requestAttempt === 2 && ["eth_getCode", "eth_call"].includes(String(request.method)),
    )
    .map(({ request }) => (request.params as unknown[])[1]);
  assert.deepEqual(secondAttemptSelectors, [
    { blockHash: BLOCK_C, requireCanonical: true },
    { blockHash: BLOCK_C, requireCanonical: true },
  ]);
});

test("canonical propagation exhaustion remains inconclusive", async () => {
  const transport = rpcTransport((request) => {
    if (request.method === "eth_chainId") return "0x38";
    if (request.method === "eth_blockNumber") return "0x64";
    if (request.method === "eth_getBlockByNumber") return null;
    throw new Error("unexpected method");
  });

  const result = await verifyErc8004Ownership({
    transport,
    chainId: 56,
    tokenId: "265375",
  });
  assert.equal(result.status, "inconclusive");
  if (result.status !== "inconclusive") return;
  assert.equal(result.code, "SNAPSHOT_INCONSISTENT");
  assert.equal(result.attempts, 2);
});

function successfulRpcResult(
  request: Record<string, unknown>,
  blockHash: string,
): unknown {
  switch (request.method) {
    case "eth_chainId":
      return "0x38";
    case "eth_blockNumber":
      return "0x64";
    case "eth_getBlockByNumber":
      return { number: "0x62", hash: blockHash };
    case "eth_getCode":
      return "0x60006000";
    case "eth_call":
      return `0x${"0".repeat(24)}${OWNER.slice(2)}`;
    default:
      throw new Error(`unexpected RPC method: ${String(request.method)}`);
  }
}

function rpcTransport(
  responder: (request: Record<string, unknown>) => unknown,
): { request(route: TransportRoute): Promise<BoundedHttpResponse> } {
  let count = 0;
  return {
    async request(route) {
      assert.equal(route.kind, "bsc-rpc");
      if (route.kind !== "bsc-rpc") throw new Error("unexpected route");
      const request = JSON.parse(route.body) as Record<string, unknown>;
      const result = responder(request);
      const body = Buffer.from(
        JSON.stringify({ jsonrpc: "2.0", id: request.id, result }),
      );
      count += 1;
      return response(body, count);
    },
  };
}

function response(body: Buffer, count: number): BoundedHttpResponse {
  return {
    status: 200,
    contentType: "application/json",
    retryAfter: null,
    rateLimitRemaining: null,
    body,
    responseSha256: createHash("sha256").update(body).digest("hex"),
    resolvedAddress: "1.1.1.1",
    startedAt: `2026-08-16T10:00:${String(count).padStart(2, "0")}.000Z`,
    finishedAt: `2026-08-16T10:00:${String(count).padStart(2, "0")}.010Z`,
    latencyMs: 10,
  };
}

void (null as Erc8004Result | null);
