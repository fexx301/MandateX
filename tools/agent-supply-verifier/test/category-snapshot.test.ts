import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  createCategorySnapshotCapability,
} from "../src/category/rpc.js";
import type {
  BoundedHttpResponse,
  TransportRoute,
} from "../src/transport/http.js";

const BLOCK_HASH = `0x${"ab".repeat(32)}`;
const POOL = "0x1111111111111111111111111111111111111111";

test("snapshot capability pins one confirmed block and readers reuse it", async () => {
  const routes: TransportRoute[] = [];
  const transport = fixtureTransport(routes);
  const capability = createCategorySnapshotCapability({
    transport,
    randomUUID: sequentialIds(),
  });

  let retainedSnapshot: unknown;
  const result = await capability.withSnapshot(async (snapshot) => {
    retainedSnapshot = snapshot;
    assert.equal(snapshot.chainId, 56);
    assert.deepEqual(snapshot.anchor, {
      number: 98,
      hash: BLOCK_HASH,
      timestamp: 1_786_874_407,
    });
    assert.equal(snapshot.confirmationDepth, 2);
    assert.equal(Object.isFrozen(snapshot), true);
    assert.equal(Object.isFrozen(snapshot.anchor), true);
    assert.doesNotThrow(() => capability.assertActive(snapshot));

    const reader = await capability.createReader(snapshot, [
      { label: "slot0", to: POOL, data: "0x3850c7bd" },
    ]);
    assert.deepEqual(reader.anchor, snapshot.anchor);
    const call = await reader.call({
      label: "slot0",
      to: POOL,
      data: "0x3850c7bd",
    });
    assert.equal(call?.data, "0x1234");
    assert.equal(reader.attempts().length, 1);
    return call?.data;
  });
  assert.equal(result, "0x1234");
  assert.throws(() => capability.assertActive(retainedSnapshot), /category adapter/);

  assert.deepEqual(
    routes.map((route) =>
      route.kind === "bsc-category-rpc" ? route.purpose : route.kind,
    ),
    ["chain-id", "head-block-number", "block-header", "state-read", "block-header"],
  );
});

test("snapshot provenance rejects clones and anchors from another capability", async () => {
  const first = createCategorySnapshotCapability({
    transport: fixtureTransport([]),
    randomUUID: sequentialIds(),
  });
  const second = createCategorySnapshotCapability({
    transport: fixtureTransport([]),
    randomUUID: sequentialIds(),
  });
  await first.withSnapshot(async (snapshot) => {
    assert.throws(() => first.assertActive(structuredClone(snapshot)), /category adapter/);
    assert.throws(() => second.assertActive(snapshot), /category adapter/);
    await assert.rejects(
      second.createReader(snapshot, [
        { label: "slot0", to: POOL, data: "0x3850c7bd" },
      ]),
      /category adapter/,
    );
  });
});

test("snapshot capability rejects a supplied anchor outside the current confirmation boundary", async () => {
  const routes: TransportRoute[] = [];
  const capability = createCategorySnapshotCapability({
    transport: fixtureTransport(routes),
    randomUUID: sequentialIds(),
  });
  await assert.rejects(
    capability.withSnapshot(
      async () => "unreachable",
      {
        number: 97,
        hash: BLOCK_HASH,
        timestamp: 1_786_874_407,
      },
    ),
    /canonical BSC block anchor/,
  );
});

test("opaque snapshot finalization fences and commits exactly once", async () => {
  const routes: TransportRoute[] = [];
  const capability = createCategorySnapshotCapability({
    transport: fixtureTransport(routes),
    randomUUID: sequentialIds(),
  });
  let commits = 0;
  const result = await capability.withOpaqueSnapshot(async (snapshot) => {
    const finalized = await capability.finalizeOpaqueSnapshot(
      snapshot,
      async () => {
        commits += 1;
        return "committed" as const;
      },
    );
    await assert.rejects(
      capability.finalizeOpaqueSnapshot(snapshot, async () => "duplicate"),
      /category adapter/,
    );
    await assert.rejects(
      capability.assertOpaqueCanonical(snapshot),
      /category adapter/,
    );
    return finalized;
  });
  assert.equal(result, "committed");
  assert.equal(commits, 1);
  assert.deepEqual(
    routes.map((route) =>
      route.kind === "bsc-category-rpc" ? route.purpose : route.kind,
    ),
    ["chain-id", "head-block-number", "block-header", "block-header"],
  );
});

test("failed opaque snapshot finalization never runs its commit", async () => {
  const routes: TransportRoute[] = [];
  const capability = createCategorySnapshotCapability({
    transport: fixtureTransport(routes, { reorgAtHeaderRead: 2 }),
    randomUUID: sequentialIds(),
  });
  let commits = 0;
  await assert.rejects(
    capability.withOpaqueSnapshot(async (snapshot) =>
      capability.finalizeOpaqueSnapshot(snapshot, async () => {
        commits += 1;
      }),
    ),
    /no longer canonical/,
  );
  assert.equal(commits, 0);
});

function fixtureTransport(
  routes: TransportRoute[],
  options: Readonly<{ readonly reorgAtHeaderRead?: number }> = {},
) {
  let responseCounter = 0;
  let headerReads = 0;
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      routes.push(route);
      assert.equal(route.kind, "bsc-category-rpc");
      if (route.kind !== "bsc-category-rpc") throw new Error("unexpected route");
      const request = JSON.parse(route.body) as {
        id: string;
        method: string;
      };
      let result: unknown;
      switch (request.method) {
        case "eth_chainId":
          result = "0x38";
          break;
        case "eth_blockNumber":
          result = "0x64";
          break;
        case "eth_getBlockByNumber":
          headerReads += 1;
          result = {
            number: "0x62",
            hash:
              headerReads === options.reorgAtHeaderRead
                ? `0x${"cd".repeat(32)}`
                : BLOCK_HASH,
            timestamp: "0x6a818a27",
          };
          break;
        case "eth_call":
          result = "0x1234";
          break;
        default:
          throw new Error(`unexpected method ${request.method}`);
      }
      const body = Buffer.from(
        JSON.stringify({ jsonrpc: "2.0", id: request.id, result }),
      );
      responseCounter += 1;
      return {
        status: 200,
        contentType: "application/json",
        retryAfter: null,
        rateLimitRemaining: null,
        body,
        responseSha256: createHash("sha256").update(body).digest("hex"),
        resolvedAddress: "1.1.1.1",
        startedAt: `2026-08-19T10:00:${String(responseCounter).padStart(2, "0")}.000Z`,
        finishedAt: `2026-08-19T10:00:${String(responseCounter).padStart(2, "0")}.010Z`,
        latencyMs: 10,
      };
    },
  };
}

function sequentialIds() {
  let value = 0;
  return () => String(++value);
}
