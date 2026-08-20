import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  createCategoryCandidateIdentityCapability,
} from "../src/category/identity.js";
import type {
  BoundedHttpResponse,
  TransportRoute,
} from "../src/transport/http.js";

const OWNER = "0x20f1ca5d1e5a3ee94c29dbf95e6bf6cea6a8d64b";
const REGISTRY = "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432";
const BLOCK_HASH = `0x${"ab".repeat(32)}`;
const EMPTY_CODE_SHA256 = createHash("sha256").update(Buffer.alloc(0)).digest("hex");
const CONTRACT_CODE = "0x60006000";
const CONTRACT_CODE_SHA256 = createHash("sha256")
  .update(Buffer.from(CONTRACT_CODE.slice(2), "hex"))
  .digest("hex");

test("identity capability binds canonical ERC-8004 owner evidence to the selector", async () => {
  const routes: TransportRoute[] = [];
  const capability = createCategoryCandidateIdentityCapability({
    transport: rpcTransport(routes),
    registryAddress: REGISTRY,
  });
  const selector = { chainId: 56, tokenId: "265375" } as const;
  const result = await capability.capture(selector);
  assert.equal(result.outcome, "verified");
  if (result.outcome !== "verified") return;

  assert.equal(result.identity.ownerAddress, OWNER);
  assert.equal(result.identity.observedBlock, 98);
  assert.equal(result.identity.observedBlockHash, BLOCK_HASH);
  assert.equal(result.identity.observedAt, 1_786_874_407);
  assert.deepEqual(Object.keys(result.identity).sort(), [
    "chainId",
    "confirmationDepth",
    "identitySha256",
    "observedAt",
    "observedBlock",
    "observedBlockHash",
    "ownerAddress",
    "registryAddress",
    "registryCodeSha256",
    "schema",
    "tokenId",
  ]);
  assert.deepEqual(capability.providerFor(result.identity, selector), {
    providerKind: "eoa",
    providerCodeSha256: EMPTY_CODE_SHA256,
  });
  assert.equal(Object.isFrozen(result.identity), true);
  assert.doesNotThrow(() => capability.assertVerified(result.identity, selector));
  assert.throws(
    () => capability.assertVerified({ ...result.identity }, selector),
    /provenance/,
  );
  assert.throws(
    () =>
      capability.assertVerified(result.identity, {
        chainId: 56,
        tokenId: "265376",
      }),
    /provenance/,
  );
  assert.deepEqual(routes.map((route) => route.kind), [
    ...Array.from({ length: 6 }, () => "bsc-rpc"),
    "bsc-quote-rpc",
  ]);
  const providerCodeRoute = routes.at(-1);
  assert.equal(providerCodeRoute?.kind, "bsc-quote-rpc");
  if (providerCodeRoute?.kind === "bsc-quote-rpc") {
    assert.equal(providerCodeRoute.rpcMethod, "eth_getCode");
    assert.equal(providerCodeRoute.approvedProvider, OWNER);
    assert.equal(providerCodeRoute.approvedBlockHash, BLOCK_HASH);
    const body = JSON.parse(providerCodeRoute.body) as Record<string, unknown>;
    assert.deepEqual(body.params, [
      OWNER,
      { blockHash: BLOCK_HASH, requireCanonical: true },
    ]);
  }
});

test("identity capability discovers ERC-1271 owners and hashes exact block-pinned code", async () => {
  const capability = createCategoryCandidateIdentityCapability({
    transport: rpcTransport([], (request) =>
      isOwnerCodeRequest(request) ? CONTRACT_CODE : undefined,
    ),
    registryAddress: REGISTRY,
  });
  const result = await capability.capture({ chainId: 56, tokenId: "7" });
  assert.equal(result.outcome, "verified");
  if (result.outcome !== "verified") return;

  assert.deepEqual(
    capability.providerFor(result.identity, { chainId: 56, tokenId: "7" }),
    {
      providerKind: "erc1271",
      providerCodeSha256: CONTRACT_CODE_SHA256,
    },
  );
  assert.doesNotThrow(() =>
    capability.assertVerified(result.identity, { chainId: 56, tokenId: "7" }),
  );
});

test("identity capability can reuse a verifier-owned shared block anchor", async () => {
  const capability = createCategoryCandidateIdentityCapability({
    transport: rpcTransport([]),
    registryAddress: REGISTRY,
  });
  const result = await capability.capture(
    { chainId: 56, tokenId: "7" },
    { number: 98, hash: BLOCK_HASH, timestamp: 100 },
  );
  assert.equal(result.outcome, "verified");
  if (result.outcome !== "verified") return;
  assert.equal(result.identity.observedBlock, 98);
  assert.equal(result.identity.observedBlockHash, BLOCK_HASH);
  assert.equal(result.identity.observedAt, 100);
});

test("selector and transport are captured before RPC and accessor inputs fail closed", async () => {
  const routes: TransportRoute[] = [];
  const mutableTransport = rpcTransport(routes);
  const capability = createCategoryCandidateIdentityCapability({
    transport: mutableTransport,
    registryAddress: REGISTRY,
  });
  mutableTransport.request = async () => {
    throw new Error("mutated transport");
  };
  const selector = { chainId: 56, tokenId: "265375" };
  const pending = capability.capture(selector as never);
  selector.tokenId = "9";
  const result = await pending;
  assert.equal(result.outcome, "verified");
  if (result.outcome === "verified") {
    assert.equal(result.identity.tokenId, "265375");
  }

  assert.throws(
    () =>
      createCategoryCandidateIdentityCapability({
        registryAddress: REGISTRY,
        get transport() {
          return rpcTransport([]);
        },
      } as never),
    /data properties/,
  );
});

test("token absence and inconclusive chain results never receive provenance", async () => {
  const unavailable = createCategoryCandidateIdentityCapability({
    transport: rpcTransport([], (request) =>
      request.method === "eth_call"
        ? { error: { code: 3, message: "owner query for nonexistent token" } }
        : undefined,
    ),
    registryAddress: REGISTRY,
  });
  const absent = await unavailable.capture({ chainId: 56, tokenId: "7" });
  assert.equal(absent.outcome, "unavailable");
  assert.throws(
    () => unavailable.assertVerified(absent, { chainId: 56, tokenId: "7" }),
    /provenance/,
  );

  const inconclusive = createCategoryCandidateIdentityCapability({
    transport: rpcTransport([], (request) =>
      request.method === "eth_chainId" ? "0x1" : undefined,
    ),
    registryAddress: REGISTRY,
  });
  const failed = await inconclusive.capture({ chainId: 56, tokenId: "7" });
  assert.equal(failed.outcome, "inconclusive");

  const invalidProviderCode = createCategoryCandidateIdentityCapability({
    transport: rpcTransport([], (request) =>
      isOwnerCodeRequest(request) ? "0x0" : undefined,
    ),
    registryAddress: REGISTRY,
  });
  const invalid = await invalidProviderCode.capture({ chainId: 56, tokenId: "7" });
  assert.deepEqual(invalid, {
    outcome: "inconclusive",
    code: "RPC_INVALID_RESPONSE",
  });
});

function rpcTransport(
  routes: TransportRoute[],
  override?: (request: Record<string, unknown>) => unknown,
): { request(route: TransportRoute): Promise<BoundedHttpResponse> } {
  let count = 0;
  return {
    async request(route) {
      routes.push(route);
      assert.ok(route.kind === "bsc-rpc" || route.kind === "bsc-quote-rpc");
      if (route.kind !== "bsc-rpc" && route.kind !== "bsc-quote-rpc") {
        throw new Error("unexpected route");
      }
      const request = JSON.parse(route.body) as Record<string, unknown>;
      const overridden = override?.(request);
      const envelope =
        overridden !== undefined &&
        typeof overridden === "object" &&
        overridden !== null &&
        "error" in overridden
          ? { jsonrpc: "2.0", id: request.id, ...overridden }
          : {
              jsonrpc: "2.0",
              id: request.id,
              result: overridden ?? successfulResult(request),
            };
      const body = Buffer.from(JSON.stringify(envelope));
      count += 1;
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
    },
  };
}

function successfulResult(request: Record<string, unknown>): unknown {
  switch (request.method) {
    case "eth_chainId":
      return "0x38";
    case "eth_blockNumber":
      return "0x64";
    case "eth_getBlockByNumber":
      return { number: "0x62", hash: BLOCK_HASH, timestamp: "0x64" };
    case "eth_getCode":
      return isOwnerCodeRequest(request) ? "0x" : CONTRACT_CODE;
    case "eth_call":
      return `0x${"0".repeat(24)}${OWNER.slice(2)}`;
    default:
      throw new Error(`unexpected method ${String(request.method)}`);
  }
}

function isOwnerCodeRequest(request: Record<string, unknown>): boolean {
  return (
    request.method === "eth_getCode" &&
    Array.isArray(request.params) &&
    request.params[0] === OWNER
  );
}
