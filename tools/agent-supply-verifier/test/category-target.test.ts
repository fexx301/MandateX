import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  CATEGORY_TARGET_OBSERVATION_SCHEMA,
  CategoryTargetObservationError,
  createCategoryTargetObservationCapability,
} from "../src/category/target.js";
import {
  BSC_CATEGORY_TARGET_BEACON_IMPLEMENTATION_SELECTOR,
  BSC_CATEGORY_TARGET_BEACON_SLOT,
  BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT,
  BSC_MAINNET_RPC_ORIGIN,
  PinnedHttpsTransport,
  TransportError,
  validateTransportRoute,
  type BoundedHttpResponse,
  type TransportRoute,
} from "../src/transport/http.js";

const TARGET = "0x1111111111111111111111111111111111111111";
const IMPLEMENTATION = "0x2222222222222222222222222222222222222222";
const BEACON = "0x3333333333333333333333333333333333333333";
const BLOCK_HASH = `0x${"ab".repeat(32)}`;
const ANCHOR = Object.freeze({ number: 98, hash: BLOCK_HASH, timestamp: 100 });
const ZERO_SLOT = `0x${"0".repeat(64)}`;
const TARGET_CODE = "0x6001600055";
const PROXY_TARGET_CODE = "0x6001600055f4";
const BEACON_CODE = "0x6003600055";
const IMPLEMENTATION_CODE = "0x6002600055";
const ACCOUNT = "0x4444444444444444444444444444444444444444";
const PROVENANCE_ROOTS = Object.freeze({
  pancakeV3Factory: "0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865",
  aavePoolAddressesProvider: null,
  venusComptroller: "0xfd36e2c2a6789db23113685031d7f16329158384",
});

test("target capability emits a frozen Core-compatible unendorsed observation", async () => {
  const routes: TransportRoute[] = [];
  const capability = createCategoryTargetObservationCapability({
    transport: targetTransport(routes),
    randomUUID: sequentialIds(),
    provenanceRoots: PROVENANCE_ROOTS,
  });
  const input = {
    adapterId: "pancakeswap-v3-grid-v1",
    role: "pool",
    targetAddress: TARGET,
    anchor: ANCHOR,
    expectedProvenance: [
      { label: "slot0", to: TARGET, data: "0x3850c7bd" },
    ],
  } as const;

  const result = await capability.observe(input);
  assert.equal(result.outcome, "verified");
  if (result.outcome !== "verified") return;
  assert.deepEqual(Object.keys(result.observation).sort(), [
    "adapterId",
    "assurance",
    "observedAt",
    "observedBlock",
    "observedBlockHash",
    "provenance",
    "proxy",
    "role",
    "runtimeCodeSha256",
    "schema",
    "targetAddress",
  ]);
  assert.equal(result.observation.schema, CATEGORY_TARGET_OBSERVATION_SCHEMA);
  assert.equal(result.observation.assurance, "interface_only_unendorsed");
  assert.equal(result.observation.provenance.status, "unendorsed");
  assert.equal(
    result.observation.provenance.source,
    "interface-only-unendorsed-v1",
  );
  assert.equal(result.observation.proxy.kind, "none");
  assert.equal(
    result.observation.runtimeCodeSha256,
    sha256Hex(TARGET_CODE),
  );
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.observation), true);
  assert.equal(Object.isFrozen(result.routeEvidence), true);
  assert.equal(result.reads, result.routeEvidence);
  assert.doesNotThrow(() => capability.assertObserved(result.observation, input));
  assert.throws(
    () => capability.assertObserved(result, input),
    /provenance/,
  );
  assert.throws(
    () => capability.assertObserved(structuredClone(result.observation), input),
    /provenance/,
  );
  assert.deepEqual(
    routes.map((route) =>
      route.kind === "bsc-category-target-rpc" ? route.purpose : route.kind,
    ),
    [
      "chain-id",
      "head-block-number",
      "block-header",
      "contract-code",
      "proxy-slot",
      "proxy-slot",
      "provenance-read",
      "provenance-read",
      "block-header",
    ],
  );
});

test("target capability resolves EIP-1967 implementations and hashes their code", async () => {
  const routes: TransportRoute[] = [];
  const result = await capabilityFor(
    routes,
    targetTransport(routes, (request) => {
      if (isCodeRequest(request, TARGET)) return PROXY_TARGET_CODE;
      if (isSlotRequest(request, BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT)) {
        return addressWord(IMPLEMENTATION);
      }
      if (isCodeRequest(request, IMPLEMENTATION)) return IMPLEMENTATION_CODE;
      return undefined;
    }),
  ).observe(baseInput());
  assert.equal(result.outcome, "verified");
  if (result.outcome !== "verified") return;
  assert.deepEqual(result.observation.proxy, {
    kind: "eip1967",
    implementationAddress: IMPLEMENTATION,
    implementationCodeSha256: sha256Hex(IMPLEMENTATION_CODE),
  });
  assert.equal(
    routes.filter(
      (route) =>
        route.kind === "bsc-category-target-rpc" &&
        route.purpose === "contract-code",
    ).length,
    2,
  );
});

test("target capability resolves EIP-1967 beacons through the fixed getter", async () => {
  const routes: TransportRoute[] = [];
  const result = await capabilityFor(
    routes,
    targetTransport(routes, (request) => {
      if (isCodeRequest(request, TARGET)) return PROXY_TARGET_CODE;
      if (isSlotRequest(request, BSC_CATEGORY_TARGET_BEACON_SLOT)) {
        return addressWord(BEACON);
      }
      if (isCodeRequest(request, BEACON)) return BEACON_CODE;
      if (isCodeRequest(request, IMPLEMENTATION)) return IMPLEMENTATION_CODE;
      if (
        request.method === "eth_call" &&
        Array.isArray(request.params) &&
        isRecord(request.params[0]) &&
        request.params[0].to === BEACON
      ) {
        return addressWord(IMPLEMENTATION);
      }
      return undefined;
    }),
  ).observe(baseInput());
  assert.equal(result.outcome, "verified");
  if (result.outcome !== "verified") return;
  assert.deepEqual(result.observation.proxy, {
    kind: "beacon",
    beaconAddress: BEACON,
    beaconCodeSha256: sha256Hex(BEACON_CODE),
    implementationAddress: IMPLEMENTATION,
    implementationCodeSha256: sha256Hex(IMPLEMENTATION_CODE),
  });
  const beaconRoute = routes.find(
    (route) =>
      route.kind === "bsc-category-target-rpc" &&
      route.purpose === "provenance-read" &&
      route.approvedCalldata === BSC_CATEGORY_TARGET_BEACON_IMPLEMENTATION_SELECTOR,
  );
  assert.ok(beaconRoute?.kind === "bsc-category-target-rpc");
  if (
    beaconRoute?.kind === "bsc-category-target-rpc" &&
    beaconRoute.purpose === "provenance-read"
  ) {
    const body = JSON.parse(beaconRoute.body) as {
      params: readonly [Readonly<{ data: string; to: string }>];
    };
    assert.equal(body.params[0].data, BSC_CATEGORY_TARGET_BEACON_IMPLEMENTATION_SELECTOR);
    assert.equal(body.params[0].to, BEACON);
  }
});

test("target capability fails closed on empty code and unsafe proxy evidence", async () => {
  const cases = [
    {
      code: "EMPTY_TARGET_CODE",
      override: (request: Record<string, unknown>) =>
        isCodeRequest(request, TARGET) ? "0x" : undefined,
    },
    {
      code: "MALFORMED_PROXY_SLOT",
      override: (request: Record<string, unknown>) =>
        isSlotRequest(request, BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT)
          ? "0x01"
          : undefined,
    },
    {
      code: "CONFLICTING_PROXY_SLOTS",
      override: (request: Record<string, unknown>) =>
        request.method === "eth_getStorageAt"
          ? addressWord(IMPLEMENTATION)
          : undefined,
    },
    {
      code: "EMPTY_IMPLEMENTATION_CODE",
      override: (request: Record<string, unknown>) => {
        if (isCodeRequest(request, TARGET)) return PROXY_TARGET_CODE;
        if (isSlotRequest(request, BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT)) {
          return addressWord(IMPLEMENTATION);
        }
        return isCodeRequest(request, IMPLEMENTATION) ? "0x" : undefined;
      },
    },
    {
      code: "UNKNOWN_PROXY",
      override: (request: Record<string, unknown>) =>
        isCodeRequest(request, TARGET) ? "0x5af4" : undefined,
    },
    {
      code: "UNKNOWN_PROXY",
      override: (request: Record<string, unknown>) =>
        isSlotRequest(request, BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT)
          ? addressWord(TARGET)
          : undefined,
    },
    {
      code: "UNKNOWN_PROXY",
      override: (request: Record<string, unknown>) =>
        isSlotRequest(request, BSC_CATEGORY_TARGET_BEACON_SLOT)
          ? addressWord(TARGET)
          : undefined,
    },
  ] as const;

  for (const [index, fixture] of cases.entries()) {
    const routes: TransportRoute[] = [];
    const result = await capabilityFor(
      routes,
      targetTransport(routes, fixture.override),
    ).observe(baseInput());
    assert.equal(result.outcome, "inconclusive", `case ${index} (${fixture.code})`);
    if (result.outcome === "inconclusive") {
      assert.equal(result.code, fixture.code);
      assert.equal(Object.isFrozen(result.routeEvidence), true);
    }
  }
});

test("target capability requires verifier-owned reads and ABI-shaped returns", async () => {
  await assert.rejects(
    capabilityFor([], targetTransport([], undefined)).observe({
      ...baseInput(),
      expectedProvenance: [
        { label: "slot0", to: TARGET, data: "0x3850c7bd" },
        { label: "factory", to: TARGET, data: "0xc45a0155" },
      ],
    }),
    (error: unknown) =>
      error instanceof CategoryTargetObservationError &&
      error.code === "INVALID_INPUT",
  );

  const malformed = await capabilityFor(
    [],
    targetTransport([], (request) =>
      request.method === "eth_call" ? `0x${"01".repeat(32)}` : undefined,
    ),
  ).observe(baseInput());
  assert.equal(malformed.outcome, "inconclusive");
  if (malformed.outcome === "inconclusive") {
    assert.equal(malformed.code, "PROVENANCE_READ_INVALID");
  }
});

test("target capability rejects conflicting provenance aliases and spoofed proxy slots", async () => {
  await assert.rejects(
    capabilityFor([], targetTransport([])).observe({
      ...baseInput(),
      expectedProvenance: [
        {
          label: "slot0",
          to: TARGET,
          data: "0x3850c7bd",
          selector: "0x18160ddd",
        },
      ],
    } as never),
    (error: unknown) =>
      error instanceof CategoryTargetObservationError &&
      error.code === "INVALID_INPUT",
  );

  const spoofed = await capabilityFor(
    [],
    targetTransport([], (request) =>
      isSlotRequest(request, BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT)
        ? addressWord(IMPLEMENTATION)
        : undefined,
    ),
  ).observe(baseInput());
  assert.equal(spoofed.outcome, "inconclusive");
  if (spoofed.outcome === "inconclusive") {
    assert.equal(spoofed.code, "UNKNOWN_PROXY");
  }
});

test("target transport cannot widen the ordinary category RPC route", () => {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: "target-test",
    method: "eth_getCode",
    params: [TARGET, { blockHash: BLOCK_HASH, requireCanonical: true }],
  });
  const targetRoute = {
    kind: "bsc-category-target-rpc",
    purpose: "contract-code",
    method: "POST",
    url: BSC_MAINNET_RPC_ORIGIN,
    rpcMethod: "eth_getCode",
    approvedTargets: [TARGET],
    approvedBlockHash: BLOCK_HASH,
    body,
  } as const;
  assert.doesNotThrow(() => validateTransportRoute(targetRoute));

  assert.throws(
    () =>
      validateTransportRoute({
        ...targetRoute,
        kind: "bsc-category-rpc",
      } as unknown as TransportRoute),
    (error: unknown) =>
      error instanceof TransportError &&
      error.code === "RPC_METHOD_NOT_ALLOWED",
  );
});

test("target capability rejects a supplied anchor that is no longer canonical", async () => {
  const routes: TransportRoute[] = [];
  const result = await capabilityFor(
    routes,
    targetTransport(routes, (request) =>
      request.method === "eth_getBlockByNumber"
        ? { number: "0x62", hash: `0x${"cd".repeat(32)}`, timestamp: "0x64" }
        : undefined,
    ),
  ).observe(baseInput());
  assert.deepEqual(result, {
    outcome: "inconclusive",
    code: "SNAPSHOT_INCONSISTENT",
    routeEvidence: result.routeEvidence,
    reads: result.reads,
  });
  assert.equal(result.routeEvidence.at(-1)?.purpose, "block-header");
});

test("target capability rejects a supplied anchor without current confirmation", async () => {
  const routes: TransportRoute[] = [];
  const result = await capabilityFor(routes, targetTransport(routes)).observe({
    ...baseInput(),
    anchor: { ...ANCHOR, number: 99 },
  });
  assert.equal(result.outcome, "inconclusive");
  if (result.outcome !== "inconclusive") return;
  assert.equal(result.code, "BLOCK_PIN_FAILED");
  assert.deepEqual(
    routes.map((route) =>
      route.kind === "bsc-category-target-rpc" ? route.purpose : route.kind,
    ),
    ["chain-id", "head-block-number"],
  );
});

test("target capability accepts an older canonical shared anchor after head advance", async () => {
  const routes: TransportRoute[] = [];
  const result = await capabilityFor(
    routes,
    targetTransport(routes, (request) =>
      request.method === "eth_blockNumber" ? "0x65" : undefined,
    ),
  ).observe(baseInput());
  assert.equal(result.outcome, "verified");
  assert.equal(
    routes.filter(
      (route) =>
        route.kind === "bsc-category-target-rpc" &&
        route.purpose === "block-header",
    ).length >= 2,
    true,
  );
});

test("target capability requires explicit Core adapter and role identity", async () => {
  const capability = createCategoryTargetObservationCapability({
    transport: targetTransport([]),
    randomUUID: sequentialIds(),
    provenanceRoots: PROVENANCE_ROOTS,
  });
  await assert.rejects(
    capability.observe({
      targetAddress: TARGET,
      anchor: ANCHOR,
    } as never),
    (error: unknown) =>
      error instanceof Error &&
      error.name === "CategoryTargetObservationError" &&
      (error as { code?: unknown }).code === "INVALID_INPUT",
  );
  await assert.rejects(
    capability.observe({
      adapterId: "bogus-v1",
      role: "pool",
      targetAddress: TARGET,
      anchor: ANCHOR,
    } as never),
    (error: unknown) =>
      error instanceof CategoryTargetObservationError &&
      error.code === "INVALID_INPUT",
  );
});

test("target capability accepts the real prototype-backed pinned transport", () => {
  assert.doesNotThrow(() =>
    createCategoryTargetObservationCapability({
      transport: new PinnedHttpsTransport(),
      randomUUID: sequentialIds(),
      provenanceRoots: PROVENANCE_ROOTS,
    }),
  );

  const accessorTransport = Object.defineProperty({}, "request", {
    enumerable: true,
    get() {
      throw new Error("transport accessor must not run");
    },
  });
  assert.throws(
    () =>
      createCategoryTargetObservationCapability({
        transport: accessorTransport as never,
        randomUUID: sequentialIds(),
        provenanceRoots: PROVENANCE_ROOTS,
      }),
    (error: unknown) =>
      error instanceof CategoryTargetObservationError &&
      error.code === "INVALID_INPUT",
  );
});

test("target capability accepts standard block-header fields when pinning", async () => {
  const routes: TransportRoute[] = [];
  const result = await capabilityFor(routes, targetTransport(routes)).observe({
    adapterId: "pancakeswap-v3-grid-v1",
    role: "pool",
    target: TARGET,
  });
  assert.equal(result.outcome, "verified");
  assert.deepEqual(
    routes.slice(0, 3).map((route) =>
      route.kind === "bsc-category-target-rpc" ? route.purpose : route.kind,
    ),
    ["chain-id", "head-block-number", "block-header"],
  );
});

test("target provenance digest binds adapter and role", async () => {
  const pool = await observeWithFreshTransport(baseInput());
  const otherRole = await observeWithFreshTransport({
    adapterId: "venus-health-v1",
    role: "comptroller",
    targetAddress: TARGET,
    accountAddress: ACCOUNT,
    anchor: ANCHOR,
  });
  const otherAdapter = await observeWithFreshTransport({
    adapterId: "erc4626-yield-v1",
    role: "vault",
    targetAddress: TARGET,
    anchor: ANCHOR,
  });
  assert.equal(pool.outcome, "verified");
  assert.equal(otherRole.outcome, "verified");
  assert.equal(otherAdapter.outcome, "verified");
  if (
    pool.outcome !== "verified" ||
    otherRole.outcome !== "verified" ||
    otherAdapter.outcome !== "verified"
  ) {
    return;
  }
  assert.notEqual(
    pool.observation.provenance.proofSha256,
    otherRole.observation.provenance.proofSha256,
  );
  assert.notEqual(
    pool.observation.provenance.proofSha256,
    otherAdapter.observation.provenance.proofSha256,
  );
});

test("grid factory membership upgrades only on the pinned factory return", async () => {
  const routes: TransportRoute[] = [];
  const result = await capabilityFor(
    routes,
    targetTransport(routes, (request) => {
      if (
        request.method === "eth_call" &&
        Array.isArray(request.params) &&
        isRecord(request.params[0]) &&
        request.params[0].data === "0xc45a0155"
      ) {
        return addressWord("0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865");
      }
      return undefined;
    }),
  ).observe(baseInput());
  assert.equal(result.outcome, "verified");
  if (result.outcome !== "verified") return;
  assert.equal(result.observation.assurance, "protocol_instance_verified");
  assert.equal(
    result.observation.provenance.source,
    "pancakeswap-v3-factory-membership-v1",
  );

  const wrong = await capabilityFor(
    [],
    targetTransport([], (request) => {
      if (
        request.method === "eth_call" &&
        Array.isArray(request.params) &&
        isRecord(request.params[0]) &&
        request.params[0].data === "0xc45a0155"
      ) {
        return addressWord("0x9999999999999999999999999999999999999999");
      }
      return undefined;
    }),
  ).observe(baseInput());
  assert.equal(wrong.outcome, "verified");
  if (wrong.outcome !== "verified") return;
  assert.equal(wrong.observation.assurance, "interface_only_unendorsed");
  assert.equal(wrong.observation.provenance.status, "unendorsed");
});

test("protocol proof material is mutation-bound", async () => {
  const first = await observeWithFreshTransport(baseInput());
  const second = await observeWithFreshTransport({
    ...baseInput(),
    targetAddress: "0x9999999999999999999999999999999999999999",
  });
  assert.equal(first.outcome, "verified");
  assert.equal(second.outcome, "verified");
  if (first.outcome !== "verified" || second.outcome !== "verified") return;
  assert.notEqual(
    first.observation.provenance.proofSha256,
    second.observation.provenance.proofSha256,
  );
});

test("malformed factory proof return is inconclusive", async () => {
  const result = await capabilityFor(
    [],
    targetTransport([], (request) => {
      if (
        request.method === "eth_call" &&
        Array.isArray(request.params) &&
        isRecord(request.params[0]) &&
        request.params[0].data === "0xc45a0155"
      ) {
        return "0x01";
      }
      return undefined;
    }),
  ).observe(baseInput());
  assert.equal(result.outcome, "inconclusive");
  if (result.outcome === "inconclusive") {
    assert.equal(result.code, "PROVENANCE_READ_INVALID");
  }
});

function baseInput() {
  return {
    adapterId: "pancakeswap-v3-grid-v1",
    role: "pool",
    targetAddress: TARGET,
    anchor: ANCHOR,
  } as const;
}

function capabilityFor(
  _routes: TransportRoute[],
  transport: ReturnType<typeof targetTransport>,
) {
  return createCategoryTargetObservationCapability({
    transport,
    randomUUID: sequentialIds(),
    provenanceRoots: PROVENANCE_ROOTS,
  });
}

async function observeWithFreshTransport(
  input: Parameters<
    ReturnType<typeof createCategoryTargetObservationCapability>["observe"]
  >[0],
) {
  const routes: TransportRoute[] = [];
  return capabilityFor(routes, targetTransport(routes)).observe(input);
}

function targetTransport(
  routes: TransportRoute[],
  override?: (request: Record<string, unknown>) => unknown,
) {
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      routes.push(route);
      assert.equal(route.kind, "bsc-category-target-rpc");
      if (route.kind !== "bsc-category-target-rpc") {
        throw new Error("unexpected route");
      }
      validateTransportRoute(route);
      const request = JSON.parse(route.body) as Record<string, unknown>;
      const result = override?.(request) ?? successfulResult(request);
      const body = Buffer.from(
        JSON.stringify({ jsonrpc: "2.0", id: request.id, result }),
      );
      return {
        status: 200,
        contentType: "application/json",
        retryAfter: null,
        rateLimitRemaining: null,
        body,
        responseSha256: createHash("sha256").update(body).digest("hex"),
        resolvedAddress: "1.1.1.1",
        startedAt: "2026-08-19T10:00:00.000Z",
        finishedAt: "2026-08-19T10:00:00.001Z",
        latencyMs: 1,
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
      return {
        number: "0x62",
        hash: BLOCK_HASH,
        timestamp: "0x64",
        parentHash: `0x${"cd".repeat(32)}`,
        transactions: [],
      };
    case "eth_getCode":
      return TARGET_CODE;
    case "eth_getStorageAt":
      return ZERO_SLOT;
    case "eth_call":
      return calldataResult(request);
    default:
      throw new Error(`unexpected RPC method ${String(request.method)}`);
  }
}

function slot0Result(): string {
  return `0x${word(2n ** 96n)}${word(0n)}`;
}

function calldataResult(request: Record<string, unknown>): string {
  const params = request.params;
  const call = Array.isArray(params) && isRecord(params[0]) ? params[0] : undefined;
  const selector = typeof call?.data === "string" ? call.data.slice(0, 10) : undefined;
  if (selector === "0x3850c7bd") return slot0Result();
  if (selector === "0x01e1d114" || selector === "0x18160ddd") return `0x${word(1n)}`;
  if (selector === "0xbf92857c") return `0x${Array.from({ length: 6 }, () => word(0n)).join("")}`;
  if (selector === "0x5ec88c79") {
    return `0x${word(0n)}${word(0n)}${word(0n)}`;
  }
  if (selector === "0xabfceffc") return `0x${word(32n)}${word(0n)}`;
  if (selector === "0x95dd9193") return `0x${word(1n)}${word(0n)}${word(0n)}`;
  return addressWord(IMPLEMENTATION);
}

function word(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

function isSlotRequest(
  request: Record<string, unknown>,
  slot: string,
): boolean {
  return (
    request.method === "eth_getStorageAt" &&
    Array.isArray(request.params) &&
    request.params[1] === slot
  );
}

function isCodeRequest(
  request: Record<string, unknown>,
  target: string,
): boolean {
  return (
    request.method === "eth_getCode" &&
    Array.isArray(request.params) &&
    request.params[0] === target
  );
}

function addressWord(address: string): string {
  return `0x${"0".repeat(24)}${address.slice(2)}`;
}

function sha256Hex(value: string): string {
  return createHash("sha256")
    .update(Buffer.from(value.slice(2), "hex"))
    .digest("hex");
}

function sequentialIds() {
  let value = 0;
  return () => String(++value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
