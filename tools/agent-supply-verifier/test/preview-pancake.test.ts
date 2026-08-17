import assert from "node:assert/strict";
import test from "node:test";

import {
  encodeAbiParameters,
  parseAbiParameters,
  type Hex,
} from "viem";

import {
  BSC_PANCAKE_V3,
  verifyPancakeV3State,
  type PancakeStateRpc,
  type PancakeStateRpcRequest,
} from "../src/preview/pancake.js";

const POOL = "0x1000000000000000000000000000000000000001";
const TOKEN0 = "0x2000000000000000000000000000000000000002";
const TOKEN1 = "0x3000000000000000000000000000000000000003";
const POSITION_OWNER = "0x4000000000000000000000000000000000000004";
const PROVIDER = "0x5000000000000000000000000000000000000005";
const OTHER = "0x6000000000000000000000000000000000000006";
const BLOCK_A = `0x${"aa".repeat(32)}`;
const BLOCK_B = `0x${"bb".repeat(32)}`;
const BLOCK_C = `0x${"cc".repeat(32)}`;
const BLOCK_D = `0x${"dd".repeat(32)}`;

test("Pancake state uses one canonical N-2 EIP-1898 snapshot", async () => {
  const rpc = fixtureRpc();
  const result = await verifyPancakeV3State(options(rpc));

  assert.equal(result.status, "verified");
  if (result.status !== "verified") return;
  assert.deepEqual(result.snapshot.pin, {
    mode: "fresh",
    headBlockNumber: "100",
    observedBlockNumber: "98",
    observedBlockHash: BLOCK_A,
    observedAt: "1770000000",
    confirmationDepth: 2,
    requireCanonical: true,
    attempts: 1,
  });
  assert.equal(result.snapshot.deployments.positionManager.factory, BSC_PANCAKE_V3.factory);
  assert.equal(result.snapshot.deployments.positionManager.deployer, BSC_PANCAKE_V3.deployer);
  assert.equal(result.snapshot.pool.token0, TOKEN0);
  assert.equal(result.snapshot.pool.token1, TOKEN1);
  assert.equal(result.snapshot.pool.currentTick, 100);
  assert.equal(result.snapshot.position.liquidity, "1000");
  assert.equal(result.snapshot.tokens.token0.decimals, 18);
  assert.equal(result.snapshot.tokens.token1.decimals, 6);

  const stateReads = rpc.requests.filter(
    (request) => request.method === "eth_getCode" || request.method === "eth_call",
  );
  assert.equal(stateReads.length, 30);
  for (const request of stateReads) {
    assert.deepEqual(request.params[1], {
      blockHash: BLOCK_A,
      requireCanonical: true,
    });
  }
  assert.equal(JSON.stringify(rpc.requests).includes("latest"), false);
  assert.deepEqual(
    rpc.requests.filter((request) => request.method === "eth_getBlockByNumber").map(
      (request) => request.params[0],
    ),
    ["0x62", "0x62"],
  );

  const codeTargets = rpc.requests
    .filter((request) => request.method === "eth_getCode")
    .map((request) => request.params[0]);
  assert.deepEqual(codeTargets, [
    BSC_PANCAKE_V3.erc8004Registry,
    PROVIDER,
    BSC_PANCAKE_V3.positionManager,
    BSC_PANCAKE_V3.factory,
    BSC_PANCAKE_V3.deployer,
    POOL,
    TOKEN0,
    TOKEN1,
  ]);
});

test("canonical mismatch retries the entire fresh snapshot once", async () => {
  const rpc = fixtureRpc({ canonicality: "retry" });
  const result = await verifyPancakeV3State(options(rpc));

  assert.equal(result.status, "verified");
  if (result.status !== "verified") return;
  assert.equal(result.snapshot.pin.attempts, 2);
  assert.equal(result.snapshot.pin.observedBlockHash, BLOCK_C);
  assert.equal(
    rpc.requests.filter((request) => request.method === "eth_chainId").length,
    2,
  );

  const attemptTwoReads = rpc.taggedRequests
    .filter(
      ({ attempt, request }) =>
        attempt === 2 &&
        (request.method === "eth_getCode" || request.method === "eth_call"),
    )
    .map(({ request }) => request.params[1]);
  assert.ok(attemptTwoReads.length > 0);
  assert.ok(
    attemptTwoReads.every(
      (selector) =>
        JSON.stringify(selector) ===
        JSON.stringify({ blockHash: BLOCK_C, requireCanonical: true }),
    ),
  );
});

test("canonical propagation exhaustion is inconclusive", async () => {
  const rpc = fixtureRpc({ canonicality: "exhaust" });
  const result = await verifyPancakeV3State(options(rpc));

  assert.deepEqual(result, {
    status: "inconclusive",
    code: "SNAPSHOT_INCONSISTENT",
    message: "a canonical pinned BSC snapshot could not be established",
    attempts: 2,
  });
});

test("exact mode re-reads only the provider-signed number and hash", async () => {
  const rpc = fixtureRpc({ exactHash: BLOCK_D });
  const result = await verifyPancakeV3State({
    ...options(rpc),
    target: {
      mode: "exact",
      blockNumber: "77",
      blockHash: BLOCK_D,
    },
  });

  assert.equal(result.status, "verified");
  if (result.status !== "verified") return;
  assert.deepEqual(result.snapshot.pin, {
    mode: "exact",
    headBlockNumber: null,
    observedBlockNumber: "77",
    observedBlockHash: BLOCK_D,
    observedAt: "1770000000",
    confirmationDepth: null,
    requireCanonical: true,
    attempts: 1,
  });
  assert.equal(
    rpc.requests.some((request) => request.method === "eth_blockNumber"),
    false,
  );
  assert.deepEqual(
    rpc.requests.filter((request) => request.method === "eth_getBlockByNumber").map(
      (request) => request.params[0],
    ),
    ["0x4d", "0x4d"],
  );
  for (const request of rpc.requests.filter(
    (entry) => entry.method === "eth_getCode" || entry.method === "eth_call",
  )) {
    assert.deepEqual(request.params[1], {
      blockHash: BLOCK_D,
      requireCanonical: true,
    });
  }
});

test("deployment and factory pool mismatches are stable invalid results", async (t) => {
  await t.test("manager deployment pointer", async () => {
    const result = await verifyPancakeV3State(
      options(fixtureRpc({ managerFactory: OTHER })),
    );
    assert.equal(result.status, "invalid");
    if (result.status !== "invalid") return;
    assert.equal(result.code, "DEPLOYMENT_POINTER_MISMATCH");
    assert.equal(result.attempts, 1);
  });

  await t.test("factory-resolved pool", async () => {
    const result = await verifyPancakeV3State(
      options(fixtureRpc({ factoryPool: OTHER })),
    );
    assert.equal(result.status, "invalid");
    if (result.status !== "invalid") return;
    assert.equal(result.code, "FACTORY_POOL_MISMATCH");
    assert.equal(result.attempts, 1);
  });
});

test("zero pool or position liquidity cannot pass preview state", async (t) => {
  await t.test("position liquidity", async () => {
    const result = await verifyPancakeV3State(
      options(fixtureRpc({ positionLiquidity: 0n })),
    );
    assert.equal(result.status, "invalid");
    if (result.status !== "invalid") return;
    assert.equal(result.code, "POSITION_INACTIVE");
  });

  await t.test("pool liquidity", async () => {
    const result = await verifyPancakeV3State(
      options(fixtureRpc({ poolLiquidity: 0n })),
    );
    assert.equal(result.status, "invalid");
    if (result.status !== "invalid") return;
    assert.equal(result.code, "POOL_INACTIVE");
  });
});

test("ownership and approvals are preserved and management authority is derived", async (t) => {
  await t.test("token approval", async () => {
    const result = await verifyPancakeV3State(options(fixtureRpc()));
    assert.equal(result.status, "verified");
    if (result.status !== "verified") return;
    assert.equal(result.snapshot.identity.currentOwner, PROVIDER);
    assert.equal(result.snapshot.identity.providerCode.bytes, 0);
    assert.equal(result.snapshot.position.owner, POSITION_OWNER);
    assert.equal(result.snapshot.position.approved, PROVIDER);
    assert.equal(result.snapshot.position.callerApprovedForAll, false);
    assert.equal(result.snapshot.position.callerCanManage, true);
  });

  await t.test("operator approval for all", async () => {
    const result = await verifyPancakeV3State(
      options(fixtureRpc({ approved: OTHER, approvedForAll: true })),
    );
    assert.equal(result.status, "verified");
    if (result.status !== "verified") return;
    assert.equal(result.snapshot.position.approved, OTHER);
    assert.equal(result.snapshot.position.callerApprovedForAll, true);
    assert.equal(result.snapshot.position.callerCanManage, true);
  });
});

type FixtureOptions = Readonly<{
  canonicality?: "stable" | "retry" | "exhaust";
  exactHash?: string;
  managerFactory?: string;
  factoryPool?: string;
  poolLiquidity?: bigint;
  positionLiquidity?: bigint;
  approved?: string;
  approvedForAll?: boolean;
}>;

type FixtureRpc = PancakeStateRpc & {
  requests: PancakeStateRpcRequest[];
  taggedRequests: Array<{
    attempt: number;
    request: PancakeStateRpcRequest;
  }>;
};

function options(rpc: PancakeStateRpc) {
  return {
    rpc,
    chainId: 56,
    poolAddress: POOL,
    positionManagerAddress: BSC_PANCAKE_V3.positionManager,
    positionTokenId: "783",
    caller: PROVIDER,
    agentTokenId: "265375",
    expectedProvider: PROVIDER,
  } as const;
}

function fixtureRpc(config: FixtureOptions = {}): FixtureRpc {
  const requests: PancakeStateRpcRequest[] = [];
  const taggedRequests: FixtureRpc["taggedRequests"] = [];
  const blockReads = new Map<number, number>();
  let attempt = 0;

  return {
    requests,
    taggedRequests,
    async request<T>(request: PancakeStateRpcRequest): Promise<T> {
      if (request.method === "eth_chainId") attempt += 1;
      requests.push(request);
      taggedRequests.push({ attempt, request });

      switch (request.method) {
        case "eth_chainId":
          return "0x38" as T;
        case "eth_blockNumber":
          return "0x64" as T;
        case "eth_getBlockByNumber": {
          const count = (blockReads.get(attempt) ?? 0) + 1;
          blockReads.set(attempt, count);
          return {
            number: request.params[0],
            hash: blockHash(config, attempt, count),
            timestamp: "0x69800e80",
          } as T;
        }
        case "eth_getCode":
          return (request.params[0] === PROVIDER ? "0x" : "0x60006000") as T;
        case "eth_call":
          return contractResult(request, config) as T;
      }
    },
  };
}

function blockHash(config: FixtureOptions, attempt: number, count: number): string {
  if (config.exactHash !== undefined) return config.exactHash;
  switch (config.canonicality ?? "stable") {
    case "retry":
      if (attempt === 1) return count === 1 ? BLOCK_A : BLOCK_B;
      return BLOCK_C;
    case "exhaust":
      if (attempt === 1) return count === 1 ? BLOCK_A : BLOCK_B;
      return count === 1 ? BLOCK_C : BLOCK_D;
    default:
      return BLOCK_A;
  }
}

function contractResult(
  request: PancakeStateRpcRequest,
  config: FixtureOptions,
): Hex {
  const call = request.params[0] as { to: string; data: string };
  const target = call.to.toLowerCase();
  const selector = call.data.slice(0, 10);

  switch (selector) {
    case "0x6352211e":
      return encode("address", [
        target === BSC_PANCAKE_V3.erc8004Registry
          ? PROVIDER
          : POSITION_OWNER,
      ]);
    case "0x081812fc":
      return encode("address", [config.approved ?? PROVIDER]);
    case "0xe985e9c5":
      return encode("bool", [config.approvedForAll ?? false]);
    case "0xc45a0155":
      return encode("address", [
        target === BSC_PANCAKE_V3.positionManager
          ? config.managerFactory ?? BSC_PANCAKE_V3.factory
          : BSC_PANCAKE_V3.factory,
      ]);
    case "0xd5f39488":
      return encode("address", [BSC_PANCAKE_V3.deployer]);
    case "0x99fbab88":
      return encode(
        "uint96,address,address,address,uint24,int24,int24,uint128,uint256,uint256,uint128,uint128",
        [
          7n,
          config.approved ?? PROVIDER,
          TOKEN0,
          TOKEN1,
          500,
          60,
          180,
          config.positionLiquidity ?? 1_000n,
          11n,
          12n,
          13n,
          14n,
        ],
      );
    case "0x3850c7bd":
      return encode("uint160,int24,uint16,uint16,uint16,uint32,bool", [
        79_228_162_514_264_337_593_543_950_336n,
        100,
        1,
        2,
        3,
        4,
        true,
      ]);
    case "0x1a686502":
      return encode("uint128", [config.poolLiquidity ?? 5_000n]);
    case "0x0dfe1681":
      return encode("address", [TOKEN0]);
    case "0xd21220a7":
      return encode("address", [TOKEN1]);
    case "0xddca3f43":
      return encode("uint24", [500]);
    case "0xd0c93a7c":
      return encode("int24", [60]);
    case "0x1698ee82":
      return encode("address", [config.factoryPool ?? POOL]);
    case "0x22afcccb":
      return encode("int24", [60]);
    case "0x313ce567":
      return encode("uint8", [target === TOKEN0 ? 18 : 6]);
    case "0x70a08231":
      return encode("uint256", [target === TOKEN0 ? 10_000n : 20_000n]);
    case "0xdd62ed3e":
      return encode("uint256", [target === TOKEN0 ? 9_000n : 19_000n]);
    default:
      throw new Error(`unexpected selector ${selector} for ${target}`);
  }
}

function encode(types: string, values: readonly unknown[]): Hex {
  return encodeAbiParameters(parseAbiParameters(types), values as never);
}
