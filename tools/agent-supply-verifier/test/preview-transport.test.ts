import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { IncomingHttpHeaders } from "node:http";
import type { RequestOptions } from "node:https";
import { request as nodeHttpsRequest } from "node:https";
import test from "node:test";

import {
  BSC_MAINNET_RPC_ORIGIN,
  BSC_PREVIEW_MULTICALL_SELECTOR,
  BSC_PREVIEW_POSITION_MANAGER,
  BSC_PREVIEW_RPC_LIMITS,
  BSC_PREVIEW_SIMULATION_GAS,
  BSC_PREVIEW_STATE_READ_SELECTORS,
  PinnedHttpsTransport,
  TransportError,
  computeBscPreviewCalldataSha256,
  validateTransportRoute,
  type BscPreviewRpcRoute,
  type TransportErrorCode,
  type TransportRoute,
} from "../src/transport/http.js";

const RPC_URL = `${BSC_MAINNET_RPC_ORIGIN}/`;
const BLOCK_NUMBER = "0x1234";
const BLOCK_HASH = `0x${"a".repeat(64)}`;
const TARGET = `0x${"1".repeat(40)}`;
const OTHER_TARGET = `0x${"2".repeat(40)}`;
const CALLER = `0x${"3".repeat(40)}`;
const STATE_DATA = `0x6352211e${"0".repeat(64)}`;
const SIMULATION_DATA = `${BSC_PREVIEW_MULTICALL_SELECTOR}${"0".repeat(64)}`;

test("preview RPC accepts only the fixed origin and exact purpose/method shapes", () => {
  const validRoutes: readonly BscPreviewRpcRoute[] = [
    chainIdRoute(),
    headBlockRoute(),
    blockHeaderRoute(),
    contractCodeRoute(),
    stateReadRoute(),
    simulationRoute(),
  ];
  for (const route of validRoutes) {
    assert.equal(validateTransportRoute(route).href, RPC_URL);
  }

  assertPolicyReject(
    { ...chainIdRoute(), url: "https://rpc.example/" },
    "ORIGIN_NOT_ALLOWED",
  );
  assertPolicyReject(
    { ...chainIdRoute(), url: `${BSC_MAINNET_RPC_ORIGIN}/rpc` },
    "ORIGIN_NOT_ALLOWED",
  );
  assertPolicyReject(
    { ...chainIdRoute(), method: "GET" },
    "METHOD_NOT_ALLOWED",
  );

  for (const rpcMethod of [
    "eth_getBlockByHash",
    "eth_sendRawTransaction",
    "eth_signTransaction",
    "eth_estimateGas",
    "debug_traceCall",
  ]) {
    assertPolicyReject({
      ...chainIdRoute(),
      rpcMethod,
      body: rpcBody(rpcMethod, []),
    });
  }

  assertPolicyReject({
    ...chainIdRoute(),
    body: JSON.stringify([
      JSON.parse(chainIdRoute().body),
      JSON.parse(headBlockRoute().body),
    ]),
  });
  assertPolicyReject({
    ...chainIdRoute(),
    body: rpcBody("eth_chainId", [], { extra: true }),
  });
  assertPolicyReject({
    ...chainIdRoute(),
    body: rpcBody("eth_chainId", ["latest"]),
  });
  assertPolicyReject({
    ...headBlockRoute(),
    purpose: "chain-id",
  });
  assertPolicyReject({
    ...chainIdRoute(),
    approvedBlockHash: BLOCK_HASH,
  });

  assertPolicyReject({
    ...blockHeaderRoute(),
    approvedBlockNumber: "0x01234",
  });
  assertPolicyReject({
    ...blockHeaderRoute(),
    body: rpcBody("eth_getBlockByNumber", ["0x1235", false]),
  });
  assertPolicyReject({
    ...blockHeaderRoute(),
    body: rpcBody("eth_getBlockByNumber", [BLOCK_NUMBER, true]),
  });
  assertPolicyReject({
    ...blockHeaderRoute(),
    body: rpcBody("eth_getBlockByNumber", [BLOCK_NUMBER, false, {}]),
  });
});

test("preview snapshot reads pin one target, selector, and canonical block", () => {
  assert.equal(
    BSC_PREVIEW_POSITION_MANAGER,
    "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364",
  );
  assert.equal(BSC_PREVIEW_MULTICALL_SELECTOR, "0xac9650d8");
  assert.equal(BSC_PREVIEW_SIMULATION_GAS, "0x7a1200");
  assert.deepEqual(BSC_PREVIEW_STATE_READ_SELECTORS, [
    "0x6352211e",
    "0xc45a0155",
    "0xd5f39488",
    "0x99fbab88",
    "0x081812fc",
    "0xe985e9c5",
    "0x3850c7bd",
    "0x1a686502",
    "0x0dfe1681",
    "0xd21220a7",
    "0xddca3f43",
    "0xd0c93a7c",
    "0x1698ee82",
    "0x22afcccb",
    "0x313ce567",
    "0x70a08231",
    "0xdd62ed3e",
  ]);

  for (const selector of BSC_PREVIEW_STATE_READ_SELECTORS) {
    assert.equal(
      validateTransportRoute(stateReadRoute(selector)).href,
      RPC_URL,
      selector,
    );
  }

  assertPolicyReject({
    ...contractCodeRoute(),
    approvedTargets: [],
  });
  assertPolicyReject({
    ...contractCodeRoute(),
    approvedTargets: [TARGET, OTHER_TARGET],
  });
  assertPolicyReject({
    ...contractCodeRoute(),
    approvedTargets: [TARGET.toUpperCase()],
  });
  assertPolicyReject({
    ...contractCodeRoute(),
    approvedTargets: [`0x${"0".repeat(40)}`],
  });
  assertPolicyReject({
    ...contractCodeRoute(),
    body: rpcBody("eth_getCode", [OTHER_TARGET, canonicalBlock()]),
  });
  assertPolicyReject({
    ...contractCodeRoute(),
    body: rpcBody("eth_getCode", [TARGET, BLOCK_NUMBER]),
  });
  assertPolicyReject({
    ...contractCodeRoute(),
    approvedBlockHash: `0x${"b".repeat(64)}`,
  });
  assertPolicyReject({
    ...contractCodeRoute(),
    body: rpcBody("eth_getCode", [
      TARGET,
      { ...canonicalBlock(), blockNumber: BLOCK_NUMBER },
    ]),
  });

  assertPolicyReject({
    ...stateReadRoute(),
    body: rpcBody("eth_call", [
      { to: OTHER_TARGET, data: STATE_DATA },
      canonicalBlock(),
    ]),
  });
  assertPolicyReject({
    ...stateReadRoute(),
    body: rpcBody("eth_call", [
      { to: TARGET, data: `0xdeadbeef${"0".repeat(64)}` },
      canonicalBlock(),
    ]),
  });
  assertPolicyReject({
    ...stateReadRoute(),
    body: rpcBody("eth_call", [
      { to: TARGET, data: STATE_DATA, from: CALLER },
      canonicalBlock(),
    ]),
  });
  assertPolicyReject({
    ...stateReadRoute(),
    body: rpcBody("eth_call", [
      { to: TARGET, data: STATE_DATA },
      canonicalBlock(),
      { [TARGET]: { balance: "0x1" } },
    ]),
  });
  assertPolicyReject({
    ...stateReadRoute(),
    body: rpcBody("eth_call", [
      { to: TARGET, data: STATE_DATA },
      { ...canonicalBlock(), extra: true },
    ]),
  });
});

test("preview simulation binds caller, manager, value, gas, calldata hash, and block", () => {
  assert.equal(validateTransportRoute(simulationRoute()).href, RPC_URL);

  const invalidCalls: readonly Record<string, unknown>[] = [
    simulationCall({ to: OTHER_TARGET }),
    simulationCall({ from: OTHER_TARGET }),
    simulationCall({ value: "0x1" }),
    simulationCall({ value: "0x00" }),
    simulationCall({ gas: "0x7a1201" }),
    simulationCall({ data: `0xdeadbeef${"0".repeat(64)}` }),
    { ...simulationCall(), nonce: "0x0" },
  ];
  for (const call of invalidCalls) {
    assertPolicyReject({
      ...simulationRoute(),
      body: rpcBody("eth_call", [call, canonicalBlock()]),
    });
  }

  assertPolicyReject({
    ...simulationRoute(),
    approvedCaller: OTHER_TARGET,
  });
  assertPolicyReject({
    ...simulationRoute(),
    approvedCaller: CALLER.toUpperCase(),
  });
  assertPolicyReject({
    ...simulationRoute(),
    approvedCalldataSha256: "f".repeat(64),
  });
  assertPolicyReject({
    ...simulationRoute(),
    approvedCalldataSha256:
      computeBscPreviewCalldataSha256(SIMULATION_DATA).toUpperCase(),
  });
  assertPolicyReject({
    ...simulationRoute(),
    approvedBlockHash: `0x${"b".repeat(64)}`,
  });
  assertPolicyReject({
    ...simulationRoute(),
    body: rpcBody("eth_call", [
      simulationCall(),
      { ...canonicalBlock(), requireCanonical: false },
    ]),
  });
  assertPolicyReject({
    ...simulationRoute(),
    body: rpcBody("eth_call", [
      simulationCall(),
      canonicalBlock(),
      { [CALLER]: { nonce: "0x1" } },
    ]),
  });
  assertPolicyReject({
    ...simulationRoute(),
    approvedTargets: [BSC_PREVIEW_POSITION_MANAGER],
  });
});

test("preview RPC applies dedicated request and response byte budgets", async () => {
  const oversizedData = `${BSC_PREVIEW_MULTICALL_SELECTOR}${"00".repeat(13 * 1024)}`;
  const oversizedRoute = simulationRoute(oversizedData);
  assert.ok(
    Buffer.byteLength(oversizedRoute.body, "utf8") >
      BSC_PREVIEW_RPC_LIMITS.maxRequestBytes,
  );

  let requestCalls = 0;
  const requestTransport = new PinnedHttpsTransport({
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    requestFactory: fakeRequestFactory(
      {
        status: 200,
        headers: { "content-type": "application/json" },
        body: Buffer.from("{}"),
        remoteAddress: "93.184.216.34",
      },
      () => {
        requestCalls += 1;
      },
    ),
    limits: { maxRequestBytes: 1024 * 1024 },
  });
  await assert.rejects(
    requestTransport.request(oversizedRoute),
    hasTransportCode("REQUEST_TOO_LARGE"),
  );
  assert.equal(requestCalls, 0);

  const responseTransport = new PinnedHttpsTransport({
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    requestFactory: fakeRequestFactory({
      status: 200,
      headers: {
        "content-type": "application/json",
        "content-length": String(BSC_PREVIEW_RPC_LIMITS.maxResponseBytes + 1),
      },
      body: Buffer.alloc(0),
      remoteAddress: "93.184.216.34",
    }),
    limits: { maxResponseBytes: 1024 * 1024 },
  });
  await assert.rejects(
    responseTransport.request(chainIdRoute()),
    hasTransportCode("RESPONSE_TOO_LARGE"),
  );
});

function chainIdRoute(): BscPreviewRpcRoute {
  return {
    kind: "bsc-preview-rpc",
    method: "POST",
    url: RPC_URL,
    purpose: "chain-id",
    rpcMethod: "eth_chainId",
    body: rpcBody("eth_chainId", []),
  };
}

function headBlockRoute(): BscPreviewRpcRoute {
  return {
    kind: "bsc-preview-rpc",
    method: "POST",
    url: RPC_URL,
    purpose: "head-block-number",
    rpcMethod: "eth_blockNumber",
    body: rpcBody("eth_blockNumber", []),
  };
}

function blockHeaderRoute(): BscPreviewRpcRoute {
  return {
    kind: "bsc-preview-rpc",
    method: "POST",
    url: RPC_URL,
    purpose: "block-header",
    rpcMethod: "eth_getBlockByNumber",
    approvedBlockNumber: BLOCK_NUMBER,
    body: rpcBody("eth_getBlockByNumber", [BLOCK_NUMBER, false]),
  };
}

function contractCodeRoute(): BscPreviewRpcRoute {
  return {
    kind: "bsc-preview-rpc",
    method: "POST",
    url: RPC_URL,
    purpose: "contract-code",
    rpcMethod: "eth_getCode",
    approvedTargets: [TARGET],
    approvedBlockHash: BLOCK_HASH,
    body: rpcBody("eth_getCode", [TARGET, canonicalBlock()]),
  };
}

function stateReadRoute(selectorOrData = STATE_DATA): BscPreviewRpcRoute {
  return {
    kind: "bsc-preview-rpc",
    method: "POST",
    url: RPC_URL,
    purpose: "state-read",
    rpcMethod: "eth_call",
    approvedTargets: [TARGET],
    approvedBlockHash: BLOCK_HASH,
    body: rpcBody("eth_call", [
      { to: TARGET, data: selectorOrData },
      canonicalBlock(),
    ]),
  };
}

function simulationRoute(data = SIMULATION_DATA): BscPreviewRpcRoute {
  return {
    kind: "bsc-preview-rpc",
    method: "POST",
    url: RPC_URL,
    purpose: "simulation",
    rpcMethod: "eth_call",
    approvedCaller: CALLER,
    approvedCalldataSha256: computeBscPreviewCalldataSha256(data),
    approvedBlockHash: BLOCK_HASH,
    body: rpcBody("eth_call", [simulationCall({ data }), canonicalBlock()]),
  };
}

function simulationCall(
  overrides: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    from: CALLER,
    to: BSC_PREVIEW_POSITION_MANAGER,
    value: "0x0",
    gas: BSC_PREVIEW_SIMULATION_GAS,
    data: SIMULATION_DATA,
    ...overrides,
  };
}

function canonicalBlock(): Record<string, unknown> {
  return { blockHash: BLOCK_HASH, requireCanonical: true };
}

function rpcBody(
  method: string,
  params: readonly unknown[],
  extra: Readonly<Record<string, unknown>> = {},
): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: "preview-rpc-1",
    method,
    params,
    ...extra,
  });
}

function assertPolicyReject(
  route: unknown,
  code: TransportErrorCode = "RPC_METHOD_NOT_ALLOWED",
): void {
  assert.throws(
    () => validateTransportRoute(route as TransportRoute),
    hasTransportCode(code),
  );
}

function hasTransportCode(code: TransportErrorCode) {
  return (error: unknown): boolean =>
    error instanceof TransportError && error.code === code;
}

type FakeScenario = Readonly<{
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
  remoteAddress: string;
}>;

function fakeRequestFactory(
  scenario: FakeScenario,
  capture?: (options: RequestOptions, body: string) => void,
): typeof nodeHttpsRequest {
  return ((options: RequestOptions, callback: (response: unknown) => void) => {
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
      capture?.(options, writtenBody);
      const socket = new EventEmitter() as EventEmitter & {
        remoteAddress: string;
      };
      socket.remoteAddress = scenario.remoteAddress;
      request.emit("socket", socket);
      socket.emit("secureConnect");

      const response = new EventEmitter() as EventEmitter & {
        statusCode: number;
        headers: IncomingHttpHeaders;
        destroy: () => void;
      };
      response.statusCode = scenario.status;
      response.headers = scenario.headers;
      response.destroy = () => undefined;
      callback(response);
      if (scenario.body.byteLength > 0) response.emit("data", scenario.body);
      response.emit("end");
    };
    return request;
  }) as unknown as typeof nodeHttpsRequest;
}
