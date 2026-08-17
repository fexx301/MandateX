import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { IncomingHttpHeaders } from "node:http";
import type { RequestOptions } from "node:https";
import { request as nodeHttpsRequest } from "node:https";
import test from "node:test";

import {
  PinnedHttpsTransport,
  TransportError,
  isPublicDestination,
  selectPinnedAddress,
  validateTransportRoute,
  type TransportRoute,
} from "../src/transport/http.js";

test("transport rejects unsafe URLs, origins, paths, and RPC methods", () => {
  for (const url of [
    "http://8004scan.io/api/v1/public/agents/56/1",
    "https://user:pass@8004scan.io/api/v1/public/agents/56/1",
    "https://127.0.0.1/api/v1/public/agents/56/1",
    "https://8004scan.io:444/api/v1/public/agents/56/1",
  ]) {
    assert.throws(
      () =>
        validateTransportRoute({
          kind: "scan-detail",
          method: "GET",
          url,
          chainId: 56,
          tokenId: "1",
        }),
      TransportError,
    );
  }

  assert.throws(
    () =>
      validateTransportRoute({
        kind: "scan-detail",
        method: "GET",
        url: "https://8004scan.io/api/v1/public/agents/56/2",
        chainId: 56,
        tokenId: "1",
      }),
    (error: unknown) => error instanceof TransportError && error.code === "PATH_NOT_ALLOWED",
  );

  assert.throws(
    () =>
      validateTransportRoute({
        kind: "bsc-rpc",
        method: "POST",
        url: "https://bsc-dataseed.binance.org",
        rpcMethod: "eth_chainId",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_sendRawTransaction", params: [] }),
      }),
    (error: unknown) =>
      error instanceof TransportError && error.code === "RPC_METHOD_NOT_ALLOWED",
  );

  assert.throws(
    () =>
      validateTransportRoute({
        kind: "scan-detail",
        method: "POST",
        url: "https://8004scan.io/api/v1/public/agents/56/1",
        chainId: 56,
        tokenId: "1",
      } as unknown as TransportRoute),
    (error: unknown) => error instanceof TransportError && error.code === "METHOD_NOT_ALLOWED",
  );
});

test("DNS policy rejects every private/reserved family and mixed rebinding answers", () => {
  for (const address of [
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "198.51.100.10",
    "::",
    "::1",
    "::ffff:127.0.0.1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
  ]) {
    assert.equal(isPublicDestination(address), false, address);
  }
  assert.equal(isPublicDestination("8.8.8.8", 4), true);
  assert.equal(isPublicDestination("2606:4700:4700::1111", 6), true);

  assert.throws(
    () =>
      selectPinnedAddress([
        { address: "93.184.216.34", family: 4 },
        { address: "127.0.0.1", family: 4 },
      ]),
    (error: unknown) =>
      error instanceof TransportError && error.code === "DNS_UNSAFE_ADDRESS",
  );
});

test("request socket is pinned while TLS SNI and hostname remain original", async () => {
  let capturedOptions: RequestOptions | undefined;
  const factory = fakeRequestFactory(
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body: Buffer.from("{}"),
      remoteAddress: "93.184.216.34",
    },
    (options) => {
      capturedOptions = options;
    },
  );
  const transport = new PinnedHttpsTransport({
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    requestFactory: factory,
    now: sequentialClock(),
    monotonicNow: sequentialMonotonicClock(),
  });

  const response = await transport.request({
    kind: "agent-card",
    method: "GET",
    url: "https://agent.example/.well-known/agent-card.json",
    expectedOrigin: "https://agent.example",
    expectedPath: "/.well-known/agent-card.json",
  });

  assert.equal(response.status, 200);
  assert.equal(response.resolvedAddress, "93.184.216.34");
  assert.equal(capturedOptions?.hostname, "agent.example");
  assert.equal(capturedOptions?.servername, "agent.example");
  assert.equal(capturedOptions?.path, "/.well-known/agent-card.json");
  assert.equal(capturedOptions?.agent, false);
  assert.equal((capturedOptions?.headers as Record<string, string>)["Accept-Encoding"], "identity");

  const lookup = capturedOptions?.lookup;
  assert.equal(typeof lookup, "function");
  await new Promise<void>((resolve, reject) => {
    lookup!("agent.example", { all: false }, (error, address, family) => {
      if (error) return reject(error);
      assert.equal(address, "93.184.216.34");
      assert.equal(family, 4);
      resolve();
    });
  });
});

test("transport refuses redirects, compressed bodies, and oversized bodies", async () => {
  for (const scenario of [
    {
      expectedCode: "REDIRECT_REJECTED",
      status: 302,
      headers: { location: "https://other.example/card" },
      body: Buffer.alloc(0),
    },
    {
      expectedCode: "COMPRESSED_RESPONSE_REJECTED",
      status: 200,
      headers: { "content-encoding": "gzip", "content-type": "application/json" },
      body: Buffer.from("compressed"),
    },
    {
      expectedCode: "RESPONSE_TOO_LARGE",
      status: 200,
      headers: { "content-type": "application/json" },
      body: Buffer.from("12345"),
    },
  ] as const) {
    const transport = new PinnedHttpsTransport({
      resolver: async () => [{ address: "93.184.216.34", family: 4 }],
      requestFactory: fakeRequestFactory({ ...scenario, remoteAddress: "93.184.216.34" }),
      limits: { maxResponseBytes: 4 },
    });
    await assert.rejects(
      transport.request({
        kind: "agent-card",
        method: "GET",
        url: "https://agent.example/.well-known/agent-card.json",
        expectedOrigin: "https://agent.example",
        expectedPath: "/.well-known/agent-card.json",
      }),
      (error: unknown) =>
        error instanceof TransportError && error.code === scenario.expectedCode,
    );
  }
});

type FakeScenario = Readonly<{
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
  remoteAddress: string;
}>;

function fakeRequestFactory(
  scenario: FakeScenario,
  capture?: (options: RequestOptions) => void,
): typeof nodeHttpsRequest {
  return ((options: RequestOptions, callback: (response: unknown) => void) => {
    capture?.(options);
    const request = new EventEmitter() as EventEmitter & {
      write: (body: string) => void;
      end: () => void;
      destroy: (error?: Error) => void;
    };
    request.write = () => undefined;
    request.destroy = (error?: Error) => {
      if (error !== undefined) request.emit("error", error);
    };
    request.end = () => {
      const socket = new EventEmitter() as EventEmitter & { remoteAddress: string };
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

function sequentialClock(): () => Date {
  let count = 0;
  return () => new Date(Date.UTC(2026, 7, 16, 10, 0, 0, count++));
}

function sequentialMonotonicClock(): () => number {
  let value = 0;
  return () => (value += 5);
}
