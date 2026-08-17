import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { IncomingHttpHeaders } from "node:http";
import type { RequestOptions } from "node:https";
import { request as nodeHttpsRequest } from "node:https";
import test from "node:test";

import {
  PinnedHttpsTransport,
  TransportError,
  validateTransportRoute,
  type TransportRoute,
} from "../src/transport/http.js";

const ENDPOINT = "https://agent.example/";

test("quote route pins the exact endpoint and negotiate-only wire shape", () => {
  assert.equal(validateTransportRoute(route(quoteBody())).href, ENDPOINT);

  assert.throws(
    () => validateTransportRoute({ ...route(quoteBody()), approvedUrl: "https://agent.example/a2a" }),
    (error: unknown) =>
      error instanceof TransportError && error.code === "ORIGIN_NOT_ALLOWED",
  );
  assert.throws(
    () =>
      validateTransportRoute(
        route(
          quoteBody({
            skill: "notify_funded",
          }),
        ),
      ),
    (error: unknown) =>
      error instanceof TransportError && error.code === "RPC_METHOD_NOT_ALLOWED",
  );
  assert.throws(
    () =>
      validateTransportRoute({
        ...route(quoteBody()),
        body: JSON.stringify({
          ...JSON.parse(quoteBody()),
          method: "tasks/send",
        }),
      }),
    (error: unknown) =>
      error instanceof TransportError && error.code === "RPC_METHOD_NOT_ALLOWED",
  );
});

test("quote POST sends no credentials and is attempted exactly once", async () => {
  let calls = 0;
  let capturedOptions: RequestOptions | undefined;
  let writtenBody = "";
  const body = quoteBody();
  const transport = new PinnedHttpsTransport({
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    requestFactory: fakeRequestFactory(
      {
        status: 503,
        headers: { "content-type": "application/json" },
        body: Buffer.from(JSON.stringify({ error: "unavailable" })),
        remoteAddress: "93.184.216.34",
      },
      (options, written) => {
        calls += 1;
        capturedOptions = options;
        writtenBody = written;
      },
    ),
  });

  const response = await transport.request(route(body));
  assert.equal(response.status, 503);
  assert.equal(calls, 1);
  assert.equal(writtenBody, body);
  assert.equal(capturedOptions?.method, "POST");
  assert.equal(capturedOptions?.path, "/");
  const headers = capturedOptions?.headers as Record<string, string>;
  assert.equal(headers.Authorization, undefined);
  assert.equal(headers.Cookie, undefined);
  assert.equal(headers["Proxy-Authorization"], undefined);
  assert.equal(headers["Content-Type"], "application/json");
});

test("quote route applies its smaller request and response budgets", async () => {
  const oversizedRequest = quoteBody({
    mandate: { category: "rebalancing", padding: "x".repeat(17 * 1024) },
  });
  const requestTransport = new PinnedHttpsTransport({
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    requestFactory: fakeRequestFactory({
      status: 200,
      headers: { "content-type": "application/json" },
      body: Buffer.from("{}"),
      remoteAddress: "93.184.216.34",
    }),
  });
  await assert.rejects(
    requestTransport.request(route(oversizedRequest)),
    (error: unknown) =>
      error instanceof TransportError && error.code === "REQUEST_TOO_LARGE",
  );

  const responseTransport = new PinnedHttpsTransport({
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    requestFactory: fakeRequestFactory({
      status: 200,
      headers: {
        "content-type": "application/json",
        "content-length": String(65 * 1024),
      },
      body: Buffer.alloc(0),
      remoteAddress: "93.184.216.34",
    }),
  });
  await assert.rejects(
    responseTransport.request(route(quoteBody())),
    (error: unknown) =>
      error instanceof TransportError && error.code === "RESPONSE_TOO_LARGE",
  );
});

test("ERC-1271 quote RPC is method-limited and uses dedicated byte budgets", async () => {
  assert.equal(
    validateTransportRoute(bscQuoteRpcRoute("eth_getCode")).href,
    "https://bsc-dataseed.binance.org/",
  );
  assert.throws(
    () =>
      validateTransportRoute({
        ...bscQuoteRpcRoute("eth_getCode"),
        rpcMethod: "eth_chainId",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "quote-rpc-1",
          method: "eth_chainId",
          params: [],
        }),
      } as unknown as TransportRoute),
    (error: unknown) =>
      error instanceof TransportError && error.code === "RPC_METHOD_NOT_ALLOWED",
  );

  const requestTransport = new PinnedHttpsTransport({
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    requestFactory: fakeRequestFactory({
      status: 200,
      headers: { "content-type": "application/json" },
      body: Buffer.from("{}"),
      remoteAddress: "93.184.216.34",
    }),
  });
  await assert.rejects(
    requestTransport.request(
      bscQuoteRpcRoute("eth_call", "aa".repeat(9 * 1024)),
    ),
    (error: unknown) =>
      error instanceof TransportError && error.code === "REQUEST_TOO_LARGE",
  );

  const responseTransport = new PinnedHttpsTransport({
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    requestFactory: fakeRequestFactory({
      status: 200,
      headers: {
        "content-type": "application/json",
        "content-length": String(17 * 1024),
      },
      body: Buffer.alloc(0),
      remoteAddress: "93.184.216.34",
    }),
  });
  await assert.rejects(
    responseTransport.request(bscQuoteRpcRoute("eth_getCode")),
    (error: unknown) =>
      error instanceof TransportError && error.code === "RESPONSE_TOO_LARGE",
  );
});

function route(body: string) {
  return {
    kind: "a2a-quote" as const,
    method: "POST" as const,
    url: ENDPOINT,
    approvedUrl: ENDPOINT,
    rpcMethod: "message/send" as const,
    body,
  };
}

function bscQuoteRpcRoute(
  method: "eth_getCode" | "eth_call",
  padding = "",
) {
  const provider = `0x${"1".repeat(40)}`;
  const block = {
    blockHash: `0x${"a".repeat(64)}`,
    requireCanonical: true,
  };
  return {
    kind: "bsc-quote-rpc" as const,
    method: "POST" as const,
    url: "https://bsc-dataseed.binance.org",
    rpcMethod: method,
    approvedProvider: provider,
    approvedBlockHash: block.blockHash,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "quote-rpc-1",
      method,
      params:
        method === "eth_getCode"
          ? [provider, block]
          : [{ to: provider, data: `0x1626ba7e${padding}` }, block],
    }),
  };
}

function quoteBody(
  options: {
    skill?: string;
    mandate?: Record<string, unknown>;
  } = {},
): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: "request-1",
    method: "message/send",
    params: {
      message: {
        kind: "message",
        messageId: "message-1",
        role: "user",
        parts: [
          {
            kind: "data",
            data: {
              skill: options.skill ?? "negotiate",
              request: {
                mandate: options.mandate ?? { category: "rebalancing" },
              },
            },
          },
        ],
      },
    },
  });
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
    let body = "";
    const request = new EventEmitter() as EventEmitter & {
      write: (chunk: string) => void;
      end: () => void;
      destroy: (error?: Error) => void;
    };
    request.write = (chunk: string) => {
      body += chunk;
    };
    request.destroy = (error?: Error) => {
      if (error !== undefined) request.emit("error", error);
    };
    request.end = () => {
      capture?.(options, body);
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
