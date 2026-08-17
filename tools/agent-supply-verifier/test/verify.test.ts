import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { manifestFileSchema } from "../src/schema.js";
import type {
  BoundedHttpResponse,
  TransportErrorCode,
  TransportRoute,
} from "../src/transport/http.js";
import { TransportError } from "../src/transport/http.js";
import { verifyManifest } from "../src/verify.js";

const OWNER = "0x20f1ca5d1e5a3ee94c29dbf95e6bf6cea6a8d64b";
const BLOCK_HASH = `0x${"ab".repeat(32)}`;

test("scan 404 plus canonical owner remains REGISTERED_ONLY", async () => {
  const card = await fixture("agent-card.json");
  const routes: TransportRoute[] = [];
  const manifest = manifestFileSchema.parse({
    version: 1,
    candidates: [candidateFixture()],
  });

  const report = await verifyManifest({
    manifest,
    transport: combinedTransport({ scanStatus: 404, card, routes }),
    now: sequentialClock(),
  });

  assert.equal(report.runStatus, "complete");
  assert.equal(report.candidates[0]?.status, "REGISTERED_ONLY");
  assert.equal(report.candidates[0]?.scan?.indexed, false);
  assert.equal(report.candidates[0]?.owner, OWNER);
  assert.equal(
    report.candidates[0]?.sources.find((source) => source.source === "8004scan")
      ?.disposition,
    "mismatch",
  );
  assert.equal(
    report.candidates[0]?.gates.find((gate) => gate.gate === "quote_signature")
      ?.state,
    "unknown",
  );
  assert.equal(
    report.candidates[0]?.evidence.some(
      (item) => item.id === "card.erc8183-declaration" && item.level === "claimed",
    ),
    true,
  );

  const cardRoutes = routes.filter((route) => route.kind === "agent-card");
  assert.equal(cardRoutes.length, 1);
  assert.equal(cardRoutes[0]?.method, "GET");
  const networkPayloads = routes
    .filter((route): route is Extract<TransportRoute, { kind: "bsc-rpc" }> =>
      route.kind === "bsc-rpc",
    )
    .map((route) => route.body)
    .join("\n");
  assert.equal(networkPayloads.includes("negotiate"), false);
  assert.equal(networkPayloads.includes("notify_funded"), false);
  assert.equal(networkPayloads.includes("eth_send"), false);
});

test("HTTP 429 stops the run before chain or endpoint probes", async () => {
  const routes: TransportRoute[] = [];
  const manifest = manifestFileSchema.parse({
    version: 1,
    candidates: [candidateFixture()],
  });
  const report = await verifyManifest({
    manifest,
    transport: combinedTransport({ scanStatus: 429, card: {}, routes }),
    now: sequentialClock(),
  });

  assert.equal(report.runStatus, "inconclusive");
  assert.equal(report.candidates[0]?.status, "INCONCLUSIVE");
  assert.equal(routes.length, 1);
  assert.equal(routes[0]?.kind, "scan-detail");
});

test("passive reports preserve Agent Card timeout, network, redirect, and policy classifications", async () => {
  const cases: ReadonlyArray<{
    transportCode: TransportErrorCode;
    reportCode:
      | "ENDPOINT_TIMEOUT"
      | "SOURCE_UNAVAILABLE"
      | "ENDPOINT_REDIRECTED"
      | "ENDPOINT_DNS_REJECTED"
      | "ENDPOINT_MALFORMED"
      | "POLICY_REJECTED";
    candidateStatus: "UNAVAILABLE" | "INCONCLUSIVE";
  }> = [
    { transportCode: "TOTAL_TIMEOUT", reportCode: "ENDPOINT_TIMEOUT", candidateStatus: "UNAVAILABLE" },
    { transportCode: "NETWORK_ERROR", reportCode: "SOURCE_UNAVAILABLE", candidateStatus: "UNAVAILABLE" },
    { transportCode: "RESPONSE_ABORTED", reportCode: "SOURCE_UNAVAILABLE", candidateStatus: "UNAVAILABLE" },
    { transportCode: "REDIRECT_REJECTED", reportCode: "ENDPOINT_REDIRECTED", candidateStatus: "UNAVAILABLE" },
    { transportCode: "DNS_UNSAFE_ADDRESS", reportCode: "ENDPOINT_DNS_REJECTED", candidateStatus: "UNAVAILABLE" },
    { transportCode: "COMPRESSED_RESPONSE_REJECTED", reportCode: "ENDPOINT_MALFORMED", candidateStatus: "UNAVAILABLE" },
    { transportCode: "DNS_ERROR", reportCode: "SOURCE_UNAVAILABLE", candidateStatus: "INCONCLUSIVE" },
    { transportCode: "ORIGIN_NOT_ALLOWED", reportCode: "POLICY_REJECTED", candidateStatus: "INCONCLUSIVE" },
  ];

  for (const scenario of cases) {
    const routes: TransportRoute[] = [];
    const report = await verifyManifest({
      manifest: manifestFileSchema.parse({
        version: 1,
        candidates: [candidateFixture()],
      }),
      transport: combinedTransport({
        scanStatus: 404,
        card: {},
        cardError: scenario.transportCode,
        routes,
      }),
      now: sequentialClock(),
    });
    const candidate = report.candidates[0]!;
    const cardSource = candidate.sources.find(
      (source) => source.source === "agent_card",
    );

    assert.equal(candidate.status, scenario.candidateStatus, scenario.transportCode);
    assert.equal(cardSource?.error?.code, scenario.reportCode, scenario.transportCode);
    assert.equal(
      candidate.errors.some((error) => error.code === "ENDPOINT_TLS_FAILED"),
      false,
      scenario.transportCode,
    );
    assert.equal(
      routes.filter((route) => route.kind === "agent-card").length,
      1,
      scenario.transportCode,
    );
  }
});

function combinedTransport(options: {
  scanStatus: 404 | 429;
  card: unknown;
  cardError?: TransportErrorCode;
  routes: TransportRoute[];
}): { request(route: TransportRoute): Promise<BoundedHttpResponse> } {
  let count = 0;
  return {
    async request(route) {
      options.routes.push(route);
      count += 1;
      if (route.kind === "scan-detail") {
        return response(
          options.scanStatus,
          Buffer.from("{}"),
          count,
          options.scanStatus === 429 ? "60" : null,
        );
      }
      if (route.kind === "agent-card") {
        if (options.cardError !== undefined) {
          throw new TransportError(options.cardError);
        }
        return response(200, Buffer.from(JSON.stringify(options.card)), count);
      }

      const request = JSON.parse(route.body) as Record<string, unknown>;
      const body = Buffer.from(
        JSON.stringify({
          jsonrpc: "2.0",
          id: request.id,
          result: rpcResult(request),
        }),
      );
      return response(200, body, count);
    },
  };
}

function rpcResult(request: Record<string, unknown>): unknown {
  switch (request.method) {
    case "eth_chainId":
      return "0x38";
    case "eth_blockNumber":
      return "0x64";
    case "eth_getBlockByNumber":
      return { number: "0x62", hash: BLOCK_HASH };
    case "eth_getCode":
      return "0x60006000";
    case "eth_call":
      return `0x${"0".repeat(24)}${OWNER.slice(2)}`;
    default:
      throw new Error(`unexpected method ${String(request.method)}`);
  }
}

function response(
  status: number,
  body: Buffer,
  count: number,
  retryAfter: string | null = null,
): BoundedHttpResponse {
  return {
    status,
    contentType: "application/json",
    retryAfter,
    rateLimitRemaining: null,
    body,
    responseSha256: createHash("sha256").update(body).digest("hex"),
    resolvedAddress: "1.1.1.1",
    startedAt: `2026-08-16T10:00:${String(count).padStart(2, "0")}.000Z`,
    finishedAt: `2026-08-16T10:00:${String(count).padStart(2, "0")}.010Z`,
    latencyMs: 10,
  };
}

function candidateFixture() {
  return {
    chainId: 56,
    tokenId: "265375",
    expectedName: "BNB LP Range Rebalancer",
    expectedEndpoint:
      "https://bnb-lp.172-104-171-139.nip.io/.well-known/agent-card.json",
    expectedOrigin: "https://bnb-lp.172-104-171-139.nip.io",
    categories: ["rebalancing"],
    source: "8004scan" as const,
    provider: "MandateX reference cohort",
    teamOperatedReference: true,
  };
}

async function fixture(name: string): Promise<unknown> {
  return JSON.parse(
    await readFile(new URL(`./fixtures/${name}`, import.meta.url), "utf8"),
  );
}

function sequentialClock(): () => Date {
  let count = 0;
  return () => new Date(Date.UTC(2026, 7, 16, 10, 0, 30, count++));
}
