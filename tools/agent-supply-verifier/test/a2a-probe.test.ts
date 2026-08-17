import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { probeAgentCard } from "../src/probes/a2a.js";
import { inspectPassiveErc8183 } from "../src/probes/erc8183.js";
import type {
  BoundedHttpResponse,
  TransportErrorCode,
  TransportRoute,
} from "../src/transport/http.js";
import { TransportError } from "../src/transport/http.js";

const ENDPOINT =
  "https://bnb-lp.172-104-171-139.nip.io/.well-known/agent-card.json";
const ORIGIN = "https://bnb-lp.172-104-171-139.nip.io";

test("passive Agent Card probe detects metadata but never verifies ERC-8183", async () => {
  const fixture = await readFixture();
  const routes: TransportRoute[] = [];
  const result = await probeAgentCard({
    transport: fixtureTransport(fixture, routes),
    endpoint: ENDPOINT,
    expectedOrigin: ORIGIN,
  });

  assert.equal(result.status, "detected");
  if (result.status !== "detected") return;
  assert.deepEqual(result.card.skills.map((skill) => skill.id), [
    "negotiate",
    "notify_funded",
  ]);
  assert.equal(routes.length, 1);
  assert.deepEqual(routes[0], {
    kind: "agent-card",
    method: "GET",
    url: ENDPOINT,
    expectedOrigin: ORIGIN,
    expectedPath: "/.well-known/agent-card.json",
  });

  const erc8183 = inspectPassiveErc8183(result.card);
  assert.equal(erc8183.level, "claimed");
  assert.equal(erc8183.declared, true);
  assert.equal(erc8183.activeProbePerformed, false);
  assert.equal(erc8183.verified, false);
});

test("protocol incompatibility is a candidate-specific failure", async () => {
  const fixture = {
    ...(await readFixture()),
    protocolVersion: "0.4.0",
  };
  const result = await probeAgentCard({
    transport: fixtureTransport(fixture),
    endpoint: ENDPOINT,
    expectedOrigin: ORIGIN,
  });
  assert.equal(result.status, "unavailable");
  if (result.status !== "unavailable") return;
  assert.equal(result.code, "CARD_INCOMPATIBLE");
});

test("Agent Card transport failures preserve timeout, network, redirect, and DNS taxonomy", async () => {
  const cases: ReadonlyArray<{
    transportCode: TransportErrorCode;
    status: "unavailable" | "inconclusive";
    cardCode:
      | "CARD_ENDPOINT_TIMEOUT"
      | "CARD_NETWORK_ERROR"
      | "CARD_REDIRECTED"
      | "CARD_DNS_REJECTED"
      | "CARD_RESPONSE_POLICY_REJECTED"
      | "CARD_RESOLVER_UNAVAILABLE"
      | "CARD_CONFIGURATION_ERROR";
  }> = [
    { transportCode: "CONNECT_TIMEOUT", status: "unavailable", cardCode: "CARD_ENDPOINT_TIMEOUT" },
    { transportCode: "HEADERS_TIMEOUT", status: "unavailable", cardCode: "CARD_ENDPOINT_TIMEOUT" },
    { transportCode: "TOTAL_TIMEOUT", status: "unavailable", cardCode: "CARD_ENDPOINT_TIMEOUT" },
    { transportCode: "NETWORK_ERROR", status: "unavailable", cardCode: "CARD_NETWORK_ERROR" },
    { transportCode: "RESPONSE_ABORTED", status: "unavailable", cardCode: "CARD_NETWORK_ERROR" },
    { transportCode: "REDIRECT_REJECTED", status: "unavailable", cardCode: "CARD_REDIRECTED" },
    { transportCode: "DNS_UNSAFE_ADDRESS", status: "unavailable", cardCode: "CARD_DNS_REJECTED" },
    { transportCode: "REMOTE_ADDRESS_MISMATCH", status: "unavailable", cardCode: "CARD_DNS_REJECTED" },
    { transportCode: "COMPRESSED_RESPONSE_REJECTED", status: "unavailable", cardCode: "CARD_RESPONSE_POLICY_REJECTED" },
    { transportCode: "RESPONSE_TOO_LARGE", status: "unavailable", cardCode: "CARD_RESPONSE_POLICY_REJECTED" },
    { transportCode: "DNS_EMPTY", status: "inconclusive", cardCode: "CARD_RESOLVER_UNAVAILABLE" },
    { transportCode: "DNS_ERROR", status: "inconclusive", cardCode: "CARD_RESOLVER_UNAVAILABLE" },
    { transportCode: "ORIGIN_NOT_ALLOWED", status: "inconclusive", cardCode: "CARD_CONFIGURATION_ERROR" },
  ];

  for (const scenario of cases) {
    const result = await probeAgentCard({
      transport: {
        async request() {
          throw new TransportError(scenario.transportCode);
        },
      },
      endpoint: ENDPOINT,
      expectedOrigin: ORIGIN,
    });

    assert.equal(result.status, scenario.status, scenario.transportCode);
    assert.equal(result.code, scenario.cardCode, scenario.transportCode);
    assert.equal(result.observation.url, ENDPOINT, scenario.transportCode);
    assert.equal(result.observation.httpStatus, null, scenario.transportCode);
  }
});

function fixtureTransport(
  fixture: unknown,
  routes: TransportRoute[] = [],
): { request(route: TransportRoute): Promise<BoundedHttpResponse> } {
  return {
    async request(route) {
      routes.push(route);
      const body = Buffer.from(JSON.stringify(fixture));
      return {
        status: 200,
        contentType: "application/json",
        retryAfter: null,
        rateLimitRemaining: null,
        body,
        responseSha256: createHash("sha256").update(body).digest("hex"),
        resolvedAddress: "172.104.171.139",
        startedAt: "2026-08-16T10:00:00.000Z",
        finishedAt: "2026-08-16T10:00:00.100Z",
        latencyMs: 100,
      };
    },
  };
}

async function readFixture(): Promise<Record<string, unknown>> {
  return JSON.parse(
    await readFile(new URL("./fixtures/agent-card.json", import.meta.url), "utf8"),
  ) as Record<string, unknown>;
}
