// HTTP routes.
//
// Deliberately built on node:http with no framework. Three reasons, in order of
// weight: Railway bills measured memory at $10/GB/month so a lean resident set is
// a direct cost saving; this process is the one that pins the verifier's trust, so
// every dependency added here is a dependency inside the trust boundary; and five
// routes do not need a router.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { IncomingMessage, ServerResponse } from "node:http";

import {
  CATEGORY_POLICIES,
  MARKETPLACE_CATEGORY_ADAPTER_IDS,
} from "@mandatex/marketplace-core";

import type { AppConfig } from "./config.js";
import type { MarketplaceEvaluator } from "./core.js";
import { buildComparisonView } from "./display.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/** dist/ -> apps/marketplace-api -> apps -> repo root */
const DEFAULT_FIXTURES_DIR = join(HERE, "..", "..", "..", "fixtures", "attestations");

const VERIFIER_PROBE_TIMEOUT_MS = 2_000;

interface JsonBody {
  readonly status: number;
  readonly body: unknown;
}

function json(response: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body, null, 2);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  response.end(payload);
}

function problem(response: ServerResponse, status: number, code: string, detail: string): void {
  json(response, status, { error: { code, detail } });
}

/**
 * Read a request body under a hard byte cap, destroying the socket if exceeded.
 *
 * The cap is enforced on accumulated bytes rather than content-length: a
 * chunked request can lie about its length, and Core's own attestation ceiling
 * (131072 bytes each) is only meaningful if the body that carries them is bounded
 * too.
 */
async function readBody(request: IncomingMessage, maxBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;

  // `destroyOnReturn: false` matters. The default async iterator destroys the
  // request stream when the loop exits early, which tears the socket down before
  // the 413 can be written — the caller then sees a dropped connection instead of
  // a status that says what was wrong.
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > maxBytes) {
      throw new PayloadTooLarge(maxBytes);
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

class PayloadTooLarge extends Error {
  constructor(readonly maxBytes: number) {
    super(`request body exceeds ${maxBytes} bytes`);
    this.name = "PayloadTooLarge";
  }
}

/**
 * Validate the evaluate request shape.
 *
 * Hand-rolled rather than schema-driven: the shape is two fields, and adding a
 * validation library here would mean a second copy of zod resolving inside the
 * trust boundary alongside the one Core pins.
 */
function parseEvaluateRequest(
  raw: string,
): { ok: true; mandate: unknown; attestations: string[] } | { ok: false; detail: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    return { ok: false, detail: `body is not valid JSON: ${(cause as Error).message}` };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, detail: "body must be a JSON object" };
  }

  const record = parsed as Record<string, unknown>;
  const unknownKeys = Object.keys(record).filter(
    (key) => key !== "mandate" && key !== "attestations",
  );
  if (unknownKeys.length > 0) {
    return { ok: false, detail: `unexpected field(s): ${unknownKeys.join(", ")}` };
  }
  if (record.mandate === undefined) {
    return { ok: false, detail: "mandate is required" };
  }
  if (!Array.isArray(record.attestations)) {
    return { ok: false, detail: "attestations must be an array of attestation wire strings" };
  }
  if (record.attestations.length === 0) {
    return { ok: false, detail: "attestations must contain at least one attestation" };
  }

  const attestations: string[] = [];
  for (const [index, entry] of record.attestations.entries()) {
    if (typeof entry !== "string") {
      return {
        ok: false,
        detail:
          `attestations[${index}] must be a string containing the attestation wire text ` +
          "exactly as issued. Do not parse and re-serialize it: canonical-encoding defects " +
          "are part of what verification checks, and a round-trip repairs them silently.",
      };
    }
    attestations.push(entry);
  }
  return { ok: true, mandate: record.mandate, attestations };
}

interface VerifierProbe {
  readonly status: "ok" | "key_mismatch" | "unreachable" | "no_trust_endpoint" | "not_configured";
  readonly detail: string;
  readonly url: string | null;
}

/**
 * Probe the verifier runtime and compare its advertised key against our pin.
 *
 * A fingerprint mismatch is the failure the contract asks to be proven absent:
 * the verifier rotating its signing key while the app still pins the old public
 * key produces attestations that fail every signature check. Surfacing it here
 * means a broken lockstep redeploy shows up as a red readiness probe instead of
 * as a marketplace that silently rejects every quote.
 */
async function probeVerifier(config: AppConfig): Promise<VerifierProbe> {
  if (config.verifierUrl === null) {
    return {
      status: "not_configured",
      detail:
        "MANDATEX_VERIFIER_URL is unset. The API still evaluates attestations supplied in the " +
        "request body, but lockstep key agreement with the verifier cannot be checked.",
      url: null,
    };
  }

  const url = `${config.verifierUrl}/v1/trust`;
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(VERIFIER_PROBE_TIMEOUT_MS),
      headers: { accept: "application/json" },
    });

    if (response.status === 404) {
      return {
        status: "no_trust_endpoint",
        detail:
          "verifier is reachable but does not expose GET /v1/trust, so key agreement is " +
          "unverified. Ask the verifier to advertise publicKeyFingerprintSha256.",
        url,
      };
    }
    if (!response.ok) {
      return { status: "unreachable", detail: `verifier returned HTTP ${response.status}`, url };
    }

    const body = (await response.json()) as { publicKeyFingerprintSha256?: unknown };
    const advertised = body.publicKeyFingerprintSha256;
    if (typeof advertised !== "string") {
      return {
        status: "no_trust_endpoint",
        detail: "verifier /v1/trust did not report publicKeyFingerprintSha256",
        url,
      };
    }
    if (advertised.toLowerCase() !== config.trust.publicKeyFingerprintSha256) {
      return {
        status: "key_mismatch",
        detail:
          "verifier signing key does not match the key this API pins. Every attestation it " +
          `issues will fail signature verification. Verifier advertises ${advertised}, ` +
          `this API pins ${config.trust.publicKeyFingerprintSha256}. Redeploy both together.`,
        url,
      };
    }
    return { status: "ok", detail: "verifier key matches the pinned key", url };
  } catch (cause) {
    return {
      status: "unreachable",
      detail: `could not reach verifier: ${(cause as Error).message}`,
      url,
    };
  }
}

/**
 * Candidate identity as Marketplace Core defines it: chainId and tokenId only.
 *
 * Deliberately not the whole candidate object. Core rejects a set in which this
 * pair repeats, so deduplicating on anything broader (owner, publisher) would
 * keep two entries Core still considers the same candidate and the set would be
 * rejected anyway.
 */
function candidateIdentity(wire: string): { identity: string; quoteId: string } | null {
  try {
    const parsed = JSON.parse(wire) as {
      payload?: { candidate?: { chainId?: unknown; tokenId?: unknown }; quoteId?: unknown };
    };
    const candidate = parsed.payload?.candidate;
    if (candidate === undefined) return null;
    return {
      identity: `${String(candidate.chainId)}:${String(candidate.tokenId)}`,
      quoteId: String(parsed.payload?.quoteId ?? ""),
    };
  } catch {
    return null;
  }
}

function loadFixtureIndex(config: AppConfig): JsonBody {
  const dir = process.env.MANDATEX_FIXTURES_DIR?.trim() || DEFAULT_FIXTURES_DIR;
  const validDir = join(dir, "vectors", "valid");

  if (!existsSync(validDir)) {
    return {
      status: 503,
      body: {
        error: {
          code: "FIXTURES_UNAVAILABLE",
          detail:
            `no fixture vectors at ${validDir}. Run: node fixtures/attestations/lib/build.mjs, ` +
            "or set MANDATEX_FIXTURES_DIR.",
        },
      },
    };
  }

  const loaded = readdirSync(validDir)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map(
      (name) => JSON.parse(readFileSync(join(validDir, name), "utf8")) as Record<string, unknown>,
    );

  const vectors = loaded.map((vector) => ({
    name: vector.name,
    description: vector.description,
    evaluatedAt: vector.evaluatedAt,
    maxClockSkewSeconds: vector.maxClockSkewSeconds,
    wire: vector.wire,
  }));

  // Every vector is bound to the same mandate, so one copy serves the whole set.
  const mandate = loaded[0]?.mandate ?? null;

  // The valid vectors are individually valid but are NOT collectively a candidate
  // set: several are TTL-boundary variants of the same quote, and Core rejects a
  // comparison in which one candidate or quote id repeats. Posting all of them to
  // /v1/evaluate is a 422, correctly. So the ready-to-post subset is derived here
  // rather than left as a trap for the next caller.
  const seenIdentities = new Set<string>();
  const seenQuoteIds = new Set<string>();
  const comparisonSet: unknown[] = [];
  const notInComparisonSet: { name: unknown; reason: string }[] = [];

  for (const vector of vectors) {
    const key = candidateIdentity(String(vector.wire));
    if (key === null) {
      notInComparisonSet.push({ name: vector.name, reason: "candidate identity unreadable" });
      continue;
    }
    if (seenIdentities.has(key.identity)) {
      notInComparisonSet.push({
        name: vector.name,
        reason: `candidate ${key.identity} already in the set (Core rejects DUPLICATE_CANDIDATE)`,
      });
      continue;
    }
    if (seenQuoteIds.has(key.quoteId)) {
      notInComparisonSet.push({
        name: vector.name,
        reason: `quote ${key.quoteId} already in the set (Core rejects DUPLICATE_QUOTE_ID)`,
      });
      continue;
    }
    seenIdentities.add(key.identity);
    seenQuoteIds.add(key.quoteId);
    comparisonSet.push(vector.wire);
  }

  return {
    status: 200,
    body: {
      warning:
        "Development fixtures signed by a publicly-committed key. Any signature they carry is " +
        "forgeable. Never enabled in production.",
      trustPinned: config.trust.keyId,
      mandate,
      note:
        "These vectors are frozen at a fixed clock and carry a 300-second TTL, so they read as " +
        "expired against a real clock. comparisonSet is the subset that forms a valid candidate " +
        "set and can be posted to /v1/evaluate as-is.",
      comparisonSet,
      notInComparisonSet,
      count: vectors.length,
      vectors,
    },
  };
}

export interface Router {
  (request: IncomingMessage, response: ServerResponse): Promise<void>;
}

export function createRouter(config: AppConfig, evaluator: MarketplaceEvaluator): Router {
  const startedAt = Date.now();

  return async function route(request, response) {
    const method = request.method ?? "GET";
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // ── Liveness ────────────────────────────────────────────────────────────
    if (path === "/healthz" && method === "GET") {
      json(response, 200, { status: "ok", uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000) });
      return;
    }

    // ── Readiness, including lockstep key agreement ──────────────────────────
    if (path === "/readyz" && method === "GET") {
      const verifier = await probeVerifier(config);

      // Fail readiness only for conditions that make responses wrong, not for a
      // verifier that has yet to implement its trust endpoint.
      const ready = verifier.status !== "key_mismatch" && verifier.status !== "unreachable";

      json(response, ready ? 200 : 503, {
        status: ready ? "ready" : "not_ready",
        checks: {
          core: { status: "ok", detail: "Marketplace Core loaded and trust material accepted" },
          trust: {
            status: config.trustIsDevelopmentKey && config.production ? "fail" : "ok",
            keyId: config.trust.keyId,
            publicKeyFingerprintSha256: config.trust.publicKeyFingerprintSha256,
            developmentKey: config.trustIsDevelopmentKey,
          },
          verifier,
        },
      });
      return;
    }

    // ── What this API trusts ─────────────────────────────────────────────────
    if (path === "/v1/trust" && method === "GET") {
      json(response, 200, {
        keyId: config.trust.keyId,
        publicKeyFingerprintSha256: config.trust.publicKeyFingerprintSha256,
        verifierPolicySha256: config.trust.verifierPolicySha256,
        maxClockSkewSeconds: config.maxClockSkewSeconds,
        developmentKey: config.trustIsDevelopmentKey,
        ...(config.trustIsDevelopmentKey
          ? {
              warning:
                "This API pins a development key whose private half is public. Attestations it " +
                "accepts are forgeable and must not be presented as verified.",
            }
          : {}),
        note:
          "This API holds no signing key. It pins the public half of the verifier runtime's " +
          "key and checks signatures through Marketplace Core.",
      });
      return;
    }

    // ── Categories ───────────────────────────────────────────────────────────
    //
    // Reports Marketplace Core's own category policy, verbatim. This exists so
    // that no consumer has to keep a second copy of which categories are
    // evaluable.
    //
    // The UI previously hardcoded that list. That is the kind of duplication that
    // is correct on the day it is written and wrong the day Core changes, with
    // nothing to signal the drift: the interface would keep offering or refusing
    // a category on its own stale authority. Reading it from here means Core is
    // the single source of truth and the interface simply follows — including
    // following Core when it says a category is NOT supported, which is the
    // direction that actually matters.
    if (path === "/v1/categories" && method === "GET") {
      json(response, 200, {
        source: "marketplace-core",
        note:
          "Marketplace Core's category policy, reported unchanged. A category is evaluable " +
          "only when evaluationSupport is 'supported'; anything else must not be offered.",
        registeredAdapterIds: MARKETPLACE_CATEGORY_ADAPTER_IDS,
        categories: Object.fromEntries(
          Object.entries(CATEGORY_POLICIES).map(([category, policy]) => [
            category,
            {
              evaluationSupport: policy.evaluationSupport,
              // Present only when unsupported: the exact Core code a caller would
              // receive, so the interface can name the real reason rather than
              // inventing prose for it.
              //
              // A supported category reports `name` for a single adapter or
              // `names` for several. `health` has two — Aave v3 and Venus — because
              // BSC has two lending protocols with incompatible interfaces. Both
              // forms are handled rather than assuming one: collapsing them would
              // silently drop the second adapter from anything reading this.
              ...(policy.receiptAdapter.status === "unsupported"
                ? { unsupportedCode: policy.receiptAdapter.code }
                : "names" in policy.receiptAdapter
                  ? { adapters: policy.receiptAdapter.names }
                  : { adapters: [policy.receiptAdapter.name] }),
            },
          ]),
        ),
      });
      return;
    }

    // ── Evaluate ─────────────────────────────────────────────────────────────
    if (path === "/v1/evaluate" && method === "POST") {
      let raw: string;
      try {
        raw = await readBody(request, config.maxRequestBytes);
      } catch (cause) {
        if (cause instanceof PayloadTooLarge) {
          // The unread remainder of the body would wedge keep-alive, so this
          // response ends the connection rather than trying to drain it.
          response.setHeader("connection", "close");
          problem(response, 413, "PAYLOAD_TOO_LARGE", cause.message);
          return;
        }
        problem(response, 400, "BODY_UNREADABLE", (cause as Error).message);
        return;
      }

      const parsed = parseEvaluateRequest(raw);
      if (!parsed.ok) {
        problem(response, 400, "REQUEST_INVALID", parsed.detail);
        return;
      }

      const outcome = evaluator.evaluate(parsed.mandate, parsed.attestations);
      if (!outcome.ok) {
        problem(response, outcome.clientFault ? 422 : 500, outcome.code, outcome.message);
        return;
      }

      const receipt = outcome.result?.receipt as
        | { mandateId?: string; category?: string; evaluatedAt?: number }
        | undefined;

      // Core only issues a receipt when it actually evaluated something, so when
      // every attestation is rejected at verification there is no receipt and no
      // attested mandate identity. Falling back to `""` there loses the mandate id
      // exactly when the reader most needs it: a page reporting that nothing
      // qualified is not much use if it cannot say what was asked for. The
      // submitted mandate is the honest fallback, and it is clearly a different
      // thing from an attested value, so it is only read when the receipt is absent.
      const requested = parsed.mandate as
        | { mandateId?: unknown; category?: unknown }
        | null;
      const requestedText = (value: unknown): string =>
        typeof value === "string" ? value : "";

      json(
        response,
        200,
        buildComparisonView({
          result: outcome.result,
          submitted: parsed.attestations.length,
          unverified: outcome.rejected,
          mandateId: receipt?.mandateId ?? requestedText(requested?.mandateId),
          category: receipt?.category ?? requestedText(requested?.category),
          evaluatedAt: receipt?.evaluatedAt ?? Math.floor(Date.now() / 1000),
        }),
      );
      return;
    }

    // ── Development fixtures ─────────────────────────────────────────────────
    if (path === "/v1/fixtures" && method === "GET") {
      if (!config.exposeFixtures) {
        problem(
          response,
          404,
          "NOT_FOUND",
          "fixture vectors are not served in production",
        );
        return;
      }
      const loaded = loadFixtureIndex(config);
      json(response, loaded.status, loaded.body);
      return;
    }

    // ── Service description ──────────────────────────────────────────────────
    if (path === "/" && method === "GET") {
      json(response, 200, {
        service: "mandatex-marketplace-api",
        effect: "evaluation_only",
        description:
          "Verifies signed evaluation attestations from the MandateX verifier runtime and " +
          "serves display-safe quote comparisons. Performs no signing, funding, or settlement.",
        routes: {
          "GET /healthz": "liveness",
          "GET /readyz": "readiness, including verifier key agreement",
          "GET /v1/trust": "the verifier key and policy this API pins",
          "GET /v1/categories": "Marketplace Core's category policy, reported verbatim",
          "POST /v1/evaluate": "{ mandate, attestations[] } -> ranked comparison view",
          ...(config.exposeFixtures
            ? { "GET /v1/fixtures": "development attestation vectors (non-production only)" }
            : {}),
        },
      });
      return;
    }

    problem(response, 404, "NOT_FOUND", `no route for ${method} ${path}`);
  };
}
