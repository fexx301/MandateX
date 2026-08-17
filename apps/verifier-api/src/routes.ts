// HTTP routes for the verifier.
//
// Same node:http-only posture as the marketplace app, and here the argument is
// stronger: this process holds the signing key, so every dependency added is a
// dependency with access to it.
//
// The single most important rule in this file: NOTHING in any response may
// contain private key material. `GET /v1/trust` exists to publish the PUBLIC
// half, and `assertNoSecretLeak` checks every serialized body against the actual
// configured secret before it is written to the socket. That check is cheap and
// it is the difference between a bug and a catastrophe.

import type { IncomingMessage, ServerResponse } from "node:http";

import { signingKeyPkcs8Der, type VerifierConfig } from "./config.js";
import type { Verifier } from "./runtime.js";

/** Hex of the raw secret, held only to check that it never appears in a response. */
let secretNeedles: readonly string[] = [];

/**
 * Record the secret's serializations so responses can be checked against them.
 *
 * Deliberately derived from the configured key rather than from a pattern: a
 * regex for "things that look like keys" would both miss encodings and produce
 * false positives, whereas an exact match on this deployment's actual secret is
 * precise. The seed is checked as well as the full PKCS#8 form, because the seed
 * is the part that is sufficient to forge signatures.
 */
export function armSecretLeakCheck(config: VerifierConfig): void {
  const pkcs8 = Buffer.from(signingKeyPkcs8Der(config));
  const pkcs8Hex = pkcs8.toString("hex");
  const seedHex = pkcs8Hex.slice(-64);
  secretNeedles = Object.freeze([
    pkcs8Hex,
    pkcs8.toString("base64"),
    seedHex,
    Buffer.from(seedHex, "hex").toString("base64"),
  ]);
}

class SecretLeak extends Error {
  constructor(readonly route: string) {
    super(
      `response for ${route} contained signing key material and was blocked. ` +
        "This is a bug in the verifier, not a configuration problem.",
    );
    this.name = "SecretLeak";
  }
}

function assertNoSecretLeak(payload: string, route: string): void {
  const haystack = payload.toLowerCase();
  for (const needle of secretNeedles) {
    if (needle.length > 0 && haystack.includes(needle.toLowerCase())) {
      throw new SecretLeak(route);
    }
  }
}

function json(response: ServerResponse, route: string, status: number, body: unknown): void {
  const payload = JSON.stringify(body, null, 2);
  assertNoSecretLeak(payload, route);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  response.end(payload);
}

function problem(
  response: ServerResponse,
  route: string,
  status: number,
  code: string,
  detail: string,
): void {
  json(response, route, status, { error: { code, detail } });
}

class PayloadTooLarge extends Error {
  constructor(readonly maxBytes: number) {
    super(`request body exceeds ${maxBytes} bytes`);
    this.name = "PayloadTooLarge";
  }
}

async function readBody(request: IncomingMessage, maxBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  // `destroyOnReturn: false` matters. The default async iterator destroys the
  // request stream when the loop exits early, which tears the socket down before
  // the 413 can be written — the caller then sees a dropped connection instead of
  // a status that says what was wrong. Reading stops either way; only the teardown
  // is deferred to the response.
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

export interface Router {
  (request: IncomingMessage, response: ServerResponse): Promise<void>;
}

export function createRouter(config: VerifierConfig, verifier: Verifier): Router {
  const startedAt = Date.now();

  return async function route(request, response) {
    const method = request.method ?? "GET";
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // ── Liveness ────────────────────────────────────────────────────────────
    if (path === "/healthz" && method === "GET") {
      json(response, path, 200, {
        status: "ok",
        uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
        canEvaluate: verifier.canEvaluate,
      });
      return;
    }

    // ── Readiness ────────────────────────────────────────────────────────────
    // Signing identity is the readiness condition, NOT the presence of a
    // configured agent. A verifier with a valid key and no agent is correctly
    // deployed and half-configured; a verifier that cannot sign is broken.
    if (path === "/readyz" && method === "GET") {
      json(response, path, 200, {
        status: "ready",
        checks: {
          signingKey: {
            status: "ok",
            keyId: config.keyId,
            developmentKey: config.keyIsDevelopmentKey,
          },
          evaluation: {
            status: verifier.canEvaluate ? "ok" : "not_configured",
            detail: verifier.runtimeDetail,
          },
        },
      });
      return;
    }

    // ── Trust identity: the lockstep mechanism ───────────────────────────────
    // The marketplace app polls this and compares publicKeyFingerprintSha256
    // against the key it pins, returning 503 on mismatch. That comparison is how
    // the v2 contract's "prove lockstep redeploy" requirement is satisfied, so
    // this route is the reason the verifier is deployable before it can evaluate
    // anything.
    if (path === "/v1/trust" && method === "GET") {
      json(response, path, 200, {
        keyId: config.keyId,
        publicKeySpkiDerHex: config.publicKeySpkiDerHex,
        publicKeyFingerprintSha256: config.publicKeyFingerprintSha256,
        verifierPolicySha256: verifier.policySha256,
        developmentKey: config.keyIsDevelopmentKey,
        ...(config.keyIsDevelopmentKey
          ? {
              warning:
                "This verifier signs with a development key whose private half is public. " +
                "Attestations it issues are forgeable and must not be presented as verified.",
            }
          : {}),
        note:
          "Public trust material only. Pin these values in the marketplace app; it compares " +
          "publicKeyFingerprintSha256 against its pin on every readiness check.",
      });
      return;
    }

    // ── Evaluate and attest ──────────────────────────────────────────────────
    if (path === "/v1/evaluate" && method === "POST") {
      let raw: string;
      try {
        raw = await readBody(request, config.maxRequestBytes);
      } catch (cause) {
        if (cause instanceof PayloadTooLarge) {
          // The unread remainder of the body would wedge keep-alive, so this
          // response ends the connection rather than trying to drain it.
          response.setHeader("connection", "close");
          problem(response, path, 413, "PAYLOAD_TOO_LARGE", cause.message);
          return;
        }
        problem(response, path, 400, "BODY_UNREADABLE", (cause as Error).message);
        return;
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (cause) {
        problem(response, path, 400, "REQUEST_INVALID", `body is not valid JSON: ${(cause as Error).message}`);
        return;
      }

      const outcome = await verifier.evaluate(parsed);

      if (!outcome.ok) {
        const status =
          outcome.code === "VERIFIER_NOT_CONFIGURED" ? 503 : outcome.clientFault ? 422 : 500;
        problem(response, path, status, outcome.code, outcome.message);
        return;
      }

      if (outcome.result.outcome === "not_attested") {
        // 200, not an error status. The verifier worked; the candidate did not
        // qualify, and that is a result the caller asked for.
        json(response, path, 200, {
          outcome: "not_attested",
          detail: "the candidate did not pass verification, so no attestation was issued",
          verifierResult: outcome.result.verifierResult,
        });
        return;
      }

      // `wire` is the exact signed text. It is returned as a JSON *string* so it
      // survives transport byte-for-byte. Re-serializing the parsed attestation
      // instead would repair canonical-encoding defects silently and could turn a
      // rejection into a false acceptance downstream.
      json(response, path, 200, {
        outcome: "attested",
        wire: outcome.result.wire,
        keyId: config.keyId,
        publicKeyFingerprintSha256: config.publicKeyFingerprintSha256,
        note:
          "Pass `wire` to the marketplace API verbatim. Do not parse and re-serialize it: " +
          "canonical encoding is part of what the signature covers.",
      });
      return;
    }

    // ── Service description ──────────────────────────────────────────────────
    if (path === "/" && method === "GET") {
      json(response, path, 200, {
        service: "mandatex-verifier",
        role: "signer",
        description:
          "Evaluates candidate agents over a pinned HTTPS transport and issues Ed25519-signed " +
          "evaluation attestations. Holds the signing key. Performs no funding or settlement.",
        canEvaluate: verifier.canEvaluate,
        routes: {
          "GET /healthz": "liveness",
          "GET /readyz": "readiness",
          "GET /v1/trust": "public trust material for the marketplace app to pin",
          "POST /v1/evaluate": "evaluate a candidate and issue a signed attestation",
        },
      });
      return;
    }

    problem(response, path, 404, "NOT_FOUND", `no route for ${method} ${path}`);
  };
}

export { SecretLeak };
