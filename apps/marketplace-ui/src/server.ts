import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { MarketplaceApiClient, type FixtureBundle } from "./api.js";
import { render } from "./html.js";
import {
  buildMandate,
  categoryOptionsFrom,
  parseFormBody,
  type CategoryOption,
} from "./mandate.js";
import { page } from "./page.js";
import { renderComparison, renderError, renderMandateForm } from "./render.js";

/**
 * The marketplace UI server.
 *
 * `node:http` and nothing else — no framework, no bundler, no client-side build.
 * The deployed artifact is a Node process that serves strings, so there is no
 * build step that can fail at deploy time and no `npm install` between a judge
 * clicking a link and seeing a page. Every screen is rendered server-side and
 * works with JavaScript disabled.
 *
 * This process has no key, no chain access, and no database. It reads the
 * marketplace API over HTTP and renders what comes back.
 */

export interface UiConfig {
  readonly apiUrl: string;
  readonly host: string;
  readonly port: number;
  readonly maxRequestBytes: number;
  readonly production: boolean;
}

export class UiConfigError extends Error {}

/**
 * Variable names that must never be set on this process.
 *
 * The UI is the least privileged part of the system and should stay that way. It
 * is checked here for the same reason the API checks it: the guard costs nothing,
 * and a signing key reaching the one process that renders untrusted strings into a
 * document is the worst possible place for it to be.
 */
const FORBIDDEN_KEY_PATTERNS: readonly RegExp[] = [
  /SIGNING_KEY$/i,
  /PRIVATE_KEY$/i,
  /SECRET_KEY$/i,
  /SEED_HEX$/i,
  /^MNEMONIC$/i,
];

const PKCS8_ED25519 = /302e020100300506032b657004220420[0-9a-f]{64}/i;
const PEM_PRIVATE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;

export function loadUiConfig(env: NodeJS.ProcessEnv = process.env): UiConfig {
  for (const [name, value] of Object.entries(env)) {
    if (FORBIDDEN_KEY_PATTERNS.some((pattern) => pattern.test(name))) {
      throw new UiConfigError(
        `${name} must not be set on the marketplace UI. This process renders pages and ` +
          "holds no signing authority.",
      );
    }
    if (typeof value === "string" && (PKCS8_ED25519.test(value) || PEM_PRIVATE.test(value))) {
      // Checked by content as well as by name: a key pasted into an
      // innocuously-named variable is the likelier accident and survives a review
      // that only reads names.
      throw new UiConfigError(
        `${name} appears to contain private key material. The marketplace UI must not be ` +
          "given signing authority.",
      );
    }
  }

  const production = env.NODE_ENV === "production";
  const apiUrl = (env.MANDATEX_API_URL ?? "").trim().replace(/\/+$/, "");
  if (apiUrl.length === 0) {
    throw new UiConfigError(
      "MANDATEX_API_URL is required: it is the marketplace API this interface reads.",
    );
  }
  let parsed: URL;
  try {
    parsed = new URL(apiUrl);
  } catch {
    throw new UiConfigError(`MANDATEX_API_URL is not a valid URL: ${apiUrl}`);
  }
  if (production && parsed.protocol !== "https:" && !parsed.hostname.endsWith(".internal")) {
    // Same waiver as the API's verifier hop: Railway's private network does not
    // terminate TLS and `.internal` names do not resolve outside the project.
    throw new UiConfigError(
      "MANDATEX_API_URL must be https in production unless it is a *.internal " +
        `private-network address, received ${apiUrl}`,
    );
  }

  const port = Number(env.PORT ?? "8081");
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new UiConfigError(`PORT must be a valid port number, received ${String(env.PORT)}`);
  }
  const maxRequestBytes = Number(env.MANDATEX_MAX_REQUEST_BYTES ?? "1048576");
  if (!Number.isInteger(maxRequestBytes) || maxRequestBytes <= 0) {
    throw new UiConfigError("MANDATEX_MAX_REQUEST_BYTES must be a positive integer");
  }

  return {
    apiUrl,
    host: env.HOST ?? "0.0.0.0",
    port,
    maxRequestBytes,
    production,
  };
}

interface BodyResult {
  readonly ok: boolean;
  readonly body: string;
}

async function readBody(
  request: IncomingMessage,
  response: ServerResponse,
  limit: number,
): Promise<BodyResult> {
  const chunks: Buffer[] = [];
  let total = 0;
  // `destroyOnReturn: false` matters. The default async iterator destroys the
  // request stream when the loop exits early, which tears the socket down before
  // the 413 can be written — the caller then sees a dropped connection instead of
  // a status that says what was wrong.
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    total += buffer.byteLength;
    if (total > limit) {
      // The unread remainder of the body would wedge keep-alive, so this
      // response ends the connection rather than trying to drain it.
      response.setHeader("connection", "close");
      response.writeHead(413, { "content-type": "text/plain; charset=utf-8" });
      response.end("request body too large\n");
      return { ok: false, body: "" };
    }
    chunks.push(buffer);
  }
  return { ok: true, body: Buffer.concat(chunks).toString("utf8") };
}

function sendHtml(response: ServerResponse, status: number, body: string): void {
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    // The pages embed no external resources and run no inline script, so the
    // policy can be strict enough to make a successful injection inert even if
    // an escaping bug slipped through.
    //
    // `frame-ancestors` is listed explicitly because it does NOT inherit from
    // `default-src` — a policy of `default-src 'none'` leaves framing wide open.
    // These headers live here rather than in a reverse proxy so they hold however
    // this is served: behind nginx, behind Caddy, or straight off the port. A
    // header set only at the edge is a header that disappears the day the edge
    // changes.
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    // Redundant with frame-ancestors for modern browsers, kept for older ones.
    "x-frame-options": "DENY",
  });
  response.end(body);
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(`${JSON.stringify(body)}\n`);
}

export type UiRouter = (request: IncomingMessage, response: ServerResponse) => Promise<void>;

export function createUiRouter(config: UiConfig, client = new MarketplaceApiClient(config.apiUrl)): UiRouter {
  async function loadFixtures(): Promise<FixtureBundle | null> {
    const result = await client.fixtures();
    return result.ok ? result.value : null;
  }

  /**
   * Core's category policy, fetched per request rather than cached.
   *
   * Not cached on purpose. The whole point of reading this from Core is that the
   * interface tracks Core, and a cache would reintroduce exactly the staleness
   * the hardcoded table had — the category would flip in Core and the form would
   * keep showing the old answer until a restart. It is one local call against an
   * API this handler already talks to.
   *
   * On failure it returns undefined, and `categoryOptionsFrom` falls back to the
   * conservative list that offers only rebalancing.
   */
  async function loadCategoryOptions(): Promise<readonly CategoryOption[]> {
    const result = await client.categories();
    return categoryOptionsFrom(result.ok ? result.value : undefined);
  }

  return async function route(request, response): Promise<void> {
    const url = new URL(request.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = request.method ?? "GET";

    if (path === "/healthz" && method === "GET") {
      sendJson(response, 200, { status: "ok", api: config.apiUrl, effect: "evaluation_only" });
      return;
    }

    if (path === "/readyz" && method === "GET") {
      // Ready means "the API this UI reads is answering". A UI that renders a
      // form it cannot submit is not ready, and reporting it as ready would make
      // an API outage look like a UI bug.
      const ready = await client.readyz();
      sendJson(response, ready.ok ? 200 : 503, {
        status: ready.ok ? "ready" : "degraded",
        api: config.apiUrl,
        detail: ready.ok ? undefined : ready.detail,
      });
      return;
    }

    if (path === "/" && method === "GET") {
      const fixtures = await loadFixtures();
      sendHtml(
        response,
        200,
        page({
          title: "Mandate | MandateX",
          body: renderMandateForm({
            categoryOptions: await loadCategoryOptions(),
            mandate: fixtures?.mandate ?? null,
            attestationCount: fixtures?.comparisonSet.length ?? 0,
            apiBase: config.apiUrl,
            fixturesAvailable: fixtures !== null,
            ...(fixtures === null ? {} : { fixtureWarning: fixtures.warning }),
          }),
        }),
      );
      return;
    }

    if (path === "/evaluate" && method === "POST") {
      const body = await readBody(request, response, config.maxRequestBytes);
      if (!body.ok) return;

      const fixtures = await loadFixtures();
      if (fixtures === null) {
        sendHtml(
          response,
          503,
          page({
            title: "Unavailable | MandateX",
            body: renderError({
              heading: "No candidate attestations are available",
              detail:
                "This interface submits attestations issued by the verifier; it cannot mint " +
                "them. The marketplace API is not serving development fixtures, which is " +
                "correct in production, so there is nothing to evaluate.",
              apiBase: config.apiUrl,
            }),
          }),
        );
        return;
      }

      const form = parseFormBody(body.body);
      const built = buildMandate(fixtures.mandate, form, await loadCategoryOptions());
      const evaluated = await client.evaluate({
        mandate: built.mandate,
        attestations: fixtures.comparisonSet,
      });

      if (!evaluated.ok) {
        // The API's own code and message are preserved. A 422
        // DUPLICATE_CANDIDATE is a precise answer, and replacing it with
        // "something went wrong" would discard the only useful part.
        sendHtml(
          response,
          evaluated.status === 0 ? 502 : evaluated.status,
          page({
            title: "Not evaluated | MandateX",
            body: renderError({
              heading: "The marketplace API did not evaluate this mandate",
              detail: evaluated.detail,
              apiBase: config.apiUrl,
            }),
          }),
        );
        return;
      }

      sendHtml(
        response,
        200,
        page({
          title: "Comparison | MandateX",
          body: renderComparison({
            view: evaluated.value,
            mandate: built.mandate,
            problems: built.problems,
          }),
        }),
      );
      return;
    }

    if (path === "/evaluate" && method === "GET") {
      // A refresh after POST would otherwise 404. Send the user back to the form
      // rather than re-running an evaluation whose verdicts are clock-dependent.
      response.writeHead(303, { location: "/" });
      response.end();
      return;
    }

    sendHtml(
      response,
      404,
      page({
        title: "Not found | MandateX",
        body: renderError({
          heading: "No such page",
          detail: `${method} ${path} is not a route this interface serves.`,
          apiBase: config.apiUrl,
        }),
      }),
    );
  };
}

export function createUiServer(config: UiConfig, client?: MarketplaceApiClient): Server {
  const router = createUiRouter(config, client);
  return createServer((request, response) => {
    void router(request, response).catch(() => {
      if (!response.headersSent) {
        sendHtml(
          response,
          500,
          page({
            title: "Error | MandateX",
            body: renderError({
              heading: "The interface failed to render this page",
              detail: "No detail is reported here, deliberately, because it is not attributable to the request.",
              apiBase: config.apiUrl,
            }),
          }),
        );
        return;
      }
      response.destroy();
    });
  });
}

/** Exported for the smoke suite, which renders pages without a socket. */
export { page, render };

const isEntryPoint =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;

if (isEntryPoint) {
  let config: UiConfig;
  try {
    config = loadUiConfig();
  } catch (cause) {
    process.stderr.write(`${(cause as Error).message}\n`);
    // 78 is EX_CONFIG, matching both sibling services: a misconfigured trust
    // surface should stop the process rather than degrade quietly.
    process.exit(78);
  }

  const server = createUiServer(config);
  server.listen(config.port, config.host, () => {
    const address = server.address();
    // Log the *bound* address, not the requested one. With PORT=0 the requested
    // value is 0, and a log line that says 0 is worse than no log line.
    process.stdout.write(
      `${JSON.stringify({
        level: "info",
        message: "listening",
        host: typeof address === "object" && address !== null ? address.address : config.host,
        port: typeof address === "object" && address !== null ? address.port : config.port,
        api: config.apiUrl,
        effect: "evaluation_only",
      })}\n`,
    );
  });

  const shutdown = (signal: string): void => {
    process.stdout.write(`${JSON.stringify({ level: "info", message: "closing", signal })}\n`);
    server.close(() => {
      process.stdout.write(`${JSON.stringify({ level: "info", message: "closed cleanly" })}\n`);
      process.exit(0);
    });
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
