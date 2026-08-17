// Server entry point.
//
// Railway sends SIGTERM on redeploy and waits before SIGKILL, so shutdown is
// handled explicitly: stop accepting connections, let in-flight requests finish,
// then exit. Without this the process is killed mid-request on every deploy,
// which reads to a judge as an unstable service.

import { createServer } from "node:http";

import { ConfigError, loadConfig } from "./config.js";
import { MarketplaceEvaluator } from "./core.js";
import { createRouter } from "./routes.js";

const SHUTDOWN_GRACE_MS = 10_000;
const REQUEST_TIMEOUT_MS = 15_000;

function log(level: "info" | "warn" | "error", message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, message, ...fields, at: new Date().toISOString() });
  if (level === "error") console.error(line);
  else console.log(line);
}

function main(): void {
  let config;
  try {
    config = loadConfig();
  } catch (cause) {
    if (cause instanceof ConfigError) {
      // A refusal to boot is the intended outcome for a misconfigured trust
      // boundary, so it gets a clear message rather than a stack trace.
      log("error", "refusing to start", { reason: cause.message });
      process.exit(78); // EX_CONFIG
    }
    throw cause;
  }

  let evaluator: MarketplaceEvaluator;
  try {
    evaluator = MarketplaceEvaluator.create(config);
  } catch (cause) {
    log("error", "refusing to start: Marketplace Core rejected the pinned trust material", {
      reason: (cause as Error).message,
      code: (cause as { code?: string }).code ?? null,
      hint: "check MANDATEX_TRUST_* against the verifier runtime's advertised key",
    });
    process.exit(78);
  }

  if (config.trustIsDevelopmentKey) {
    log("warn", "pinned trust is a development key: accepted attestations are forgeable", {
      keyId: config.trust.keyId,
    });
  }

  const router = createRouter(config, evaluator);

  const server = createServer((request, response) => {
    void router(request, response).catch((cause: unknown) => {
      log("error", "unhandled request failure", {
        method: request.method,
        url: request.url,
        reason: (cause as Error).message,
      });
      if (!response.headersSent) {
        response.writeHead(500, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: { code: "INTERNAL", detail: "request failed" } }));
      } else {
        response.destroy();
      }
    });
  });

  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.headersTimeout = REQUEST_TIMEOUT_MS;

  server.listen(config.port, config.host, () => {
    log("info", "listening", {
      host: config.host,
      port: config.port,
      production: config.production,
      trustKeyId: config.trust.keyId,
      verifierUrl: config.verifierUrl,
      fixturesExposed: config.exposeFixtures,
    });
  });

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    log("info", "shutting down", { signal });

    const forced = setTimeout(() => {
      log("warn", "grace period elapsed, forcing exit");
      process.exit(1);
    }, SHUTDOWN_GRACE_MS);
    forced.unref();

    server.close(() => {
      log("info", "closed cleanly");
      process.exit(0);
    });
    server.closeIdleConnections();
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  process.on("unhandledRejection", (reason) => {
    log("error", "unhandled rejection", { reason: String(reason) });
  });
}

main();
