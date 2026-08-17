// Verifier server entry point.
//
// Mirrors apps/marketplace-api/src/server.ts, with one addition that matters:
// nothing here logs the configured environment. The marketplace app can safely
// log its whole trust configuration because all of it is public; this process
// cannot, because one of its variables is a signing key. So the boot log names
// the key by ID and fingerprint only.

import { createServer } from "node:http";

import { ConfigError, loadConfig } from "./config.js";
import { armSecretLeakCheck, createRouter, SecretLeak } from "./routes.js";
import { Verifier } from "./runtime.js";

const SHUTDOWN_GRACE_MS = 10_000;
const REQUEST_TIMEOUT_MS = 30_000;

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
      log("error", "refusing to start", { reason: cause.message });
      process.exit(78); // EX_CONFIG
    }
    throw cause;
  }

  // Arm the response leak check before any route can run.
  armSecretLeakCheck(config);

  let verifier: Verifier;
  try {
    verifier = Verifier.create(config);
  } catch (cause) {
    log("error", "refusing to start: verifier configuration was rejected", {
      reason: (cause as Error).message,
      code: (cause as { code?: string }).code ?? null,
    });
    process.exit(78);
  }

  if (config.keyIsDevelopmentKey) {
    log("warn", "signing with a development key: every attestation issued is forgeable", {
      keyId: config.keyId,
    });
  }
  if (!verifier.canEvaluate) {
    log("warn", "no agent configured; POST /v1/evaluate will return 503", {
      detail: verifier.runtimeDetail,
    });
  }

  const router = createRouter(config, verifier);

  const server = createServer((request, response) => {
    void router(request, response).catch((cause: unknown) => {
      // A blocked leak is logged at error and returns 500 without detail. The
      // detail is exactly what must not be echoed.
      if (cause instanceof SecretLeak) {
        log("error", "BLOCKED a response containing signing key material", {
          route: cause.route,
        });
      } else {
        log("error", "unhandled request failure", {
          method: request.method,
          url: request.url,
          reason: (cause as Error).message,
        });
      }
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
    // The bound address, not the configured one: with PORT=0 the OS chooses the
    // port, and logging the requested value would report 0 and leave nothing that
    // says where the service actually is.
    const address = server.address();
    log("info", "listening", {
      host: typeof address === "object" && address !== null ? address.address : config.host,
      port: typeof address === "object" && address !== null ? address.port : config.port,
      production: config.production,
      keyId: config.keyId,
      publicKeyFingerprintSha256: config.publicKeyFingerprintSha256,
      canEvaluate: verifier.canEvaluate,
      verifierPolicySha256: verifier.policySha256,
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
