// Smoke checks for the verifier service.
//
// Boots the real server on an ephemeral port and drives it over HTTP. Nothing is
// mocked: the signing key is loaded through the real config path, the trust
// identity is derived from the real key, and the fingerprint is checked against
// the fixture trust file that the marketplace app pins — so a drift between the
// two services fails here rather than in a deployed readiness probe.

import { spawn, type ChildProcess } from "node:child_process";
import { createHash, createPrivateKey, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const SERVER = join(HERE, "server.js");
const TRUST_FILE = join(REPO_ROOT, "fixtures", "attestations", "keys", "dev-signer.public.json");

/** RFC 8032 test vector 1, the same seed fixtures/attestations/lib/signer.mjs uses. */
const FIXTURE_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) {
    passed += 1;
    console.log(`  ✓ ${name}`);
  } else {
    failed += 1;
    failures.push(name);
    console.log(`  ✗ ${name}${detail === "" ? "" : ` — ${detail}`}`);
  }
}

function group(name: string): void {
  console.log(`\n${name}`);
}

interface BootResult {
  readonly code: number | null;
  readonly stderr: string;
  readonly stdout: string;
}

/** Run the server to completion, for the cases where it must refuse to start. */
function bootExpectingExit(env: NodeJS.ProcessEnv): Promise<BootResult> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SERVER], {
      env: { PATH: process.env.PATH ?? "", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("exit", (code) => resolve({ code, stderr, stdout }));
    // A server that wrongly starts would hang this promise, so bound it.
    setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ code: null, stderr, stdout });
    }, 10_000).unref();
  });
}

interface RunningServer {
  readonly base: string;
  readonly child: ChildProcess;
  readonly stop: () => Promise<number | null>;
}

/** Boot the server and wait until it reports the port it bound. */
async function boot(env: NodeJS.ProcessEnv): Promise<RunningServer> {
  const child = spawn(process.execPath, [SERVER], {
    env: { PATH: process.env.PATH ?? "", PORT: "0", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stdout = "";
  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server did not start: ${stdout}`)), 15_000);
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
      for (const line of stdout.split("\n")) {
        if (line.trim() === "") continue;
        try {
          const parsed = JSON.parse(line) as { message?: string; port?: number };
          if (parsed.message === "listening" && typeof parsed.port === "number") {
            clearTimeout(timer);
            // Reject 0 explicitly: it means the server logged its *requested*
            // port rather than the bound one, which produces an obscure
            // EADDRNOTAVAIL several lines later instead of naming the cause.
            if (parsed.port === 0) {
              reject(new Error("server logged port 0; it must log the bound port, not config.port"));
              return;
            }
            resolve(parsed.port);
            return;
          }
        } catch {
          // Partial line; wait for more.
        }
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited ${code}: ${stdout}`));
    });
  });

  // PORT=0 lets the OS choose, so the log line is the only source of truth.
  return {
    base: `http://127.0.0.1:${port}`,
    child,
    stop: () =>
      new Promise((resolve) => {
        child.on("exit", (code) => resolve(code));
        child.kill("SIGTERM");
      }),
  };
}

function fixtureEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    MANDATEX_SIGNING_KEY_ID: "fixture-insecure-do-not-deploy-1",
    MANDATEX_SIGNING_KEY: FIXTURE_SEED_HEX,
    ...extra,
  };
}

/** A throwaway real key, for the production-posture checks. */
function productionEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const { privateKey } = generateKeyPairSync("ed25519");
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  return {
    NODE_ENV: "production",
    MANDATEX_SIGNING_KEY_ID: "mandatex-verifier-1",
    MANDATEX_SIGNING_KEY: Buffer.from(pkcs8).toString("hex"),
    ...extra,
  };
}

async function main(): Promise<void> {
  console.log("Verifier API smoke checks\n" + "=".repeat(70));

  // ── Boot guards ───────────────────────────────────────────────────────────
  group("Boot guards");

  {
    const result = await bootExpectingExit({});
    check(
      "refuses to start with no signing key configured",
      result.code === 78 && result.stderr.includes("MANDATEX_SIGNING_KEY_ID is required"),
      `code=${result.code}`,
    );
  }

  {
    const result = await bootExpectingExit({ MANDATEX_SIGNING_KEY_ID: "k1" });
    check(
      "refuses to start with a key id but no key",
      result.code === 78 && result.stderr.includes("MANDATEX_SIGNING_KEY is required"),
      `code=${result.code}`,
    );
  }

  {
    const result = await bootExpectingExit({
      MANDATEX_SIGNING_KEY_ID: "k1",
      MANDATEX_SIGNING_KEY: "not-a-key",
    });
    check(
      "refuses to start on unusable key material, without echoing it",
      result.code === 78 &&
        result.stderr.includes("must be an Ed25519 private key") &&
        !result.stderr.includes("not-a-key"),
      `code=${result.code}`,
    );
  }

  {
    // The decisive production guard: the fixture key's private half is committed.
    const result = await bootExpectingExit(fixtureEnv({ NODE_ENV: "production" }));
    check(
      "refuses the publicly-committed fixture key under NODE_ENV=production",
      result.code === 78 && result.stderr.includes("publicly-committed fixture key"),
      `code=${result.code}`,
    );
  }

  {
    // Recognising the key material means a rename cannot smuggle it in.
    const result = await bootExpectingExit({
      NODE_ENV: "production",
      MANDATEX_SIGNING_KEY_ID: "mandatex-verifier-prod-1",
      MANDATEX_SIGNING_KEY: FIXTURE_SEED_HEX,
    });
    check(
      "refuses the fixture key in production even under an innocuous key id",
      result.code === 78 && result.stderr.includes("publicly-committed fixture key"),
      `code=${result.code}`,
    );
  }

  {
    const result = await bootExpectingExit(
      productionEnv({ MANDATEX_SIGNING_KEY_ID: "dev-verifier-1" }),
    );
    check(
      "refuses a development-marked key id under production",
      result.code === 78 && result.stderr.includes("development-only"),
      `code=${result.code}`,
    );
  }

  {
    const result = await bootExpectingExit(
      fixtureEnv({ MANDATEX_VERIFIER_POLICY_SHA256: "nothex" }),
    );
    check(
      "refuses a malformed pinned policy hash",
      result.code === 78 && result.stderr.includes("64 lowercase hex"),
      `code=${result.code}`,
    );
  }

  // ── Trust identity, the lockstep mechanism ────────────────────────────────
  group("Trust identity");

  const trustFile = JSON.parse(readFileSync(TRUST_FILE, "utf8")) as {
    keyId: string;
    publicKeySpkiDerHex: string;
    publicKeyFingerprintSha256: string;
  };

  const server = await boot(fixtureEnv());
  try {
    const trust = (await (await fetch(`${server.base}/v1/trust`)).json()) as Record<string, unknown>;

    check(
      "GET /v1/trust reports the key id it was configured with",
      trust.keyId === "fixture-insecure-do-not-deploy-1",
      String(trust.keyId),
    );
    check(
      "derived public key matches fixtures/attestations/keys/dev-signer.public.json",
      trust.publicKeySpkiDerHex === trustFile.publicKeySpkiDerHex,
      `got ${String(trust.publicKeySpkiDerHex)}`,
    );
    check(
      "derived fingerprint matches the key the marketplace app pins",
      trust.publicKeyFingerprintSha256 === trustFile.publicKeyFingerprintSha256,
      `got ${String(trust.publicKeyFingerprintSha256)}`,
    );
    check(
      "fingerprint is genuinely sha256 of the published SPKI DER",
      trust.publicKeyFingerprintSha256 ===
        createHash("sha256")
          .update(Buffer.from(String(trust.publicKeySpkiDerHex), "hex"))
          .digest("hex"),
    );
    check("a development key is flagged as such", trust.developmentKey === true);
    check(
      "a development key carries an explicit forgeability warning",
      typeof trust.warning === "string" && trust.warning.includes("forgeable"),
    );

    // ── The secret must never appear in any response ────────────────────────
    group("Signing key containment");

    const pkcs8Hex = Buffer.from(
      createPrivateKey({
        key: Buffer.from("302e020100300506032b657004220420" + FIXTURE_SEED_HEX, "hex"),
        format: "der",
        type: "pkcs8",
      }).export({ type: "pkcs8", format: "der" }),
    ).toString("hex");

    const bodies: string[] = [];
    for (const path of ["/", "/healthz", "/readyz", "/v1/trust", "/v1/nope"]) {
      bodies.push(await (await fetch(`${server.base}${path}`)).text());
    }
    const joined = bodies.join("\n").toLowerCase();

    check("no response contains the raw seed", !joined.includes(FIXTURE_SEED_HEX));
    check("no response contains the PKCS#8 DER form", !joined.includes(pkcs8Hex));
    check(
      "no response contains the base64 seed",
      !joined.includes(Buffer.from(FIXTURE_SEED_HEX, "hex").toString("base64").toLowerCase()),
    );
    check(
      "the public key IS published, so containment is not just an empty response",
      joined.includes(trustFile.publicKeySpkiDerHex.toLowerCase()),
    );

    // ── Unconfigured evaluation ─────────────────────────────────────────────
    group("Evaluation without a configured agent");

    check("GET /healthz reports canEvaluate=false", await healthCanEvaluate(server.base) === false);

    {
      const response = await fetch(`${server.base}/v1/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ request: {} }),
      });
      const body = (await response.json()) as { error?: { code?: string; detail?: string } };
      check(
        "POST /v1/evaluate is 503 VERIFIER_NOT_CONFIGURED, not a 500",
        response.status === 503 && body.error?.code === "VERIFIER_NOT_CONFIGURED",
        `HTTP ${response.status} ${body.error?.code ?? ""}`,
      );
      check(
        "the 503 explains what to populate",
        (body.error?.detail ?? "").includes("MANDATEX_VERIFIER_CONFIG_DIR"),
      );
    }

    {
      const response = await fetch(`${server.base}/v1/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{not json",
      });
      check("malformed JSON is a 400", response.status === 400);
    }

    // ── Readiness posture ───────────────────────────────────────────────────
    group("Readiness");

    const ready = await fetch(`${server.base}/readyz`);
    const readyBody = (await ready.json()) as {
      status?: string;
      checks?: { evaluation?: { status?: string } };
    };
    check(
      "an unconfigured verifier is still READY, because it can sign",
      ready.status === 200 && readyBody.status === "ready",
      `HTTP ${ready.status}`,
    );
    check(
      "readiness distinguishes signing from evaluation",
      readyBody.checks?.evaluation?.status === "not_configured",
    );
  } finally {
    const code = await server.stop();
    group("Shutdown");
    check("SIGTERM exits 0 rather than being killed", code === 0, `code=${code}`);
  }

  // ── Request limits ────────────────────────────────────────────────────────
  // Booted with a deliberately tiny cap, so the rejection can only come from the
  // byte limit and not from a downstream parse failure.
  group("Request limits");
  const capped = await boot(fixtureEnv({ MANDATEX_MAX_REQUEST_BYTES: "16" }));
  try {
    const response = await fetch(`${capped.base}/v1/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ request: { padding: "x".repeat(4096) } }),
    });
    const body = (await response.json()) as { error?: { code?: string } };
    check(
      "a body over MANDATEX_MAX_REQUEST_BYTES is 413, refused before parsing",
      response.status === 413 && body.error?.code === "PAYLOAD_TOO_LARGE",
      `HTTP ${response.status} ${body.error?.code ?? ""}`,
    );
  } finally {
    await capped.stop();
  }

  // ── Production posture with a real key ────────────────────────────────────
  group("Production posture");
  const prod = await boot(productionEnv());
  try {
    const trust = (await (await fetch(`${prod.base}/v1/trust`)).json()) as Record<string, unknown>;
    check("a real key is not flagged as a development key", trust.developmentKey === false);
    check("no forgeability warning is attached to a real key", trust.warning === undefined);
    check(
      "production still publishes a usable fingerprint for the app to pin",
      typeof trust.publicKeyFingerprintSha256 === "string" &&
        /^[a-f0-9]{64}$/.test(String(trust.publicKeyFingerprintSha256)),
    );
  } finally {
    await prod.stop();
  }

  console.log("\n" + "-".repeat(70));
  console.log(`passed: ${passed}   failed: ${failed}`);
  if (failed > 0) {
    console.log("\nfailed checks:");
    for (const name of failures) console.log(`  - ${name}`);
    process.exit(1);
  }
  console.log("\nAll checks passed: the verifier signs, publishes its identity, and leaks nothing.");
}

async function healthCanEvaluate(base: string): Promise<boolean> {
  const body = (await (await fetch(`${base}/healthz`)).json()) as { canEvaluate?: boolean };
  return body.canEvaluate === true;
}

await main();
