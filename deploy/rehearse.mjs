#!/usr/bin/env node
// Two-service deployment rehearsal.
//
// Boots the real verifier and the real marketplace API as separate OS processes,
// on ephemeral ports, and checks the trust boundary between them. This is the
// local stand-in for the Railway pair, and it exists to answer one question that
// no single-process test can: is the pinned key actually load-bearing?
//
// A test where one process both signs and verifies proves nothing, because every
// signature it checked is one it could have produced. So the arrangement here is
// deliberately asymmetric and the negative cases are the point:
//
//   1. verifier publishes a key      → app pins what it published  → /readyz 200
//   2. verifier publishes a key      → app pins a DIFFERENT key     → /readyz 503
//   3. verifier is not running       → app cannot check agreement   → /readyz 503
//   4. app is handed a signing key   → app refuses to boot          → exit 78
//   5. verifier is handed no key     → verifier refuses to boot     → exit 78
//
// Case 2 is the one that matters most. If it returned 200 the pin would be
// decorative, and the two-service split would be theatre.
//
// Usage:  node deploy/rehearse.mjs
// Requires both apps built:  (cd apps/verifier-api && corepack pnpm build) etc.

import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VERIFIER_ENTRY = join(REPO_ROOT, "apps", "verifier-api", "dist", "server.js");
const APP_ENTRY = join(REPO_ROOT, "apps", "marketplace-api", "dist", "server.js");

/** The committed fixture seed. Safe to use here; refused under NODE_ENV=production. */
const FIXTURE_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/**
 * The policy hash the fixture attestations declare.
 *
 * The app requires a pinned policy hash at boot, and the verifier can only derive
 * one once a real artifact set is present — so during the rehearsal the two cannot
 * learn it from each other. Taking it from the vectors keeps the rehearsal honest:
 * it is the value the attestations under test were actually signed under, so the
 * evaluate step exercises a real policy-identity match rather than a placeholder.
 *
 * This is a genuine ordering constraint on the first production deploy, not just a
 * test detail; see deploy/README.md.
 */
const FIXTURE_POLICY_SHA256 = "2ce16c724b5e109338301048513e7f31a2216d69f7b01f47512d2c5f4ff7b2a8";

let passed = 0;
const failures = [];

function check(name, condition, detail = "") {
  if (condition) {
    passed += 1;
    console.log(`  ✓ ${name}`);
  } else {
    failures.push(name);
    console.log(`  ✗ ${name}${detail === "" ? "" : ` — ${detail}`}`);
  }
}

function group(name) {
  console.log(`\n${name}`);
}

/** Boot a service on an ephemeral port and resolve once it logs the bound port. */
function boot(entry, env, label) {
  const child = spawn(process.execPath, [entry], {
    env: { PATH: process.env.PATH ?? "", PORT: "0", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d.toString()));

  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`${label} did not start within 15s\n${stdout}\n${stderr}`)),
      15_000,
    );
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      for (const line of stdout.split("\n")) {
        if (line.trim() === "") continue;
        let parsed;
        try {
          parsed = JSON.parse(line);
        } catch {
          continue;
        }
        if (parsed.message === "listening" && typeof parsed.port === "number" && parsed.port > 0) {
          clearTimeout(timer);
          resolve(parsed.port);
          return;
        }
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`${label} exited ${code}\n${stderr}`));
    });
  });

  return ready.then((port) => ({
    base: `http://127.0.0.1:${port}`,
    port,
    stderr: () => stderr,
    stop: () =>
      new Promise((resolve) => {
        child.on("exit", (code) => resolve(code));
        child.kill("SIGTERM");
      }),
  }));
}

/** Run a service expecting it to refuse to start, and return how it refused. */
function bootExpectingRefusal(entry, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [entry], {
      env: { PATH: process.env.PATH ?? "", PORT: "0", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("exit", (code) => resolve({ code, stderr }));
    setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ code: null, stderr });
    }, 10_000).unref();
  });
}

async function getJson(url) {
  const response = await fetch(url, { headers: { accept: "application/json" } });
  return { status: response.status, body: await response.json() };
}

/** A port nothing is listening on, for the unreachable-verifier case. */
async function closedPort() {
  const { createServer } = await import("node:net");
  return new Promise((resolve) => {
    const probe = createServer();
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

async function main() {
  console.log("MandateX two-service deployment rehearsal\n" + "=".repeat(70));

  for (const [label, entry] of [
    ["verifier-api", VERIFIER_ENTRY],
    ["marketplace-api", APP_ENTRY],
  ]) {
    if (!existsSync(entry)) {
      console.error(
        `\n${label} is not built: ${entry} does not exist.\n` +
          `Run:  cd apps/${label} && corepack pnpm install && corepack pnpm build`,
      );
      process.exit(1);
    }
  }

  // ── The verifier comes up first and declares its identity ──────────────────
  group("Verifier declares its signing identity");

  const verifier = await boot(
    VERIFIER_ENTRY,
    {
      MANDATEX_SIGNING_KEY_ID: "fixture-insecure-do-not-deploy-1",
      MANDATEX_SIGNING_KEY: FIXTURE_SEED_HEX,
    },
    "verifier-api",
  );

  try {
    const trust = await getJson(`${verifier.base}/v1/trust`);
    check("GET /v1/trust is 200", trust.status === 200, `HTTP ${trust.status}`);
    check(
      "it advertises a public key fingerprint for the app to pin",
      /^[a-f0-9]{64}$/.test(trust.body.publicKeyFingerprintSha256 ?? ""),
      String(trust.body.publicKeyFingerprintSha256),
    );
    check(
      "the fingerprint is sha256 of the advertised SPKI DER, not an unrelated value",
      trust.body.publicKeyFingerprintSha256 ===
        createHash("sha256")
          .update(Buffer.from(trust.body.publicKeySpkiDerHex, "hex"))
          .digest("hex"),
    );
    check(
      "it flags itself as signing with a forgeable development key",
      trust.body.developmentKey === true && typeof trust.body.warning === "string",
    );

    const advertised = trust.body.publicKeyFingerprintSha256;
    const spki = trust.body.publicKeySpkiDerHex;

    const appEnv = (extra = {}) => ({
      MANDATEX_TRUST_KEY_ID: "fixture-insecure-do-not-deploy-1",
      MANDATEX_TRUST_SPKI_DER_HEX: spki,
      MANDATEX_TRUST_KEY_FINGERPRINT_SHA256: advertised,
      MANDATEX_TRUST_POLICY_SHA256: FIXTURE_POLICY_SHA256,
      MANDATEX_VERIFIER_URL: verifier.base,
      ...extra,
    });

    // ── 1. Agreement ────────────────────────────────────────────────────────
    group("1. App pins what the verifier published — lockstep holds");

    const agreed = await boot(APP_ENTRY, appEnv(), "marketplace-api (agreeing)");
    try {
      const ready = await getJson(`${agreed.base}/readyz`);
      check("GET /readyz is 200", ready.status === 200, `HTTP ${ready.status}`);
      check("status is ready", ready.body.status === "ready", String(ready.body.status));
      check(
        "the verifier check reports ok, having actually reached the other process",
        ready.body.checks?.verifier?.status === "ok",
        JSON.stringify(ready.body.checks?.verifier),
      );
      check(
        "the probe names the URL it contacted, so agreement is attributable",
        ready.body.checks?.verifier?.url === `${verifier.base}/v1/trust`,
        String(ready.body.checks?.verifier?.url),
      );

      // The strongest available cross-process signature statement. The fixture
      // vectors are signed by the same key the live verifier just advertised, so
      // if the pin were wrong this would fail on the SIGNATURE. It fails on the
      // CLOCK instead — the vectors are anchored to a fixed past instant — which
      // is precisely the evidence that the pinned key was accepted.
      const vector = JSON.parse(
        readFileSync(join(REPO_ROOT, "fixtures", "attestations", "vectors", "valid", "baseline.json"), "utf8"),
      );
      const evaluated = await fetch(`${agreed.base}/v1/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mandate: vector.mandate, attestations: [vector.wire] }),
      });
      const evaluatedBody = await evaluated.json();
      const serialized = JSON.stringify(evaluatedBody);
      check(
        "an attestation signed by the live verifier's key clears signature checks",
        !/SIGNATURE|KEY_ID|UNKNOWN_KEY|TRUST/i.test(serialized),
        serialized.slice(0, 200),
      );
      check(
        "it is rejected on freshness instead, the fixture vectors being time-anchored",
        /EXPIRED|STALE|SKEW|FRESH/i.test(serialized),
        serialized.slice(0, 200),
      );
    } finally {
      const code = await agreed.stop();
      check("the app shuts down cleanly on SIGTERM", code === 0, `code=${code}`);
    }

    // ── 2. Disagreement: the case that makes the split meaningful ────────────
    group("2. App pins a DIFFERENT key — lockstep must fail");

    const other = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" });
    const otherHex = Buffer.from(other).toString("hex");
    const otherFingerprint = createHash("sha256").update(other).digest("hex");
    check("the decoy key really is a different key", otherFingerprint !== advertised);

    const mismatched = await boot(
      APP_ENTRY,
      appEnv({
        MANDATEX_TRUST_KEY_ID: "some-other-verifier-1",
        MANDATEX_TRUST_SPKI_DER_HEX: otherHex,
        MANDATEX_TRUST_KEY_FINGERPRINT_SHA256: otherFingerprint,
      }),
      "marketplace-api (mismatched)",
    );
    try {
      const ready = await getJson(`${mismatched.base}/readyz`);
      check("GET /readyz is 503, not 200", ready.status === 503, `HTTP ${ready.status}`);
      check("status is not_ready", ready.body.status === "not_ready", String(ready.body.status));
      check(
        "the failure is named key_mismatch, not a generic outage",
        ready.body.checks?.verifier?.status === "key_mismatch",
        JSON.stringify(ready.body.checks?.verifier?.status),
      );
      check(
        "the detail quotes both fingerprints so the operator can see which is stale",
        (ready.body.checks?.verifier?.detail ?? "").includes(advertised) &&
          (ready.body.checks?.verifier?.detail ?? "").includes(otherFingerprint),
      );
      check(
        "and it says what to do about it",
        /redeploy both together/i.test(ready.body.checks?.verifier?.detail ?? ""),
      );
    } finally {
      await mismatched.stop();
    }

    // ── 3. Verifier unreachable ─────────────────────────────────────────────
    group("3. Verifier unreachable — the app must not claim ready");

    const dead = await closedPort();
    const orphaned = await boot(
      APP_ENTRY,
      appEnv({ MANDATEX_VERIFIER_URL: `http://127.0.0.1:${dead}` }),
      "marketplace-api (orphaned)",
    );
    try {
      const ready = await getJson(`${orphaned.base}/readyz`);
      check("GET /readyz is 503", ready.status === 503, `HTTP ${ready.status}`);
      check(
        "the failure is named unreachable, distinct from a key mismatch",
        ready.body.checks?.verifier?.status === "unreachable",
        JSON.stringify(ready.body.checks?.verifier?.status),
      );
      const live = await getJson(`${orphaned.base}/healthz`);
      check(
        "liveness stays 200, so an orphaned app is restarted rather than looped",
        live.status === 200,
        `HTTP ${live.status}`,
      );
    } finally {
      await orphaned.stop();
    }

    // ── 4. No verifier configured ───────────────────────────────────────────
    group("4. No verifier configured — degrade honestly, do not fail");

    const solo = await boot(
      APP_ENTRY,
      {
        MANDATEX_TRUST_KEY_ID: "fixture-insecure-do-not-deploy-1",
        MANDATEX_TRUST_SPKI_DER_HEX: spki,
        MANDATEX_TRUST_KEY_FINGERPRINT_SHA256: advertised,
        MANDATEX_TRUST_POLICY_SHA256: FIXTURE_POLICY_SHA256,
      },
      "marketplace-api (solo)",
    );
    try {
      const ready = await getJson(`${solo.base}/readyz`);
      check(
        "readiness is 200: an unpaired app can still verify supplied attestations",
        ready.status === 200,
        `HTTP ${ready.status}`,
      );
      check(
        "but it says agreement is unchecked rather than implying it passed",
        ready.body.checks?.verifier?.status === "not_configured",
        JSON.stringify(ready.body.checks?.verifier?.status),
      );
    } finally {
      await solo.stop();
    }
  } finally {
    const code = await verifier.stop();
    group("Verifier shutdown");
    check("the verifier shuts down cleanly on SIGTERM", code === 0, `code=${code}`);
  }

  // ── 5. The boundary itself ─────────────────────────────────────────────────
  // Each process refuses the other's posture. Without these two guards the split
  // is a deployment convention rather than an enforced boundary, because nothing
  // would stop a future operator from setting every variable on one service.
  group("5. Neither process will accept the other's role");

  {
    const spki = "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const refusal = await bootExpectingRefusal(APP_ENTRY, {
      MANDATEX_TRUST_KEY_ID: "fixture-insecure-do-not-deploy-1",
      MANDATEX_TRUST_SPKI_DER_HEX: spki,
      MANDATEX_TRUST_KEY_FINGERPRINT_SHA256: createHash("sha256")
        .update(Buffer.from(spki, "hex"))
        .digest("hex"),
      MANDATEX_TRUST_POLICY_SHA256: FIXTURE_POLICY_SHA256,
      MANDATEX_SIGNING_KEY: FIXTURE_SEED_HEX,
    });
    check(
      "the app refuses to boot when handed signing material (exit 78)",
      refusal.code === 78,
      `code=${refusal.code} ${refusal.stderr.slice(0, 160)}`,
    );
    check(
      "and it does not echo the key it refused",
      !refusal.stderr.includes(FIXTURE_SEED_HEX),
    );
  }

  {
    const refusal = await bootExpectingRefusal(VERIFIER_ENTRY, {
      MANDATEX_SIGNING_KEY_ID: "mandatex-verifier-1",
    });
    check(
      "the verifier refuses to boot with no signing key (exit 78)",
      refusal.code === 78,
      `code=${refusal.code}`,
    );
  }

  {
    const refusal = await bootExpectingRefusal(VERIFIER_ENTRY, {
      NODE_ENV: "production",
      MANDATEX_SIGNING_KEY_ID: "mandatex-verifier-1",
      MANDATEX_SIGNING_KEY: FIXTURE_SEED_HEX,
    });
    check(
      "the verifier refuses the committed fixture key under production (exit 78)",
      refusal.code === 78,
      `code=${refusal.code}`,
    );
  }

  console.log("\n" + "-".repeat(70));
  console.log(`passed: ${passed}   failed: ${failures.length}`);
  if (failures.length > 0) {
    console.log("\nfailed checks:");
    for (const name of failures) console.log(`  - ${name}`);
    process.exit(1);
  }
  console.log(
    "\nRehearsal passed. The pinned key is load-bearing: agreement is 200, " +
      "disagreement is 503,\nand neither process will take the other's role.",
  );
}

await main();
