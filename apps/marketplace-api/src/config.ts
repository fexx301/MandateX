// Configuration and boot-time safety assertions.
//
// This process is the EVALUATOR side of the trust boundary. It pins a verifier's
// public key and checks signatures. It must never hold a signing key: if it did,
// every signature it verified would be one it could have produced itself, which
// collapses the two-process boundary back into the single-process design the user
// explicitly rejected — while additionally leaving a forgeable credential on a
// public host.
//
// That property is not documentation here. `loadConfig` refuses to boot when it
// can detect a violation.

import { readFileSync } from "node:fs";

/** Trust material this process pins, as it appears in configuration. */
export interface TrustConfig {
  readonly keyId: string;
  readonly publicKeySpkiDerHex: string;
  readonly publicKeyFingerprintSha256: string;
  readonly verifierPolicySha256: string;
}

export interface AppConfig {
  readonly port: number;
  readonly host: string;
  readonly production: boolean;
  readonly trust: TrustConfig;
  readonly maxClockSkewSeconds: number;
  readonly maxRequestBytes: number;
  /** Base URL of the verifier runtime, when one is configured. Used by /readyz. */
  readonly verifierUrl: string | null;
  /** True when the pinned key is a known-forgeable development key. */
  readonly trustIsDevelopmentKey: boolean;
  /** Serve fixture vectors from /v1/fixtures. Never enabled in production. */
  readonly exposeFixtures: boolean;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/**
 * Substrings that mark a key id as a development key. Matched rather than
 * compared against one constant so that any future fixture key is caught too,
 * and so this module never imports a signer to learn the name.
 */
const DEVELOPMENT_KEY_MARKERS = ["fixture", "insecure", "do-not-deploy", "test", "dev-"];

/**
 * Byte patterns that indicate private key material. The DER prefix is the
 * PKCS#8 header for an Ed25519 private key, which is exactly what the verifier
 * runtime holds and this process must not.
 */
const PRIVATE_KEY_MARKERS = [
  "302e020100300506032b6570", // PKCS#8 Ed25519 private key prefix, hex
  "BEGIN PRIVATE KEY",
  "BEGIN ED25519 PRIVATE KEY",
  "BEGIN OPENSSH PRIVATE KEY",
  "BEGIN RSA PRIVATE KEY",
  "BEGIN EC PRIVATE KEY",
];

/** Env vars whose names alone suggest they carry signing authority. */
const FORBIDDEN_NAME_PATTERN =
  /(SIGNING|SIGNER|PRIVATE)_?(KEY|SEED)|_?SEED_HEX$|MNEMONIC|PRIVATE_KEY/i;

const HEX_64 = /^[a-f0-9]{64}$/;
const SPKI_ED25519_HEX = /^302a300506032b6570032100[a-f0-9]{64}$/;

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.trim() === "") {
    throw new ConfigError(`${name} is required`);
  }
  return value.trim();
}

function optionalInteger(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw.trim());
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ConfigError(`${name} must be a non-negative integer, received ${raw}`);
  }
  return value;
}

/**
 * Fail if this process was handed anything that looks like signing authority.
 *
 * Checked by name *and* by content: a key pasted into an innocuously named
 * variable is the more likely accident, and the more dangerous one, because it
 * survives a review that only reads variable names.
 */
function assertNoSigningAuthority(env: NodeJS.ProcessEnv): void {
  const offences: string[] = [];

  for (const [name, value] of Object.entries(env)) {
    if (value === undefined || value === "") continue;

    // Ignore the trust material itself: a public key is meant to be here.
    if (name.startsWith("MANDATEX_TRUST_")) continue;

    if (FORBIDDEN_NAME_PATTERN.test(name)) {
      offences.push(`${name} (name indicates signing material)`);
      continue;
    }
    const matched = PRIVATE_KEY_MARKERS.find((marker) =>
      value.toLowerCase().includes(marker.toLowerCase()),
    );
    if (matched !== undefined) {
      offences.push(`${name} (contains "${matched}")`);
    }
  }

  if (offences.length > 0) {
    throw new ConfigError(
      "this process must not hold signing authority, but the environment appears to " +
        `carry it: ${offences.join(", ")}. The signing key belongs only to the verifier ` +
        "runtime. If the marketplace API can sign, its signature checks prove nothing.",
    );
  }
}

function loadTrust(env: NodeJS.ProcessEnv): TrustConfig {
  const file = env.MANDATEX_TRUST_FILE?.trim();
  const raw: unknown =
    file !== undefined && file !== ""
      ? JSON.parse(readFileSync(file, "utf8"))
      : {
          keyId: required(env, "MANDATEX_TRUST_KEY_ID"),
          publicKeySpkiDerHex: required(env, "MANDATEX_TRUST_SPKI_DER_HEX"),
          publicKeyFingerprintSha256: required(env, "MANDATEX_TRUST_KEY_FINGERPRINT_SHA256"),
          verifierPolicySha256: required(env, "MANDATEX_TRUST_POLICY_SHA256"),
        };

  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError("trust material must be a JSON object");
  }
  const record = raw as Record<string, unknown>;

  const field = (name: string): string => {
    const value = record[name];
    if (typeof value !== "string" || value.trim() === "") {
      throw new ConfigError(
        `trust material is missing "${name}"` + (file !== undefined ? ` (from ${file})` : ""),
      );
    }
    return value.trim();
  };

  const trust: TrustConfig = {
    keyId: field("keyId"),
    publicKeySpkiDerHex: field("publicKeySpkiDerHex").toLowerCase(),
    publicKeyFingerprintSha256: field("publicKeyFingerprintSha256").toLowerCase(),
    verifierPolicySha256: field("verifierPolicySha256").toLowerCase(),
  };

  // Shape-check locally so a typo surfaces as a config error at boot rather than
  // as an attestation rejection at request time, where it would read like a
  // signature problem. Core re-validates all of this and is the authority.
  if (!SPKI_ED25519_HEX.test(trust.publicKeySpkiDerHex)) {
    throw new ConfigError(
      "MANDATEX_TRUST_SPKI_DER_HEX must be a 44-byte Ed25519 SPKI DER key in lowercase hex " +
        "(prefix 302a300506032b6570032100)",
    );
  }
  if (!HEX_64.test(trust.publicKeyFingerprintSha256)) {
    throw new ConfigError("MANDATEX_TRUST_KEY_FINGERPRINT_SHA256 must be 64 lowercase hex chars");
  }
  if (!HEX_64.test(trust.verifierPolicySha256)) {
    throw new ConfigError("MANDATEX_TRUST_POLICY_SHA256 must be 64 lowercase hex chars");
  }

  return trust;
}

function isDevelopmentKey(keyId: string): boolean {
  const normalized = keyId.toLowerCase();
  return DEVELOPMENT_KEY_MARKERS.some((marker) => normalized.includes(marker));
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const production = env.NODE_ENV === "production";

  assertNoSigningAuthority(env);

  const trust = loadTrust(env);
  const trustIsDevelopmentKey = isDevelopmentKey(trust.keyId);

  // The fixture signing seed is committed to this repository, so anyone can mint
  // a signature this key accepts. Pinning it on a public host would present
  // forgeable claims as verified evaluations.
  if (production && trustIsDevelopmentKey) {
    throw new ConfigError(
      `refusing to serve production traffic pinned to development key "${trust.keyId}": ` +
        "its private half is public, so any attestation it accepts is forgeable by anyone. " +
        "Pin the deployed verifier runtime's key instead.",
    );
  }

  const exposeFixtures = !production && env.MANDATEX_EXPOSE_FIXTURES !== "false";

  const verifierUrlRaw = env.MANDATEX_VERIFIER_URL?.trim();
  let verifierUrl: string | null = null;
  if (verifierUrlRaw !== undefined && verifierUrlRaw !== "") {
    let parsed: URL;
    try {
      parsed = new URL(verifierUrlRaw);
    } catch {
      throw new ConfigError(`MANDATEX_VERIFIER_URL is not a valid URL: ${verifierUrlRaw}`);
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new ConfigError("MANDATEX_VERIFIER_URL must be http or https");
    }
    // Railway private networking is plain http over an internal hostname, so
    // http is permitted — but only there. A public http verifier URL would let a
    // network attacker strip attestations in transit.
    if (production && parsed.protocol === "http:" && !parsed.hostname.endsWith(".internal")) {
      throw new ConfigError(
        "MANDATEX_VERIFIER_URL must be https in production unless it is a *.internal " +
          `private-network address, received ${parsed.protocol}//${parsed.hostname}`,
      );
    }
    verifierUrl = parsed.origin + parsed.pathname.replace(/\/$/, "");
  }

  return {
    port: optionalInteger(env, "PORT", 8080),
    host: env.HOST?.trim() ?? "0.0.0.0",
    production,
    trust,
    maxClockSkewSeconds: optionalInteger(env, "MANDATEX_MAX_CLOCK_SKEW_SECONDS", 30),
    maxRequestBytes: optionalInteger(env, "MANDATEX_MAX_REQUEST_BYTES", 1_048_576),
    verifierUrl,
    trustIsDevelopmentKey,
    exposeFixtures,
  };
}
