// Configuration and boot guards for the SIGNER side of the trust boundary.
//
// This process is the mirror image of apps/marketplace-api. That process must
// never hold a signing key; this one must always hold one, because a verifier
// that cannot sign cannot issue attestations at all. The asymmetry is the whole
// point of running two services:
//
//   marketplace-api : pins the PUBLIC key, verifies, holds no secret
//   verifier-api    : holds the PRIVATE key, evaluates and signs
//
// So the guards here are inverted. Instead of refusing to boot when a key is
// present, this process refuses to boot when one is ABSENT, when the key is the
// publicly-committed fixture key under production, or when the key material is
// not a well-formed Ed25519 private key.
//
// The key is read from the environment only. It is never read from a file inside
// the repository and never written to one: a signing key in the tree is
// permanently compromised the moment the tree is pushed, and the fixture key
// already demonstrates what that costs.

import { createPrivateKey, createPublicKey, createHash, type KeyObject } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/** Key-id substrings that mark a key as development-only. Refused in production. */
const DEVELOPMENT_KEY_MARKERS = ["fixture", "insecure", "do-not-deploy", "test", "dev-"];

/**
 * The publicly-committed fixture seed, as an Ed25519 PKCS#8 DER prefix match.
 *
 * This is RFC 8032 test vector 1 and it lives in
 * fixtures/attestations/lib/signer.mjs. Anyone who can read the repository can
 * sign with it. Recognising the key material itself — not just its key id —
 * means renaming the key id cannot smuggle it into production.
 */
const FIXTURE_PUBLIC_KEY_SPKI_HEX =
  "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/** PKCS#8 Ed25519 private key, DER, hex: 48 bytes total. */
const PKCS8_ED25519_HEX = /^302e020100300506032b657004220420[a-f0-9]{64}$/;

/** Raw 32-byte Ed25519 seed, hex. Accepted as a convenience and wrapped into PKCS#8. */
const RAW_SEED_HEX = /^[a-f0-9]{64}$/;

/** DER prefix that turns a raw 32-byte Ed25519 seed into a PKCS#8 private key. */
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";

export interface VerifierArtifacts {
  readonly manifest: unknown;
  readonly passiveReport: unknown;
  readonly trustFile: unknown;
  readonly sourceDir: string;
}

export interface VerifierConfig {
  readonly port: number;
  readonly host: string;
  readonly production: boolean;
  readonly keyId: string;
  readonly signingKey: KeyObject;
  readonly publicKeySpkiDerHex: string;
  readonly publicKeyFingerprintSha256: string;
  readonly keyIsDevelopmentKey: boolean;
  /** Present only when a complete artifact set was configured and parsed. */
  readonly artifacts: VerifierArtifacts | null;
  /** Why artifacts are absent, for the /v1/trust and /healthz payloads. */
  readonly artifactsDetail: string;
  readonly verifierPolicySha256: string | null;
  readonly maxRequestBytes: number;
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (value === undefined || value === "") {
    throw new ConfigError(`${name} is required`);
  }
  return value;
}

function optionalInteger(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name]?.trim();
  if (raw === undefined || raw === "") return fallback;
  if (!/^\d+$/.test(raw)) throw new ConfigError(`${name} must be a non-negative integer`);
  return Number.parseInt(raw, 10);
}

/**
 * Turn the configured secret into a KeyObject without ever returning its bytes.
 *
 * Accepts either full PKCS#8 DER hex or a bare 32-byte seed. The seed form is
 * accepted because it is what most Ed25519 tooling prints, and rejecting it
 * would push operators toward ad-hoc conversion scripts that leave the key in
 * shell history.
 */
function loadSigningKey(hex: string): KeyObject {
  const normalized = hex.toLowerCase().replace(/\s+/g, "");

  let pkcs8Hex: string;
  if (PKCS8_ED25519_HEX.test(normalized)) {
    pkcs8Hex = normalized;
  } else if (RAW_SEED_HEX.test(normalized)) {
    pkcs8Hex = PKCS8_ED25519_PREFIX + normalized;
  } else {
    throw new ConfigError(
      "MANDATEX_SIGNING_KEY must be an Ed25519 private key as either a 32-byte seed " +
        "in hex (64 chars) or full PKCS#8 DER in hex starting 302e020100300506032b6570. " +
        "The value given matched neither. Nothing about the value itself is logged.",
    );
  }

  try {
    return createPrivateKey({
      key: Buffer.from(pkcs8Hex, "hex"),
      format: "der",
      type: "pkcs8",
    });
  } catch (cause) {
    throw new ConfigError(
      `MANDATEX_SIGNING_KEY is not a usable Ed25519 private key: ${(cause as Error).message}`,
    );
  }
}

const ARTIFACT_FILES = Object.freeze({
  manifest: "manifest.json",
  passiveReport: "passive-report.json",
  trustFile: "quote-trust.json",
});

/**
 * Load the three verifier artifacts, or explain precisely why they are absent.
 *
 * Absence is not an error. The artifacts are outputs of the agent-supply
 * verifier's passive pipeline run against a live agent, so they do not exist
 * until that has been run. Refusing to boot without them would mean the service
 * cannot be deployed until the whole supply pipeline is finished, and would block
 * the one thing that is needed first: standing up the trust boundary and proving
 * lockstep key agreement with the marketplace app.
 */
function loadArtifacts(dir: string | undefined): {
  artifacts: VerifierArtifacts | null;
  detail: string;
} {
  if (dir === undefined || dir === "") {
    return {
      artifacts: null,
      detail:
        "MANDATEX_VERIFIER_CONFIG_DIR is unset, so no agent is configured for evaluation. " +
        "GET /v1/trust and GET /healthz work; POST /v1/evaluate returns 503. Populate the " +
        "directory with " +
        Object.values(ARTIFACT_FILES).join(", ") +
        " from an agent-supply-verifier passive run.",
    };
  }

  const missing = Object.values(ARTIFACT_FILES).filter(
    (name) => !existsSync(join(dir, name)),
  );
  if (missing.length > 0) {
    return {
      artifacts: null,
      detail: `MANDATEX_VERIFIER_CONFIG_DIR=${dir} is missing: ${missing.join(", ")}`,
    };
  }

  const read = (name: string): unknown => {
    try {
      return JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch (cause) {
      throw new ConfigError(`${join(dir, name)} is not readable JSON: ${(cause as Error).message}`);
    }
  };

  return {
    artifacts: {
      manifest: read(ARTIFACT_FILES.manifest),
      passiveReport: read(ARTIFACT_FILES.passiveReport),
      trustFile: read(ARTIFACT_FILES.trustFile),
      sourceDir: dir,
    },
    detail: `loaded from ${dir}`,
  };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): VerifierConfig {
  const production = env.NODE_ENV === "production";

  const keyId = required(env, "MANDATEX_SIGNING_KEY_ID");
  const signingKey = loadSigningKey(required(env, "MANDATEX_SIGNING_KEY"));

  const publicKeySpkiDer = createPublicKey(signingKey).export({ type: "spki", format: "der" });
  const publicKeySpkiDerHex = publicKeySpkiDer.toString("hex");
  const publicKeyFingerprintSha256 = createHash("sha256").update(publicKeySpkiDer).digest("hex");

  const keyIdLooksDevelopment = DEVELOPMENT_KEY_MARKERS.some((marker) =>
    keyId.toLowerCase().includes(marker),
  );
  const isFixtureKey = publicKeySpkiDerHex === FIXTURE_PUBLIC_KEY_SPKI_HEX;
  const keyIsDevelopmentKey = keyIdLooksDevelopment || isFixtureKey;

  if (production && isFixtureKey) {
    throw new ConfigError(
      "the configured signing key is the publicly-committed fixture key from " +
        "fixtures/attestations/lib/signer.mjs. Its private half is in the repository, so " +
        "every attestation it issues is forgeable by anyone who can read the tree. " +
        "Generate a real key and set it as a deployment secret.",
    );
  }
  if (production && keyIdLooksDevelopment) {
    throw new ConfigError(
      `MANDATEX_SIGNING_KEY_ID "${keyId}" is marked as development-only ` +
        `(contains one of: ${DEVELOPMENT_KEY_MARKERS.join(", ")}) and NODE_ENV=production. ` +
        "A development key id tells every consumer not to trust what it signs.",
    );
  }

  const { artifacts, detail } = loadArtifacts(env.MANDATEX_VERIFIER_CONFIG_DIR?.trim());

  // The policy hash may be pinned explicitly, which is what the marketplace app
  // compares against. When artifacts are loaded it is derived from them instead,
  // and a mismatch between the two is a configuration error surfaced at boot by
  // createMarketplaceVerifierRuntime rather than silently preferring one.
  const verifierPolicySha256 = env.MANDATEX_VERIFIER_POLICY_SHA256?.trim().toLowerCase() ?? null;
  if (verifierPolicySha256 !== null && !/^[a-f0-9]{64}$/.test(verifierPolicySha256)) {
    throw new ConfigError("MANDATEX_VERIFIER_POLICY_SHA256 must be 64 lowercase hex characters");
  }

  return {
    port: optionalInteger(env, "PORT", 8080),
    host: env.HOST?.trim() ?? "0.0.0.0",
    production,
    keyId,
    signingKey,
    publicKeySpkiDerHex,
    publicKeyFingerprintSha256,
    keyIsDevelopmentKey,
    artifacts,
    artifactsDetail: detail,
    verifierPolicySha256,
    maxRequestBytes: optionalInteger(env, "MANDATEX_MAX_REQUEST_BYTES", 1_048_576),
  };
}

/**
 * The private key as PKCS#8 DER, for handing to the marketplace-service signer.
 *
 * Isolated in a named function so that every place the raw secret is materialized
 * is greppable. Callers must not log, echo, or serialize the result.
 */
export function signingKeyPkcs8Der(config: VerifierConfig): Uint8Array {
  return config.signingKey.export({ type: "pkcs8", format: "der" });
}
