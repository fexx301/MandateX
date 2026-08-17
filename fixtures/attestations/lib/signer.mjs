// Deterministic Ed25519 stub signer for MandateX evaluation-attestation fixtures.
//
// ┌───────────────────────────────────────────────────────────────────────────┐
// │  TEST KEY ONLY. NEVER USE FOR ANYTHING REAL.                              │
// │                                                                           │
// │  The seed below is a hardcoded, publicly-committed constant. Any          │
// │  signature it produces is forgeable by anyone who can read this repo.     │
// │  It exists so fixture vectors are byte-reproducible across machines and    │
// │  so Codex can independently regenerate and compare golden signing bytes.  │
// │                                                                           │
// │  The real signer key lives ONLY inside the separately deployed verifier    │
// │  runtime, per EVALUATION_ATTESTATION_V2.md §"Deployment boundary". It      │
// │  must never appear in this repository, and the evaluator image must never  │
// │  pin this test key.                                                       │
// └───────────────────────────────────────────────────────────────────────────┘

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

/** Loudly non-production key id. If this ever reaches a deployed evaluator, it is a bug. */
export const DEV_KEY_ID = "fixture-insecure-do-not-deploy-1";

/** Fixed 32-byte Ed25519 seed. Test-only; see banner above. */
const DEV_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

// DER wrappers for raw Ed25519 key material. Building these by hand keeps this
// module dependency-free and makes the byte layout auditable.
//
// PKCS#8 private key (48 bytes total):
//   30 2e             SEQUENCE, 46 bytes
//   02 01 00          INTEGER 0                  (version)
//   30 05 06 03 2b 65 70   SEQUENCE / OID 1.3.101.112  (Ed25519)
//   04 22 04 20       OCTET STRING(34) wrapping OCTET STRING(32)
//   <32-byte seed>
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

// SPKI public key (44 bytes total):
//   30 2a             SEQUENCE, 42 bytes
//   30 05 06 03 2b 65 70   SEQUENCE / OID 1.3.101.112  (Ed25519)
//   03 21 00          BIT STRING(33), 0 unused bits
//   <32-byte public key>
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function assertNotProduction() {
  const env = process.env.NODE_ENV;
  if (env === "production") {
    throw new Error(
      "fixture stub signer refuses to run with NODE_ENV=production — " +
        "the real signer key belongs only to the deployed verifier runtime",
    );
  }
}

/** Deterministic dev keypair. Same bytes on every machine, every run. */
export function devKeyPair() {
  assertNotProduction();
  const seed = Buffer.from(DEV_SEED_HEX, "hex");
  if (seed.length !== 32) throw new Error("Ed25519 seed must be exactly 32 bytes");

  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey);

  const spkiDer = publicKey.export({ format: "der", type: "spki" });

  // Verify our hand-built DER round-trips to canonical SPKI. validateMarketplace-
  // AttestationTrust re-exports and byte-compares, so a non-canonical encoding
  // here would fail there with a confusing message. Fail loudly now instead.
  const rebuilt = Buffer.concat([SPKI_ED25519_PREFIX, spkiDer.subarray(12)]);
  if (!rebuilt.equals(spkiDer)) {
    throw new Error("hand-built SPKI prefix does not match Node's canonical encoding");
  }

  return {
    keyId: DEV_KEY_ID,
    privateKey,
    publicKey,
    spkiDer,
    /** SHA-256 over canonical SPKI DER — the fingerprint format Core pins. */
    fingerprintSha256: createHash("sha256").update(spkiDer).digest("hex"),
  };
}

/** Ed25519 signature as 128 lowercase hex characters, matching the wire schema. */
export function signBytes(message, privateKey) {
  assertNotProduction();
  return sign(null, message, privateKey).toString("hex");
}

/** Verify a hex signature. Used by build.mjs to self-check every vector it emits. */
export function verifyBytes(message, signatureHex, publicKey) {
  if (!/^[a-f0-9]{128}$/.test(signatureHex)) return false;
  return verify(null, message, publicKey, Buffer.from(signatureHex, "hex"));
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}
