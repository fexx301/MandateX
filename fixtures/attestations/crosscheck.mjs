// Cross-checks the fixture vectors against the REAL Marketplace Core verifier.
//
// Run:  node fixtures/attestations/crosscheck.mjs
//
// Four independent checks, in increasing strength:
//
//   1. CANONICALIZATION PARITY — my from-scratch canonicalJson (lib/canonical.mjs)
//      must produce byte-identical output to marketplace-core's canonical.ts for
//      every vector and for the mandate. Two independent implementations agreeing
//      is the actual check; a shared import would prove nothing.
//
//   2. SIGNING-BYTES PARITY — my signing message must equal Core's
//      marketplaceEvaluationAttestationSigningMessage byte for byte. This is what
//      the contract means by "lock the exact signing bytes before the signer
//      service is deployed".
//
//   3. MANDATE NORMALIZATION — marketplaceMandateSchema applies .toLowerCase() to
//      addresses and .transform(sortUnique) to arrays, and Core hashes the PARSED
//      mandate. If the fixture mandate were not already in normalized form, every
//      mandateSha256 would silently disagree. Asserted, not assumed.
//
//   4. VERDICT PARITY — every valid vector must verify, every invalid vector must
//      be rejected, and the rejection code must be the one the vector predicts.
//
// Marketplace Core is Codex-owned and under active development. This script
// therefore degrades gracefully: if its dist cannot be imported, the parity
// checks are reported as unavailable and the script still verifies everything it
// can prove on its own. It never builds inside Codex's package.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { canonicalJson } from "./lib/canonical.mjs";
import { devKeyPair, sha256Hex } from "./lib/signer.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORE_DIST = join(HERE, "..", "..", "tools", "marketplace-core", "dist");

const SIGNING_DOMAIN = "MandateX Marketplace Evaluation Attestation v1\0";

// ── Reporting ───────────────────────────────────────────────────────────────
const failures = [];
const skipped = [];
let passed = 0;

const ok = (label) => {
  passed += 1;
  console.log(`  ✓ ${label}`);
};
const fail = (label, detail) => {
  failures.push({ label, detail });
  console.log(`  ✗ ${label}`);
  console.log(`      ${detail}`);
};
const skip = (label, reason) => {
  skipped.push({ label, reason });
  console.log(`  - ${label} (${reason})`);
};
const heading = (text) => console.log(`\n${text}`);

// ── Load fixtures ───────────────────────────────────────────────────────────
function loadVectors(kind) {
  const dir = join(HERE, "vectors", kind);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => JSON.parse(readFileSync(join(dir, name), "utf8")));
}

const validVectors = loadVectors("valid");
const invalidVectors = loadVectors("invalid");
const allVectors = [...validVectors, ...invalidVectors];

if (allVectors.length === 0) {
  console.error("no vectors found — run: node fixtures/attestations/lib/build.mjs");
  process.exit(1);
}

const golden = JSON.parse(readFileSync(join(HERE, "golden", "signing-bytes.json"), "utf8"));
const trustFile = JSON.parse(readFileSync(join(HERE, "keys", "dev-signer.public.json"), "utf8"));

console.log(
  `MandateX evaluation-attestation fixture cross-check\n` +
    `${validVectors.length} valid, ${invalidVectors.length} invalid vectors`,
);

// ── Self-consistency: provable without Marketplace Core ─────────────────────
heading("Fixture self-consistency");
{
  let mismatched = 0;
  for (const vector of allVectors) {
    if (sha256Hex(vector.wire) !== vector.wireSha256) {
      fail(`${vector.name}: recorded wireSha256 does not match its wire`, "fixture file corrupt");
      mismatched += 1;
    }
  }
  if (mismatched === 0) ok(`all ${allVectors.length} recorded wire digests match their wire text`);

  const key = devKeyPair();
  if (key.fingerprintSha256 === trustFile.publicKeyFingerprintSha256) {
    ok("dev key regenerates to the same fingerprint (vectors are reproducible)");
  } else {
    fail(
      "dev key fingerprint drifted",
      `signer produces ${key.fingerprintSha256}, keys/dev-signer.public.json pins ` +
        `${trustFile.publicKeyFingerprintSha256}`,
    );
  }

  const names = new Set();
  const duplicates = allVectors.map((v) => v.name).filter((n) => names.size === names.add(n).size);
  if (duplicates.length === 0) ok("vector names are unique");
  else fail("duplicate vector names", duplicates.join(", "));
}

// ── Import Marketplace Core ─────────────────────────────────────────────────
let core = null;
let coreSchemas = null;
let coreUnavailableReason = null;

try {
  core = await import(pathToFileURL(join(CORE_DIST, "attestation.js")).href);
  const canonicalModule = await import(pathToFileURL(join(CORE_DIST, "canonical.js")).href);
  core = { ...core, canonicalJson: canonicalModule.canonicalJson };
  try {
    coreSchemas = await import(pathToFileURL(join(CORE_DIST, "schemas.js")).href);
  } catch {
    coreSchemas = null; // non-fatal; only the mandate-normalization check needs it
  }
} catch (cause) {
  // There is no root package or pnpm workspace, so each tool builds standalone.
  coreUnavailableReason =
    cause?.code === "ERR_MODULE_NOT_FOUND"
      ? "marketplace-core is not built (run: cd tools/marketplace-core && corepack pnpm build)"
      : `import failed: ${String(cause?.message ?? cause).split("\n")[0]}`;
}

if (coreUnavailableReason !== null) {
  heading("Marketplace Core parity");
  skip("canonicalization parity", coreUnavailableReason);
  skip("signing-bytes parity", coreUnavailableReason);
  skip("mandate normalization", coreUnavailableReason);
  skip("verdict parity", coreUnavailableReason);
  console.log(
    "\nCross-check against the real verifier is UNAVAILABLE. This is expected while " +
      "Marketplace Core is mid-implementation:\nfixture self-consistency above still holds, " +
      "but conformance to the deployed verifier is unproven.",
  );
} else {
  // ── 1. Canonicalization parity ────────────────────────────────────────────
  heading("Canonicalization parity (independent implementation vs marketplace-core)");
  {
    let divergences = 0;
    let compared = 0;
    for (const vector of allVectors) {
      let parsed;
      try {
        parsed = JSON.parse(vector.wire);
      } catch {
        continue; // the not-json vector has nothing to canonicalize
      }
      let mine;
      let theirs;
      try {
        mine = canonicalJson(parsed);
      } catch (cause) {
        mine = `THREW: ${cause.message}`;
      }
      try {
        theirs = core.canonicalJson(parsed);
      } catch (cause) {
        theirs = `THREW: ${cause.message}`;
      }
      compared += 1;
      if (mine !== theirs) {
        divergences += 1;
        fail(
          `${vector.name}: canonical output diverges`,
          `mine sha256=${sha256Hex(mine)} theirs sha256=${sha256Hex(theirs)}`,
        );
      }
    }
    if (divergences === 0) {
      ok(`${compared} vectors canonicalize identically in both implementations`);
    }

    const mineMandate = canonicalJson(allVectors[0].mandate);
    if (mineMandate === core.canonicalJson(allVectors[0].mandate)) {
      ok("mandate canonicalizes identically in both implementations");
    } else {
      fail("mandate canonical output diverges", "independent canonicalizers disagree");
    }
  }

  // ── 2. Signing-bytes parity ───────────────────────────────────────────────
  heading("Signing-bytes parity (golden vectors vs marketplace-core)");
  {
    let divergences = 0;
    for (const record of golden.vectors) {
      const vector = validVectors.find((candidate) => candidate.name === record.name);
      if (vector === undefined) {
        fail(`${record.name}: golden record has no matching valid vector`, "regenerate fixtures");
        divergences += 1;
        continue;
      }
      const { signature, ...unsigned } = JSON.parse(vector.wire);

      const mine = Buffer.concat([
        Buffer.from(SIGNING_DOMAIN, "utf8"),
        Buffer.from(canonicalJson(unsigned), "utf8"),
      ]);
      let theirs;
      try {
        theirs = Buffer.from(core.marketplaceEvaluationAttestationSigningMessage(unsigned));
      } catch (cause) {
        fail(
          `${record.name}: Core rejected the unsigned envelope`,
          String(cause?.message ?? cause).split("\n")[0],
        );
        divergences += 1;
        continue;
      }

      if (!mine.equals(theirs)) {
        fail(
          `${record.name}: signing bytes diverge`,
          `mine ${mine.length}B sha256=${sha256Hex(mine)}; ` +
            `Core ${theirs.length}B sha256=${sha256Hex(theirs)}`,
        );
        divergences += 1;
        continue;
      }
      if (sha256Hex(mine) !== record.signingMessageSha256) {
        fail(
          `${record.name}: recorded golden digest is stale`,
          `recomputed ${sha256Hex(mine)}, file records ${record.signingMessageSha256}`,
        );
        divergences += 1;
      }
    }
    if (divergences === 0) {
      ok(
        `${golden.vectors.length} golden signing messages are byte-identical across both ` +
          `implementations and match their recorded digests`,
      );
    }
  }

  // ── 3. Mandate normalization ──────────────────────────────────────────────
  heading("Mandate normalization");
  if (coreSchemas?.marketplaceMandateSchema === undefined) {
    skip("mandate is already in schema-normalized form", "schemas.js did not export the schema");
  } else {
    const raw = allVectors[0].mandate;
    const parsed = coreSchemas.marketplaceMandateSchema.safeParse(raw);
    if (!parsed.success) {
      fail(
        "fixture mandate does not satisfy marketplaceMandateSchema",
        JSON.stringify(parsed.error.issues.slice(0, 3)),
      );
    } else if (core.canonicalJson(parsed.data) !== core.canonicalJson(raw)) {
      fail(
        "fixture mandate is not in normalized form",
        "schema transforms changed it, so every mandateSha256 in these fixtures is wrong",
      );
    } else if (sha256Hex(core.canonicalJson(parsed.data)) !== golden.mandateSha256) {
      fail(
        "recorded mandateSha256 is stale",
        `Core computes ${sha256Hex(core.canonicalJson(parsed.data))}, ` +
          `golden records ${golden.mandateSha256}`,
      );
    } else {
      ok("mandate survives schema parsing unchanged, and its recorded digest matches Core's");
    }
  }

  // ── 4. Verdict parity ─────────────────────────────────────────────────────
  heading("Verdict parity (real verifier)");

  let trust = null;
  try {
    trust = core.validateMarketplaceAttestationTrust({
      keyId: trustFile.keyId,
      publicKeySpkiDer: Buffer.from(trustFile.publicKeySpkiDerHex, "hex"),
      publicKeyFingerprintSha256: trustFile.publicKeyFingerprintSha256,
      verifierPolicySha256: trustFile.verifierPolicySha256,
    });
    ok("Core accepted the fixture trust material (pinned key, fingerprint, policy hash)");
  } catch (cause) {
    fail(
      "Core rejected the fixture trust material",
      `${cause?.code ?? "?"}: ${String(cause?.message ?? cause).split("\n")[0]}`,
    );
  }

  if (trust !== null) {
    const mandateForVerify =
      coreSchemas?.marketplaceMandateSchema !== undefined
        ? coreSchemas.marketplaceMandateSchema.parse(allVectors[0].mandate)
        : allVectors[0].mandate;

    const verdict = (vector) => {
      try {
        core.verifyMarketplaceEvaluationAttestation({
          wire: vector.wire,
          mandate: mandateForVerify,
          evaluatedAt: vector.evaluatedAt,
          maxClockSkewSeconds: vector.maxClockSkewSeconds,
          trust,
        });
        return { accepted: true };
      } catch (cause) {
        return {
          accepted: false,
          code: cause?.code ?? null,
          message: String(cause?.message ?? cause).split("\n")[0],
        };
      }
    };

    let rejectedValid = 0;
    for (const vector of validVectors) {
      const result = verdict(vector);
      if (!result.accepted) {
        rejectedValid += 1;
        fail(
          `${vector.name}: expected accept, got reject`,
          `${result.code ?? "no code"}: ${result.message}`,
        );
      }
    }
    if (rejectedValid === 0) {
      ok(`all ${validVectors.length} valid vectors verified against the real verifier`);
    }

    let acceptedInvalid = 0;
    const codeMismatches = [];
    for (const vector of invalidVectors) {
      const result = verdict(vector);
      if (result.accepted) {
        acceptedInvalid += 1;
        fail(
          `${vector.name}: expected reject, got ACCEPT`,
          `attack class "${vector.attackClass}" is not defended — ${vector.description}`,
        );
        continue;
      }
      if (vector.expectedCode !== null && result.code !== vector.expectedCode) {
        codeMismatches.push(
          `${vector.name}: predicted ${vector.expectedCode}, got ${result.code ?? "no code"}`,
        );
      }
    }
    if (acceptedInvalid === 0) {
      ok(`all ${invalidVectors.length} invalid vectors were rejected`);
    }

    // A code mismatch is not a security failure — the envelope was still
    // rejected — but it means a vector is exercising a different check than
    // intended, so it is reported rather than swallowed.
    if (codeMismatches.length === 0) {
      ok("every rejection used the error code its vector predicted");
    } else {
      console.log(
        `  ! ${codeMismatches.length} rejection(s) used a different code than predicted ` +
          `(rejected, but exercising a different check):`,
      );
      for (const mismatch of codeMismatches) console.log(`      ${mismatch}`);
    }
  }
}

// ── Summary ─────────────────────────────────────────────────────────────────
console.log(`\n${"-".repeat(70)}`);
console.log(`passed: ${passed}   failed: ${failures.length}   skipped: ${skipped.length}`);
if (failures.length > 0) {
  console.log("\nFAILURES");
  for (const failure of failures) console.log(`  ${failure.label}\n    ${failure.detail}`);
  process.exit(1);
}
console.log(
  skipped.length > 0
    ? "\nAll available checks passed. Some checks were skipped — see above."
    : "\nAll checks passed: fixtures conform to the real verifier.",
);
