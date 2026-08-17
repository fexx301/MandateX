// End-to-end smoke test against the real Marketplace Core and the real fixture
// vectors, over a real HTTP socket.
//
//   node dist/smoke.js
//
// This is not a unit test. It boots the actual server, posts the actual signed
// attestation vectors, and asserts on the HTTP responses — because the failures
// worth catching here live in the seams: trust material that Core rejects, a
// display projection that misreports the ranking basis, a route that returns 200
// with an empty comparison, a boot guard that does not actually fire.
//
// It runs with an injected fixed clock. The fixture vectors carry a 300-second
// TTL anchored at a frozen instant, so against a real clock every one of them is
// correctly expired and the test would prove only that expiry works.

import { createServer, type Server } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadConfig, ConfigError, type AppConfig } from "./config.js";
import { MarketplaceEvaluator } from "./core.js";
import { createRouter } from "./routes.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures", "attestations");
const TRUST_FILE = join(FIXTURES, "keys", "dev-signer.public.json");

let passed = 0;
const failures: string[] = [];

function ok(label: string): void {
  passed += 1;
  console.log(`  ✓ ${label}`);
}
function fail(label: string, detail: string): void {
  failures.push(`${label}: ${detail}`);
  console.log(`  ✗ ${label}`);
  console.log(`      ${detail}`);
}
function check(condition: boolean, label: string, detail: string): void {
  if (condition) ok(label);
  else fail(label, detail);
}
function heading(text: string): void {
  console.log(`\n${text}`);
}

interface Vector {
  readonly name: string;
  readonly wire: string;
  readonly mandate: unknown;
  readonly evaluatedAt: number;
  readonly expectedResult: string;
  readonly expectedCode?: string;
  readonly attackClass?: string;
}

async function loadVectors(kind: "valid" | "invalid"): Promise<Vector[]> {
  const { readdirSync, readFileSync, existsSync } = await import("node:fs");
  const dir = join(FIXTURES, "vectors", kind);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => JSON.parse(readFileSync(join(dir, name), "utf8")) as Vector);
}

function baseEnv(): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "development",
    PORT: "0",
    MANDATEX_TRUST_FILE: TRUST_FILE,
    MANDATEX_FIXTURES_DIR: FIXTURES,
  };
}

/**
 * Production env pinned to a non-development key id.
 *
 * The key material is still the fixture's public half — that is fine, because
 * every check using this asserts routing or configuration policy, never
 * cryptography. A development key id would trip the earlier dev-key refusal and
 * mask the check actually under test.
 */
function productionTrustEnv(): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "production",
    PORT: "0",
    MANDATEX_FIXTURES_DIR: FIXTURES,
    MANDATEX_TRUST_KEY_ID: "mandatex-verifier-1",
    MANDATEX_TRUST_SPKI_DER_HEX:
      "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    MANDATEX_TRUST_KEY_FINGERPRINT_SHA256:
      "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9",
    MANDATEX_TRUST_POLICY_SHA256:
      "2ce16c724b5e109338301048513e7f31a2216d69f7b01f47512d2c5f4ff7b2a8",
  };
}

/**
 * The subset of valid vectors that forms a legal candidate set.
 *
 * The five valid vectors are each individually valid, but three of them are
 * TTL-boundary variants of the same quote. Core rejects a comparison in which a
 * candidate (chainId + tokenId) or a quote id repeats, so posting all five is a
 * 422 — correctly. Deduplicating on exactly Core's identity rule rather than on
 * vector names keeps this correct if the fixtures are regenerated.
 */
function comparisonSet(vectors: readonly Vector[]): Vector[] {
  const identities = new Set<string>();
  const quoteIds = new Set<string>();
  const set: Vector[] = [];

  for (const vector of vectors) {
    const parsed = JSON.parse(vector.wire) as {
      payload: { candidate: { chainId: number; tokenId: string }; quoteId: string };
    };
    const identity = `${parsed.payload.candidate.chainId}:${parsed.payload.candidate.tokenId}`;
    if (identities.has(identity) || quoteIds.has(parsed.payload.quoteId)) continue;
    identities.add(identity);
    quoteIds.add(parsed.payload.quoteId);
    set.push(vector);
  }
  return set;
}

async function withServer(
  config: AppConfig,
  clock: () => number,
  body: (base: string) => Promise<void>,
): Promise<void> {
  const evaluator = MarketplaceEvaluator.create(config, clock);
  const router = createRouter(config, evaluator);
  const server: Server = createServer((request, response) => {
    void router(request, response).catch(() => response.destroy());
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port assigned");
  try {
    await body(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

async function main(): Promise<void> {
  const validVectors = await loadVectors("valid");
  const invalidVectors = await loadVectors("invalid");

  if (validVectors.length === 0) {
    console.error(
      "no fixture vectors found. Run: node fixtures/attestations/lib/build.mjs",
    );
    process.exit(1);
  }

  console.log(
    `MandateX marketplace API smoke test\n` +
      `${validVectors.length} valid, ${invalidVectors.length} invalid fixture vectors`,
  );

  const anchor = validVectors[0] as Vector;
  const clock = (): number => anchor.evaluatedAt;
  const config = loadConfig(baseEnv());
  const compare = comparisonSet(validVectors);

  console.log(
    `comparison set: ${compare.length} distinct candidates ` +
      `(${validVectors.length - compare.length} valid vectors are same-candidate variants)`,
  );

  // ── Boot guards ───────────────────────────────────────────────────────────
  heading("Boot guards (the trust boundary must be unforgeable by construction)");
  {
    try {
      loadConfig({ ...baseEnv(), NODE_ENV: "production" });
      fail(
        "production boot refuses a development key",
        "loadConfig accepted the publicly-forgeable fixture key for production traffic",
      );
    } catch (cause) {
      check(
        cause instanceof ConfigError && /development key/i.test(cause.message),
        "production boot refuses a development key",
        `expected a ConfigError about the development key, got: ${(cause as Error).message}`,
      );
    }
  }
  {
    // A signing key handed to this process, in a deliberately innocuous name.
    const leaked = {
      ...baseEnv(),
      APP_CREDENTIAL:
        "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    };
    try {
      loadConfig(leaked);
      fail(
        "boot refuses signing authority hidden in an innocuous variable name",
        "loadConfig accepted an environment carrying a PKCS#8 Ed25519 private key",
      );
    } catch (cause) {
      check(
        cause instanceof ConfigError && /signing authority/i.test(cause.message),
        "boot refuses signing authority hidden in an innocuous variable name",
        `expected a ConfigError about signing authority, got: ${(cause as Error).message}`,
      );
    }
  }
  {
    try {
      loadConfig({ ...baseEnv(), SIGNING_KEY: "anything" });
      fail("boot refuses a variable named like signing material", "loadConfig accepted SIGNING_KEY");
    } catch (cause) {
      check(
        cause instanceof ConfigError,
        "boot refuses a variable named like signing material",
        `expected a ConfigError, got: ${(cause as Error).message}`,
      );
    }
  }
  {
    try {
      // A non-development key id, because the development-key refusal fires
      // earlier in loadConfig and would mask the check under test.
      loadConfig({
        ...productionTrustEnv(),
        MANDATEX_VERIFIER_URL: "http://verifier.example.com",
      });
      fail("production refuses a plaintext public verifier URL", "loadConfig accepted http:// in production");
    } catch (cause) {
      check(
        cause instanceof ConfigError && /https/i.test(cause.message),
        "production refuses a plaintext public verifier URL",
        `expected a ConfigError about https, got: ${(cause as Error).message}`,
      );
    }
  }
  {
    const config = loadConfig({
      ...productionTrustEnv(),
      MANDATEX_VERIFIER_URL: "http://mandatex-verifier.railway.internal:8080",
    });
    check(
      config.verifierUrl === "http://mandatex-verifier.railway.internal:8080",
      "production allows plaintext over a *.internal private network address",
      `Railway private networking is plain http, so refusing it would block the ` +
        `two-service deployment; got ${String(config.verifierUrl)}`,
    );
  }

  await withServer(config, clock, async (base) => {
    // ── Service endpoints ───────────────────────────────────────────────────
    heading("Service endpoints");
    {
      const response = await fetch(`${base}/healthz`);
      check(response.status === 200, "GET /healthz returns 200", `got ${response.status}`);
    }
    {
      const response = await fetch(`${base}/v1/trust`);
      const body = (await response.json()) as Record<string, unknown>;
      check(
        response.status === 200 &&
          body.publicKeyFingerprintSha256 === config.trust.publicKeyFingerprintSha256,
        "GET /v1/trust advertises the pinned key fingerprint",
        `got ${response.status} ${JSON.stringify(body).slice(0, 120)}`,
      );
      check(
        body.developmentKey === true && typeof body.warning === "string",
        "GET /v1/trust flags the development key as forgeable",
        "expected developmentKey=true with a warning; a silent dev key is the dangerous case",
      );
    }
    {
      const response = await fetch(`${base}/readyz`);
      const body = (await response.json()) as { checks?: { verifier?: { status?: string } } };
      check(
        response.status === 200 && body.checks?.verifier?.status === "not_configured",
        "GET /readyz is ready with no verifier configured, and says so",
        `got ${response.status}, verifier status ${body.checks?.verifier?.status}`,
      );
    }

    // ── Candidate-set rules ─────────────────────────────────────────────────
    heading("Candidate-set rules are enforced, not silently repaired");
    {
      // All five valid vectors include three TTL variants of the same quote.
      // Each verifies alone; together they are not a legal candidate set. The
      // API must refuse rather than quietly drop duplicates: a comparison that
      // silently returns three rows for five submitted quotes is worse than an
      // error, because the caller cannot tell what was dropped.
      const duplicated = await fetch(`${base}/v1/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          mandate: anchor.mandate,
          attestations: validVectors.map((vector) => vector.wire),
        }),
      });
      const body = (await duplicated.json()) as { error?: { code?: string } };
      check(
        duplicated.status === 422 && body.error?.code === "DUPLICATE_CANDIDATE",
        "a set repeating one candidate is refused with Core's own code",
        `expected 422 DUPLICATE_CANDIDATE, got ${duplicated.status} ${JSON.stringify(body.error)}`,
      );
    }

    // ── Evaluation: the comparison set ──────────────────────────────────────
    heading("Evaluation of the comparison set");
    const response = await fetch(`${base}/v1/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        mandate: anchor.mandate,
        attestations: compare.map((vector) => vector.wire),
      }),
    });
    const view = (await response.json()) as {
      summary?: Record<string, number>;
      candidates?: {
        quoteId: string;
        outcome: string;
        score: {
          discriminatingScoreBps: number;
          discriminatingWeightPoints: number;
          factors: { key: string }[];
          confirmations: { key: string; discriminatingWeight: number }[];
          coreScoreBps: number;
        } | null;
        findings: { code: string; message: string }[];
      }[];
      rankingBasis?: { discriminatingWeightPoints: number; confirmationWeightPoints: number };
      warnings?: string[];
      unverified?: unknown[];
      effect?: string;
      receipt?: unknown;
    };

    if (response.status !== 200) {
      fail(
        "POST /v1/evaluate accepts the comparison set",
        `got ${response.status}: ${JSON.stringify(view).slice(0, 400)}`,
      );
    } else {
      ok("POST /v1/evaluate accepts the comparison set");

      check(
        view.summary?.verified === compare.length && view.summary?.rejectedAtVerification === 0,
        `all ${compare.length} attestations in the comparison set verified through Core`,
        `verified=${view.summary?.verified} rejected=${view.summary?.rejectedAtVerification}`,
      );
      check(
        view.effect === "evaluation_only",
        "the comparison view declares evaluation_only effect",
        `got effect=${view.effect}`,
      );
      check(
        view.receipt !== null && view.receipt !== undefined,
        "the comparison view carries Core's receipt",
        "receipt was absent, so the result is not traceable to an evaluation",
      );
      check(
        (view.warnings ?? []).length === 0,
        "no integrity warnings were raised",
        `warnings: ${JSON.stringify(view.warnings)}`,
      );

      // ── The honesty rule from plan.md §4 ─────────────────────────────────
      heading("Ranking display honesty (plan.md §4)");
      const ranked = (view.candidates ?? []).filter((candidate) => candidate.score !== null);
      check(
        ranked.length > 0,
        "at least one candidate was ranked",
        "nothing was scored, so the honesty rule is untested",
      );

      if (ranked.length > 0) {
        const score = (ranked[0] as { score: NonNullable<(typeof ranked)[0]["score"]> }).score;

        check(
          score.confirmations.length === 2 &&
            score.confirmations.every((entry) => entry.discriminatingWeight === 0),
          "mandateFit and executionReadiness are reported at zero discriminating weight",
          `confirmations: ${JSON.stringify(score.confirmations.map((c) => c.key))}`,
        );
        check(
          score.factors.length === 4,
          "exactly four factors are presented as scoring",
          `scoring factors: ${JSON.stringify(score.factors.map((f) => f.key))}`,
        );
        check(
          score.discriminatingWeightPoints === 50 &&
            view.rankingBasis?.discriminatingWeightPoints === 50 &&
            view.rankingBasis?.confirmationWeightPoints === 50,
          "the 50/50 split between discriminating and pinned weight is stated explicitly",
          `score=${score.discriminatingWeightPoints} basis=${JSON.stringify(view.rankingBasis)}`,
        );

        // The whole point: the pinned factors inflate Core's number, so the two
        // must differ for at least one candidate or the renormalization is a no-op.
        const differs = ranked.some(
          (candidate) =>
            candidate.score !== null &&
            candidate.score.discriminatingScoreBps !== candidate.score.coreScoreBps,
        );
        check(
          differs,
          "the renormalized score differs from Core's six-factor score",
          "every candidate scored identically under both, so the pinned factors are not " +
            "actually inflating the displayed number and this projection is unnecessary",
        );
      }

      // ── Ordering ─────────────────────────────────────────────────────────
      heading("Comparison ordering");
      const outcomes = (view.candidates ?? []).map((candidate) => candidate.outcome);
      const lastEligible = outcomes.lastIndexOf("eligible");
      const firstNonEligible = outcomes.findIndex((outcome) => outcome !== "eligible");
      check(
        firstNonEligible === -1 || lastEligible < firstNonEligible,
        "eligible candidates sort ahead of every non-eligible one",
        `outcome order: ${JSON.stringify(outcomes)}`,
      );

      const scores = ranked.map((candidate) => candidate.score?.discriminatingScoreBps ?? -1);
      const descending = scores.every((value, index) => index === 0 || (scores[index - 1] as number) >= value);
      check(descending, "ranked candidates are ordered best-first", `scores: ${JSON.stringify(scores)}`);
    }

    // ── Per-candidate rejection reasons ─────────────────────────────────────
    heading("Per-candidate verification failures are attributed, not fatal");
    {
      // Filtered to the anchor clock: a vector anchored elsewhere would be
      // rejected for the right reason but the wrong one, making the assertion
      // on predicted codes meaningless.
      const poisoned = invalidVectors
        .filter((vector) => vector.evaluatedAt === anchor.evaluatedAt)
        .slice(0, 3);
      const mixedResponse = await fetch(`${base}/v1/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          mandate: anchor.mandate,
          attestations: [
            ...compare.map((vector) => vector.wire),
            ...poisoned.map((vector) => vector.wire),
          ],
        }),
      });
      const mixed = (await mixedResponse.json()) as {
        summary?: Record<string, number>;
        unverified?: { index: number; code: string }[];
      };

      check(
        mixedResponse.status === 200,
        "a set containing invalid attestations still returns a comparison",
        `got ${mixedResponse.status}: one bad attestation must not fail the whole request`,
      );
      check(
        mixed.summary?.verified === compare.length &&
          mixed.summary?.rejectedAtVerification === poisoned.length,
        `the ${poisoned.length} invalid attestations were isolated from the ${compare.length} valid ones`,
        `verified=${mixed.summary?.verified} rejected=${mixed.summary?.rejectedAtVerification}`,
      );

      const codesMatch = poisoned.every((vector, offset) => {
        const reported = (mixed.unverified ?? []).find(
          (entry) => entry.index === compare.length + offset,
        );
        return vector.expectedCode === undefined || reported?.code === vector.expectedCode;
      });
      check(
        codesMatch,
        "each rejection reports the Core error code its vector predicts",
        `expected ${JSON.stringify(poisoned.map((v) => v.expectedCode))}, ` +
          `got ${JSON.stringify((mixed.unverified ?? []).map((entry) => entry.code))}`,
      );
    }

    // Every-invalid-vector coverage runs after this block: those vectors are
    // anchored to different clocks and need a server per clock.

    // ── Request validation ──────────────────────────────────────────────────
    heading("Request validation");
    const cases: { label: string; body: string; status: number }[] = [
      { label: "rejects a non-object body", body: '"nope"', status: 400 },
      { label: "rejects unknown fields", body: '{"mandate":{},"attestations":[],"extra":1}', status: 400 },
      { label: "rejects an empty attestation array", body: '{"mandate":{},"attestations":[]}', status: 400 },
      {
        label: "rejects a non-string attestation",
        body: '{"mandate":{},"attestations":[{"schema":"x"}]}',
        status: 400,
      },
      { label: "rejects a malformed mandate with 422", body: '{"mandate":{"nope":1},"attestations":["{}"]}', status: 422 },
    ];
    for (const testCase of cases) {
      const result = await fetch(`${base}/v1/evaluate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: testCase.body,
      });
      check(
        result.status === testCase.status,
        testCase.label,
        `expected HTTP ${testCase.status}, got ${result.status}`,
      );
    }

    // ── Fixtures endpoint ───────────────────────────────────────────────────
    heading("Development fixtures endpoint");
    {
      const result = await fetch(`${base}/v1/fixtures`);
      const body = (await result.json()) as { count?: number; warning?: string };
      check(
        result.status === 200 && body.count === validVectors.length,
        "GET /v1/fixtures serves the valid vectors in development",
        `got ${result.status}, count=${body.count}`,
      );
      check(
        typeof body.warning === "string" && /forgeable/i.test(body.warning),
        "GET /v1/fixtures warns that the vectors are forgeable",
        "a fixtures endpoint that does not say so invites treating them as real evidence",
      );
    }
  });

  // ── Every invalid vector, at its own clock ────────────────────────────────
  //
  // Each vector records the `evaluatedAt` it assumes, and the time-rule vectors
  // deliberately assume a different instant from the rest — `expired` sits past
  // its own expiry. Evaluating every vector against one shared clock would accept
  // it, correctly, and quietly turn the most important time-rule vector into a
  // false pass. So vectors are grouped by their clock and each group gets a
  // server whose clock matches.
  heading("Every invalid vector is rejected through the HTTP surface, at its own clock");
  {
    const byClock = new Map<number, Vector[]>();
    for (const vector of invalidVectors) {
      const group = byClock.get(vector.evaluatedAt);
      if (group === undefined) byClock.set(vector.evaluatedAt, [vector]);
      else group.push(vector);
    }

    let leaked = 0;
    let tested = 0;
    const mismatches: string[] = [];

    for (const [evaluatedAt, group] of [...byClock.entries()].sort((a, b) => a[0] - b[0])) {
      await withServer(config, () => evaluatedAt, async (base) => {
        for (const vector of group) {
          tested += 1;
          const each = await fetch(`${base}/v1/evaluate`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ mandate: anchor.mandate, attestations: [vector.wire] }),
          });
          const body = (await each.json()) as {
            summary?: Record<string, number>;
            unverified?: { code: string }[];
          };
          if (each.status !== 200) {
            mismatches.push(`${vector.name}: HTTP ${each.status}`);
            continue;
          }
          if ((body.summary?.verified ?? 0) > 0) {
            leaked += 1;
            mismatches.push(`${vector.name}: ACCEPTED (${vector.attackClass})`);
            continue;
          }
          const reported = body.unverified?.[0]?.code;
          if (vector.expectedCode !== undefined && reported !== vector.expectedCode) {
            mismatches.push(`${vector.name}: expected ${vector.expectedCode}, got ${reported}`);
          }
        }
      });
    }

    check(
      tested === invalidVectors.length,
      `all ${invalidVectors.length} invalid vectors were exercised across ${byClock.size} clock(s)`,
      `only ${tested} were tested`,
    );
    check(
      leaked === 0,
      `no invalid attestation reached the comparison view (${tested} tested)`,
      `${leaked} were accepted: ${mismatches.join("; ")}`,
    );
    check(
      mismatches.length === 0,
      "every rejection surfaced the predicted error code over HTTP",
      mismatches.join("; "),
    );
  }

  // ── Production hides fixtures ────────────────────────────────────────────
  heading("Production posture");
  {
    const productionConfig = loadConfig(productionTrustEnv());
    check(
      productionConfig.exposeFixtures === false,
      "production configuration does not expose fixtures",
      "exposeFixtures was true in production",
    );

    await withServer(productionConfig, clock, async (base) => {
      const result = await fetch(`${base}/v1/fixtures`);
      check(result.status === 404, "GET /v1/fixtures is 404 in production", `got ${result.status}`);
    });
  }

  // ── Summary ──────────────────────────────────────────────────────────────
  console.log(`\n${"-".repeat(70)}`);
  console.log(`passed: ${passed}   failed: ${failures.length}`);
  if (failures.length > 0) {
    console.log("\nFAILURES");
    for (const failure of failures) console.log(`  ${failure}`);
    process.exit(1);
  }
  console.log("\nAll checks passed: the API surface conforms to the real verifier and Core.");
}

await main();
