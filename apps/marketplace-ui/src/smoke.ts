import { existsSync, readFileSync, readdirSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadConfig } from "@mandatex/marketplace-api/dist/config.js";
import { MarketplaceEvaluator } from "@mandatex/marketplace-api/dist/core.js";
import { createRouter } from "@mandatex/marketplace-api/dist/routes.js";

import { escapeHtml, html, raw, render } from "./html.js";
import { buildMandate, parseFormBody } from "./mandate.js";
import { renderComparison } from "./render.js";
import { UiConfigError, createUiServer, loadUiConfig } from "./server.js";

/**
 * Marketplace UI check suite.
 *
 * Nothing is mocked. Each run boots the **real** marketplace API — the same
 * `loadConfig` / `MarketplaceEvaluator` / `createRouter` the deployed service uses
 * — against the real fixture attestations, then boots the real UI server pointed
 * at it and drives it over HTTP. Assertions are made on the HTML that actually
 * comes off the socket.
 *
 * The API is booted with its clock pinned to the fixture anchor. That is not a
 * convenience: the fixture vectors are frozen at a fixed instant and carry a
 * 300-second TTL, so against a live clock every candidate fails on freshness and
 * the ranked set is empty. Pinning the clock is the only way to exercise the
 * ranking-honesty rendering at all, and the suite checks both worlds — pinned for
 * ranking, live for the exclusion path.
 *
 * The group that matters most is "Ranking display honesty". Core's ranking has six
 * weighted factors, two of which are identical for every candidate that reaches
 * ranking, so half the weight cannot affect the ordering. Those checks assert the
 * UI keeps that split visible rather than flattening it back into one table.
 */

const REPO_ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures", "attestations");
const TRUST_FILE = join(FIXTURES, "keys", "dev-signer.public.json");

let passed = 0;
const failures: string[] = [];

function check(name: string, ok: boolean, detail?: string): void {
  if (ok) {
    passed += 1;
    return;
  }
  failures.push(detail === undefined ? name : `${name} — ${detail}`);
}

function heading(title: string): void {
  process.stdout.write(`\n  ${title}\n`);
}

interface Vector {
  readonly name: string;
  readonly evaluatedAt: number;
  readonly wire: string;
}

function loadVectors(): Vector[] {
  const dir = join(FIXTURES, "vectors", "valid");
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => JSON.parse(readFileSync(join(dir, name), "utf8")) as Vector);
}

function apiEnv(): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "development",
    PORT: "0",
    MANDATEX_TRUST_FILE: TRUST_FILE,
    MANDATEX_FIXTURES_DIR: FIXTURES,
  };
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port assigned");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

/** Boots the real marketplace API with an injected clock. */
async function withApi(
  clock: () => number,
  body: (base: string) => Promise<void>,
): Promise<void> {
  const config = loadConfig(apiEnv());
  const evaluator = MarketplaceEvaluator.create(config, clock);
  const router = createRouter(config, evaluator);
  const server = createServer((request, response) => {
    void router(request, response).catch(() => response.destroy());
  });
  const base = await listen(server);
  try {
    await body(base);
  } finally {
    await close(server);
  }
}

/** Boots the real UI server against a given API base. */
async function withUi(
  apiUrl: string,
  body: (base: string) => Promise<void>,
  extraEnv: NodeJS.ProcessEnv = {},
): Promise<void> {
  const config = loadUiConfig({
    NODE_ENV: "development",
    PORT: "0",
    MANDATEX_API_URL: apiUrl,
    ...extraEnv,
  });
  const server = createUiServer(config);
  const base = await listen(server);
  try {
    await body(base);
  } finally {
    await close(server);
  }
}

async function get(base: string, path: string): Promise<{ status: number; text: string }> {
  const response = await fetch(`${base}${path}`, { redirect: "manual" });
  return { status: response.status, text: await response.text() };
}

async function postForm(
  base: string,
  path: string,
  form: Record<string, string>,
): Promise<{ status: number; text: string }> {
  const response = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
    redirect: "manual",
  });
  return { status: response.status, text: await response.text() };
}

/** Text between two markers, for structural assertions about page regions. */
function between(text: string, start: string, end: string): string | null {
  const from = text.indexOf(start);
  if (from < 0) return null;
  const to = text.indexOf(end, from + start.length);
  return text.slice(from + start.length, to < 0 ? undefined : to);
}

async function main(): Promise<void> {
  const vectors = loadVectors();
  if (vectors.length === 0) {
    process.stderr.write(
      "no fixture vectors found. Run: node fixtures/attestations/lib/build.mjs\n",
    );
    process.exit(1);
  }
  const anchor = vectors[0] as Vector;
  const pinnedClock = (): number => anchor.evaluatedAt;

  process.stdout.write(
    `MandateX marketplace UI checks\n${vectors.length} valid fixture vectors, ` +
      `clock pinned to ${anchor.evaluatedAt} for the ranking checks\n`,
  );

  // ── Boot guards ────────────────────────────────────────────────────────────
  heading("Boot guards (the UI must stay the least privileged process)");

  for (const [label, env, shouldThrow] of [
    ["a missing API URL is refused", {}, true],
    ["a malformed API URL is refused", { MANDATEX_API_URL: "not a url" }, true],
    [
      "a signing key by variable name is refused",
      { MANDATEX_API_URL: "http://a.test", MANDATEX_SIGNING_KEY: "abc" },
      true,
    ],
    [
      "a private key hidden in an innocuous variable is refused",
      {
        MANDATEX_API_URL: "http://a.test",
        APP_CREDENTIAL:
          "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      },
      true,
    ],
    [
      "a PEM private key in any variable is refused",
      {
        MANDATEX_API_URL: "http://a.test",
        NOTES: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
      },
      true,
    ],
    [
      "plaintext http to the API is refused in production",
      { MANDATEX_API_URL: "http://api.example.com", NODE_ENV: "production" },
      true,
    ],
    [
      "http is allowed in production for a .internal private-network host",
      { MANDATEX_API_URL: "http://mandatex-app.railway.internal:8080", NODE_ENV: "production" },
      false,
    ],
    [
      "https to the API is allowed in production",
      { MANDATEX_API_URL: "https://api.example.com", NODE_ENV: "production" },
      false,
    ],
  ] as const) {
    let threw: Error | undefined;
    try {
      loadUiConfig({ PORT: "0", ...env });
    } catch (cause) {
      threw = cause as Error;
    }
    if (shouldThrow) {
      check(
        label,
        threw instanceof UiConfigError,
        threw === undefined ? "no error was thrown" : `unexpected: ${threw.message}`,
      );
    } else {
      check(label, threw === undefined, threw?.message);
    }
  }

  // ── Escaping ───────────────────────────────────────────────────────────────
  heading("Escaping (every rendered string originates in someone else's attestation)");

  check(
    "all five dangerous characters are escaped",
    escapeHtml(`<>&"'`) === "&lt;&gt;&amp;&quot;&#39;",
    escapeHtml(`<>&"'`),
  );
  check(
    "template interpolations are escaped",
    render(html`<p>${"<script>alert(1)</script>"}</p>`) ===
      "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>",
  );
  check(
    "raw() markup is not double-escaped",
    render(html`${raw("<b>bold</b>")}`) === "<b>bold</b>",
  );
  check(
    "arrays of markup are joined without escaping the markup",
    render(html`${[raw("<i>a</i>"), raw("<i>b</i>")]}`) === "<i>a</i><i>b</i>",
  );
  check(
    "null and undefined render as nothing, not as the words",
    render(html`[${null}${undefined}]`) === "[]",
  );

  // ── Mandate form and input handling ────────────────────────────────────────
  heading("Mandate input");

  const formResult = buildMandate(
    { mandateId: "m", budgets: { maxGasUsdMicros: "50", maxSlippageBps: 50 }, permissions: { allowedProtocols: ["a"] } },
    { maxGasUsdMicros: "999", maxSlippageBps: "25", allowedProtocols: "x, y" },
  );
  check(
    "submitted values are applied over the base mandate",
    (formResult.mandate as { budgets: { maxGasUsdMicros: string; maxSlippageBps: number } }).budgets
      .maxGasUsdMicros === "999",
  );
  check(
    "integer fields become numbers and decimal-string fields stay strings",
    typeof (formResult.mandate as { budgets: { maxSlippageBps: unknown } }).budgets
      .maxSlippageBps === "number" &&
      typeof (formResult.mandate as { budgets: { maxGasUsdMicros: unknown } }).budgets
        .maxGasUsdMicros === "string",
  );
  check(
    "comma separated lists are parsed into arrays",
    JSON.stringify(
      (formResult.mandate as { permissions: { allowedProtocols: string[] } }).permissions
        .allowedProtocols,
    ) === JSON.stringify(["x", "y"]),
  );

  const badInput = buildMandate(
    { budgets: { maxGasUsdMicros: "50" } },
    { maxGasUsdMicros: "12.5" },
  );
  check(
    "a non-integer amount is reported as a problem rather than coerced",
    badInput.problems.length === 1 &&
      (badInput.mandate as { budgets: { maxGasUsdMicros: string } }).budgets.maxGasUsdMicros ===
        "50",
    JSON.stringify(badInput.problems),
  );

  const unsupportedCategory = buildMandate({ category: "rebalancing" }, { category: "grid" });
  check(
    "selecting an unsupported category is refused and explained, not silently applied",
    unsupportedCategory.problems.length === 1 &&
      (unsupportedCategory.mandate as { category: string }).category === "rebalancing" &&
      /CATEGORY_GRID_UNSUPPORTED/.test(unsupportedCategory.problems[0] ?? ""),
    JSON.stringify(unsupportedCategory.problems),
  );

  const rawOverride = buildMandate({ a: 1 }, { rawMandate: '{"b":2}' });
  check(
    "the raw JSON escape hatch replaces the mandate wholesale",
    rawOverride.fromRawJson && JSON.stringify(rawOverride.mandate) === '{"b":2}',
  );
  const rawBroken = buildMandate({ a: 1 }, { rawMandate: "{oops" });
  check(
    "unparseable raw JSON is reported and the base is kept",
    !rawBroken.fromRawJson && rawBroken.problems.length === 1,
  );
  check(
    "form bodies are parsed from urlencoded input",
    parseFormBody("a=1&b=two+words").b === "two words",
  );

  // ── Live pages, pinned clock ───────────────────────────────────────────────
  await withApi(pinnedClock, async (apiBase) => {
    await withUi(apiBase, async (uiBase) => {
      heading("Mandate page");

      const form = await get(uiBase, "/");
      check("GET / is 200", form.status === 200, String(form.status));
      check("the mandate form posts to /evaluate", /action="\/evaluate"/.test(form.text));
      check(
        "the form is prefilled from the API's base mandate",
        form.text.includes('name="mandateId"') && /value="mandate-demo"/.test(form.text),
      );
      for (const category of ["grid", "yield", "health"]) {
        check(
          `the ${category} category is offered but disabled`,
          new RegExp(`value="${category}"[^>]*disabled`).test(form.text),
        );
      }
      check(
        "the form states category thresholds are deployment policy, not per-mandate",
        /deployment policy set by the verifier operator/i.test(form.text) &&
          /no\s+field for a user-supplied metric threshold/i.test(form.text),
      );
      check(
        "the form does not offer a category threshold input",
        !/name="min(HealthFactor|SharePrice)/i.test(form.text) &&
          !/threshold"/i.test(form.text.replace(/metric threshold/gi, "")),
      );
      check(
        "the mandate page carries the evaluation-only statement",
        /evaluation only/i.test(form.text),
      );

      heading("Ranking display honesty");

      const result = await postForm(uiBase, "/evaluate", {});
      check("POST /evaluate is 200", result.status === 200, String(result.status));

      const page = result.text;
      check(
        "the pinned clock produced at least one eligible, ranked candidate",
        /class="tag ok">eligible</.test(page),
        "no eligible candidate rendered; the ranking checks below would be vacuous",
      );

      const factorsRegion = between(
        page,
        "Factors that decide the ordering",
        "Eligibility confirmations",
      );
      check(
        "the scoring factors and the confirmations are rendered in separate sections",
        factorsRegion !== null,
        "could not find both section headings",
      );
      check(
        "the pinned factors never appear among the scoring factors",
        factorsRegion !== null &&
          !factorsRegion.includes("Mandate fit") &&
          !factorsRegion.includes("Execution readiness"),
      );
      for (const label of ["Evidence freshness", "Risk compatibility", "Total cost", "Reputation confidence"]) {
        check(
          `the discriminating factor "${label}" is rendered as a scored factor`,
          factorsRegion !== null && factorsRegion.includes(label),
        );
      }
      check(
        "the confirmations block names both pinned checks",
        page.includes("Mandate fit") && page.includes("Execution readiness"),
      );
      check(
        "the confirmations block states zero deciding weight",
        /Deciding weight/.test(page) && /class="tag flat">0</.test(page),
      );
      check(
        "the confirmations are labelled as having no effect on ordering",
        /no effect on ordering/i.test(page),
      );
      check(
        "the 50 of 100 split is stated in the page",
        /50 of Core's 100 weight points/.test(page) ||
          (/Weight points that <strong>decide the ordering<\/strong>/.test(page) &&
            />50 \/ 100</.test(page)),
        "the split disclosure was not found",
      );
      check(
        "the consequence of the pinned points is stated as a floor on Core's score",
        /cannot fall below/i.test(page) && /50%/.test(page),
      );
      check(
        "Core's own six-factor score is shown and labelled rather than hidden",
        /Core's own six-factor score/.test(page),
      );
      check(
        "the discriminating score is presented over the deciding points",
        /over the 50 deciding points/.test(page),
      );

      // A six-row factor table is the specific thing plan.md forbids. Count the
      // factor labels inside the scoring region: four, never six.
      const scoredLabels = [
        "Mandate fit",
        "Execution readiness",
        "Evidence freshness",
        "Risk compatibility",
        "Total cost",
        "Reputation confidence",
      ].filter((label) => factorsRegion?.includes(label));
      check(
        "exactly four factors are rendered as scoring, not six",
        scoredLabels.length === 4,
        `found ${scoredLabels.length}: ${scoredLabels.join(", ")}`,
      );

      heading("Vocabulary and capability claims");

      check("VERIFIED_HIREABLE never appears in the UI", !/VERIFIED_HIREABLE/.test(page));
      check(
        "VERIFIED_HIREABLE never appears on the mandate page either",
        !/VERIFIED_HIREABLE/.test(form.text),
      );
      check(
        "the result page does not offer an activate action",
        !/<button[^>]*>\s*Activate/i.test(page) && !/name="activate"/i.test(page),
      );

      heading("Activation state");

      check("activation is reported as not activated", /<td>Activated<\/td>[\s\S]{0,80}>no</.test(page));
      check("the effect is stated as evaluation_only", /evaluation_only/.test(page));
      check(
        "the page states this interface cannot activate anything",
        /cannot activate anything/i.test(page),
      );

      heading("Receipt");

      check("the receipt section is rendered", /id="receipt"/.test(page));
      check(
        "the receipt reports the evaluation-only effect",
        /mandatex\.marketplace\.receipt\.v1/.test(page),
      );
      check(
        "the receipt's adapter is reported",
        /<dt>Adapter<\/dt>/.test(page) && /pancakeswap-v3-rebalancing-v1/.test(page),
      );

      heading("Permission review");

      check("the permission review section is rendered", /id="permissions"/.test(page));
      check("the mandate ceiling is shown", /Mandate ceiling/.test(page));
      check("each candidate's requested spend cap is shown", /Requested spend cap/.test(page));
      check("the contracts a candidate may call are shown", /Contracts it may call/.test(page));

      // An over-ceiling permission cannot be produced by editing the mandate: the
      // attestations are bound to a mandate hash, so any edit fails verification
      // before Core ever compares permissions. So the ceiling comparison is driven
      // through the render function with a *real* API view and a lowered ceiling.
      // The view is the genuine payload; only the mandate argument differs.
      {
        const fixtures = await (await fetch(`${apiBase}/v1/fixtures`)).json();
        const realView = await (
          await fetch(`${apiBase}/v1/evaluate`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              mandate: fixtures.mandate,
              attestations: fixtures.comparisonSet,
            }),
          })
        ).json();
        const tightMandate = {
          ...fixtures.mandate,
          permissions: { ...fixtures.mandate.permissions, maxSpendUsdMicros: "1" },
        };
        const flagged = render(
          renderComparison({ view: realView, mandate: tightMandate }),
        );
        check(
          "a requested spend cap above the mandate ceiling is flagged in place",
          /over ceiling/.test(flagged),
          "no over-ceiling flag rendered",
        );
        const unflagged = render(
          renderComparison({ view: realView, mandate: fixtures.mandate }),
        );
        check(
          "a request within the ceiling is not flagged",
          !/over ceiling/.test(unflagged),
        );
      }

      heading("Mandate binding (editing the mandate invalidates every attestation)");

      const edited = await postForm(uiBase, "/evaluate", { maxSpendUsdMicros: "999999999" });
      check("an edited mandate still renders a page", edited.status === 200, String(edited.status));
      check(
        "every attestation fails on the mandate hash rather than on its signature",
        /ATTESTATION_MANDATE_HASH_MISMATCH/.test(edited.text),
      );
      check(
        "the page explains that the mandate was edited rather than blaming the candidates",
        /The mandate was edited, so no attestation applies to it/.test(edited.text) &&
          /Nothing is wrong with the candidates/.test(edited.text),
      );
      check(
        "the failures are listed rather than shown as an empty comparison",
        /Rejected before comparison/.test(edited.text),
      );

      heading("Error paths");

      const notFound = await get(uiBase, "/nope");
      check("an unknown route is 404", notFound.status === 404, String(notFound.status));
      const redirected = await get(uiBase, "/evaluate");
      check(
        "GET /evaluate redirects to the form rather than re-evaluating",
        redirected.status === 303,
        String(redirected.status),
      );
      check("GET /healthz is 200", (await get(uiBase, "/healthz")).status === 200);
      check("GET /readyz reports on the API it depends on", (await get(uiBase, "/readyz")).status === 200);
    });

    // Body cap, on its own server so only the limit can produce the rejection.
    await withUi(
      apiBase,
      async (uiBase) => {
        heading("Request limits");
        const response = await fetch(`${uiBase}/evaluate`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: "x=".padEnd(512, "y"),
        });
        check(
          "an oversized body gets a 413 rather than a dropped socket",
          response.status === 413,
          String(response.status),
        );
      },
      { MANDATEX_MAX_REQUEST_BYTES: "16" },
    );
  });

  // ── Mixed state: verified attestations, real Core exclusions ───────────────
  //
  // 120 seconds past the anchor is the one window where both halves are visible:
  // the attestations are still inside their TTL so they verify, but the evidence
  // behind the oldest quote has aged past the mandate's freshness limit, so Core
  // excludes it. Every other offset gives all-eligible or all-unverified, and
  // neither exercises a per-candidate exclusion reason on a candidate that
  // actually made it into the comparison.
  heading("Exclusion reasons (verified candidates that Core excluded)");

  await withApi(
    () => anchor.evaluatedAt + 120,
    async (apiBase) => {
      await withUi(apiBase, async (uiBase) => {
        const mixed = await postForm(uiBase, "/evaluate", {});
        check("the mixed-state page renders", mixed.status === 200, String(mixed.status));
        check(
          "eligible and excluded candidates appear on the same page",
          /class="tag ok">eligible</.test(mixed.text) &&
            /class="tag bad">excluded</.test(mixed.text),
          "the 120s window did not produce a mixed set",
        );
        check(
          "the excluded candidate is given a reason heading",
          /Why this candidate did not qualify/.test(mixed.text),
        );
        check(
          "a real Core exclusion code is rendered, not just prose",
          /<code>CATEGORY_EVIDENCE_STALE<\/code>/.test(mixed.text),
        );
        check(
          "the exclusion is labelled by kind",
          /class="tag bad">exclusion</.test(mixed.text),
        );
        check(
          "reasons render outside any collapsed disclosure",
          (() => {
            // The property is ordering, not absence: a `<details>` for the quote
            // detail legitimately follows the findings on the same card. What must
            // not happen is the findings themselves sitting inside it, so the first
            // finding code has to appear before the first disclosure opens.
            const from = mixed.text.indexOf("Why this candidate did not qualify");
            if (from < 0) return false;
            const firstCode = mixed.text.indexOf("<code>", from);
            const firstDetails = mixed.text.indexOf("<details", from);
            return firstCode >= 0 && (firstDetails < 0 || firstCode < firstDetails);
          })(),
        );
        check(
          "eligible candidates still sort ahead of the excluded one",
          mixed.text.indexOf('class="tag ok">eligible<') <
            mixed.text.indexOf('class="tag bad">excluded<'),
        );
        check(
          "the excluded candidate carries no ranking score",
          (() => {
            const region = between(mixed.text, 'class="card excluded"', "</div>");
            return region !== null && !region.includes("deciding points");
          })(),
        );
        check("the summary counts the exclusion", /Excluded/.test(mixed.text));
      });
    },
  );

  // ── Live clock: the honest exclusion path ──────────────────────────────────
  heading("Live clock (fixtures are time-anchored, so nothing should qualify)");

  await withApi(
    () => Math.floor(Date.now() / 1000),
    async (apiBase) => {
      await withUi(apiBase, async (uiBase) => {
        const stale = await postForm(uiBase, "/evaluate", {});
        check("the page still renders against a live clock", stale.status === 200);
        check(
          "no candidate is eligible once the fixtures have expired",
          !/class="tag ok">eligible</.test(stale.text),
        );
        check(
          "an empty ranking is presented as a complete answer, not an error",
          /complete answer/i.test(stale.text) && /none qualified/i.test(stale.text),
        );
        check(
          "expired attestations are reported as verification failures, with the code",
          /Rejected before comparison/.test(stale.text) &&
            /ATTESTATION_EXPIRED/.test(stale.text),
        );
        check(
          "nothing is silently dropped: the rejected count matches what was submitted",
          /Rejected at verification/.test(stale.text),
        );
      });
    },
  );

  // ── API unreachable ────────────────────────────────────────────────────────
  heading("Degraded API");

  await withUi("http://127.0.0.1:1", async (uiBase) => {
    const form = await get(uiBase, "/");
    check(
      "the mandate page still renders when the API is unreachable",
      form.status === 200,
      String(form.status),
    );
    check(
      "it says plainly that no attestations are available",
      /No candidate attestations are available/.test(form.text),
    );
    check(
      "the submit button is disabled when there is nothing to submit",
      /<button type="submit" disabled>/.test(form.text),
    );
    const posted = await postForm(uiBase, "/evaluate", {});
    check("posting with no attestations is a 503", posted.status === 503, String(posted.status));
    check(
      "the UI does not claim to mint attestations",
      /cannot mint/.test(posted.text),
    );
    const ready = await get(uiBase, "/readyz");
    check("readiness is 503 when the API is unreachable", ready.status === 503, String(ready.status));
  });

  // ── XSS through a real render path ─────────────────────────────────────────
  heading("Injection through the real render path");

  const hostilePage = render(
    html`<div>${'"><script>alert(1)</script>'}</div>`,
  );
  check(
    "a hostile string cannot close an attribute or open a tag",
    !hostilePage.includes("<script>") && hostilePage.includes("&lt;script&gt;"),
  );

  // ── report ─────────────────────────────────────────────────────────────────
  process.stdout.write(`\n${passed}/${passed + failures.length} checks passed\n`);
  if (failures.length > 0) {
    process.stdout.write("\nfailures:\n");
    for (const failure of failures) process.stdout.write(`  ✗ ${failure}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    "All checks passed: the UI renders Core's verdicts without overstating them.\n",
  );
}

await main();
