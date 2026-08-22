import type {
  ComparisonView,
  DisplayCandidate,
  DisplayConfirmation,
  DisplayFactor,
  DisplayFinding,
} from "./api.js";
import { bps, html, instant, raw, usdMicros, type Html } from "./html.js";
import {
  type CategoryOption,
  MANDATE_FIELDS,
  fieldValue,
  type MandateField,
} from "./mandate.js";
import { sectionNav } from "./page.js";

/** Safe field access into the untyped quote/receipt payloads. */
function at(source: unknown, ...path: readonly string[]): unknown {
  let cursor: unknown = source;
  for (const key of path) {
    if (typeof cursor !== "object" || cursor === null) return undefined;
    cursor = (cursor as Record<string, unknown>)[key];
  }
  return cursor;
}

function list(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

const FACTOR_LABELS: Readonly<Record<string, string>> = Object.freeze({
  mandateFit: "Mandate fit",
  executionReadiness: "Execution readiness",
  evidenceFreshness: "Evidence freshness",
  riskCompatibility: "Risk compatibility",
  totalCost: "Total cost",
  reputationConfidence: "Reputation confidence",
});

function factorLabel(key: string): string {
  return FACTOR_LABELS[key] ?? key;
}

const OUTCOME_TAG: Readonly<Record<string, string>> = Object.freeze({
  eligible: "ok",
  excluded: "bad",
  inconclusive: "warn",
  unsupported: "flat",
});

// ── mandate form ─────────────────────────────────────────────────────────────

export function renderMandateForm(input: {
  readonly mandate: unknown;
  readonly attestationCount: number;
  readonly apiBase: string;
  readonly fixturesAvailable: boolean;
  readonly fixtureWarning?: string;
  readonly problems?: readonly string[];
  readonly notice?: string;
  /** Core's category policy, derived via GET /v1/categories. */
  readonly categoryOptions: readonly CategoryOption[];
}): Html {
  return html`
    <h1>Hire an agent under a mandate</h1>
    <p class="sub">
      Submit a mandate; the marketplace verifies each candidate's signed evaluation
      attestation, then ranks the ones that qualify and states why the rest did not.
    </p>

    ${input.notice === undefined ? null : html`<div class="banner info" role="status">${input.notice}</div>`}
    ${(input.problems ?? []).length === 0
      ? null
      : html`<div class="banner bad" role="alert">
          <strong>The mandate was not submitted as typed.</strong>
          <ul class="plain">
            ${(input.problems ?? []).map((problem) => html`<li>${problem}</li>`)}
          </ul>
        </div>`}

    ${input.fixturesAvailable
      ? html`<div class="banner">
          <strong>Development fixtures.</strong>
          ${input.fixtureWarning ??
          "These attestations are signed by a publicly committed key and are forgeable."}
          ${input.attestationCount} candidate attestation${raw(
            input.attestationCount === 1 ? "" : "s",
          )}
          will be submitted with this mandate.
        </div>`
      : html`<div class="banner bad" role="alert">
          <strong>No candidate attestations are available.</strong>
          This UI does not mint attestations. It submits ones issued by the verifier.
          The marketplace API at <span class="mono">${input.apiBase}</span> is not serving
          development fixtures, which is correct in production, so there is nothing to
          compare until a verifier supplies real attestations.
        </div>`}

    <form method="post" action="/evaluate">
      <div class="panel">
        <h3>Mandate</h3>
        <div class="grid">
          <div class="span-2">
            <label for="category">Category</label>
            <select id="category" name="category">
              ${input.categoryOptions.map(
                (option) => html`<option
                  value="${option.value}"
                  ${raw(option.supported ? "" : "disabled")}
                  ${raw(
                    option.value === String(at(input.mandate, "category") ?? "")
                      ? "selected"
                      : "",
                  )}
                >
                  ${option.label}
                </option>`,
              )}
            </select>
          </div>
          ${MANDATE_FIELDS.map((field) => renderField(field, input.mandate))}
        </div>
      </div>

      <div class="panel">
        <h3>Editing this mandate invalidates the attestations</h3>
        <p class="soft" style="font-size:13px">
          Each attestation commits to the hash of the exact mandate it was issued for. Change
          any field above and every candidate will fail verification with
          <code>ATTESTATION_MANDATE_HASH_MISMATCH</code>. Not because the agent did anything
          wrong, but because the evidence it signed no longer describes what is being asked.
        </p>
        <p class="soft" style="font-size:13px">
          That binding is the point: it is what stops a mandate being swapped after quotes are
          collected. To evaluate a different mandate, the verifier has to re-issue attestations
          against it. The fields are left editable because seeing that failure is a more useful
          demonstration of the trust model than a form that cannot be touched.
        </p>
      </div>

      <div class="panel">
        <h3>Category coverage</h3>
        <p class="soft" style="font-size:13px">
          Only <strong>rebalancing</strong> is evaluable today. Marketplace Core reports
          grid, yield and lending health as unsupported, so they are listed above but
          cannot be selected. Offering them would return a category mismatch against the
          rebalancing quotes that do exist, which reads like a different fault.
        </p>
        <p class="soft" style="font-size:13px">
          Telemetry adapters for those three categories exist as evidence producers but are
          not registered in Core. When they are, their metric thresholds will be
          <strong>deployment policy set by the verifier operator, identical for every
          mandate in a category</strong>, not a per-mandate value. The mandate schema has no
          field for a user-supplied metric threshold, so this form deliberately does not
          offer one.
        </p>
      </div>

      <details class="panel">
        <summary class="soft" style="cursor:pointer;font-size:13px">
          Advanced: submit a raw mandate JSON instead
        </summary>
        <p id="rawMandate-hint" class="soft" style="font-size:12.5px;margin-top:10px">
          Overrides every field above. The base mandate below is the one the API's fixture
          bundle ships, whose timestamps are consistent with the frozen fixture clock.
        </p>
        <!-- The label is visually hidden rather than absent. Sighted users get the
             field's purpose from the summary and paragraph above it; a screen reader
             reaching this control by tab order gets neither, and would hear only
             "edit text, blank". A control with no accessible name is a WCAG 4.1.2
             failure, and this is the one field that rewrites the entire mandate. -->
        <label for="rawMandate" class="sr-only">Raw mandate JSON</label>
        <textarea
          id="rawMandate"
          name="rawMandate"
          spellcheck="false"
          aria-describedby="rawMandate-hint"
          placeholder="${"Leave empty to use the fields above"}"
        ></textarea>
      </details>

      <div class="row">
        <button type="submit"${raw(input.attestationCount === 0 ? " disabled" : "")}>
          Evaluate candidates
        </button>
        <span class="faint" style="font-size:12.5px">
          Evaluation only. Nothing is signed, funded, settled or broadcast.
        </span>
      </div>
    </form>

    <h2>Base mandate</h2>
    <div class="panel"><pre>${JSON.stringify(input.mandate, null, 2)}</pre></div>
  `;
}

/**
 * One editable mandate field.
 *
 * The hint is wired to the input with `aria-describedby` rather than merely
 * sitting next to it. Visually the association is obvious from proximity; to a
 * screen reader an unassociated `<div>` is unrelated content, so a user would
 * hear "Max agent fee, edit text" and never hear "USD micros" — which is the part
 * that tells them what to type. Nine of these fields carry a unit or a
 * consequence in the hint, so the association is load-bearing, not decorative.
 */
function renderField(field: MandateField, mandate: unknown): Html {
  const hintId = `${field.name}-hint`;
  return html`<div>
    <label for="${field.name}">${field.label}</label>
    <input
      id="${field.name}"
      name="${field.name}"
      value="${fieldValue(mandate, field)}"
      spellcheck="false"
      ${raw(field.hint === undefined ? "" : `aria-describedby="${hintId}"`)}
      ${raw(field.kind === "integer" ? 'inputmode="numeric"' : "")}
    />
    ${field.hint === undefined
      ? null
      : html`<div id="${hintId}" class="faint" style="font-size:11.5px;margin-top:2px">
          ${field.hint}
        </div>`}
  </div>`;
}

// ── comparison ───────────────────────────────────────────────────────────────

export function renderComparison(input: {
  readonly view: ComparisonView;
  readonly mandate: unknown;
  readonly problems?: readonly string[];
}): Html {
  const view = input.view;
  const eligible = view.candidates.filter((candidate) => candidate.outcome === "eligible");
  const rest = view.candidates.filter((candidate) => candidate.outcome !== "eligible");

  return html`
    <h1>Comparison</h1>
    <dl class="meta">
      <div><dt>Mandate</dt><dd class="mono">${view.mandateId.length > 0 ? view.mandateId : "-"}</dd></div>
      <div><dt>Category</dt><dd class="mono">${view.category.length > 0 ? view.category : "-"}</dd></div>
      <div><dt>Evaluated</dt><dd class="mono">${instant(view.evaluatedAt)}</dd></div>
      <div><dt>Effect</dt><dd><span class="tag flat">${view.effect}</span></dd></div>
    </dl>

    ${renderMandateBindingNotice(view)}

    ${(input.problems ?? []).length === 0
      ? null
      : html`<div class="banner bad" role="alert">
          <ul class="plain">${(input.problems ?? []).map((p) => html`<li>${p}</li>`)}</ul>
        </div>`}

    ${view.warnings.length === 0
      ? null
      : html`<div class="banner bad" role="alert">
          <strong>Integrity notices from the marketplace API.</strong>
          <ul class="plain">${view.warnings.map((w) => html`<li>${w}</li>`)}</ul>
        </div>`}

    ${sectionNav()}
    ${renderSummary(view)}
    <div id="basis"></div>
    ${renderRankingBasis(view)}

    <h2 id="ranked">Ranked candidates${raw(eligible.length === 0 ? ": none qualified" : "")}</h2>
    ${eligible.length === 0
      ? html`<div class="panel soft" style="font-size:13.5px">
          No candidate is eligible under this mandate. Every submitted candidate is listed
          below with the reason it did not qualify. An empty ranking is a complete answer,
          not an error.
        </div>`
      : eligible.map((candidate, index) => renderCandidate(candidate, index + 1))}

    ${rest.length === 0
      ? null
      : html`<h2>Not eligible (${rest.length})</h2>
          ${rest.map((candidate) => renderCandidate(candidate, null))}`}

    ${renderUnverified(view)}
    ${renderPermissionReview(view, input.mandate)}
    ${renderActivation(view)}
    ${renderReceipt(view)}

    <div class="row"><a href="/" class="mono" style="font-size:13px">← revise the mandate</a></div>
  `;
}

/**
 * Explains the one failure mode a user is most likely to cause themselves.
 *
 * An attestation commits to the hash of the mandate it was issued for, so editing
 * any mandate field makes every candidate fail verification. Without this notice
 * the page would show three verification failures and no candidates, which reads
 * as "the agents are broken" rather than "you changed the question after they
 * answered it".
 */
function renderMandateBindingNotice(view: ComparisonView): Html {
  if (view.candidates.length > 0 || view.unverified.length === 0) return raw("");
  const codes = view.unverified.map((entry) =>
    String((entry as unknown as Record<string, unknown>).code ?? ""),
  );
  if (!codes.every((code) => code === "ATTESTATION_MANDATE_HASH_MISMATCH")) return raw("");
  return html`<div class="banner" role="status">
    <strong>The mandate was edited, so no attestation applies to it.</strong>
    Every candidate failed with <code>ATTESTATION_MANDATE_HASH_MISMATCH</code>: each attestation
    commits to the hash of the exact mandate it was issued for, and this one no longer matches.
    Nothing is wrong with the candidates. The mandate they answered is not the mandate that was
    submitted. Revert the fields, or have the verifier re-issue attestations against the new
    mandate.
  </div>`;
}

function renderSummary(view: ComparisonView): Html {
  const s = view.summary;
  const cells: readonly (readonly [string, number, string])[] = [
    ["Submitted", s.submitted, "flat"],
    ["Verified", s.verified, "flat"],
    ["Rejected at verification", s.rejectedAtVerification, s.rejectedAtVerification > 0 ? "bad" : "flat"],
    ["Eligible", s.eligible, s.eligible > 0 ? "ok" : "flat"],
    ["Excluded", s.excluded, s.excluded > 0 ? "bad" : "flat"],
    ["Inconclusive", s.inconclusive, s.inconclusive > 0 ? "warn" : "flat"],
    ["Unsupported", s.unsupported, "flat"],
  ];
  // A count of zero is dimmed rather than coloured. Seven identically-weighted
  // numbers make the reader hunt for the ones that matter; dimming the empty
  // ones means the populated buckets are what the eye lands on.
  return html`<div class="panel">
    <dl class="stats">
      ${cells.map(
        ([label, value, tone]) => html`<div>
          <dt>${label}</dt>
          <dd class="${value === 0 ? "zero" : tone}">${String(value)}</dd>
        </div>`,
      )}
    </dl>
  </div>`;
}

/**
 * The ranking-honesty disclosure.
 *
 * This block is not decoration. Core's ranking has six weighted factors, but two
 * of them are identical for every candidate that reaches ranking, so half the
 * weight cannot affect the ordering. Rendering all six as scored factors would
 * tell a reader that fit and readiness drove half the decision when the entire
 * ordering came from the other four. The API already splits them; this UI's job is
 * to keep the split visible rather than flatten it back into one table.
 *
 * The floor is stated explicitly because it is the most misleading part of the raw
 * number: with 50 points awarded identically, Core's score cannot go below 5000 bps
 * for an eligible candidate, so a candidate at "50%" scored zero on everything
 * that actually varies.
 */
function renderRankingBasis(view: ComparisonView): Html {
  const basis = view.rankingBasis;
  const floorBps = basis.confirmationWeightPoints * 100;
  return html`<div class="panel">
    <h3>How this ranking is decided</h3>
    <p style="font-size:13.5px;margin-bottom:8px">${basis.note}</p>
    <table>
      <tbody>
        <tr>
          <td>Weight points that <strong>decide the ordering</strong></td>
          <td class="num mono">${basis.discriminatingWeightPoints} / 100</td>
        </tr>
        <tr>
          <td>Weight points identical for every ranked candidate</td>
          <td class="num mono">${basis.confirmationWeightPoints} / 100</td>
        </tr>
        <tr>
          <td class="soft">
            Consequence: Core's six-factor score cannot fall below this for any eligible
            candidate, so that value means zero on everything that varies
          </td>
          <td class="num mono">${bps(floorBps)}</td>
        </tr>
      </tbody>
    </table>
  </div>`;
}

function renderCandidate(candidate: DisplayCandidate, rank: number | null): Html {
  const tone = OUTCOME_TAG[candidate.outcome] ?? "flat";
  const chainId = at(candidate.candidate, "chainId");
  const tokenId = at(candidate.candidate, "tokenId");
  const identity =
    chainId === undefined || tokenId === undefined ? null : `${String(chainId)}:${String(tokenId)}`;

  return html`<div class="card ${candidate.outcome}">
    <div style="display:flex;gap:14px;align-items:baseline;flex-wrap:wrap">
      ${rank === null ? null : html`<div class="rank">#${rank}</div>`}
      <div style="flex:1;min-width:200px">
        <div class="mono" style="font-size:13.5px;font-weight:600">${candidate.quoteId}</div>
        <div class="faint mono" style="font-size:11.5px">
          ${identity === null ? "candidate identity unavailable" : `candidate ${identity}`}
        </div>
      </div>
      <span class="tag ${tone}">${candidate.outcome}</span>
      ${candidate.score === null
        ? null
        : html`<div style="text-align:right">
            <div class="rank">${bps(candidate.score.discriminatingScoreBps)}</div>
            <div class="faint" style="font-size:11px">
              over the ${candidate.score.discriminatingWeightPoints} deciding points
            </div>
          </div>`}
    </div>

    ${candidate.score === null
      ? null
      : html`
          <h3>Factors that decide the ordering</h3>
          ${renderFactors(candidate.score.factors)}
          ${candidate.score.confirmations.length === 0
            ? null
            : renderConfirmations(candidate.score.confirmations)}
          <table style="margin-top:10px">
            <tbody>
              <tr>
                <td class="soft">
                  Core's own six-factor score, including the points identical for every
                  candidate
                </td>
                <td class="num mono">
                  ${bps(candidate.score.coreScoreBps)}
                  <span class="faint">(${candidate.score.coreWeightedTotal} pts)</span>
                </td>
              </tr>
            </tbody>
          </table>
        `}

    ${renderFindings(candidate)}
    ${renderQuoteFacts(candidate)}
  </div>`;
}

function renderFactors(factors: readonly DisplayFactor[]): Html {
  if (factors.length === 0) {
    return html`<p class="soft" style="font-size:13px">
      No scoring factor varied for this candidate.
    </p>`;
  }
  return html`<div class="scroll">
    <table>
      <thead>
        <tr>
          <th>Factor</th>
          <th class="num">Weight</th>
          <th class="num">Score</th>
          <th style="width:32%">&nbsp;</th>
        </tr>
      </thead>
      <tbody>
        ${factors.map(
          (factor) => html`<tr>
            <td>${factorLabel(factor.key)}</td>
            <td class="num mono">${factor.weight}</td>
            <td class="num mono">${bps(factor.scoreBps)}</td>
            <td>
              <div class="bar">
                <i style="width:${String(Math.max(0, Math.min(100, factor.scoreBps / 100)))}%"></i>
              </div>
            </td>
          </tr>`,
        )}
      </tbody>
    </table>
  </div>`;
}

/**
 * Confirmations are rendered in their own block, with the zero explicit.
 *
 * They must not appear in the same table as the scoring factors. Same table means
 * same visual weight, and the reader concludes six factors competed when four did.
 */
function renderConfirmations(confirmations: readonly DisplayConfirmation[]): Html {
  return html`<h3>Eligibility confirmations (no effect on ordering)</h3>
    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th>Check</th>
            <th class="num">Weight in Core's total</th>
            <th class="num">Deciding weight</th>
            <th class="num">Value</th>
          </tr>
        </thead>
        <tbody>
          ${confirmations.map(
            (confirmation) => html`<tr>
              <td>
                ${factorLabel(confirmation.key)}
                <div class="faint" style="font-size:11.5px">${confirmation.note}</div>
              </td>
              <td class="num mono">${confirmation.weightInCoreTotal}</td>
              <td class="num mono"><span class="tag flat">${confirmation.discriminatingWeight}</span></td>
              <td class="num mono">${bps(confirmation.scoreBps)}</td>
            </tr>`,
          )}
        </tbody>
      </table>
    </div>`;
}

/**
 * Findings, always rendered and never collapsed.
 *
 * For a non-eligible candidate this is the entire answer to "why not", and it is
 * the reason the API runs two evaluation passes instead of one. Hiding it behind a
 * disclosure would undo that work.
 */
function renderFindings(candidate: DisplayCandidate): Html {
  if (candidate.findings.length === 0) {
    return candidate.outcome === "eligible"
      ? html`<p class="soft" style="font-size:13px;margin-top:10px">
          No exclusions or inconclusive checks were recorded.
        </p>`
      : html`<p class="soft" style="font-size:13px;margin-top:10px">
          This candidate is <strong>${candidate.outcome}</strong> but reported no findings,
          which should not happen. Treat the verdict as unexplained rather than benign.
        </p>`;
  }
  return html`<h3>
      ${candidate.outcome === "eligible" ? "Notes" : "Why this candidate did not qualify"}
      (${candidate.findings.length})
    </h3>
    <div>${candidate.findings.map(renderFinding)}</div>`;
}

function renderFinding(finding: DisplayFinding): Html {
  const tone =
    finding.kind === "exclusion" ? "bad" : finding.kind === "inconclusive" ? "warn" : "flat";
  return html`<div class="finding">
    <span class="tag ${tone}">${finding.kind}</span>
    <code>${finding.code}</code>
    <div class="soft" style="margin-top:2px">${finding.message}</div>
  </div>`;
}

function renderQuoteFacts(candidate: DisplayCandidate): Html {
  const quote = candidate.quote;
  if (quote === null || quote === undefined) return raw("");
  const rows: readonly (readonly [string, unknown])[] = [
    ["Proposed action", at(quote, "proposedAction")],
    ["Observed", instant(at(quote, "observedAt"))],
    ["Expires", instant(at(quote, "expiresAt"))],
    ["Gas", usdMicros(at(quote, "estimates", "gasUsdMicros"))],
    ["Exposure", usdMicros(at(quote, "estimates", "exposureUsdMicros"))],
    ["Slippage", bps(at(quote, "estimates", "slippageBps"))],
    ["Preview", at(quote, "preview", "status")],
    ["Reputation samples", at(quote, "reputation", "sampleSize")],
  ];
  return html`<details style="margin-top:10px">
    <summary class="soft" style="cursor:pointer;font-size:12.5px">Quote detail</summary>
    <dl class="kv grid" style="margin-top:10px">
      ${rows
        .filter(([, value]) => value !== undefined && value !== null)
        .map(([label, value]) => html`<div><dt>${label}</dt><dd>${value}</dd></div>`)}
    </dl>
  </details>`;
}

function renderUnverified(view: ComparisonView): Html {
  if (view.unverified.length === 0) return raw("");
  return html`<h2>Rejected before comparison (${view.unverified.length})</h2>
    <div class="panel">
      <p class="soft" style="font-size:13px">
        These attestations failed signature or contract verification, so they never entered
        the comparison. They are listed rather than dropped: a comparison that silently
        shows fewer rows than were submitted hides the most important failures.
      </p>
      ${view.unverified.map((entry) => {
        const record = entry as unknown as Record<string, unknown>;
        return html`<div class="finding">
          <code>${String(record.code ?? "UNVERIFIED")}</code>
          <div class="soft" style="margin-top:2px">
            ${String(record.message ?? record.reason ?? "verification failed")}
          </div>
          ${record.index === undefined
            ? null
            : html`<div class="faint mono" style="font-size:11.5px">
                submitted attestation #${String(record.index)}
              </div>`}
        </div>`;
      })}
    </div>`;
}

// ── permission review ────────────────────────────────────────────────────────

/**
 * What each candidate is asking to be allowed to do, against the mandate ceiling.
 *
 * This is the screen a user should read before trusting anything, so the
 * comparison is explicit rather than left as two numbers to eyeball: a requested
 * spend cap above the mandate's is flagged in place. Core has already excluded
 * such a candidate — the flag explains a verdict, it does not replace it.
 */
function renderPermissionReview(view: ComparisonView, mandate: unknown): Html {
  const ranked = view.candidates.filter((candidate) => candidate.quote !== null);
  if (ranked.length === 0) return raw("");

  const ceilingSpend = at(mandate, "permissions", "maxSpendUsdMicros");
  const ceilingExpiry = at(mandate, "permissions", "expiresAt");
  const allowedProtocols = list(at(mandate, "permissions", "allowedProtocols")).map(String);
  const allowedContracts = list(at(mandate, "permissions", "allowedContracts")).map(String);
  const allowedCalls = list(at(mandate, "permissions", "allowedCalls")).map(String);

  return html`<h2 id="permissions">Permission review</h2>
    <div class="panel">
      <h3>Mandate ceiling</h3>
      <dl class="kv grid">
        <div><dt>Max spend</dt><dd>${usdMicros(ceilingSpend)}</dd></div>
        <div><dt>Permissions expire</dt><dd>${instant(ceilingExpiry)}</dd></div>
        <div><dt>Allowed protocols</dt><dd>${allowedProtocols.join(", ") || "-"}</dd></div>
        <div><dt>Allowed contracts</dt><dd>${allowedContracts.join(", ") || "-"}</dd></div>
        <div><dt>Allowed calls</dt><dd>${allowedCalls.join(", ") || "-"}</dd></div>
      </dl>
    </div>

    ${ranked.map((candidate) => {
      const requestedSpend = at(candidate.quote, "permissions", "spendCapUsdMicros");
      const requestedExpiry = at(candidate.quote, "permissions", "expiresAt");
      const contracts = list(at(candidate.quote, "permissions", "contracts")).map(String);
      const calls = list(at(candidate.quote, "permissions", "calls")).map(String);

      const overSpend = exceeds(requestedSpend, ceilingSpend);
      const overExpiry =
        typeof requestedExpiry === "number" &&
        typeof ceilingExpiry === "number" &&
        requestedExpiry > ceilingExpiry;
      const strayContracts = contracts.filter(
        (contract) => allowedContracts.length > 0 && !allowedContracts.includes(contract),
      );
      const strayCalls = calls.filter(
        (call) => allowedCalls.length > 0 && !allowedCalls.includes(call),
      );

      return html`<div class="card ${candidate.outcome}">
        <div class="mono" style="font-size:13px;font-weight:600">${candidate.quoteId}</div>
        <table style="margin-top:8px">
          <tbody>
            <tr>
              <td>Requested spend cap</td>
              <td class="num mono">
                ${usdMicros(requestedSpend)}
                ${overSpend ? html`<span class="tag bad">over ceiling</span>` : null}
              </td>
            </tr>
            <tr>
              <td>Requested expiry</td>
              <td class="num mono">
                ${instant(requestedExpiry)}
                ${overExpiry ? html`<span class="tag bad">beyond mandate</span>` : null}
              </td>
            </tr>
            <tr>
              <td>Contracts it may call</td>
              <td class="num mono">
                ${contracts.length === 0 ? "-" : contracts.join(", ")}
                ${strayContracts.length === 0
                  ? null
                  : html`<span class="tag bad">not in mandate</span>`}
              </td>
            </tr>
            <tr>
              <td>Calls it may make</td>
              <td class="num mono">
                ${calls.length === 0 ? "-" : calls.join(", ")}
                ${strayCalls.length === 0 ? null : html`<span class="tag bad">not in mandate</span>`}
              </td>
            </tr>
          </tbody>
        </table>
      </div>`;
    })}`;
}

/** Compares two uint256 decimal strings without a float. */
function exceeds(requested: unknown, ceiling: unknown): boolean {
  const a = String(requested ?? "");
  const b = String(ceiling ?? "");
  if (!/^\d+$/.test(a) || !/^\d+$/.test(b)) return false;
  return BigInt(a) > BigInt(b);
}

// ── activation ───────────────────────────────────────────────────────────────

/**
 * Activation state.
 *
 * There is nothing to activate, and saying so plainly is the whole content of this
 * section. The marketplace's only effect is `evaluation_only`: it holds no key,
 * signs nothing, and moves no funds. A UI that rendered an "Activate" button, a
 * pending state, or a progress indicator would imply a capability that does not
 * exist anywhere in the deployed system.
 */
function renderActivation(view: ComparisonView): Html {
  const top = view.candidates.find((candidate) => candidate.outcome === "eligible");
  return html`<h2 id="activation">Activation state</h2>
    <div class="panel">
      <p style="font-size:13.5px">
        <span class="tag flat">${view.effect}</span>
        Nothing has been activated, and this interface cannot activate anything. The
        marketplace evaluates and ranks; it holds no key and performs no signing, funding,
        settlement or broadcasting. The receipt below records an evaluation, not an
        engagement.
      </p>
      <table>
        <tbody>
          <tr><td>Activated</td><td class="num"><span class="tag flat">no</span></td></tr>
          <tr>
            <td>Selected candidate</td>
            <td class="num mono">
              ${top === undefined
                ? html`<span class="soft">none eligible</span>`
                : top.quoteId}
            </td>
          </tr>
          <tr>
            <td class="soft">
              What activation would additionally require, none of which happens here
            </td>
            <td class="num soft" style="font-size:12.5px">
              a funded account, an explicit permission grant, and a settlement path
            </td>
          </tr>
        </tbody>
      </table>
    </div>`;
}

// ── receipt ──────────────────────────────────────────────────────────────────

function renderReceipt(view: ComparisonView): Html {
  if (view.receipt === null || view.receipt === undefined) {
    return html`<h2 id="receipt">Receipt</h2>
      <div class="panel soft" style="font-size:13.5px">
        No receipt was issued, which happens when no candidate survived verification.
      </div>`;
  }
  const receipt = view.receipt;
  const adapterStatus = at(receipt, "adapter", "status");
  const adapterName = at(receipt, "adapter", "name");
  const adapterCode = at(receipt, "adapter", "code");

  return html`<h2 id="receipt">Receipt</h2>
    <div class="panel">
      <dl class="kv grid">
        <div><dt>Schema</dt><dd>${String(at(receipt, "schema") ?? "-")}</dd></div>
        <div><dt>Effect</dt><dd>${String(at(receipt, "effect") ?? "-")}</dd></div>
        <div><dt>Evaluated at</dt><dd>${instant(at(receipt, "evaluatedAt"))}</dd></div>
        <div><dt>Mandate</dt><dd>${String(at(receipt, "mandateId") ?? "-")}</dd></div>
        <div><dt>Category</dt><dd>${String(at(receipt, "category") ?? "-")}</dd></div>
        <div>
          <dt>Adapter</dt>
          <dd>
            ${adapterStatus === "supported"
              ? String(adapterName ?? "-")
              : html`<span class="tag flat">${String(adapterStatus ?? "unknown")}</span>
                  ${String(adapterCode ?? "")}`}
          </dd>
        </div>
      </dl>
      <details style="margin-top:6px">
        <summary class="soft" style="cursor:pointer;font-size:12.5px">
          Full receipt as returned
        </summary>
        <pre style="margin-top:10px">${JSON.stringify(receipt, null, 2)}</pre>
      </details>
    </div>`;
}

// ── errors ───────────────────────────────────────────────────────────────────

export function renderError(input: {
  readonly heading: string;
  readonly detail: string;
  readonly apiBase: string;
}): Html {
  return html`
    <h1>${input.heading}</h1>
    <div class="banner bad" role="alert">${input.detail}</div>
    <div class="panel soft" style="font-size:13px">
      The marketplace API this interface reads is
      <span class="mono">${input.apiBase}</span>. Nothing was evaluated, and no state
      changed. This interface only ever reads.
    </div>
    <div class="row"><a href="/">← back to the mandate</a></div>
  `;
}
