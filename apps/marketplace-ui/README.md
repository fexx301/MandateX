# `@mandatex/marketplace-ui`

The marketplace's human interface: mandate input, quote comparison, per-candidate
exclusion reasons, permission review, activation state and receipts.

It computes nothing. Every verdict on screen is produced by Marketplace Core inside
`marketplace-api`; this process fetches that payload and renders it. The whole job
is **not misrepresenting it**.

```bash
corepack pnpm install
corepack pnpm build
corepack pnpm smoke     # 91 checks against a real API and real fixtures
MANDATEX_API_URL=http://127.0.0.1:8080 corepack pnpm start
```

---

## Why server-rendered strings and no framework

`node:http`, no framework, no bundler, no client-side build, and **zero production
dependencies** — the runtime uses only Node builtins and `fetch`.

That is a deployment decision, not minimalism for its own sake. The deployed
artifact is a Node process that serves strings, so there is no build step that can
fail at deploy time and no `npm install` between a judge clicking a link and seeing
a page. Every screen renders fully server-side and works with JavaScript disabled.

`@mandatex/marketplace-api` is a **devDependency**, used for two things: the
`ComparisonView` types, and booting a real API in the check suite. Nothing in the
shipped runtime imports it.

### The types come from the API, deliberately

`src/api.ts` imports `ComparisonView`, `DisplayFactor`, `DisplayConfirmation` and
friends from the API package rather than restating them. A renamed field is then a
compile error here instead of a blank spot on the page.

This matters most for the ranking split: if `confirmations` were ever renamed, a
locally-redeclared type would let this UI keep rendering four factors and quietly
stop disclosing the two pinned ones — the exact failure the split exists to
prevent.

## Ranking display honesty

`plan.md` §4 requires that this UI not present Core's six ranking factors as if all
six discriminate. **Verified against `tools/marketplace-core/src/ranking.ts`
directly rather than taken on trust**, and the finding is slightly more precise
than the plan's wording:

- `mandateFit` is `factor(STRATEGY_WEIGHTS.mandateFit, 10_000)` — a hardcoded
  literal. It is always 10000 bps.
- `executionReadiness` is `quote.preview.status === "passed" ? 10_000 : 0`, so it
  is **not** literally pinned. It is *structurally* pinned: `score` is non-null only
  when `outcome === "eligible"` (`evaluate.ts:606`), and a preview that failed is
  an exclusion while one that is unavailable is inconclusive — either way the quote
  never reaches ranking. So every scored quote has a passed preview, and this factor
  is 10000 bps for every ranked candidate.

Weights are `mandateFit: 30` and `executionReadiness: 20`, so **50 of 100 weight
points are identical on every row and cannot change any ordering.** The four that
decide it are `evidenceFreshness` (20), `riskCompatibility` (15), `totalCost` (10)
and `reputationConfidence` (5).

The API already splits its payload accordingly (`factors[]` vs `confirmations[]`,
plus `coreScoreBps` retained and labelled). This UI's contribution is to keep the
split visible:

- the headline number per candidate is `discriminatingScoreBps`, annotated
  "over the 50 deciding points"
- the four scoring factors are one table; the two confirmations are a **separate**
  table under "Eligibility confirmations — no effect on ordering", showing
  `discriminatingWeight: 0` explicitly
- Core's own six-factor score is shown and labelled, so nothing is hidden
- the API's `rankingBasis.note` is printed verbatim

One consequence is stated that neither the plan nor the API spells out. With 50
points awarded identically, **Core's six-factor score cannot fall below 5000 bps
for any eligible candidate** — so a candidate displaying "50%" scored *zero* on
everything that varies. The page says so in the ranking-basis panel, because that
is the single most misleading thing about the raw number.

A check asserts the scoring table contains exactly four factor labels, never six.

## Capabilities that do not exist are not implied

**Categories.** Only `rebalancing` is evaluable. Grid, yield and lending health are
listed in the category selector but `disabled`, with the reason given. They are not
silently hidden — a user should know the shape of the product — and they are not
selectable either, because Core's `unsupported` outcome comes from a *quote's*
normalization, so a grid mandate against the existing rebalancing quotes would
return `MANDATE_CATEGORY_MISMATCH`: a real finding that reads like a different
fault and would send someone off debugging their input.

**Category thresholds are not per-user.** The form offers no metric-threshold input
for those three categories, and says why: the frozen mandate schema has no field
for one, so a threshold is deployment policy set by the verifier operator and
identical for every mandate in a category. See
`tools/category-adapters/README.md`.

**`VERIFIED_HIREABLE` appears nowhere.** It is unreachable by construction
(`plan.md` §4). Two checks assert the string is absent from both pages.

**No activation.** The marketplace's only effect is `evaluation_only`. There is no
Activate button, no pending state, no progress indicator — a check asserts no such
control is rendered. The activation section states plainly that nothing is
activated, that this interface cannot activate anything, and what activation would
additionally require.

## Exclusion reasons are never hidden

The API runs two evaluation passes specifically so a rejected candidate keeps its
reason instead of killing the whole request. Undoing that in the presentation
layer would waste it, so:

- findings render for every candidate, always expanded, never inside a `<details>`
- the finding **code** is shown alongside the prose, tagged by kind
- non-eligible candidates sort after eligible ones but are never omitted
- attestations that failed verification appear under "Rejected before comparison"
  rather than being dropped — a comparison showing fewer rows than were submitted
  hides the most important failures

## Editing the mandate invalidates every attestation

Found while writing the suite, and worth stating because it is a real product
constraint rather than a bug: an attestation commits to the hash of the mandate it
was issued for. Change any mandate field and every candidate fails with
`ATTESTATION_MANDATE_HASH_MISMATCH` — before Core ever compares budgets or
permissions.

The fields are left editable anyway, because seeing that binding fail is a better
demonstration of the trust model than a form that cannot be touched. What the UI
adds is an explanation: when every attestation fails on the mandate hash and there
are no candidates, the page says the mandate was edited and that nothing is wrong
with the candidates, rather than presenting three verification failures that read
as "the agents are broken".

The practical consequence is that the budget fields cannot re-rank pre-issued
candidates. Evaluating a different mandate requires the verifier to re-issue
attestations against it.

## Every rendered string is escaped

Candidate names, proposed actions, addresses and finding messages all originate in
somebody else's attestation. Verification proves an attestation was signed by the
pinned key; it says nothing about whether the strings inside are safe to
interpolate into a document.

So there is one way to put a value in the page — the `html` tagged template — and
it escapes all five dangerous characters in both text and attribute context.
Bypassing it requires the deliberately noisy `raw()`. Responses also carry a CSP
of `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'` so a
successful injection would still be inert.

## Routes

| Route | Purpose |
|---|---|
| `GET /` | Mandate form, prefilled from the API's fixture bundle |
| `POST /evaluate` | Submits the mandate, renders the full result page |
| `GET /evaluate` | `303` back to the form — a refresh must not re-evaluate |
| `GET /healthz` | Liveness |
| `GET /readyz` | `200` only while the API it reads is answering |

### One evaluation renders one page

There are no separate tab routes. Separate routes would each need their own
evaluation, and freshness verdicts are clock-dependent, so two evaluations seconds
apart can disagree — a candidate could read eligible under "Comparison" and
excluded under "Permissions". The section nav is in-page anchors over a single
result.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `MANDATEX_API_URL` | — | **Required.** The marketplace API this UI reads |
| `PORT` / `HOST` | `8081` / `0.0.0.0` | |
| `MANDATEX_MAX_REQUEST_BYTES` | `1048576` | Enforced on accumulated bytes |
| `NODE_ENV` | — | `production` requires https unless the host ends `.internal` |

### Boot guards

Exits **78** (`EX_CONFIG`) rather than serving traffic when `MANDATEX_API_URL` is
missing or malformed, when the API URL is plaintext HTTP in production (waived for
`*.internal`, which is Railway's private network), or when **any signing authority
is present** — checked by variable name and by content, including PKCS#8 Ed25519
and PEM private-key material in an innocuously named variable.

The UI is the least privileged process in the system and should stay that way. It
is also the one process that renders untrusted strings into a document, which makes
it the worst possible place for a key to be.

## Verification

91 checks, nothing mocked. Each run boots the **real** marketplace API — the same
`loadConfig` / `MarketplaceEvaluator` / `createRouter` the deployed service uses —
against the real fixture attestations, then boots the real UI server against it and
asserts on the HTML that comes off the socket.

Four genuine states are exercised, found by probing the clock rather than assumed:

| Clock | State | What it proves |
|---|---|---|
| anchor | 3 eligible | the ranking-honesty rendering |
| anchor **+120s** | 2 eligible, 1 excluded | per-candidate exclusion reasons on a *verified* candidate |
| live | 0 candidates, 3 unverified | expired attestations surface as verification failures with codes |
| edited mandate | 0 candidates, 3 hash mismatches | the mandate-binding explanation |

The +120s window is the only offset that yields a mixed set: earlier is
all-eligible, and past 300s the attestations expire and never reach Core.

One check does not run end to end. The over-ceiling permission flag needs a mandate
whose spend ceiling is below what a quote requests, and any mandate edit fails
verification before Core compares permissions — so that flag is driven through the
render function with a **real API view** and a lowered ceiling in the `mandate`
argument. The view is genuine; only the mandate differs. Flagged here rather than
presented as full coverage.
