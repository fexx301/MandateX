# Marketplace API

The public HTTP surface of the MandateX marketplace. It verifies signed
evaluation attestations issued by the verifier runtime and serves display-safe
quote comparisons.

**This process performs no signing, funding, settlement, or broadcasting.** Its
only effect is `evaluation_only`. It refuses to boot if it finds signing
authority in its environment — see [Boot guards](#boot-guards).

```bash
corepack pnpm install
corepack pnpm build
corepack pnpm smoke     # 37 checks against the real Core and real fixtures
corepack pnpm start
```

---

## Where it sits in the trust boundary

```
┌─ verifier runtime ────────────┐        ┌─ marketplace-api (this) ──────┐
│ holds the Ed25519 PRIVATE key │        │ pins only the PUBLIC key      │
│ evaluates + signs attestations│ ─wire─▶│ verifies through Core         │
│                               │        │ ranks, projects, serves JSON  │
└───────────────────────────────┘        └───────────────────────────────┘
```

The two halves are separate deployed services on purpose. A single process that
both signs and verifies proves nothing: every signature it checked would be one
it could have produced itself. That design was explicitly rejected, and this
process enforces the split at boot rather than trusting convention.

Attestations are consumed as **opaque wire strings**. This app never parses and
re-serializes one before verification — canonical-encoding defects are part of
what Core checks, and a round-trip repairs them silently, turning a rejection
into a false acceptance.

## Routes

| Route | Purpose |
|---|---|
| `GET /` | Service description and route list |
| `GET /healthz` | Liveness. Process is up |
| `GET /readyz` | Readiness, **including lockstep key agreement** with the verifier |
| `GET /v1/trust` | The key ID, public-key fingerprint, and policy hash this API pins |
| `POST /v1/evaluate` | `{ mandate, attestations[] }` → ranked comparison view |
| `GET /v1/fixtures` | Development vectors. Returns 404 in production |

### `GET /readyz` is the lockstep proof

The v2 contract requires proving that verifier and app redeploy together before
submission rehearsal. Rather than treat that as a manual checklist item, `/readyz`
fetches `${MANDATEX_VERIFIER_URL}/v1/trust` and compares the verifier's advertised
public-key fingerprint against the fingerprint this app pins.

- match → `200 ready`
- mismatch → **`503`**, naming both fingerprints
- unreachable → `503`
- reachable but no `/v1/trust` yet → `200`, with the check marked unverified

A broken lockstep redeploy therefore surfaces as a red readiness probe, not as a
marketplace that silently rejects every quote it is shown.

### `POST /v1/evaluate`

```bash
curl -sX POST localhost:8080/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{"mandate": {...}, "attestations": ["<wire text>", "..."]}'
```

`attestations` are wire strings **exactly as issued**. Unknown top-level fields
are rejected rather than ignored.

| Status | Meaning |
|---|---|
| `200` | Evaluated. Includes per-candidate outcomes, and `unverified[]` for attestations that failed verification |
| `400` | Malformed request or mandate |
| `413` | Body over `MANDATEX_MAX_REQUEST_BYTES` |
| `422` | A Core rule rejected the request — the code is Core's (`DUPLICATE_CANDIDATE`, `DUPLICATE_QUOTE_ID`, …) |
| `500` | Unanticipated failure. Not attributed to the caller |

A set where **every** candidate fails verification is a `200` with an empty
comparison and a reason per candidate — that is a complete answer, not an error.

## Two-pass evaluation, and why

`evaluateMarketplaceV2` verifies each attestation inline and throws on the first
bad one, killing the whole request. That is correct fail-closed security — never
rank partially-verified material — but it destroys the one thing a comparison
view has to show: *which* candidate was rejected and why.

So `src/core.ts` runs two passes:

1. **Classify.** Call Core once per attestation to learn accept/reject per
   candidate. Rankings from these calls are discarded; they are meaningless for a
   single-candidate set.
2. **Rank.** Call Core once more over *only* the survivors.

The ranking served is therefore always from one authoritative Core call over the
exact set being compared, while exclusion reasons survive per candidate. Cost is
N+1 verifications, bounded by Core's candidate ceiling.

A pass-2 failure is reported as a **set-level** fault, not blamed on a candidate:
every survivor already verified alone, so the fault is a property of the set.

## Ranking honesty

Core's ranking has six weighted factors totalling 100 points. Two of them —
`mandateFit` (30) and `executionReadiness` (20) — are pinned at 10000 bps for
every candidate that reaches ranking, because a candidate failing either was
already excluded before scoring. **So 50 of the 100 weight points are identical
across every row and cannot change any ordering.**

Rendering all six as scored factors would tell a reader that half the decision
came from fit and readiness, when the entire ordering comes from the other four.
So the response splits them:

- `factors[]` — the 4 that vary, with the score renormalized over the 50 points
  that actually discriminate
- `confirmations[]` — the 2 pinned ones, at explicit `discriminatingWeight: 0`
- `coreScoreBps` / `coreWeightedTotal` — Core's own six-factor number, kept and
  labelled, so nothing is hidden
- `rankingBasis.note` — states the 50/50 split in the payload itself

The difference is not cosmetic. On the fixture set, Core's spread across three
eligible quotes is 9239 → 8091 bps, while the discriminating spread is
8480 → 6183 — exactly double, because the pinned points compress every real gap
by half.

The split is **not** a hardcoded claim. If a supposedly-pinned factor is ever
observed at anything other than 10000 bps it is reclassified as scoring and a
warning is attached to the response, naming the constant to update. The API
self-corrects rather than silently understating a factor that starts to
discriminate.

## Configuration

Trust material comes either from a file or from three explicit variables.

| Variable | Default | Notes |
|---|---|---|
| `MANDATEX_TRUST_FILE` | — | Path to a JSON file with the four trust fields. Simplest option |
| `MANDATEX_TRUST_KEY_ID` | — | Required if no trust file |
| `MANDATEX_TRUST_SPKI_DER_HEX` | — | Ed25519 SPKI DER, hex. Must match `302a300506032b6570032100…` |
| `MANDATEX_TRUST_KEY_FINGERPRINT_SHA256` | — | SHA-256 of the SPKI DER, hex |
| `MANDATEX_TRUST_POLICY_SHA256` | — | Verifier policy hash, hex |
| `MANDATEX_VERIFIER_URL` | unset | Verifier base URL. Enables the `/readyz` lockstep check |
| `MANDATEX_MAX_CLOCK_SKEW_SECONDS` | `30` | Passed to Core |
| `MANDATEX_MAX_REQUEST_BYTES` | `1048576` | Enforced on accumulated bytes, not `content-length` |
| `MANDATEX_EXPOSE_FIXTURES` | on outside production | Set `false` to disable. Always off in production |
| `PORT` / `HOST` | `8080` / `0.0.0.0` | |
| `NODE_ENV` | — | `production` tightens every guard below |

Only the **public** half of the key is ever configured here. There is no variable
for a private key, seed, or mnemonic, and supplying one prevents boot.

### Boot guards

Misconfiguration of a trust boundary should stop the process, not degrade it
quietly. `loadConfig` exits `78` (`EX_CONFIG`) rather than serving traffic when:

1. **Any signing authority is present.** Checked two ways — by variable *name*
   (`*_SIGNING_KEY`, `*_PRIVATE_KEY`, `*_SEED_HEX`, `MNEMONIC`, …) and by
   variable *content*, scanning for PKCS#8 Ed25519 prefixes and PEM private-key
   headers. The content check matters more: a key pasted into an innocuously
   named variable is the likelier accident and the more dangerous one, because it
   survives a review that only reads names.
2. **A development key is pinned in production.** Any key ID containing
   `fixture`, `insecure`, `do-not-deploy`, `test`, or `dev-`.
3. **The verifier URL is plaintext HTTP in production** — unless the hostname
   ends in `.internal`, which is Railway's private network and is not reachable
   from outside the project.
4. **Trust material is malformed**, including SPKI DER that is not Ed25519.
5. **Core itself rejects the pinned trust material.**

The smoke suite proves each of these fires, including a real PKCS#8 Ed25519
private key hidden in a variable named `APP_CREDENTIAL`.

## Fixtures: the valid vectors are not a candidate set

The five valid fixture vectors are each individually valid, but they are **not
collectively a legal comparison set**. Three of them are TTL-boundary variants of
the *same* quote — Core identifies a candidate by `chainId:tokenId` alone, and
rejects any set where that pair or a `quoteId` repeats.

Posting all five to `/v1/evaluate` returns `422 DUPLICATE_CANDIDATE`, correctly.
Only `baseline` + `competing-quote-b` + `competing-quote-c-older-evidence` form a
legal three-candidate set.

`GET /v1/fixtures` therefore derives and serves `comparisonSet` — the ready-to-post
subset — alongside `notInComparisonSet` with a reason per exclusion. The trap is
resolved at the point of use rather than left for the next caller.

`/v1/evaluate` deliberately does **not** silently drop duplicates. A comparison
that returns three rows for five submitted quotes is worse than an error, because
the caller cannot tell what was dropped.

### Fixtures are expired against a real clock

Vectors are frozen at a fixed instant with a 300-second TTL, so they read as
expired against wall-clock time. `MarketplaceEvaluator.create` accepts a clock as
a **constructor argument**, used by the smoke suite.

That clock is deliberately **not** readable from the environment. A settable
clock would switch off freshness and expiry enforcement wholesale, which is most
of what the attestation contract buys.

The vectors also do not share one instant — `expired` sits past its own expiry
while the others do not. The smoke suite groups vectors by their recorded
`evaluatedAt` and runs one server per clock, because evaluating them all against a
single clock turns the most important time-rule vector into a false pass.

## Design notes

**No framework.** `node:http` only, five routes. Three reasons, in order of
weight: Railway bills *measured* memory at $10/GB/month, so a lean resident set
is a direct cost saving; this process pins the verifier's trust, so every
dependency added here is a dependency inside the trust boundary; and five routes
do not need a router.

**One module imports Core.** `src/core.ts` is the only file that touches
`@mandatex/marketplace-core`. Core is owned by the other agent and under active
development, so a contract change is a single-file repair rather than a sweep
through route handlers.

**Request validation is hand-rolled.** The evaluate body is two fields. Adding a
validation library would mean a second copy of zod resolving inside the trust
boundary alongside the one Core pins.

## Layout

| File | Role |
|---|---|
| `src/config.ts` | Env parsing and the boot guards |
| `src/core.ts` | The only importer of Core; two-pass evaluation |
| `src/display.ts` | Display projection and the ranking-honesty split |
| `src/routes.ts` | `node:http` routing, verifier probe, fixture index |
| `src/server.ts` | Boot, structured logging, graceful shutdown |
| `src/smoke.ts` | 37 checks against the real Core and real fixtures |

`corepack pnpm smoke` boots the real server on an ephemeral port and drives it
over HTTP. It asserts the boot guards fire, all 38 invalid vectors are rejected
with their predicted codes across both clocks, the candidate-set rule is
enforced, and the honesty projection provably differs from Core's six-factor
score.
