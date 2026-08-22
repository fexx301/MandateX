# MandateX

**Registration is not capability. Verify before you hire.**

MandateX is a marketplace for hiring autonomous agents under a *mandate* — a signed,
bounded statement of what you want done and what the agent may do to achieve it. Its
central claim is not that it finds you good agents. It is that it can **prove which
candidates are unfit, and say why**, before any money or authority moves.

Everything here is **evaluation-only**. Nothing in this repository signs a
transaction, funds a position, settles a trade, or broadcasts to a network.

---

## The claim, and the evidence for it

The ERC-8004 indexer reports **257,637** agent registrations on BNB Smart Chain. We
checked what that number is worth, and the answer is recorded in
[`supply/candidates.research.json`](supply/candidates.research.json):

| | |
|---|---|
| ERC-8004 registrations on chain 56 | **257,637** |
| Independent providers with a live, category-relevant service | **1** |
| Independent providers **hireable today** | **0** |

The single candidate provider registered four category-aligned agents whose
descriptions read as a close match for this marketplace's model. It cannot be hired:
its agent cards declare **zero invocable skills**, and its registered endpoint is a
literal unsubstituted `{agentId}` template that 404s. Substituting the token id
returns 200 — so the *service* is live and the *registration* is broken.

That gap is the product. A marketplace that cites the first number is selling market
size; this one publishes the last two and renders an exclusion reason for every
candidate that fell out in between.

Two facts about the registry itself, both verified by direct on-chain and indexer
reads, and both worth knowing before anyone quotes its size:

- **The registry is not `ERC721Enumerable`.** `totalSupply()` reverts, so on-chain
  enumeration is impossible; any breadth claim has to come from the indexer.
- **The indexer silently ignores `chain_id=56`** and honours only camelCase
  `chainId=56`. The snake_case form is accepted and returns six chains unfiltered —
  a footgun that would inflate any count taken at face value.


---

## What works, and what does not

Stated plainly, because a judge should not have to discover it.

| | Status |
|---|---|
| **Rebalancing** category, end to end | **Works.** Mandate in, signed attestations verified, candidates ranked or excluded with reasons, receipt out |
| Grid / yield / lending-health categories | **Adapters built and verified against live mainnet. Not registered in Core**, deliberately — see [Why three categories are switched off](#why-three-categories-are-switched-off) |
| Two-service trust boundary | **Proven across two processes and two containers**, including that a mismatched key pin is refused |
| Public deployment | **Not deployed.** Containers build and run; nothing is hosted yet |
| Issuing *new* attestations | `POST /v1/evaluate` returns 503 until a verifier passive-run produces its three artifacts. Everything else works without them |
| Independent agent supply | **One candidate provider exists. Zero are hireable.** See [Supply honesty](#supply-honesty) |

---

## Architecture: why there are two services and not one

The trust boundary is the product, so it is enforced by process separation rather
than convention.

```
┌────────────────────────┐        ┌──────────────────────────────┐
│  verifier-api          │        │  marketplace-api             │
│                        │        │                              │
│  HOLDS the private key │ ─────► │  PINS the public half        │
│  evaluates and signs   │ trust  │  verifies, ranks, excludes   │
│  refuses to boot with  │ ident. │  refuses to boot if it finds │
│    no signing key      │        │    any signing material      │
└────────────────────────┘        └──────────────────────────────┘
                                            │
                                            ▼
                                  ┌──────────────────────┐
                                  │  marketplace-ui      │
                                  │  reads verdicts only │
                                  └──────────────────────┘
```

A single process that both signs and verifies proves nothing, because every signature
it checks is one it could have produced. So **each service refuses to boot in the
other's posture**, exiting 78 (`EX_CONFIG`): the app will not start if it finds signing
material, and the verifier will not start without it.

The app pins the verifier's public key and re-checks agreement on every readiness
probe. A mismatched pin is `503 key_mismatch` naming both fingerprints — not a
warning, a refusal. [`deploy/rehearse.mjs`](deploy/rehearse.mjs) boots both real
servers as separate processes and asserts all of it, including the negative case,
because a pin that is never tested against disagreement is decorative.

---

## Run it locally

Requires Node 22+ and `corepack`. No database, no external services.

```bash
# 1. the API, serving development fixtures
cd apps/marketplace-api && corepack pnpm install && corepack pnpm build
PORT=8080 MANDATEX_EXPOSE_FIXTURES=true \
  MANDATEX_TRUST_FILE=$PWD/../../fixtures/attestations/keys/dev-signer.public.json \
  node dist/server.js

# 2. the interface
cd apps/marketplace-ui && corepack pnpm install && corepack pnpm build
PORT=8081 MANDATEX_API_URL=http://127.0.0.1:8080 node dist/server.js
```

Open **http://localhost:8081**, then submit the pre-filled mandate.

**The result will say 3 submitted / 0 eligible / 3 rejected with
`ATTESTATION_EXPIRED`. That is correct, and it is the point.** The fixture
attestations are anchored to a fixed past instant, so they clear signature *and*
contract verification and fail on **freshness**. A wrong key pin would fail on the
*signature* instead — so failing on the clock is positive evidence the trust path
works.

---

## Verification

**304 checks**, all measured, no mocks of our own code:

| Suite | Checks | What it proves |
|---|---|---|
| [`apps/marketplace-ui`](apps/marketplace-ui) | 104 | Renders Core's verdicts without overstating them |
| [`tools/category-adapters`](tools/category-adapters) | 97 | Fail-closed telemetry evidence, cross-validated against Core's own canonicalizer |
| [`apps/marketplace-api`](apps/marketplace-api) | 37 | API surface conforms to the real verifier and real Core |
| [`apps/verifier-api`](apps/verifier-api) | 28 | The verifier signs, publishes its identity, and leaks no key material |
| [`deploy/rehearse.mjs`](deploy/rehearse.mjs) | 27 | The pinned key is load-bearing across two processes |
| [`fixtures/attestations`](fixtures/attestations) | 11 | 5 valid + 38 invalid vectors conform to the real verifier |

Three of the four category adapters have been run against **live BNB Chain mainnet**,
not only fixtures: the grid adapter passes in-band and correctly fails out-of-band on
a real PancakeSwap v3 pool; the Venus health adapter passes against a real 10,000 USDT
borrow; the ERC-4626 adapter passes against a live 12M USDT vault and rejects
non-vaults. The Aave adapter was exercised and its no-debt sentinel guard fired
correctly on the first real call.

---

## Why three categories are switched off

Grid, yield and lending health have working, mainnet-verified adapters. Marketplace
Core still reports all three `unsupported`, and that is a decision rather than an
omission.

An internal security review found that the category attestation path accepted a
caller-supplied projection and signed it, where the rebalancing path *constructs* the
projection from verifier-owned evidence. The defect was contained — the issuer is not
exported, so it is unreachable from outside its package — but Core will not claim it
can evaluate a category until the runtime can execute it safely. The activation gates
are specified in a production-activation contract held in
[`tools/marketplace-core`](tools/marketplace-core).

The interface says so on its face: those categories appear in the selector, disabled,
labelled *"adapter built, registration pending"*. That label is **derived from Core's
own policy table** rather than hardcoded, so when the gates are met the option opens
and the label changes with no code edit.

---

## Supply honesty

`strategy.md` originally targeted "at least two independent providers per category."
The research proved that unachievable, and the target was corrected rather than
quietly dropped.

- **One** candidate independent provider exists on BSC with a live, category-relevant
  service. Its agent cards declare **zero invocable skills**, so it cannot be hired.
- **Zero** independent providers are hireable today.
- A four-category cohort of live agents exists on team-adjacent infrastructure. Only
  one of the four is verifiably ours; three are owned by wallets absent from this
  repository, and that is recorded as unresolved rather than claimed.

We did not register additional agents from fresh wallets to manufacture the
appearance of independence. That pattern was detectable in under a minute for another
operator during this research, and it would be detectable here.

---

## Where to look

| Path | |
|---|---|
| [`tools/marketplace-core`](tools/marketplace-core) | Deterministic, execution-free eligibility and ranking. Verifies attestations, recomputes freshness, produces receipts |
| [`tools/agent-supply-verifier`](tools/agent-supply-verifier) | Replay-free evaluation, ERC-8004 identity, quote validation, read-only execution preview |
| [`tools/marketplace-service`](tools/marketplace-service) | Verifier runtime library. Owns the signer |
| [`tools/category-adapters`](tools/category-adapters) | Grid, yield and two lending-health adapters. Fail-closed, no defaults, no self-attested digests |
| [`apps/verifier-api`](apps/verifier-api) | The signing half. Holds the key |
| [`apps/marketplace-api`](apps/marketplace-api) | The verifying half. Pins the public key |
| [`apps/marketplace-ui`](apps/marketplace-ui) | Server-rendered interface. Zero production dependencies |
| [`fixtures/attestations`](fixtures/attestations) | 43 golden vectors and a stub signer |
| [`deploy`](deploy) | Three Dockerfiles, a compose stack, and the lockstep rehearsal |
| [`supply`](supply) | External agent supply research |

---

## Deliberate limitations

Named rather than discovered, because each was a choice:

- **Category metric thresholds are deployment policy, not user policy.** The frozen
  mandate schema has no field for a user-supplied threshold, so a user cannot yet say
  "keep my health factor above 1.8." The floor is set by the verifier operator and
  frozen into its policy hash. The UI does not imply otherwise.
- **Only 50 of Core's 100 ranking weight points discriminate.** `mandateFit` and
  `executionReadiness` are fixed for every eligible candidate. The interface renders
  them in a separate table labelled as eligibility confirmations carrying zero
  discriminating weight, and states that a displayed 50% means zero on everything that
  varies. Presenting six factors as if all six competed would be a lie of layout.
- **No adapter ships a default address or threshold.** A valid-looking wrong address
  reads a contract that answers the call and returns a confidently wrong number.
- **Venus health is weaker than Aave health, and says so.** Venus exposes an absolute
  USD buffer rather than a ratio, so its floor must be sized to the position.
- **Editing the mandate invalidates every attestation.** By design — each attestation
  commits to the hash of the exact mandate it was issued for. The form leaves the
  fields editable because seeing that failure demonstrates the binding better than a
  frozen form would.

---

## License and scope

Built for the BNB Chain hackathon, September 2026. Evaluation-only by construction:
no signing of transactions, no funding, no settlement, no broadcast. The one private
key committed to this repository is RFC 8032 test vector 1 — a published constant,
used as a fixture, and refused at boot under `NODE_ENV=production` by recognition of
the key material itself rather than its name.
