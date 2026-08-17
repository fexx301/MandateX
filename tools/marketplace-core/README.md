# MandateX Marketplace Core

Milestone 6 is an API-only, execution-free core for comparing a small verified
RFQ cohort. It converts trusted in-process quote projections into versioned
marketplace artifacts, applies deterministic eligibility gates, and ranks only
eligible rebalancing candidates.

It deliberately contains no frontend, wallet, signing, funding, job lifecycle,
settlement, persistence, scheduler, Altana integration, or strategy execution.

## Public artifacts

Every artifact is strict Zod data with a stable schema identifier:

- `mandatex.marketplace.mandate.v1`
- `mandatex.marketplace.quote.v1`
- `mandatex.marketplace.eligibility-decision.v1`
- `mandatex.marketplace.receipt.v1`

The receipt is labelled `evaluation_only`. Its SHA-256 commitments make the
mandate, normalized quote order, decision order, and ranking reproducible; they
are evidence commitments, not signatures or execution proofs.

## Trust boundary

Marketplace Core does not load or reconstruct quotes from verifier sidecars.
Those redacted sidecars intentionally omit fields such as price, permissions,
estimates, and signed task data.

The application installer creates one core instance and receives its trusted
ingress exactly once. Only the already-trusted quote-validation success path
should retain that ingress and construct a display-safe payload:

```ts
let trustedIngress: TrustedProjectionIngress | undefined;
const core = createMarketplaceCore({
  installTrustedProjectionIngress(ingress) {
    trustedIngress = ingress;
  },
  clock: () => unixSeconds,
});
if (trustedIngress === undefined) throw new Error("ingress was not installed");

const captured = trustedIngress.capture(displaySafePayload);
const result = core.evaluateMarketplace({
  mandate,
  candidates: [captured],
});

const consistency = verifyMarketplaceEvaluationConsistency(result);
if (consistency.scope !== "integrity_only") throw new Error("unexpected scope");
```

Capture is represented by per-core, process-local object identity. A projection
captured by one core is rejected by every other core. JSON serialization,
cloning, persistence, or attempting to feed stamped capture metadata back into
the ingress loses or violates that identity and is rejected. The payload schema
is a narrow allowlist and rejects reserved capture fields, signed tasks,
calldata, sidecars, and unknown fields. The ingress stamps `schema`,
`captureContext`, and `capturedAt` itself.

The installer-owned ingress is an integration capability, not a cryptographic
verifier. The repository does not yet wire it into a production quote-validator
owner; an integration must retain it only in the already-trusted quote and
preview validation-success path. Marketplace Core deliberately exposes no
public recapture, raw normalization, scoring, or sidecar-loading helper.

Live evaluation reads the injected core clock exactly once and writes that time
to the receipt. Callers cannot select an historical `evaluatedAt` value for a
live eligibility decision, so expiry and freshness gates always use the core's
current trusted time authority. The ingress installer must complete
synchronously; installer and clock failures return stable coded errors.

`verifyMarketplaceEvaluationConsistency` is deliberately named and wrapped as
`integrity_only`. It reparses exact canonical artifacts and recomputes decisions,
ranking, commitments, and the receipt ID. It does not recover the process-local
capture brand and cannot establish quote origin, validator provenance,
hireability, signature authority, or execution. In particular,
`sourceCommitments` are caller-supplied digest fields; consistency verification
can prove that they were not changed inside the artifact graph, not that the
referenced validation occurred. It validates the receipt's recorded historical
time and does not establish that an artifact remains currently eligible.

## Pricing policy

Agent prices arrive as token atomic units. They are not USD values.

- An atomic price of `0` normalizes safely to `0` USD micros.
- Every nonzero atomic price becomes
  `PRICING_USD_UNAVAILABLE` / `inconclusive`.
- An inconclusive price is never given a score or ranking position.

Gas and exposure fields are integer USD micros supplied by the separately
validated display-safe projection. No floating-point money enters the core.

## Category support

`rebalancing` has one complete v1 normalizer for a bounded PancakeSwap V3
position. It verifies identity, publisher, endpoint, task interface, category,
quote completeness, freshness, expiry, mandate identity, position, protocol,
trigger, approved range, the deterministic target range derived from width and
tick spacing, price availability, fee/gas/
slippage/exposure budgets, permission allowlists, spend cap, permission expiry,
and a block-matched read-only preview.

The V3 target width must be divisible by the observed tick spacing. Marketplace
Core selects the aligned range whose midpoint is nearest the current tick,
resolving exact half-spacing ties toward the greater tick because the upper
endpoint is exclusive:

```text
lower = floor((2 * currentTick - targetWidth + tickSpacing)
              / (2 * tickSpacing)) * tickSpacing
upper = lower + targetWidth
```

Current and proposed V3 endpoints must be spacing-aligned, `upper - lower` is
exactly the declared target width, and containment uses `[lower, upper)`.

The remaining required categories are honest, stable unsupported results:

- `CATEGORY_GRID_UNSUPPORTED`
- `CATEGORY_YIELD_UNSUPPORTED`
- `CATEGORY_HEALTH_UNSUPPORTED`

No placeholder cards or fabricated category metrics are generated.

## Candidate and ranking rules

- Zero to eight candidate quotes per evaluation.
- Candidate `(chainId, tokenId)` and `quoteId` values must be unique.
- Quotes and decisions are ordered by numeric candidate identity, then quote ID.
- Exclusion dominates inconclusive when both are observed.
- Unsupported categories are never ranked.
- Only `eligible` decisions receive a score.
- Ranking uses exact integer arithmetic and these frozen weights:

| Factor | Weight |
| --- | ---: |
| Mandate fit | 30 |
| Execution readiness | 20 |
| Evidence freshness | 20 |
| Risk compatibility | 15 |
| Total cost | 10 |
| Reputation confidence | 5 |

Each factor is `0..10000` basis points. `weightedPoints` is the exact
`weight * scoreBps` integer. Ranking compares the unrounded weighted total,
then candidate identity and quote ID for deterministic ties. Scores are a
transparent comparison aid, never a guarantee of performance.

## Commands

Requires Node.js 22 or newer.

```bash
corepack pnpm install
corepack pnpm run check
corepack pnpm test
corepack pnpm run build
```

The tests cover canonical serialization, schema arithmetic and outcome
precedence, deterministic input ordering, the eight-candidate ceiling,
duplicate rejection in live and persisted artifacts, eligible-only ranking,
all scored freshness timestamps, nonzero pricing, explicit unsupported
categories, hard exclusions, mandate chronology, exact V3 widths and negative
tick ties, nested immutability, tamper rejection, strict integrity-only parsing,
and the per-core capture boundary.
