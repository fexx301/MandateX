# `@mandatex/category-adapters`

Fail-closed telemetry evidence producers for the **grid**, **yield** and
**lending-health** marketplace categories.

This package is also the hand-off artifact for the category integration boundary
recorded in `SESSION_HANDOFF.md` (2026-08-17). That note asks for *audited adapter
IDs, evidence schema versions, thresholds, and configuration* before grid, yield
and health stop being `CATEGORY_*_UNSUPPORTED` in Marketplace Core. All four are
below, in [What Codex needs](#what-codex-needs-to-register-these).

Nothing here edits Core. Core still reports all three categories as unsupported,
and it should keep doing so until the registration described below happens.

## Status

71/71 checks pass (`corepack pnpm smoke`). No network, no clock, no chain — every
on-chain read is served by return data constructed byte by byte in the suite,
because the branches that matter most cannot be produced on demand from a live
endpoint: a tick outside the legal range, a vault with zero shares, Aave's no-debt
sentinel.

Two of those checks are cross-validations against Marketplace Core itself rather
than against my own restatement of it: every evidence document is hashed with
Core's `canonicalSha256`, and the narrowed evidence is parsed by Core's own
`displaySafeQuoteProjectionPayloadSchema`.

## The three adapters

| Category | Adapter ID | Evidence schema | Reads | Metric |
|---|---|---|---|---|
| `grid` | `pancakeswap-v3-grid-v1` | `mandatex.category.grid-evidence.v1` | 1 | `slot0().tick` vs. the declared grid band |
| `yield` | `erc4626-yield-v1` | `mandatex.category.yield-evidence.v1` | 2 | `totalAssets/totalSupply` share price vs. a floor |
| `health` | `aave-v3-health-v1` | `mandatex.category.health-evidence.v1` | 1 | `getUserAccountData().healthFactor` vs. a floor |

The IDs follow the shape Core already uses for the one supported adapter,
`pancakeswap-v3-rebalancing-v1`, so these read as members of the same family
rather than a parallel naming scheme.

**One real metric each, and no more than that is claimed.** The grid adapter does
not say a grid is profitable, funded, or that its orders were ever placed — those
need order-level state a single pool read cannot see. Each metric is spelled out
in `CATEGORY_ADAPTER_REGISTRY` so the claim stays narrower than the category name
suggests.

### Every selector was computed, not recalled

```
0x3850c7bd  slot0()
0x01e1d114  totalAssets()
0x18160ddd  totalSupply()
0xbf92857c  getUserAccountData(address)
```

Verified with `viem.toFunctionSelector`. A wrong selector does not error — it
calls a different function or hits the fallback, and the number that comes back
looks fine either way.

## Result shape

```ts
type AdapterResult<Evidence> =
  | { status: "pass";    adapterId; category; evidence }
  | { status: "fail";    adapterId; category; code; message }
  | { status: "unknown"; adapterId; category; code; message }
```

The three states are Core's `gateObservationSchema` states, so
`categoryGateObservation()` is an identity on `status` and there is no translation
layer in which a `fail` could become something else.

**`fail` and `unknown` are not interchangeable.**

- `fail` — the metric was read and violates policy.
- `unknown` — the metric could not be established.

An unreachable RPC endpoint is not evidence that a position is unhealthy, and
reporting it as `fail` would manufacture a finding out of an outage. A health
factor genuinely under the floor is not "inconclusive" either. Every code is
assigned on that basis alone:

| Code | State | Meaning |
|---|---|---|
| `GRID_SPOT_OUTSIDE_BAND` | fail | Spot tick is outside the declared band |
| `YIELD_SHARE_PRICE_BELOW_FLOOR` | fail | Share price under the configured floor |
| `HEALTH_FACTOR_BELOW_FLOOR` | fail | Health factor under the configured floor |
| `READ_UNAVAILABLE` | unknown | A required call did not complete |
| `READ_RETURNDATA_MALFORMED` | unknown | A call returned non-static-ABI data |
| `YIELD_SHARE_PRICE_UNDEFINED` | unknown | No shares outstanding, so the ratio is 0/0 |
| `HEALTH_NO_DEBT_POSITION` | unknown | No debt, so no health factor to maintain |
| `GRID_TICK_UNINTERPRETABLE` | unknown | Tick outside the range a v3 pool can hold |
| `GRID_SQRT_PRICE_IMPLAUSIBLE` | unknown | Sqrt price outside the range a v3 pool can hold |

### Two failure classes, deliberately handled differently

Malformed **configuration** throws at the boundary. A verifier holding an
unparseable adapter config should refuse to start, not emit `unknown` for every
request until somebody notices.

Malformed **chain data** never throws. An exception escaping an adapter would take
down the request path that is supposed to fail closed. The suite fires empty,
non-hex, misaligned, oversized and all-ones payloads at all three adapters and
asserts none of them throws.

## Configuration

No contract address has a default. A default would be inherited silently by
whoever forgot to set it, and a valid-looking wrong address — right protocol,
wrong chain — reads a contract that answers the call and returns a confidently
wrong number. Pin addresses from each protocol's own published deployment record.

```ts
// grid
{ adapterId: "pancakeswap-v3-grid-v1", protocol: "pancakeswap-v3",
  poolAddress: "0x…", lowerTick: -1000, upperTick: 1000 }

// yield
{ adapterId: "erc4626-yield-v1", protocol: "erc4626",
  vaultAddress: "0x…", minSharePriceScaled: "1000000000000000000" }

// health
{ adapterId: "aave-v3-health-v1", protocol: "aave-v3",
  poolAddress: "0x…", accountAddress: "0x…",
  minHealthFactorScaled: "1100000000000000000" }  // optional, this is the default
```

### Thresholds

| Adapter | Threshold | Default | Units |
|---|---|---|---|
| grid | `lowerTick` / `upperTick` | **none — required** | pool ticks |
| yield | `minSharePriceScaled` | **none — required** | asset atomic units per 10¹⁸ share atomic units |
| health | `minHealthFactorScaled` | `1100000000000000000` (1.1) | 1e18-scaled |

The health default is 1.1, not 1.0. Aave liquidates below 1.0, so a floor at
exactly 1.0 passes an account one adverse tick from liquidatable — a true
statement about the present block and a useless one about the next.

Grid bands and yield floors have no default because no defensible one exists. A
grid's band *is* its strategy, so a default band silently substitutes a different
strategy; a share-price floor depends on the vault and its asset.

Yield's floor is expressed in **atomic units** rather than normalized decimals on
purpose. The obvious alternative — read `decimals()` on the vault and the asset,
then normalize — adds two reads and a class of bug where a decimals mismatch
scales the ratio by 10¹² while still producing a plausible number. In atomic units
there is nothing to mismatch.

## Three properties enforced by construction, not by convention

**All reads in one evidence document are at one block.** `PinnedBlockReader`
carries its own `anchor` and exposes no way to name a block per call, so an adapter
cannot straddle two blocks. For the yield adapter this is not hypothetical:
`totalAssets` and `totalSupply` read one block apart across a deposit produce a
share price that never existed at any block, and it looks entirely reasonable.

**Adapters have no transport, no environment, and no clock.** No URL, no fetch, no
`process.env`, no `Date.now()`. Transport pinning and endpoint trust stay in the
verifier runtime that already owns them. An adapter that could open its own socket
would be a second, unpinned trust path into the signing service.

**`observedAt` is the block's timestamp, not the local clock.** The signed payload
carries only `{ category, observedAt }` for these categories, so `observedAt` is
the entire freshness claim a consumer gets. From the local clock it would be the
verifier's opinion about when it ran; from the block it is a statement about the
chain state actually measured.

## The adapter cannot supply its own evidence digest

The integration boundary requires the verifier to canonicalize and hash evidence
itself and not to trust a digest supplied by an adapter. That is honoured by
leaving the adapter **nowhere to put one**: no field on `AdapterResult` or on any
evidence schema can hold a digest of the evidence. If the field existed, some
future caller would eventually read it instead of recomputing, and a compromised
or merely buggy adapter would then be choosing the commitment that gets signed.

The suite walks every evidence document and asserts that each hash-shaped key is
either `observedBlockHash` or a transport observation inside `reads` — the
`requestSha256` / `responseSha256` pair, which digests *transport bytes*, a
different thing from a digest of the evidence, and mirrors what the existing
preview path already records.

## Why a display sidecar is required, demonstrated rather than argued

`unsupportedCategoryEvidenceSchema` in Core is `.strict()` and carries exactly
`{ category, observedAt }` for these three categories. Metrics cannot ride along
in the signed payload. Substituting real grid evidence into a
known-valid fixture payload and handing it to Core's own parser:

```
Core accepts narrowed grid evidence:      true
Core accepts evidence with a metric added: false
  -> unrecognized_keys at categoryEvidence
```

So the detail lives in the hashed verifier artifact, and any UI-facing metric must
travel in a sidecar whose digest matches the committed artifact. `toSignedCategoryEvidence()`
performs the narrowing in one reviewable place so a caller assembling the payload
by hand cannot get it wrong.

## What Codex needs to register these

Three coordinated changes, per the integration boundary. Ordered.

**1. Core — a static policy table entry per category.** Closed and immutable: no
module discovery, no runtime callbacks, no environment-selected code, no telemetry
executed inside Core. The values to hard-code are the adapter IDs and evidence
schema strings in the table at the top of this document. The sites that currently
hard-fail are:

- `tools/marketplace-core/src/codes.ts:70-72` — the three `CATEGORY_*_UNSUPPORTED` constants
- `tools/marketplace-core/src/codes.ts:159-161` — their "not implemented in Marketplace Core v1" messages
- `tools/marketplace-core/src/codes.ts:190-192` — `unsupportedCodeForCategory`
- `tools/marketplace-core/src/evaluate.ts:294` — `mandate.category !== "rebalancing"` → `MANDATE_CATEGORY_MISMATCH`
- `tools/marketplace-core/src/evaluate.ts:390` — the early return that skips category findings
- `tools/marketplace-core/src/evaluate.ts:683-695` — the receipt's `adapter` dispatch, which needs `{ status: "supported", name: <adapterId> }` for the enabled categories

**2. Verifier runtime — call the adapter and commit its evidence.** Adapters execute
in the verifier/service runtime, never in Core. Per run:

- build a `PinnedBlockReader` for the target block from the existing pinned transport
- call `evaluateGrid` / `evaluateYield` / `evaluateHealth`
- write `result.status` into `verification.category`
- on `pass`, canonicalize and hash `result.evidence` **in the verifier**, and commit
  that digest through `sourceCommitments.quoteValidationSha256`
- set `categoryEvidence` from `toSignedCategoryEvidence(result.evidence)`

**3. Verifier policy hash — include the registry and the thresholds.** Everything in
`CATEGORY_ADAPTER_REGISTRY` plus the configured thresholds and addresses. If a
threshold changes and the digest does not, the deployment signs under a policy
identity that no longer describes it. Then redeploy signer and evaluator together.

### Flagged for Codex, not decided unilaterally

- **`fail` carries no evidence.** The boundary note specifies "verified,
  schema-parsed evidence **or** a fail-closed `fail`/`unknown` result", which is
  what is implemented. The consequence is that `HEALTH_FACTOR_BELOW_FLOOR` records
  the verdict but not the health factor that produced it, so a rejection is less
  auditable than an acceptance. Attaching the measurement to `fail` would be a
  change to the result contract and is Codex's call, not mine.
- **Thresholds are global, not per-user.** See below. If per-user thresholds are
  wanted for September, that is a mandate-schema field and therefore a coordinated
  contract version.

## Known limitation: thresholds are deployment policy, not user policy

The frozen v2 mandate schema has no field in which a user can express a metric
threshold for these three categories — `mandate.rebalancing` is the only
category-specific policy object. So **a user cannot currently say "keep my health
factor above 1.8."** The floor is set by whoever deploys the verifier, applies to
every mandate in that category, and is frozen into the verifier policy hash.

That is a coherent v1: the floor is auditable and committed rather than ambient.
It is not the same product as per-user thresholds, and the marketplace UI must not
imply otherwise. Making thresholds user-supplied requires a new mandate-schema
field, which is a coordinated contract version rather than a unilateral September
change.

## Running

```bash
corepack pnpm install
corepack pnpm build
corepack pnpm check   # tsc --noEmit
corepack pnpm smoke   # 71 checks
```

`@mandatex/marketplace-core` is a **devDependency**, linked so the suite can
validate against Core's real canonicalizer and real schemas. Nothing in `src/`
imports it outside `smoke.ts`, so the shipped adapter code depends only on `zod`
— which matters because this code runs in the container that holds the signing
key, and viem is deliberately not pulled in to decode four static words.
