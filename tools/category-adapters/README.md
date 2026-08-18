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

97/97 checks pass (`corepack pnpm smoke`). No network, no clock, no chain — every
on-chain read is served by return data constructed byte by byte in the suite,
because the branches that matter most cannot be produced on demand from a live
endpoint: a tick outside the legal range, a vault with zero shares, Aave's no-debt
sentinel.

Two of those checks are cross-validations against Marketplace Core itself rather
than against my own restatement of it: every evidence document is hashed with
Core's `canonicalSha256`, and the narrowed evidence is parsed by Core's own
`displaySafeQuoteProjectionPayloadSchema`.

## The four adapters

| Category | Adapter ID | Evidence schema | Reads | Metric |
|---|---|---|---|---|
| `grid` | `pancakeswap-v3-grid-v1` | `mandatex.category.grid-evidence.v1` | 1 | `slot0().tick` vs. the declared grid band |
| `yield` | `erc4626-yield-v1` | `mandatex.category.yield-evidence.v1` | 2 | `totalAssets/totalSupply` share price vs. a floor |
| `health` | `aave-v3-health-v1` | `mandatex.category.health-evidence.v1` | 1 | `getUserAccountData().healthFactor` vs. a floor |
| `health` | `venus-health-v1` | `mandatex.category.venus-health-evidence.v1` | 3 | `getAccountLiquidity()` liquidity/shortfall plus monitored-market `borrowBalanceStored()` vs. a floor |

**`CATEGORY_ADAPTER_REGISTRY` is keyed by adapter ID, not by category.** `health`
has two entries. That is not redundancy: BSC has two major lending protocols with
structurally incompatible interfaces, and the external supply research (`supply/`)
found that **every live health agent on chain 56 monitors Venus, not Aave** —
including the team's own `bnb-guardian`. A table keyed by category cannot express
that, and would silently pick one protocol for a category whose actual supply uses
the other.

Both health adapters are kept. Aave v3 is genuinely deployed on BSC — verified,
1933 bytes of proxy code at `0x6807dc923806fE8Fd134338EABCA509979a7e0cB` — so
`aave-v3-health-v1` is not wrong, it is aimed at supply that does not exist yet.
`venus-health-v1` is aimed at the supply that does.

The IDs follow the shape Core already uses for the one supported adapter,
`pancakeswap-v3-rebalancing-v1`, so these read as members of the same family
rather than a parallel naming scheme.

**One real metric each, and no more than that is claimed.** The grid adapter does
not say a grid is profitable, funded, or that its orders were ever placed — those
need order-level state a single pool read cannot see. Each metric is spelled out
in `CATEGORY_ADAPTER_REGISTRY` so the claim stays narrower than the category name
suggests.

### Why Venus is a separate adapter and not a configuration

Venus is a Compound-v2 fork and **has no health factor at all**.
`getAccountLiquidity(address)` returns `(error, liquidity, shortfall)` — an
absolute USD buffer above the collateral requirement, or an absolute amount below
it, with at most one of the two nonzero. Three words with different meanings and no
ratio anywhere. Verified against the live Comptroller at
`0xfD36E2c2a6789Db23113685031d7F16329158384`: three words returned, versus Aave's
six.

Two consequences that shape the adapter:

**It needs more than one read.** Venus reports both "no position at all" and "a position
with exactly zero buffer" as `liquidity == 0 && shortfall == 0`. Those deserve
opposite verdicts — nothing to maintain, versus the riskiest non-liquidatable state
there is — and one call cannot tell them apart. `getAssetsIn` disambiguates by
returning the markets entered. Without it the adapter would treat a maximally
leveraged position and an empty account identically. A third read then closes the
no-debt gap; see below.

**Its metric is weaker than Aave's, and that is recorded rather than hidden.** An
absolute USD floor does not scale with position size the way a health factor does:
a $10,000 buffer is ample on a $50,000 position and thin on a $5,000,000 one. Venus
exposes no single call that normalizes it, and deriving a true ratio would need
per-market borrow balances — far past "one real metric". So the floor has to be set
with the monitored position's size in mind.

Venus also reports failure **in band** — a nonzero first word rather than a revert
— so the error code is checked explicitly before the other two words are read. A
failed computation returns zeros, so skipping that check would make an error look
like a position with no buffer.

### The Venus no-debt gap is closed — resolved 2026-08-18

For one revision this adapter was strictly weaker than its Aave sibling. `getAssetsIn`
reports markets *entered*, and enabling an asset as collateral counts even if nothing
was borrowed, so a collateral-only account passed a health mandate that is vacuous
for it. `aave-v3-health-v1` never had that hole: it reads `totalDebtBase` and refuses
no-debt outright.

Closed by a third read — `borrowBalanceStored(address)` on a **named market**, now a
required `borrowMarketAddress` config field. Naming one market was chosen over
fanning out across every entered market: the fan-out is unbounded (52 markets exist
on BSC today), its cost scales with someone else's position, and it would make the
read count non-deterministic, which the pinned-block evidence shape depends on being
fixed. Both adapters now refuse no-debt for the same reason, and the test that
asserted the gap was **deliberately inverted** rather than deleted, so the closure is
proven rather than assumed.

**Measured, not assumed — and it caught a bug before it shipped.** Compound v2
declares `borrowBalanceStored(address)` as returning a single `uint`. The live Venus
vTokens on BSC return **three words**, balance in word 0 and two trailing zeros —
verified against a real ~10,000 USDT borrow on vUSDT. So the adapter requires only
that a word be present and reads word 0, exactly as the grid adapter tolerates a fork
appending fields to `slot0()`. Requiring exactly one word, the natural reading of the
declared ABI, would have made this adapter return `READ_RETURNDATA_MALFORMED` against
every real Venus market.

### Every selector was computed, not recalled

```
0x3850c7bd  slot0()
0x01e1d114  totalAssets()
0x18160ddd  totalSupply()
0xbf92857c  getUserAccountData(address)
0x5ec88c79  getAccountLiquidity(address)
0xabfceffc  getAssetsIn(address)
0x95dd9193  borrowBalanceStored(address)
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
| `VENUS_ACCOUNT_SHORTFALL` | fail | Below the Venus collateral requirement, liquidatable now |
| `VENUS_LIQUIDITY_BELOW_FLOOR` | fail | Excess Venus liquidity under the configured floor |
| `READ_UNAVAILABLE` | unknown | A required call did not complete |
| `READ_RETURNDATA_MALFORMED` | unknown | A call returned non-static-ABI data |
| `YIELD_SHARE_PRICE_UNDEFINED` | unknown | No shares outstanding, so the ratio is 0/0 |
| `HEALTH_NO_DEBT_POSITION` | unknown | No debt, so no health factor to maintain |
| `VENUS_NO_POSITION` | unknown | No Venus markets entered, so no position to maintain |
| `VENUS_NO_DEBT_POSITION` | unknown | No borrow balance in the monitored market, so no health to maintain |
| `VENUS_LIQUIDITY_COMPUTATION_FAILED` | unknown | Venus returned a nonzero in-band error code |
| `VENUS_LIQUIDITY_INCONSISTENT` | unknown | Both liquidity and shortfall nonzero, which Venus forbids |
| `GRID_TICK_UNINTERPRETABLE` | unknown | Tick outside the range a v3 pool can hold |
| `GRID_SQRT_PRICE_IMPLAUSIBLE` | unknown | Sqrt price outside the range a v3 pool can hold |

`VENUS_ACCOUNT_SHORTFALL` is a separate code from `VENUS_LIQUIDITY_BELOW_FLOOR`
because "liquidatable right now" is a stronger statement than "under our floor",
and collapsing them would lose that. `VENUS_NO_POSITION` is checked **before** the
shortfall branch so an empty account can never be reported as liquidatable.

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

// health (Aave v3)
{ adapterId: "aave-v3-health-v1", protocol: "aave-v3",
  poolAddress: "0x…", accountAddress: "0x…",
  minHealthFactorScaled: "1100000000000000000" }  // optional, this is the default

// health (Venus)
{ adapterId: "venus-health-v1", protocol: "venus",
  comptrollerAddress: "0x…", accountAddress: "0x…",
  borrowMarketAddress: "0x…",   // required — the vToken defining "has debt"
  minLiquidityUsdScaled: "…" }  // required, 1e18-scaled USD
```

### Thresholds

| Adapter | Threshold | Default | Units |
|---|---|---|---|
| `pancakeswap-v3-grid-v1` | `lowerTick` / `upperTick` | **none — required** | pool ticks |
| `erc4626-yield-v1` | `minSharePriceScaled` | **none — required** | asset atomic units per 10¹⁸ share atomic units |
| `aave-v3-health-v1` | `minHealthFactorScaled` | `1100000000000000000` (1.1) | 1e18-scaled ratio |
| `venus-health-v1` | `minLiquidityUsdScaled` | **none — required** | 1e18-scaled USD, absolute |

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
schema strings in the table at the top of this document.

**There are four adapter IDs, not three, and `health` has two.** If Core's policy
table is keyed by category with one adapter each, it cannot express the protocol
that the actual BSC supply uses. Key it by adapter ID, or allow a category to carry
a set. The sites that currently hard-fail are:

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
- ~~Venus cannot refuse a collateral-only account.~~ **Resolved 2026-08-18** by
  Codex choosing the named-market option; `borrowMarketAddress` is now required and
  the adapter issues three reads.

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

## Operator scripts

Two read-only tools for choosing the configuration the adapters require. Neither
signs, sends, funds, nor broadcasts anything, and neither can reach a wallet path.

```bash
corepack pnpm discover:venus                      # find a live Venus borrower
corepack pnpm discover:venus -- --market vUSDC --blocks 8000 --floor 500
corepack pnpm verify:vault 0xVault                # is this a usable ERC-4626 vault?
corepack pnpm verify:vault -- --discover --address 0xVault
```

**`discover-venus-borrower.mjs`** exists because the health adapter needs an account
that actually owes something — an account with no debt is a different case, not a
weaker one, and correctly returns `VENUS_NO_DEBT_POSITION`. It reads recent `Borrow`
events, runs the **real** adapter against each candidate at a pinned block, and
prints a paste-ready configuration for one that produces `pass` evidence.

It hardcodes no borrower, deliberately: a pinned address is a demo that breaks
silently the day that account repays. **You do not need to own the account** — every
call is a read, so monitoring requires no key. If you want a position you control,
fork BSC with Anvil instead; that is the only transaction path this project permits.

Whatever it returns, label it honestly: a live read-only observation of a public
third-party position proves the adapter produces real mainnet evidence, and implies
no mandate relationship with that account's owner.

**`verify-erc4626.mjs`** exists because the yield adapter ships no default vault. A
valid-looking wrong address is worse than a missing one — it reads a contract that
answers and returns a confidently wrong number. So it checks, in order: code exists;
`totalAssets()` returns exactly one word; `totalSupply()` returns exactly one word;
`totalSupply()` is non-zero, so share price is defined rather than 0/0; and finally
runs the real adapter, so the verdict is the adapter's rather than the script's.

`--discover` without `--address` needs an endpoint that permits unfiltered
`eth_getLogs`. Public BSC endpoints refuse it regardless of block range, and the
script says so precisely rather than blaming the range.


```bash
corepack pnpm install
corepack pnpm build
corepack pnpm check   # tsc --noEmit
corepack pnpm smoke   # 97 checks
```

`@mandatex/marketplace-core` is a **devDependency**, linked so the suite can
validate against Core's real canonicalizer and real schemas. Nothing in `src/`
imports it outside `smoke.ts`, so the shipped adapter code depends only on `zod`
— which matters because this code runs in the container that holds the signing
key, and viem is deliberately not pulled in to decode four static words.
