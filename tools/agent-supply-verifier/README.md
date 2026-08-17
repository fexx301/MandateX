# MandateX Agent Supply Verifier

This package has four deliberately separate entrypoints:

- `verify` passively checks a curated BSC ERC-8004 identity, canonical owner,
  approved Agent Card, and declared interface. It never negotiates.
- `verify:quote` sends exactly one explicitly acknowledged `negotiate` request,
  validates the returned signed MandateX rebalance quote, and writes a redacted
  replay-protected sidecar. It never creates, funds, settles, or delivers a job.
- `verify:preview` requests and validates one fresh quote, independently
  re-reads the quoted PancakeSwap position, and runs one pinned `eth_call` for
  an exact operator-supplied transaction plan before claiming replay. It never
  signs or submits the plan.
- `verify:activation` prepares and journals the narrow ERC-8183 create,
  register, zero-budget, and `fund(0)` lifecycle. It captures exact unsigned
  SDK intents, but never connects a wallet, signs, or broadcasts a transaction.

## Local verification

```bash
corepack pnpm install
corepack pnpm run check
corepack pnpm test
corepack pnpm run build
corepack pnpm run verify -- --candidates ./config/candidates.json
```

Live passive checks are opt-in:

```bash
MANDATEX_LIVE_SUPPLY=1 corepack pnpm run test:live
```

The anonymous 8004scan service is rate limited. Keep the manifest small and do
not run the live command in a tight loop.

## Trusted quote validation

An accepted quote is signed, expiring, and replayable until it expires. The
active command therefore refuses to run without all of the following:

- `--ack-actionable-quote` in the current invocation;
- a fresh passive report for the selected candidate;
- an owner-only trust file and mandate (`0600`) inside canonical owner-only
  parent directories (`0700`);
- an existing owner-only replay directory (`0700`);
- an existing owner-only output directory (`0700`); and
- a new sidecar path that does not already exist.

The v1 trust rule pins the canonical BSC ERC-8004 registry and requires the
quote signer to equal the canonical ERC-8004 owner in the passive report. EOA
signatures are verified offline. ERC-1271 contract signatures are checked with
bounded `eth_getCode` and `eth_call` requests pinned to the passive report's
canonical block hash.

Trust policy cannot allow passive evidence older than 300 seconds or clock
skew above 30 seconds. Mandate and permission expiry are checked before the
quote request and again after signature verification. Immediately before the
replay claim, the validator also rechecks passive evidence, signed evidence,
the execution estimate, and quote policy using one decision timestamp. A valid
sidecar must have at least 30 seconds of quote lifetime remaining at that
timestamp.

Rebalance proposals use one exact-width, nearest-centered range rule. The
declared `target_width_ticks` must be divisible by the observed `tick_spacing`;
the lower tick is
`floor((2 * current_tick - target_width_ticks + tick_spacing) / (2 * tick_spacing)) * tick_spacing`,
and the upper tick is the lower tick plus the exact target width. The upper tick
is exclusive. Observed position endpoints and proposed executable endpoints
must align to tick spacing, while the wider operator-approved policy envelope
may use unaligned endpoints. The exact proposal must still fit completely
inside that approved envelope.

Prepare private working files:

```bash
cd /Users/femi/Documents/My-Projects/MandateX/tools/agent-supply-verifier

mkdir -p .private/replay .private/sidecars
chmod 700 .private .private/replay .private/sidecars

cp config/quote-trust.template.json .private/quote-trust.json
cp config/rebalance-mandate.template.json .private/rebalance-mandate.json
chmod 600 .private/quote-trust.json .private/rebalance-mandate.json
```

Replace every `REPLACE_...` value and every zero timestamp in the templates.
Do not change the pinned BSC mainnet registry. The trust file must match the
deployed seller's currency, signer, Commerce contract, and exact quote
endpoint. The mandate must use fresh evidence and future mandate/permission
expiries.

Generate a fresh passive report, then request one quote:

```bash
corepack pnpm run verify -- \
  --candidates ./config/candidates.json \
  --out ./.private/passive-report.json

corepack pnpm run verify:quote -- \
  --ack-actionable-quote \
  --candidates "$PWD/config/candidates.json" \
  --passive-report "$PWD/.private/passive-report.json" \
  --trust "$PWD/.private/quote-trust.json" \
  --mandate "$PWD/.private/rebalance-mandate.json" \
  --state-dir "$PWD/.private/replay" \
  --out "$PWD/.private/sidecars/quote-265375.json" \
  --chain-id 56 \
  --token-id 265375
```

The active command performs no retries. Its sidecar contains hashes, gate
states, signer/domain evidence, expiry, and replay status, but excludes the raw
mandate, signed task, price, currency, signature, and refusal text.

Before consuming a valid sidecar, compare the current time with
`quoteExpiresAt`; the 30-second decision-time buffer is not a guarantee that an
artifact remains actionable after storage or handoff.

Input, secure-file, and preflight failures that occur before the quote POST
exit with code `1` and intentionally create no sidecar because no remote offer
was requested. The local replay directory prevents accidental and concurrent
reuse, but it is part of the operator trust boundary and is not authenticated
against a malicious process running as the same user.

The replay claim is committed before the sidecar is persisted. If sidecar
writing or directory sync fails, treat that quote as consumed, inspect the
owner-only replay marker, and request a fresh quote rather than deleting or
reusing the marker.

Exit codes for `verify:quote` are `0` valid, `2` inconclusive, `3` refused,
`4` invalid, and `1` for input or internal failure. A valid quote is still not
a funded job and does not declare the passive candidate hireable; transaction
preview and activation remain separate gates.

## Structural transaction preview

`verify:preview` is the stronger Milestone 4 path. It does not consume an
existing quote sidecar. It requests a fresh quote and keeps the verified signed
task in memory so the transaction plan can be checked before the replay claim.

The current version is deliberately narrow:

- BSC mainnet only;
- EOA quote providers only, with `plan.from` equal to the trusted provider;
- zero native value only;
- the canonical PancakeSwap V3 position manager only;
- one top-level `multicall(bytes[])` containing exactly
  `decreaseLiquidity`, `collect`, and `mint`, in that order;
- full current position liquidity, the quoted token ID and target range,
  provider recipients, bounded deadlines, and no additional selector;
- independent exact re-read of the provider-signed evidence block;
- a fresh `N - 2` EIP-1898 snapshot covering ERC-8004 owner, provider EOA
  code, Pancake deployments, pool, position, approvals, token code, balances,
  and allowances; and
- exactly one plan-simulation call with canonical ABI-result enforcement,
  followed by final signed/fresh block canonicality and
  quote/mandate/permission/transaction-deadline rechecks before replay.

The plan is operator supplied, not agent-authenticated or verifier-generated.
A passing artifact is therefore labelled `PREVIEW_SIMULATION_PASSED`. It does
not declare the candidate hireable. It proves only that the exact structural
plan did not revert at the recorded block, not profitability, independent USD
spend or gas economics, caller key control, submission, or future execution.

Prepare the additional private input:

```bash
cp config/rebalance-transaction-plan.template.json \
  .private/rebalance-transaction-plan.json
chmod 600 .private/rebalance-transaction-plan.json
```

Replace both `REPLACE_...` values. `data` must be the complete byte-aligned
Pancake position-manager multicall. The verifier intentionally does not invent
amounts, deadlines, slippage minima, or calldata.

Run the preview directly after generating a fresh passive report. Do not run
`verify:quote` first for the same offer:

```bash
corepack pnpm run verify:preview -- \
  --ack-actionable-quote \
  --ack-operator-calldata-preview \
  --candidates "$PWD/config/candidates.json" \
  --passive-report "$PWD/.private/passive-report.json" \
  --trust "$PWD/.private/quote-trust.json" \
  --mandate "$PWD/.private/rebalance-mandate.json" \
  --transaction-plan "$PWD/.private/rebalance-transaction-plan.json" \
  --state-dir "$PWD/.private/replay" \
  --out "$PWD/.private/sidecars/preview-265375.json" \
  --chain-id 56 \
  --token-id 265375
```

Exit codes are `0` preview passed, `2` inconclusive, `3` quote refused, `4`
invalid, and `1` for input or internal failure. No live preview should be run
until the trusted provider, Commerce contract, currency, LP position, and
complete private transaction plan have been independently confirmed.

## Recoverable ERC-8183 activation journal

`verify:activation prepare-create` is the Milestone 5 activation boundary. It
does not consume a previously written quote or preview sidecar. In one process
it validates a fresh signed quote, performs the structural preview, observes
the pinned ERC-8183 deployment, captures the exact unsigned create intent, and
durably installs the initial activation journal generation.

Create separate owner-only activation directories before running it:

```bash
mkdir -p .private/activation-state .private/activation-reports
chmod 700 .private/activation-state .private/activation-reports
```

The command requires the quote and preview acknowledgements plus explicit
acknowledgements that the job description is public and the client address is
operator supplied rather than provider signed:

```bash
corepack pnpm run verify:activation -- prepare-create \
  --ack-actionable-quote \
  --ack-operator-calldata-preview \
  --ack-public-job-description \
  --ack-buyer-address-not-provider-signed \
  --candidates "$PWD/config/candidates.json" \
  --passive-report "$PWD/.private/passive-report.json" \
  --trust "$PWD/.private/quote-trust.json" \
  --mandate "$PWD/.private/rebalance-mandate.json" \
  --transaction-plan "$PWD/.private/rebalance-transaction-plan.json" \
  --quote-state-dir "$PWD/.private/replay" \
  --activation-state-dir "$PWD/.private/activation-state" \
  --report-dir "$PWD/.private/activation-reports" \
  --chain-id 56 \
  --token-id 265375 \
  --client REPLACE_CLIENT_ADDRESS \
  --job-expires-at REPLACE_FUTURE_UNIX_SECONDS \
  --cleanup-owner mandatex_operator
```

The initial journal commit is a recoverable three-stage protocol:

1. `STAGED`: immutable sequence-zero state and redacted report artifacts are
   written, synced, and verified without publishing a journal head.
2. `REPLAY_CLAIMED`: a replay-v2 marker is atomically published from a synced
   private temporary file. The marker binds the complete `ActivationHead` and
   its canonical SHA-256 digest.
3. `HEAD_INSTALLED`: under the activation lock, the marker and its exact
   content-addressed artifacts are reverified before that marker-bound head is
   installed, synced, reloaded, and verified.

Generic activation persistence rejects sequence zero. Only this replay-aware
bootstrap may create or recover the initial head. On an exact retry or a
conflicting sequence-zero candidate, the marker winner's immutable artifacts
are loaded rather than recomputed, compared with the fresh candidate's client,
provider, mandate, plan, expiry, cleanup owner, and deployment bindings, and
rechecked against a fresh canonical deployment observation. A legacy replay-v1
marker remains consumed quote evidence but cannot resume activation bootstrap.

Deployment observation fails closed on code, implementation, topology, policy,
payment-token, or expiry drift and checks that both Commerce and Router are not
paused. A successful `prepare-create` writes only the redacted activation
report to stdout; the private state and report generations remain immutable and
content addressed.

Later journal commands prepare the next exact unsigned intent and reconcile
externally submitted transactions. `reconcile` requires an external
transaction hash and explicit acknowledgements that the hash came from outside
the CLI and that the CLI never signs or broadcasts. `broadcast-unknown` freezes
the current intent when an external broadcast returned no hash. No command
notifies the provider, submits delivery, completes or settles a job, or
executes the PancakeSwap LP plan.

## Local zero-budget fork proof

The Milestone 5 execution proof is deliberately limited to a disposable Anvil
BSC fork on `127.0.0.1:18545`:

```bash
./scripts/prove-zero-budget-fork.sh
```

The proof checks the pinned Commerce and Router topology and pause state, uses
only Anvil's local unlocked accounts, creates and registers one job, sets a
zero budget, calls `fund(0)`, and stops at the `FUNDED_NOT_DELIVERED` checkpoint
(`ACTIVATION_FUNDED_NOT_DELIVERED` in the journal report). It must not notify a
provider, deliver or submit a result, complete, settle, execute the LP plan,
load a production wallet, or send a mainnet transaction. This local fork proof
is not a claim that a live external ERC-8183 lifecycle has been executed.
