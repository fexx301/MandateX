# MandateX Agent Supply Verifier

## Purpose

The Agent Supply Verifier is a standalone TypeScript package whose default,
passive mode answers a narrow question:

> What evidence do we have, right now, that a curated BSC agent is registered,
> reachable, and able to describe the task interfaces that MandateX expects?

It is a supply-quality boundary for the marketplace. It is not an agent
runtime, wallet, scheduler, transaction broadcaster, or settlement client.

The default production path is intentionally read-only. It must never send
`negotiate`, `notify_funded`, `create`, or `fund` requests, invoke a wallet,
sign a message, submit a transaction, or imply that a reachable agent is safe
to hire.

A separate `verify:quote` entrypoint may send one `negotiate` request only
after an explicit acknowledgement and strict trust/file preflight. That path
still has no wallet, retry, job creation, funding, delivery, or settlement
authority.

A stricter `verify:preview` entrypoint may request one fresh quote and perform
one exact plan-simulation `eth_call` only after separate quote and calldata
acknowledgements. It keeps the decoded signed task in memory, delays replay
until preview passes, and has no signing or submission authority.

The separate `verify:activation` journal extends that armed path only far
enough to prepare and reconcile a zero-budget ERC-8183 lifecycle. Its
`prepare-create` command validates a fresh quote and preview, observes the
pinned deployment, captures an exact unsigned SDK intent, and recoverably
installs the initial journal head. It never connects a wallet, signs, or
broadcasts; reconciliation accepts only transaction hashes supplied by an
external executor.

## Package Boundary

The package lives at `MandateX/tools/agent-supply-verifier/`, outside the
BNB Agent Studio seller workspace. It has its own `package.json`, lockfile,
compiler configuration, CLI, and tests. It must not import the seller runtime,
wallet files, `.env.local`, signing code, deployment configuration, or LLM
code.

The core is importable and receives its clock, DNS resolver, HTTP transport,
RPC source, replay store, and inputs as dependencies. The passive CLI emits a
versioned report. The quote and preview CLIs emit distinct redacted sidecars.
The activation CLI writes immutable content-addressed state/report generations
and emits only a redacted activation report or failed preview sidecar to
stdout. Human-readable diagnostics go to stderr.

## Trust Model

No single source is authoritative for every claim:

| Source | What it can establish | What it cannot establish |
| --- | --- | --- |
| Curated manifest | Which candidate identity and endpoint origin MandateX permits us to inspect | That the candidate currently works or controls the endpoint |
| 8004scan | Discovery metadata, indexed service claims, and a bounded detail snapshot | Current identity ownership, endpoint control, quote validity, or hireability |
| BSC RPC | Chain ID, registry code, block provenance, and ERC-8004 `ownerOf` at a pinned block | That the owner controls the advertised endpoint |
| Agent Card | The response served by the approved origin and its declared protocol skills | Cryptographic identity binding, quote correctness, permission safety, or execution |
| Armed quote validator | A signed, expiring, category-policy-compatible offer from the pinned endpoint | Execution success, profitability, funding, or future performance |
| Armed structural preview | Independent signed-block and fresh-block state plus one exact non-reverting operator plan at block X | Agent-authenticated calldata, key control, economics, submission, profitability, or future success |
| Armed activation journal | A replay-bound unsigned ERC-8183 intent, pinned deployment observation, immutable state history, and receipt/job reconciliation for an externally submitted transaction hash | Wallet control, broadcast, provider delivery, settlement, LP execution, or live external success |

The passive report keeps identity owner, endpoint operator, and quote signer as
separate evidence fields. The armed v1 trust rule narrows them deliberately:
the trust entry must pin the code-owned BSC ERC-8004 registry, the trusted quote
signer must equal the canonical ERC-8004 owner, and the signed response must
arrive from the exact trusted quote URL. A healthy endpoint that does not match
the approved origin is never probed.

## Evidence Vocabulary

Every observation has one of three evidence levels:

- `claimed`: supplied by the manifest, 8004scan, or the remote Agent Card.
- `detected`: observed by a passive probe, such as a successful HTTPS response,
  valid JSON, or a declared skill.
- `verified`: independently checked against an allowed authority, such as an
  ERC-8004 owner read at a pinned BSC block.

Evidence levels are not collapsed into a score. A report must retain the
source, observation time, response hash, and any chain block/hash for each
observation.

The first implementation may emit only these candidate classifications:

- `REGISTERED_ONLY`: the candidate is in the approved manifest and its
  registry identity is present, but one or more endpoint, binding, protocol,
  quote, policy, or preview gates are unverified.
- `INCONCLUSIVE`: the verifier could not make a reliable decision because a
  configured source, RPC, DNS resolver, or verifier dependency was unavailable,
  rate-limited, malformed, or exceeded a safety budget.
- `UNAVAILABLE`: a candidate-specific endpoint or identity check definitively
  failed after the verifier itself was healthy and able to make the check.

Hireability is not a passive-report classification. Active quote,
category-policy, preview, and activation evidence remain separate artifacts.

An outage is never converted into candidate `UNAVAILABLE`; use `INCONCLUSIVE`
with a redacted source error instead.

## Canonical BSC Configuration

The verifier supports an explicit chain profile. Production promotion and live
v1 execution are limited to BSC mainnet (`56`). Testnet is retained as a
reference profile for fixtures; its canonical RPC uses port `8545`, so it is
not enabled by the v1 port-443 transport policy without a separate review.

| Profile | Chain ID | ERC-8004 registry | RPC origin |
| --- | ---: | --- | --- |
| BSC mainnet | `56` | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | `https://bsc-dataseed.binance.org` |
| BSC testnet | `97` | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | `https://data-seed-prebsc-2-s2.binance.org:8545` |

The registry deployments are pinned from the installed official
`@bnbagent/sdk@0.5.0` ERC-8004 chain configuration. Reports retain that source
label plus the observed proxy code hash at the target block.

Registry and RPC values are code-owned chain configuration. Neither 8004scan
nor a candidate manifest may replace them. Before an ownership result is
accepted, the RPC path must:

1. Confirm the returned `eth_chainId` matches the selected profile.
2. Read the head, select a target at `head - 2`, and retain that target's
   number and hash. The two-block gap is a consistency buffer, not a finality
   guarantee.
3. Verify the canonical registry has non-empty contract code at the target
   using EIP-1898 `{ "blockHash": targetHash, "requireCanonical": true }`.
4. Read `ownerOf(uint256)` with the same EIP-1898 selector and canonicality
   requirement.
5. Re-read the target block by number and require the same hash. Never mix
   reads from different snapshot attempts or silently fall back to `latest`.
6. Record confirmation depth, registry code SHA-256, and the registry address,
   token ID, block number/hash, RPC origin, and response hashes in the report.

If the RPC reports `header not found`, `missing trie node`, a canonicality
failure, or an equivalent propagation error, retry the complete snapshot at
most once. Exhaustion is `INCONCLUSIVE`.

The result means “owner at block X,” not proof that the owner controls the
candidate endpoint today.

## Curated Manifest

The manifest is the allowlist and identity authority for what the verifier may
probe. A remote response can add evidence or create a mismatch, but cannot
widen the set of hosts or token IDs.

Each entry includes:

```json
{
  "chainId": 56,
  "tokenId": "265375",
  "expectedName": "BNB LP Range Rebalancer",
  "expectedEndpoint": "https://bnb-lp.172-104-171-139.nip.io/.well-known/agent-card.json",
  "expectedOrigin": "https://bnb-lp.172-104-171-139.nip.io",
  "categories": ["rebalancing"],
  "source": "8004scan"
}
```

The parser requires a canonical HTTPS origin on port `443`; userinfo,
credentials, fragments, IP literals, redirects, and alternate ports are
invalid. The expected origin is compared after URL normalization and is the
only candidate endpoint origin that may be contacted.

8004scan detail requests are made only for manifest entries. A v1 invocation is
bounded to at most 8 detail requests, concurrency 2, an 8-second request
deadline, and a 256 KiB decoded body per response. It must stop immediately on
HTTP 429 or a `Retry-After` response and report `INCONCLUSIVE`; it does not
retry anonymous requests. The public allowance (10 requests/minute and 100/day)
cannot be enforced across separate stateless CLI invocations, so operators must
share a rate budget or use the authenticated API before increasing these
limits. The verifier does not crawl anonymous registry pages.

## Central Outbound Transport

Every HTTP request uses one transport module. It has no ambient proxy,
cookie jar, authorization headers, redirects, or credential forwarding. Only
HTTPS on port `443` is accepted in live v1. The disabled testnet reference
profile is the only configured URL with a different port and cannot be selected
by the v1 CLI.

The method matrix is closed:

| Origin | Allowed method/path | Purpose |
| --- | --- | --- |
| `8004scan.io` | `GET` one exact `/api/v1/public/agents/{chainId}/{tokenId}` path | Bounded discovery detail |
| Manifest-approved agent origin | `GET` the exact manifest Agent Card path | Passive card observation |
| Code-owned BSC RPC origin | `POST` JSON-RPC methods `eth_chainId`, `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_getCode`, and `eth_call` only | Pinned chain snapshot |

No input can select an HTTP method, nested card URL, RPC method, or arbitrary
path outside this matrix.

Before connecting, the transport:

1. Parses and normalizes the URL.
2. Rejects userinfo, IP literals, non-HTTPS schemes, non-443 ports, and
   unexpected hosts.
3. Resolves all A and AAAA answers through an injected resolver.
4. Rejects loopback, private, link-local, multicast, documentation, metadata,
   IPv4-mapped IPv6, and other reserved destinations.
5. Selects a stable validated address and connects the socket to that address,
   while preserving the original hostname for TLS SNI, certificate
   validation, and the `Host` header.
6. Rejects redirects instead of following them.
7. Applies connect, header, total, and decoded-body byte limits.

Responses request `Accept-Encoding: identity`; compressed responses are
rejected so the byte limit is unambiguous. JSON parsing is bounded and strict.
The transport exposes resolver and socket seams so DNS-rebinding and redirect
tests exercise the real policy rather than mocks around `fetch`.

The same policy is used for 8004scan and Agent Card requests. Fixed canonical
RPC origins use the same bounded request primitive; no third-party RPC URL is
accepted from input.

## Passive Probe Contract

The initial probes are:

### 8004scan detail

- Request one detail resource per manifest candidate.
- Record HTTP status, latency, response hash, API version/timestamp, and
  normalized fields.
- Treat malformed JSON, rate limits, and source outages as `INCONCLUSIVE`.
- A healthy 8004scan `404` or missing record is `SCAN_NOT_INDEXED` / source
  mismatch, not candidate `UNAVAILABLE`, when the authoritative on-chain
  ownership read succeeds. Only a definitive canonical `ownerOf` nonexistent-
  token result establishes identity unavailability.

### ERC-8004 ownership

- Validate chain and registry configuration through the canonical RPC.
- Read `ownerOf` at one retained block hash.
- Compare the returned owner to any claimed owner as a mismatch observation;
  never silently overwrite either value.
- A missing token or definitive `ownerOf` revert is candidate-specific failure.
- RPC, chain-ID, code, block, or selector failures are `INCONCLUSIVE`.

### Agent Card

- GET only the manifest-approved Agent Card URL.
- Require HTTP `200`, `application/json`, protocol semver `0.3.x`,
  `preferredTransport: "JSONRPC"`, and JSON in both input and output modes.
- Validate bounded, unique skill IDs, names, descriptions, tags, modes, and
  same-origin `url` metadata. A card URL may not widen the manifest origin, and
  no nested URL from the card is ever probed.
- Detect `negotiate` and `notify_funded` if advertised, but never call them.
- A valid card is `detected` reachability/interface evidence only.
- A 4xx/5xx, malformed card, TLS failure, or timeout is candidate-specific
  failure when the verifier transport itself is healthy.

### ERC-8183

The passive v1 still sends no task-creation, funding, negotiation, or
notification request. Presence of a string in an Agent Card description is not
ERC-8183 verification.

Milestone 5 adds a separate armed activation journal. It captures exact SDK
intents for create, register, zero-budget, and `fund(0)` operations and can
reconcile externally executed transactions, but it has no signer or broadcast
path. This is an activation-preparation and evidence boundary, not authority to
execute the job or its underlying DeFi plan.

## Armed Quote Validation Contract

`verify:quote` is a separate operator action, not an escalation of the passive
CLI. Before any network request it requires:

- the acknowledgement flag in the same invocation;
- a selected BSC mainnet candidate and fresh passive evidence;
- exact trust bindings for ERC-8004 registry, category, Agent Card, quote URL,
  ERC-8004 owner / quote signer, signature kind, Commerce contract, currency,
  price, and TTL;
- owner-only trust and mandate files (`0600`) whose canonical parent
  directories are pinned and owner-only (`0700`);
- canonical owner-only replay and sidecar directories (`0700`); and
- a sidecar path that does not already exist.

The transport permits one bounded A2A `message/send` request whose only data
part is `skill: negotiate`. It does not retry. EOA signatures are recovered
offline from the SDK-compatible EIP-191 negotiation hash. ERC-1271 validation
uses separate 8 KiB request / 16 KiB response budgets, first requires contract
code, and pins both `eth_getCode` and `eth_call` to the passive report's EIP-1898
block hash with `requireCanonical: true`.

The signed rebalance task must reproduce the outbound mandate and pass the
same deterministic BSC/PancakeSwap domain, evidence freshness, trigger, target
range, estimate, cap, call, contract, spend, and expiry rules as the reference
seller. The canonical BSC PancakeSwap V3 position manager is fixed in code.

Mandate and permission timing is checked before replay preparation or network
access. After signature verification, a fresh decision timestamp rechecks the
passive report, chain/card observations, signed evidence, outbound execution
estimate, mandate/permission expiry, negotiated-at skew, and quote expiry. A
valid result requires at least 30 seconds of remaining quote lifetime. That
same decision timestamp becomes both replay `claimedAt` and sidecar
`observedAt`; consumers must still reject the artifact once current time
reaches `quoteExpiresAt`.

Only after all signature and policy checks pass does the replay store atomically
claim the domain-separated quote key. Existing markers are parsed and checked
against both their filename digest and requested replay domain. The sidecar
retains hashes, stable codes, gates, signer/domain evidence, expiry, and replay
status; it excludes raw mandates, task text, terms, price, currency, signatures,
and refusal text.

Secure-file or preflight failures before the quote POST intentionally produce
no sidecar because no remote offer was requested. Replay markers provide local
atomicity and domain-integrity checks, not authenticity against a malicious
same-user process; the owner-only replay directory is part of the operator
trust boundary.

The signed projection does not authenticate evaluator display metadata or the
seller's estimated-completion display value, and current policy does not use
them. `verify:quote` alone still relies on provider-signed pool/position
evidence and is not an activation artifact.

Output creation remains path-based with pre- and post-write directory/file
verification. A malicious same-user process could race an output-parent
replacement and cause a transient unintended write before verification fails;
closing that operator-boundary race requires a reviewed directory-handle or
`openat`-style design. Replay is claimed before sidecar persistence, so an
output or directory-sync failure consumes the quote without an artifact and
requires manual replay-marker reconciliation.

## Armed Structural Preview Contract

`verify:preview` combines fresh quote validation and structural transaction
preview in one process. It requires both `--ack-actionable-quote` and
`--ack-operator-calldata-preview`, all quote inputs, and an additional private
transaction-plan file. Every file and output-availability check completes
before the quote POST.

The v1 plan is operator supplied and strictly contains chain ID, `from`, `to`,
decimal native value, and byte-aligned calldata. Only BSC mainnet, an EOA quote
provider as `from`, the canonical PancakeSwap V3 position manager as `to`, and
zero native value are supported. Contract-wallet providers and native-BNB
flows remain unsupported.

The verifier decodes and re-encodes one top-level `multicall(bytes[])`. It must
contain exactly one full-liquidity `decreaseLiquidity`, one collect-all
`collect`, and one `mint`, in that order, with no nesting or additional call.
Token ID, liquidity, recipients, token pair, fee, target ticks, deadlines,
minimum amounts, and slippage ratio are bound to the verified signed task and
fresh state. Token allowances must cover desired mint amounts. The simulation
result must canonically re-encode to the exact outer and inner ABI bytes,
decode to the same three returns, produce nonzero new liquidity, and use no
more token amount than the collect result returned in the same atomic
simulation.

Independent evidence has two explicit block semantics:

1. Re-read the provider-signed block number/hash and require exact equality for
   block timestamp, pool/position identity, owner, tokens, decimals, fee, tick
   spacing, tick, price, ranges, and liquidity.
2. Capture one fresh `N - 2` snapshot and require the same ERC-8004 owner,
   code-empty EOA provider, canonical manager/factory/deployer/pool/token code,
   static position tuple, owner, and liquidity. Re-evaluate trigger, target
   inclusion, and maximum tick drift using fresh dynamic state.

All reads use EIP-1898 `{blockHash, requireCanonical:true}` and final block
number/hash checks. After simulation, both the provider-signed evidence block
and the fresh simulation block are rechecked. The dedicated `bsc-preview-rpc`
route fixes the BSC origin, methods, read selectors, manager target, caller,
zero value, 8,000,000 gas cap, calldata SHA-256, block hash, and
request/response budgets. It exposes no send, sign, debug, trace, estimate, or
state-override method. There is exactly one plan-simulation call; state reads
are separate bounded `eth_call` operations.

After simulation, the quote pipeline takes one decision timestamp and rechecks
passive freshness, signed evidence, estimates, quote policy, mandate,
permissions, the transaction deadline, and the 30-second lifetime floor before
replay. Revert, noncanonical or malformed output, canonicality drift,
authorization drift, or temporal failure creates no replay claim.

The preview artifact stores hashes, exact ordered call summaries, block
evidence, gate states, expiry, and replay status. Passing artifacts enforce the
shared call deadline against the same decision timestamp. The artifact excludes
raw calldata, the private plan, signed task, provider signature, balances,
allowances, amount details, and revert data. A pass is named
`PREVIEW_SIMULATION_PASSED`. It is historical, operator-plan evidence only and
does not declare the passive candidate hireable.

## Armed ERC-8183 Activation Journal Contract

`verify:activation prepare-create` is a single-process trust transition. It
requires all quote and preview inputs, the four explicit quote/calldata/public-
description/client-address acknowledgements, owner-only replay/state/report
directories, a BSC client address, a future job expiry, and an assigned cleanup
owner. It then performs, in order:

1. Fresh trusted quote validation and the full structural transaction preview.
2. A fresh canonical `N - 2` activation deployment observation.
3. Exact SDK create-intent capture through a capture-only adapter that permits
   no RPC request or transaction execution.
4. Durable installation of the sequence-zero `PREPARED_CREATE` state and its
   redacted report through the replay-aware bootstrap.

The deployment observation pins chain ID, proxy and implementation addresses,
runtime code hashes, EIP-1967 implementation slots, Commerce/Router/Policy
topology, payment token, policy whitelist, dispute window, and canonical block
provenance. Both Commerce and Router `paused()` values must be false. Quote,
preview, transaction-plan, and job-expiry windows are rechecked against this
fresh observation before the unsigned intent may be exposed.

### Sequence-zero crash protocol

Initial persistence is deliberately split into
`STAGED -> REPLAY_CLAIMED -> HEAD_INSTALLED`:

1. `STAGED`: canonical sequence-zero state and report files are written as
   immutable content-addressed artifacts, synced, reloaded, and verified. No
   activation head exists yet.
2. `REPLAY_CLAIMED`: replay schema
   `mandatex.agent-supply.quote-replay.v2` is written and synced to a private
   temporary file, then atomically published with no-clobber hard-link
   semantics and directory sync. The marker binds the complete
   `ActivationHead` plus the SHA-256 of its canonical representation.
3. `HEAD_INSTALLED`: under the activation lock, the replay winner and its exact
   state/report artifacts are reverified before the marker-bound head is
   atomically installed, directory-synced, reloaded, and verified.

Generic `persistActivationSnapshot` calls reject every sequence-zero state.
Only `bootstrapActivationSnapshot` may create or recover the initial head. A
crash before replay claim leaves only unreferenced immutable artifacts; a crash
after replay claim leaves a consumed but recoverable marker; and a crash after
head replacement is idempotently verified on retry.

An existing replay-v2 marker is authoritative for the replay domain. Exact
retries reuse it. Conflicting candidates load the marker winner's exact
immutable artifacts rather than recomputing a new generation, then compare the
fresh and recovered client, provider, replay/negotiation binding, mandate,
signed task, transaction plan, job expiry, cleanup owner, deployment binding,
and captured intent/calldata. Recovery also repeats canonical deployment,
Commerce/Router pause, quote-expiry, preview-expiry, ordering, and job-expiry
checks. Tampered, missing, expired, semantically different, or incorrectly
named artifacts fail closed while the replay remains consumed. A legacy
replay-v1 marker is still consumed quote evidence but cannot authorize or
resume activation bootstrap.

### Later journal generations

After an external executor submits the current intent, `reconcile` requires an
explicit external transaction hash plus acknowledgements that the hash was
supplied externally and that the CLI never signs or broadcasts. Receipt and
canonical job-state evidence advances the immutable compare-and-swap journal.
`prepare-next` can then capture exactly one register, `setBudget(0)`, or
`fund(0)` intent, with a fresh structural preview required again before
funding. `broadcast-unknown` freezes an intent when an external broadcast
attempt returned no hash; it does not authorize a blind retry.

The supported terminal Milestone 5 checkpoint is
`ACTIVATION_FUNDED_NOT_DELIVERED`. `FUNDED` is explicitly not delivery. The
journal never calls `notify_funded`, submits a result, completes or settles a
job, executes cleanup, or executes the PancakeSwap plan.

### Local fork proof boundary

The execution proof runs only against a disposable Anvil BSC fork fixed to
`127.0.0.1:18545`. It refuses an occupied proof port, verifies pinned
Commerce/Router/Policy/payment-token topology and code, checks both Commerce
and Router are unpaused, uses only Anvil's disposable unlocked accounts, and
executes create, register, `setBudget(0)`, and `fund(0)`. It proves no payment
token balance, allowance, transfer, or approval change and stops at the state
named `FUNDED_NOT_DELIVERED`.

The fork harness is separate from the production activation CLI. It is not a
live external proof, does not load a production wallet, and must never notify,
deliver, submit, complete, settle, execute the LP plan, or send a mainnet
transaction.

## Gate Matrix

The report keeps each gate separate:

| Gate | Passive v1 rule | Evidence level |
| --- | --- | --- |
| Manifest identity | Entry parses and is allowlisted | `claimed` |
| 8004scan detail | Healthy bounded detail response | `claimed` / `detected` |
| BSC chain | Profile chain ID and registry code match | `verified` |
| Token ownership | `ownerOf` at pinned block succeeds | `verified` |
| Endpoint origin | Card URL exactly matches manifest origin | `claimed` + `detected` |
| Endpoint health | Card response passes transport and JSON checks | `detected` |
| Task interface | Supported skill/service is declared | `detected` |
| Endpoint/operator binding | Cryptographic or signed binding | `unknown` in v1 |
| Quote signature | Fresh signed quote bound to candidate | `unknown` in v1 |
| Category evidence | Adapter-specific current evidence | `unknown` in v1 |
| Mandate policy | Spend/call/expiry constraints | `unknown` in v1 |
| Transaction preview | Read-only simulation | `unknown` in v1 |
| ERC-8183 activation | Armed journal outside the passive report | `unknown` in passive v1 |

Because these active hireability gates remain outside the passive report, a
passive v1 result cannot declare a candidate hireable.

## Versioned Report

Reports use schema `mandatex.agent-supply.report.v1`. Serialization is stable:

- candidates are ordered by `(chainId, tokenId)`;
- arrays of addresses, skills, categories, and sources are sorted;
- timestamps are ISO-8601 UTC strings;
- response bodies are represented by SHA-256 hashes and bounded metadata, never
  raw unredacted content;
- errors use a fixed code and short redacted message;
- `policyFingerprint` is a SHA-256 digest of the effective transport, source,
  and gate policy;
- each source records start/end time, status, latency, response hash, and
  provenance where applicable.

The top-level report includes `runStatus` (`complete` or `inconclusive`),
`generatedAt`, `chainProfile`, `policyFingerprint`, source budgets, and
candidate results. A complete run can still contain candidate failures.

Status precedence is explicit: verifier/source/RPC budget failures produce
`INCONCLUSIVE`; definitive candidate endpoint or canonical identity failures
produce `UNAVAILABLE`; a coherent passive run with all available gates observed
but future hireability gates unknown produces `REGISTERED_ONLY`. A scan source
mismatch never overrides a successful canonical ownership result.

## Safety Invariants

Tests must prove that the verifier:

- never sends active commerce skills;
- never reads wallet files or signing configuration;
- rejects private/reserved destinations and IP literals;
- pins the socket destination while preserving TLS hostname validation;
- rejects redirects, credentials, non-HTTPS, non-443, oversized, compressed, and
  malformed responses;
- does not promote source outages to candidate `UNAVAILABLE`;
- keeps claimed, detected, and verified evidence distinct;
- never declares a candidate hireable in the passive release;
- produces identical report serialization for identical observations;
- redacts URLs, authorization material, and provider secrets from errors.

Active-path tests additionally prove explicit arming, zero network calls on
preflight failure, explicit registry binding, one quote POST, pinned ERC-1271
reads, commit-time expiry/freshness checks, deterministic policy rejection,
atomic replay claims, marker tamper detection, private parent/file modes,
symlink and hardlink rejection, and redacted sidecars. Activation tests also
cover generic sequence-zero rejection, crash points across staging/replay/head
installation, exact and conflicting recovery, marker/head/artifact tampering,
semantic binding drift, expiry on recovery, legacy-v1 non-resumption, and
concurrent initial candidates.

## Explicitly Deferred

The following are later milestones, each requiring a separate review:

- live wallet-backed ERC-8183 broadcast and external lifecycle proof;
- provider notification, delivery/result submission, completion, settlement,
  cleanup execution, or PancakeSwap LP execution;
- wallet connection, session keys, Altana permissions, and revocation;
- agent-authenticated or deterministically generated transaction plans,
  nonzero-price activation, and execution-time LP re-preview;
- the other three category adapters and protocol simulations;
- persistent storage, scheduling, and public marketplace APIs;
- broad 8004scan search or anonymous pagination.
