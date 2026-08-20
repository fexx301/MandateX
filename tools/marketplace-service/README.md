# MandateX marketplace service

This package owns the verifier-runtime boundaries for Marketplace Evaluation
Attestation v2 and category-adapter execution. It is intentionally separate
from the web/API evaluator and from Marketplace Core.

`createMarketplaceVerifierRuntime()` owns the only public operation:
`evaluateAndAttest()`. Manifest, passive-report, trust-policy, transport, and
clock capabilities are fixed when that isolated runtime is constructed; each
operation accepts only the marketplace request. It invokes
`validateTrustedPreviewForMarketplaceEvaluation()` through the replay-free
`evaluation_only` / `unreserved` path. Only an immediate
`verified_unreserved` result with verifier-owned in-process provenance is
mapped and signed. Refused, invalid, and inconclusive results are returned
without an attestation.

The package does not expose an `issue(request, artifact)` API. A serialized or
caller-constructed artifact is never accepted as a signing input. The raw
verifier result is kept inside the runtime call, and the signer rechecks the
candidate, mandate, transaction-plan, nested evidence, snapshot, and canonical
commitments before constructing the envelope.

The Ed25519 private key belongs only in this separately deployed verifier
runtime. The evaluator pins the corresponding public key and verifier-policy
hash, then passes the resulting canonical wire string to Marketplace Core v2.
This package does not authorize activation, reserve replay markers, fund tasks,
broadcast transactions, or hold wallet authority.

`createMarketplaceCategoryVerifierRuntime()` is a separate signer-free boundary
whose only operation is category evaluation. Construction binds a strict
four-adapter deployment into verifier policy v2, then cross-checks the service
and verifier deployment digests. A call may select an adapter explicitly with
its registered `adapterId`; when the ID is omitted, exactly one enabled adapter
for the requested category is selected. Multiple enabled adapters fail closed
with `CATEGORY_ADAPTER_SELECTION_REQUIRED`. The selection rule is itself
versioned in the v2 policy profile, so changing it changes the policy hash.
Each accepted selection executes its exact bounded BSC read contract,
recomputes the evidence and artifact hashes, and returns only a result carrying
trusted in-process provenance. This runtime exposes no private key, attestation
issuer, wire envelope, or generic signing method.

The successor contract is a separate private/non-production composition path.
`marketplaceCategorySuccessorPolicyManifest()` binds a static deployment with
four adapter IDs, explicit infrastructure roots, and a `trustRoot` identity
(root key ID plus SPKI fingerprint). The private runtime derives its executor
and provenance roots from that manifest; callers cannot supply a second
deployment or root override. The actual root public key stays in the
factory-created Core trust controller, and the private orchestrator rejects a
controller whose factory identity does not match the static policy before it
can commit trust state or reserve an issuance. This check is conditional on
the separately pinned successor-policy identity: the policy digest remains
unfrozen, the issuer is unexported, and transactional issuance is disabled.

An experimental category-condition issuer exists only as an unexported internal
module for contract testing. It accepts no caller-supplied artifact or display
projection, requires the factory-branded bound verifier result, and signs only a
`pass`. Executed `fail` or `unknown` outcomes fail closed; runtime
`inconclusive` outcomes return `not_attested`, and no non-pass path reaches UUID
generation or signing. The resulting condition receipt is not marketplace
eligibility: it proves a pinned-verifier commitment, not the metric itself,
candidate-to-subject ownership, mandate permission coverage, hireability,
ranking, reservation, or activation. It must remain unexported, undeployed, and
outside API/UI integration while Core category support is disabled.

The pinned verifier-policy hash is a versioned Marketplace Core canonical hash
of the passive policy fingerprint, the complete quote-trust-file digest, the
quote-trust and preview-evaluation contract identifiers, the active quote
limits, preview buffer and RPC limits, default transport limits, the BSC
PancakeSwap V3 deployment profile, and named versions for active quote
evaluation, preview validation, quote canonicalization, transport security,
and display projection. Any change to one of those policy inputs requires a
new hash and a coordinated evaluator repin. Runtime/build identity is outside
this v1 manifest and is controlled by the deployment boundary.

`marketplaceVerifierPolicyManifest()` exposes the exact object hashed by that
active v1 policy, and its locked digest remains unchanged. Category execution
uses a separate policy version: `marketplaceVerifierPolicyV2Manifest()` binds
the unchanged v1 manifest together with the category execution contracts,
transport limits, block-pinning profile, allowed selectors, and category
deployment digest.

The successor deployment intentionally omits per-request adapter
`configuration`; subjects, targets, and thresholds belong to the signed
mandate. Its separate static hash covers the registry, read descriptors,
infrastructure roots, and trust-root identity. This does not change the locked
legacy v1 digest.

`parseMarketplaceCategoryAdapterDeploymentManifest()` validates and freezes a
strict v2 manifest, while `marketplaceCategoryAdapterDeploymentSha256()` hashes
the normalized addresses, thresholds, adapter and evidence identifiers,
adapter-specific validation profiles, and exact ordered read selectors. The
manifest is keyed by adapter ID and contains exactly four entries: grid, yield,
Aave health, and Venus health. The signer-free category runtime consumes this
manifest and can execute enabled adapters, but it does not mutate the locked v1
attestation policy, issue category attestations, or make Marketplace Core accept
category evidence. Those remain separate contracts.

`enabled: false` entries omit configuration and are hashed as disabled; omission
is never treated as a default. The deployment may enable more than one adapter
for a category, including both Aave and Venus health adapters. Callers must use
the registered `adapterId` when a category is ambiguous; an omitted ID is only
valid when the pinned deployment has exactly one enabled adapter for that
category. The execution artifact always binds the chosen adapter ID.
Venus requires `comptrollerAddress`, `accountAddress`,
`borrowMarketAddress`, and `minLiquidityUsdScaled`; there is no absolute-liquidity
default. The Venus metric metadata explicitly includes the monitored-market
`borrowBalanceStored()` witness; a zero balance is unknown for that monitored
market, not proof that the account has no debt anywhere. A development-only
conformance check compares every adapter by ID,
including evidence schema, protocol, profile, metric, and exact read descriptors,
with the standalone adapter package. The production category executor already
depends on that package; this check keeps the duplicated service/verifier policy
literals in byte-for-byte agreement. Run it separately with
`corepack pnpm run test:category-contract` after the adapter package parses and
builds; it remains outside the core unit-test command because that package is a
separate ownership boundary.

At construction, manifest, passive-report, and trust-file inputs are parsed
into detached recursively frozen copies. The transport is retained only as a
bound request capability, and the clock and UUID functions are captured once;
later mutation of the bootstrap object cannot replace those capabilities.
The production installer must supply a transport that conforms to the named
pinned-HTTPS profile and default limits. The runtime captures that capability's
identity, but cannot inspect or freeze its internal implementation or mutable
state; transport conformance therefore remains part of the isolated deployment
trust boundary.

The rebalancing projection uses the verified current ERC-8004 owner/provider
as both `owner` and `publisher`; this is an explicit owner-as-publisher
mapping, not independent publisher evidence. Reputation is currently
unavailable, so the projection emits `scoreBps: 0`, `sampleSize: 0`, and
`evidenceConfidenceBps: 0` with the verifier decision time. Marketplace Core
therefore assigns the minimum reputation contribution and does not infer a
positive reputation score.

The service clock is authoritative for attestation issuance. Every payload
observation must be at or before that clock value; clock skew is not used to
emit a Core-invalid attestation. Attestation lifetime is capped by the frozen
300-second v2 contract and by the mapped payload expiry.

Use `corepack pnpm` for checks, tests, and builds.
