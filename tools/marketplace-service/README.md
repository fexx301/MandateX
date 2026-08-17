# MandateX marketplace service

This package is the verifier-runtime seam for Marketplace Evaluation Attestation
v2. It is intentionally separate from the web/API evaluator and from
Marketplace Core.

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

The pinned verifier-policy hash is a versioned Marketplace Core canonical hash
of the passive policy fingerprint, the complete quote-trust-file digest, the
quote-trust and preview-evaluation contract identifiers, the active quote
limits, preview buffer and RPC limits, default transport limits, the BSC
PancakeSwap V3 deployment profile, and named versions for active quote
evaluation, preview validation, quote canonicalization, transport security,
and display projection. Any change to one of those policy inputs requires a
new hash and a coordinated evaluator repin. Runtime/build identity is outside
this v1 manifest and is controlled by the deployment boundary.

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
