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

The service clock is authoritative for attestation issuance. Every payload
observation must be at or before that clock value; clock skew is not used to
emit a Core-invalid attestation. Attestation lifetime is capped by the frozen
300-second v2 contract and by the mapped payload expiry.

Use `corepack pnpm` for checks, tests, and builds.
