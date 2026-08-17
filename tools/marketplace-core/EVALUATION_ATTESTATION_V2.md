# Marketplace Evaluation Attestation v2

Status: frozen integration contract for the September 9 build.

This contract replaces process-local object identity for new marketplace
evaluations. It does not authorize activation, reservation, funding, signing,
or execution. The legacy v1 capture API remains a separate deprecated path
until decision-parity coverage is complete.

## Deployment boundary

- A separately deployed verifier runtime owns the Ed25519 private key.
- The web/API tier and Marketplace Core evaluator never receive that private
  key and cannot call a generic signing endpoint.
- The evaluator image pins one verifier public key, its SPKI SHA-256
  fingerprint, and the accepted verifier-policy SHA-256.
- Changing or compromising the key requires a coordinated signer and evaluator
  redeploy. Dynamic rotation and revocation are deferred from this version.
- The deployment pipeline must prove that both services can be redeployed
  together before submission rehearsal.

The pinned evaluator configuration is the v2 trust root. Anyone able to alter
the evaluator image can alter that trust root; v2 does not claim to defend
against a compromised deployment pipeline or modified evaluator binary.

## Wire envelope

The evaluator accepts canonical UTF-8 JSON only, with no BOM, whitespace, or
trailing newline. The maximum encoded size is 131,072 bytes.

```json
{
  "schema": "mandatex.marketplace.evaluation-attestation.v1",
  "signatureProfile": "mandatex-ed25519-v1",
  "issuer": "mandatex-agent-supply-verifier",
  "audience": "mandatex-marketplace-core",
  "keyId": "verifier-production-1",
  "attestationId": "018f4f5e-7d2d-7d6b-8fb8-35c1b79275a1",
  "scope": "evaluation_only",
  "activationAuthorization": "none",
  "reservation": "none",
  "replayPolicy": "reusable_until_expiry",
  "issuedAt": 1786900000,
  "expiresAt": 1786900300,
  "mandateSha256": "<64 lowercase hex characters>",
  "payloadSha256": "<64 lowercase hex characters>",
  "verifierPolicySha256": "<64 lowercase hex characters>",
  "payload": { "<strict display-safe projection payload>": "..." },
  "signature": "<128 lowercase hex characters>"
}
```

`attestationId` is a signed audit identifier, not a one-time nonce. Reuse is
allowed for read-only evaluation until the effective validity boundary.

## Hashes and signature

- `mandateSha256` is SHA-256 of the canonical complete Marketplace Core
  mandate evaluated with this attestation.
- `payloadSha256` is SHA-256 of the canonical strict display-safe payload.
- `verifierPolicySha256` identifies the exact verifier policy accepted by the
  evaluator deployment. It is distinct from the public-key fingerprint.
- The signature covers every envelope field except `signature`.
- The signed bytes are the UTF-8 concatenation of the ASCII domain separator
  `MandateX Marketplace Evaluation Attestation v1\0` and the canonical JSON of
  that unsigned envelope.
- The algorithm is fixed to Ed25519 by the schema and signature profile. No
  algorithm value supplied by an attestation can select verification code.

Canonical JSON is the existing Marketplace Core restricted profile: strict
JSON data, sorted object keys, exact array order, finite safe-integer numbers,
and no unsupported values. The evaluator reparses and reserializes the wire
value and rejects any byte difference. This rejects duplicate keys, alternate
numeric spellings, whitespace, and alternate Unicode escaping. Golden vectors
must lock the exact signing bytes before the signer service is deployed.

## Time and cache rules

- Maximum attestation TTL is 300 seconds.
- `expiresAt` must be after `issuedAt` and no later than
  `issuedAt + 300`.
- `expiresAt` must not exceed the quote payload expiry.
- Payload observation timestamps must not follow `issuedAt`.
- Effective validity ends at the earliest applicable quote, attestation,
  evidence-freshness, or evaluator-policy boundary.
- Cache keys must include `mandateSha256`, candidate identity, and attestation
  identity. A cache hit re-enters Marketplace Core; cached Core decisions are
  never returned without re-evaluation.
- Marketplace Core recomputes evidence freshness and ranking against its own
  current clock on every evaluation. Attestation reuse never freezes a
  freshness score.

The 300-second maximum is chosen for the expected compare, inspect, return,
and permission-review journey, normally completed within one to four minutes.
It permits useful in-session hits while aligning with the existing five-minute
passive/evidence freshness ceiling.

## Acceptance rules

Attestation or trust failures abort the complete evaluation. They are not
ordinary candidate exclusions.

Marketplace Core must:

1. enforce the byte limit before parsing;
2. reject noncanonical wire JSON;
3. parse the strict envelope and display-safe payload schemas;
4. require the fixed issuer, audience, scope, negative authority claims, and
   replay policy;
5. recompute and compare the mandate, payload, and verifier-policy hashes;
6. match the pinned key ID and SPKI public-key fingerprint;
7. enforce issuance, expiry, clock-skew, and 300-second TTL rules;
8. verify the Ed25519 signature over the specified domain and canonical bytes;
9. clone and recursively freeze verified data before evaluation; and
10. evaluate freshness, eligibility, and ranking using the evaluator clock.

No activation API may accept this envelope or derive authorization from it. A
selected candidate must obtain a fresh activation quote through the existing
reservation and replay-claiming path.

## Compatibility test meaning

The required legacy-v1/v2 parity test is decision parity from equivalent
evidence. It does not assert input-shape parity: v1 deliberately rejects
serialized capture objects, while v2 is specifically designed to accept a
canonical serialized attestation.

