# Evaluation Attestation Fixtures

Signed fixture attestations conforming to
[`tools/marketplace-core/EVALUATION_ATTESTATION_V2.md`](../../tools/marketplace-core/EVALUATION_ATTESTATION_V2.md),
plus a deterministic stub signer.

These exist so the API, UI, deployment, and category adapters can be built
against the frozen v2 contract **before the real verifier signer service is
deployed**. They also serve as an independent cross-check on Marketplace Core's
own canonicalization and signature handling.

```bash
node fixtures/attestations/lib/build.mjs   # regenerate every vector
node fixtures/attestations/crosscheck.mjs  # check them against the real verifier
```

Zero dependencies, plain ESM, `node:crypto` only. No install and no build step —
runnable with bare `node`, deliberately, so the other agent can reproduce and
compare these bytes without touching this package's tooling.

## The signing key is public and forgeable

`lib/signer.mjs` contains a **hardcoded Ed25519 seed**. Anyone who can read this
repository can mint a signature that these fixtures accept. That is the point:
vectors must be byte-reproducible on any machine.

Consequences, which are not negotiable:

- The key ID is `fixture-insecure-do-not-deploy-1`. If that string ever appears
  in a deployed evaluator's pinned trust material, it is a critical bug.
- The real signer key exists **only inside the separately deployed verifier
  runtime** and must never enter this repository. If the application process
  holds the signing key inline, the signature proves nothing the application
  could not forge — which reintroduces single-process trust *and* adds a
  persistent forgeable credential.
- `devKeyPair()` and `signBytes()` throw when `NODE_ENV=production`.

## Layout

| Path | Contents |
| --- | --- |
| `lib/canonical.mjs` | Independent canonical-JSON implementation |
| `lib/signer.mjs` | Deterministic Ed25519 dev signer |
| `lib/build.mjs` | Vector generator |
| `crosscheck.mjs` | Conformance check against the real verifier |
| `keys/dev-signer.public.json` | Trust material to pin in a test evaluator |
| `vectors/valid/*.json` | 5 attestations that must verify |
| `vectors/invalid/*.json` | 38 attestations that must be rejected |
| `golden/signing-bytes.json` | Exact signing-byte digests per valid vector |
| `manifest.json` | Counts, key fingerprint, time anchor |

Everything except `lib/` and `crosscheck.mjs` is generated. Edit the generator,
not the vectors.

## Vector format

Each vector is self-describing, including the clock it assumes:

```json
{
  "name": "baseline",
  "description": "...",
  "expectedResult": "accept",
  "evaluatedAt": 1786900000,
  "maxClockSkewSeconds": 30,
  "mandate": { "...": "the mandate this attestation is bound to" },
  "wire": "{\"activationAuthorization\":\"none\",...}",
  "wireSha256": "...",
  "wireByteLength": 2179
}
```

Invalid vectors add `attackClass`, `expectedCode`, and often `notes`.

`wire` is **an exact string and must never be re-parsed and re-serialized before
being handed to the verifier**. Six vectors are byte-level defects — trailing
newline, leading space, BOM, reversed key order, pretty-printing, a duplicate
`scope` key — and a parse/serialize round-trip destroys exactly the flaw under
test, turning the vector into a silent false pass.

Consume it as text:

```js
const vector = JSON.parse(readFileSync("vectors/valid/baseline.json", "utf8"));
verifyMarketplaceEvaluationAttestation({
  wire: vector.wire, // string, verbatim
  mandate: marketplaceMandateSchema.parse(vector.mandate),
  evaluatedAt: vector.evaluatedAt,
  maxClockSkewSeconds: vector.maxClockSkewSeconds,
  trust: validateMarketplaceAttestationTrust({
    keyId: trust.keyId,
    publicKeySpkiDer: Buffer.from(trust.publicKeySpkiDerHex, "hex"),
    publicKeyFingerprintSha256: trust.publicKeyFingerprintSha256,
    verifierPolicySha256: trust.verifierPolicySha256,
  }),
});
```

## The 5 valid vectors are not collectively a candidate set

Each valid vector is individually valid. They are **not** a legal comparison set
when submitted together.

Marketplace Core identifies a candidate by `chainId:tokenId` alone, and rejects
any evaluation set in which that pair — or a `quoteId` — repeats. Three valid
vectors are TTL-boundary variants of the *same* quote:

| Vector | Candidate | Quote | In a comparison set? |
| --- | --- | --- | --- |
| `baseline` | `56:7` | `quote-a` | yes |
| `competing-quote-b` | `56:8` | `quote-b` | yes |
| `competing-quote-c-older-evidence` | `56:9` | `quote-c` | yes |
| `boundary-max-ttl` | `56:7` | `quote-a` | no — duplicates `baseline` |
| `boundary-min-ttl` | `56:7` | `quote-a` | no — duplicates `baseline` |

So the largest legal set from these vectors is **3 candidates**, and submitting
all five yields `DUPLICATE_CANDIDATE`, correctly.

This is a property of the vectors, not a defect to fix: the two boundary vectors
exist to probe TTL limits on a *single* attestation, which is the right way to
test a time rule. It is recorded here because `crosscheck.mjs` verifies vectors
**one at a time** and so cannot surface it — the first set-level consumer
(`apps/marketplace-api`) hit it as a `422` instead.

Downstream consumers should either take the three-candidate subset above or read
`comparisonSet` from `GET /v1/fixtures`, which derives it and reports a reason for
each exclusion.

## Time anchor

Fixtures are frozen at `issuedAt = 1786900000`, with evidence observed 30s
earlier and the quote payload expiring 600s later. Pass `evaluatedAt` from the
vector rather than a wall clock, or every vector expires.

`competing-quote-c-older-evidence` is the one clock-sensitive valid vector: its
evidence is 200s old and the mandate allows 300s, so it stops being *eligible*
(distinct from the attestation being *valid*) once `evaluatedAt` passes
`T0 + 100`. That is deliberate — it is the vector that makes freshness visibly
discriminate between candidates.

## Adversarial coverage

38 invalid vectors across nine attack classes:

| Class | n | What it probes |
| --- | --- | --- |
| `authority-escalation` | 4 | `scope`, `activationAuthorization`, `reservation`, `replayPolicy` claiming activation authority |
| `identity-confusion` | 5 | Wrong issuer, audience, schema, signature profile, key ID |
| `binding-failure` | 4 | Mandate, payload, and policy hashes not matching their subject |
| `signature` | 5 | Bit flip, all-zero, missing domain separator, signed over the signed envelope, tampered payload with a repaired hash |
| `time-rule` | 6 | TTL over 300s, expiry before/equal to issuance, expired, future issuance, outliving the quote |
| `freshness-forgery` | 5 | Each payload observation timestamp backdated after issuance |
| `noncanonical-encoding` | 6 | Pretty-printing, trailing newline, leading space, BOM, reversed keys, duplicate key |
| `resource-exhaustion` | 1 | Over the 131072-byte ceiling, rejected before parsing |
| `malformed-input` | 2 | Not JSON; valid JSON that is not an object |

### Why the malicious envelopes carry valid signatures

Most invalid vectors are **correctly signed over their own canonical bytes**.

The verifier checks the signature *last*, after schema, hashes, and time rules.
So an envelope claiming `activationAuthorization: "granted"` and carrying a
broken signature would be rejected — but for the wrong reason, proving nothing
about whether the authority claim itself is enforced. Signing the malicious
envelope properly leaves the schema literal as the only thing that can stop it.

Two vectors make this concrete as a pair:

- `payload-tampered-hash-stale` — payload swapped, `payloadSha256` left stale.
  Rejected at the hash check, never reaching the signature.
- `payload-tampered-hash-updated` — payload swapped **and** `payloadSha256`
  repaired. Every hash inside the envelope is now internally consistent, so the
  signature is the only thing left standing between a forged quote and the
  comparison view.

The highest-severity encoding vector is `noncanonical-duplicate-key`: a second
`"scope":"activation"` appended after the canonical body. `JSON.parse` silently
keeps the *last* duplicate, so a lenient parser reads `scope=activation` while
the signature only ever covered `scope=evaluation_only`. Comparing canonical
bytes against the received bytes is what closes it.

## What `crosscheck.mjs` proves

1. **Canonicalization parity** — `lib/canonical.mjs` is a deliberate
   from-scratch reimplementation, *not* an import of `canonical.ts`. If both
   sides called the same function, a bug in that function would be invisible.
   Two independent implementations required to agree byte-for-byte is the real
   check. (41 of 43 vectors; `not-json` and `noncanonical-bom-prefix` fail
   `JSON.parse` by design and have nothing to canonicalize.)
2. **Signing-bytes parity** — my signing message equals Core's
   `marketplaceEvaluationAttestationSigningMessage` byte for byte. This is what
   the contract means by locking the signing bytes before the signer deploys.
3. **Mandate normalization** — `marketplaceMandateSchema` lowercases addresses
   and sorts arrays, and Core hashes the *parsed* mandate. If the fixture mandate
   were not already normalized, every `mandateSha256` would silently disagree.
   Asserted rather than assumed.
4. **Verdict parity** — every valid vector verifies, every invalid vector is
   rejected, and each rejection uses the error code its vector predicts. A code
   mismatch is reported but not treated as a security failure: the envelope was
   still rejected, it just exercised a different check than intended.

Marketplace Core is owned by the other agent and under active development, so
the script **degrades gracefully**: if `dist/` cannot be imported it reports the
parity checks as unavailable, still runs fixture self-consistency, and exits 0.
It never builds inside that package. Refresh it with
`cd tools/marketplace-core && corepack pnpm build`.

## Status

Last run: **43/43 vectors conform to the real verifier.** All 5 valid vectors
verify, all 38 invalid vectors are rejected, and all 38 rejection codes match
prediction. Canonicalization and signing bytes agree byte-for-byte between the
two independent implementations.

## Known portability caveat

Both canonicalizers build a plain object with keys inserted in sorted order and
rely on `JSON.stringify` preserving that order. ECMAScript does not preserve
insertion order for integer-index-like keys — it emits those first, ascending:

```js
canonicalJson({ b: 1, "10": 2, "2": 3 }); // {"2":3,"10":2,"b":1}
// true UTF-16 sorted order would be      // {"10":2,"2":3,"b":1}
```

Not currently reachable: every attestation and payload schema is `.strict()`
with fixed alphabetic keys, and `build.mjs` asserts no vector contains such a
key via `findIntegerLikeKeys`. Both JS implementations agree, so this is not a
divergence today.

It matters only if a **non-JS signer** is ever deployed, which the contract
explicitly permits. A Go, Rust, or Python signer sorting keys correctly would
produce different bytes for such an object, and its signatures would be
rejected. Logged as a cross-boundary request in `plan.md` §7.
