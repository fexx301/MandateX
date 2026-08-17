# `@mandatex/verifier-api`

The **signing** half of the MandateX trust boundary. Evaluates candidate agents and
issues Ed25519-signed evaluation attestations. It holds the private key.

```
┌──────────────────────────┐         ┌──────────────────────────────┐
│  verifier-api  (this)    │         │  marketplace-api             │
│                          │         │                              │
│  HOLDS the private key   │  ────►  │  PINS the public half        │
│  evaluates and signs     │  trust  │  verifies, ranks, excludes   │
│  refuses to boot with    │  ident. │  refuses to boot if it finds │
│    no signing key        │         │    any signing material      │
└──────────────────────────┘         └──────────────────────────────┘
```

The split is the point. A single process that both signs and verifies proves
nothing, because every signature it checks is one it could have produced. Each
service therefore refuses to boot in the other's posture — see [The boundary is
enforced, not conventional](#the-boundary-is-enforced-not-conventional).

## Routes

| Route | Purpose |
|---|---|
| `GET /healthz` | Liveness. Always 200 once the process is up. Reports `canEvaluate`. |
| `GET /readyz` | Readiness. 200 when the service can **sign**; reports evaluation separately. |
| `GET /v1/trust` | Public trust material for the marketplace app to pin. **This is the lockstep mechanism.** |
| `POST /v1/evaluate` | Evaluate a candidate and issue a signed attestation. 503 until an agent is configured. |
| `GET /` | Service description. |

### `GET /v1/trust` is why this service is deployable before it can do anything

It publishes the public half of the signing key:

```json
{
  "keyId": "mandatex-verifier-1",
  "publicKeySpkiDerHex": "302a300506032b6570032100…",
  "publicKeyFingerprintSha256": "44b86a0a…",
  "verifierPolicySha256": null,
  "developmentKey": false
}
```

The marketplace app polls this on every readiness check and compares
`publicKeyFingerprintSha256` against the key it pins. Disagreement is a 503 on the
app's `/readyz` naming both fingerprints. That comparison is how the v2 contract's
*prove lockstep redeploy* requirement is satisfied, and it works with no agent
configured — which is what lets the trust boundary be stood up before the supply
pipeline that will eventually feed it exists.

### Readiness means "can sign", not "is fully configured"

`/readyz` returns 200 with a valid key even when no agent is configured, and says
so under `checks.evaluation.status = "not_configured"`. A verifier with a valid key
and no agent is correctly deployed and half-configured. A verifier that cannot sign
is broken. Collapsing those two into one signal would tell whoever is on call the
wrong thing.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `MANDATEX_SIGNING_KEY_ID` | ✅ | Key id stamped into every attestation. |
| `MANDATEX_SIGNING_KEY` | ✅ | Ed25519 private key: 32-byte seed hex (64 chars) **or** PKCS#8 DER hex (96 chars). |
| `MANDATEX_VERIFIER_CONFIG_DIR` | – | Directory with `manifest.json`, `passive-report.json`, `quote-trust.json`. |
| `MANDATEX_VERIFIER_POLICY_SHA256` | – | Pins policy identity. Derived from artifacts when unset. |
| `MANDATEX_MAX_REQUEST_BYTES` | – | Body cap, default `1048576`. |
| `PORT` / `HOST` | – | Default `8080` / `0.0.0.0`. |

There is deliberately **no** `MANDATEX_TRUST_*` variable here. Those belong to the
marketplace app. See [`deploy/verifier.env.example`](../../deploy/verifier.env.example).

### Generating a key

```bash
node -e 'const{generateKeyPairSync}=require("node:crypto");console.log(generateKeyPairSync("ed25519").privateKey.export({type:"pkcs8",format:"der"}).toString("hex"))'
```

Paste the output straight into the platform's secret field. Note the leading space
in the command above — with `HIST_IGNORE_SPACE` (zsh) or `HISTCONTROL=ignorespace`
(bash) it keeps the line out of shell history. Never write the key to a file in the
tree; the fixture key already demonstrates what that costs permanently.

Then read the public half back from the running service's `/v1/trust` and pin those
values in the marketplace app. Deriving the app's pin from the deployed verifier —
rather than from whatever you believe you configured — is what makes the pair
actually locked together.

## Boot guards

The process exits **78** (`EX_CONFIG`) rather than starting misconfigured:

1. **No `MANDATEX_SIGNING_KEY_ID`** or **no `MANDATEX_SIGNING_KEY`** — a verifier
   that cannot sign has no function.
2. **Key material is not a well-formed Ed25519 private key.** The rejection never
   echoes the value.
3. **The key is the publicly-committed fixture key and `NODE_ENV=production`.**
   Recognised by the *key material*, not the key id, so renaming cannot smuggle it
   into production.
4. **The key id is marked development-only** (`fixture`, `insecure`,
   `do-not-deploy`, `test`, `dev-`) under production — such an id tells every
   consumer not to trust what it signs.
5. **`MANDATEX_VERIFIER_POLICY_SHA256` is malformed**, or is pinned to a value the
   configured artifacts do not derive. The service refuses to sign under a policy
   identity that does not describe its own configuration.
6. **The artifact set exists but is malformed.** Absent is fine; wrong is not.

## The signing key never appears in a response

Every serialized response body is checked against the *actual configured secret*
before it reaches the socket — the PKCS#8 hex, PKCS#8 base64, seed hex and seed
base64 forms, all derived from this deployment's own key at boot
(`armSecretLeakCheck`). A match throws, logs the route and nothing else, and
returns a detail-free 500.

This is an exact match rather than a "looks like a key" regex on purpose: a pattern
would both miss encodings and fire on innocent hex, while an exact match on this
deployment's secret is precise in both directions. It is also why nothing in this
service logs its environment, unlike the marketplace app — the app's entire trust
configuration is public, and this one's is not.

## The boundary is enforced, not conventional

| | `verifier-api` | `marketplace-api` |
|---|---|---|
| Private key present | required | **exit 78** |
| Private key absent | **exit 78** | required |
| Fixture key in production | **exit 78** | **fail readiness** |

Nothing stops a future operator from setting every variable on one service except
these guards. [`deploy/rehearse.mjs`](../../deploy/rehearse.mjs) checks all of it
against two real processes.

## Running

```bash
corepack pnpm install
corepack pnpm build
corepack pnpm smoke      # 28 checks, boots the real server on ephemeral ports

MANDATEX_SIGNING_KEY_ID=fixture-insecure-do-not-deploy-1 \
MANDATEX_SIGNING_KEY=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60 \
corepack pnpm start
```

That seed is the committed fixture key — RFC 8032 test vector 1. It is fine
locally and refused under `NODE_ENV=production`. Everything it signs is forgeable
by anyone who can read this repository, and `/v1/trust` says so in a `warning`
field so no consumer can mistake it for real.

To rehearse the pair as it will actually be deployed:

```bash
node deploy/rehearse.mjs   # 27 checks across two processes
```

## What is not here

- **No funding, settlement, or broadcasting.** This service evaluates and signs.
- **No persistence.** Every request is self-contained.
- **No agent artifacts in the tree.** `manifest.json`, `passive-report.json` and
  `quote-trust.json` are outputs of an agent-supply-verifier passive run against a
  live agent, so they describe a specific agent observed at a specific time. Only
  `.template.json` files are committed. Until they exist, `POST /v1/evaluate`
  returns 503 with instructions and everything else works.
