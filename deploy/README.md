# Deployment

Target: **Railway Hobby, $5/mo** — one project, two services.

```
project: mandatex
├── mandatex-verifier   holds the Ed25519 PRIVATE key, evaluates and signs
└── mandatex-app        pins only the PUBLIC key, verifies and serves
```

Two services, not one, because the verifier runtime *is* the signer. A single
process that both signs and verifies proves nothing — every signature it checked
would be one it could have produced itself. The v2 contract requires the split,
and requires proving both halves redeploy in lockstep before submission
rehearsal.

| File | Purpose |
|---|---|
| `app.Dockerfile` | Image for `mandatex-app`. Build context is the **repository root** |
| `railway.app.json` | Railway config-as-code for `mandatex-app` |
| `app.env.example` | Environment contract for `mandatex-app` |
| `verifier.Dockerfile` | Image for `mandatex-verifier`. Build context is the **repository root** |
| `railway.verifier.json` | Railway config-as-code for `mandatex-verifier` |
| `verifier.env.example` | Environment contract for `mandatex-verifier`, including key generation |
| `rehearse.mjs` | Boots both services as separate processes and checks the trust boundary |

---

## Status

| | |
|---|---|
| `mandatex-app` image | **builds and runs** — 353 MB. Boot guards fire, routes serve, SIGTERM exits 0 |
| `mandatex-verifier` image | **builds and runs** — 601 MB. Boot guards fire, key never appears in a response, SIGTERM exits 0 |
| Lockstep proof | **exercised end to end.** `node deploy/rehearse.mjs` → 27/27 across two processes; also verified as two containers on a private network |
| Either service on Railway | not yet pushed |
| `POST /v1/evaluate` on the verifier | returns 503 until agent artifacts exist — see [What is still missing](#what-is-still-missing) |

## The lockstep proof

This is the v2 contract's *prove lockstep redeploy* requirement, and it is now
demonstrated rather than merely designed:

```bash
cd apps/verifier-api    && corepack pnpm install && corepack pnpm build
cd ../marketplace-api   && corepack pnpm install && corepack pnpm build
cd ../.. && node deploy/rehearse.mjs
```

The rehearsal boots both real servers as separate OS processes on ephemeral ports
and checks five arrangements. The negative cases are the point — if case 2 returned
200 the pin would be decorative and the two-service split would be theatre:

| | Arrangement | App `/readyz` |
|---|---|---|
| 1 | App pins what the verifier published | `200 ready`, `verifier: ok` |
| 2 | App pins a **different** key | `503 not_ready`, `verifier: key_mismatch` |
| 3 | Verifier not running | `503 not_ready`, `verifier: unreachable` |
| 4 | No verifier configured | `200 ready`, `verifier: not_configured` |
| 5 | Either process given the other's role | **exit 78**, refuses to boot |

Case 1 also POSTs a fixture attestation to the app and checks that it clears
signature verification and is rejected on *freshness* instead. That distinction is
the evidence: the fixture vectors are anchored to a fixed past instant, so a wrong
pin would fail on the signature, and a right pin fails on the clock.

The same sequence was verified with the two **containers** on a private Docker
network, with freshly generated production keys, mirroring Railway exactly:
rotating the verifier's key while leaving the app's pin untouched flipped the app's
`/readyz` from `200 ready` to `503 key_mismatch`, quoting both fingerprints and
saying *"Redeploy both together."* Liveness stayed `200` throughout, so the
platform restarts the pair rather than crash-looping one half.

## Build and run locally

```bash
# From the repository root, not from deploy/
docker build -f deploy/app.Dockerfile -t mandatex-app .

docker run --rm -p 8080:8080 \
  -e MANDATEX_TRUST_KEY_ID=mandatex-verifier-1 \
  -e MANDATEX_TRUST_SPKI_DER_HEX=302a300506032b6570032100... \
  -e MANDATEX_TRUST_KEY_FINGERPRINT_SHA256=... \
  -e MANDATEX_TRUST_POLICY_SHA256=... \
  mandatex-app
```

Verified locally on this image:

- no trust material → exits `78`, does not serve
- a PKCS#8 Ed25519 private key in a variable named `APP_CREDENTIAL` → exits `78`
- `/srv/fixtures` does not exist in the image
- runs as `node`, not root
- `/v1/fixtures` → `404` under `NODE_ENV=production`
- `docker stop` → `closed cleanly`, exit `0` (not SIGKILL)

## Railway setup

1. Create a project, connect the repository.
2. Add a service named **`mandatex-verifier`** first, so the app has a key to pin.
   - Root directory: `/`
   - Config-as-code path: `deploy/railway.verifier.json`
   - Set variables from `verifier.env.example`. Generate the key with the command
     in that file and paste it straight into Railway's secret field.
   - Do **not** generate a public domain for it. It stays on the private network.
3. Add a service named **`mandatex-app`**.
   - Root directory: `/` (the Dockerfile needs the whole tree — see below)
   - Config-as-code path: `deploy/railway.app.json`
   - Config-as-code path: `deploy/railway.app.json`
4. Read `publicKeySpkiDerHex` and `publicKeyFingerprintSha256` from the verifier's
   `GET /v1/trust` and set them as the app's `MANDATEX_TRUST_*` pins. Take them from
   the **running verifier**, not from what you believe you configured — that is what
   makes the pair actually locked together rather than nominally agreeing.
5. Set the app's remaining variables from `app.env.example`, including
   `MANDATEX_VERIFIER_URL=http://mandatex-verifier.railway.internal:8080`. Do
   **not** set any signing key on the app; it scans its own environment and refuses
   to boot if it finds one.
6. Generate a public domain for `mandatex-app` only.
7. Check the app's `/readyz` is `200` with `checks.verifier.status = "ok"`. If it
   is `503 key_mismatch`, the pins are stale — step 4 was skipped or run against a
   previous verifier deploy.

### Why the build context is the repository root

`apps/marketplace-api` depends on Marketplace Core via
`link:../../tools/marketplace-core`. The image has to reproduce the repository's
relative layout for that symlink to resolve, so both packages are copied under
`/srv` at their original relative paths. Setting a Railway root directory of
`apps/marketplace-api` would put Core outside the build context and the install
would fail.

### Why the healthcheck is `/healthz`, not `/readyz`

`/readyz` returns `503` when the verifier is unreachable. If Railway gated
deploys on it, neither service could deploy first — the app would fail its
healthcheck until the verifier existed, and the verifier redeploy would never be
observed as healthy by the app. That is a deadlock on the very first deploy of
the pair.

So the deploy gate is liveness (`/healthz`, "the process is up") and `/readyz` is
the operator signal — the thing to check after a deploy, and the thing that turns
red if the verifier rotates its key without the app being updated.

## Cost

Railway Hobby is $5/mo including $5 of usage credit, billed on **measured** RAM
at $10/GB/month — not allocated RAM, which is what makes it cheaper than Fly.io
for two mostly-idle Node services.

Measured in the running containers at idle:

| Service | Resident | Why |
|---|---|---|
| `mandatex-app` | **36 MiB** | No framework; Core's only runtime dependency is zod |
| `mandatex-verifier` | **81 MiB** | Carries `viem` and `@bnbagent/sdk` through `agent-supply-verifier` |

Together ≈ **0.12 GB-month ≈ $1.17/mo** at idle, inside the included $5 credit.

Two corrections to earlier figures, both recorded rather than quietly replaced:
`plan.md` §5.3 originally assumed ~150 MB per service (≈$3/mo), which was too high;
the $0.50/mo figure that replaced it was measured on the **app alone** and applied
to both services, which was too low — the verifier is more than twice the app's
footprint because of its chain dependencies. $1.17/mo is the first figure measured
from both services actually running.

Load will raise this. The headroom before the $5 credit is exhausted is large.

## What is still missing

**Agent artifacts.** `POST /v1/evaluate` on the verifier returns `503
VERIFIER_NOT_CONFIGURED` until `MANDATEX_VERIFIER_CONFIG_DIR` holds
`manifest.json`, `passive-report.json` and `quote-trust.json` — the outputs of an
agent-supply-verifier passive run against a live agent. Only `.template.json` files
are committed, because those artifacts describe a specific agent observed at a
specific time.

Absence is a supported state, not a broken one. Requiring them to boot would mean
the trust boundary could not be stood up until the whole supply pipeline was
finished, which is backwards: the boundary is what everything else is verified
against. Everything except evaluation works without them, including the entire
lockstep proof above.

**A first policy pin.** The app requires `MANDATEX_TRUST_POLICY_SHA256` at boot,
and the verifier can only derive that value once artifacts are present — so on the
very first deploy the two cannot learn it from each other. Order of operations:
deploy the verifier with artifacts, read `verifierPolicySha256` from its
`/v1/trust`, then set the app's pin from that. Until artifacts exist, the
rehearsal uses the value the fixture attestations were signed under
(`2ce16c72…b2a8`), which is why the rehearsal exercises a real policy match rather
than a placeholder.

## Security posture

| Property | Where enforced |
|---|---|
| App holds no signing key | Boot guard scans env by name **and** content; exits 78 |
| Forgeable fixture key never deployed | Not copied into the image, **and** refused at boot under `NODE_ENV=production` |
| Verifier not publicly reachable | No Railway domain generated for it; app reaches it over `*.railway.internal` |
| Plaintext internal traffic | Allowed only for `.internal` hosts, which Railway does not route externally. Public URLs must be https |
| Key rotation without app update | Caught by `/readyz` fingerprint comparison |
| Container runs unprivileged | `USER node` on both images |
| Verifier never echoes its key | Every response body checked against the real secret's four encodings before it reaches the socket |
| Verifier never logs its environment | Boot log names the key by id and public fingerprint only |
| Signing key absent from image layers | No `ARG`, no `COPY`, no default — env var only, at run time |

Plaintext `http://` to `*.railway.internal` is deliberate: Railway's private
network does not terminate TLS, and those names are not resolvable from outside
the project. The production https requirement is waived for that suffix only.
