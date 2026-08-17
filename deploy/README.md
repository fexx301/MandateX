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

The verifier's image and config are **not here yet** — see [Blocked](#blocked-the-verifier-half).

---

## Status

| | |
|---|---|
| `mandatex-app` image | **builds and runs.** Verified locally: boot guards fire, routes serve, SIGTERM exits 0 |
| `mandatex-app` on Railway | not yet pushed |
| `mandatex-verifier` | **blocked** — no HTTP surface exists to containerize |
| Lockstep proof | mechanism built (`GET /readyz`), unexercised until both services are up |

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
2. Add a service named **`mandatex-app`**.
   - Root directory: `/` (the Dockerfile needs the whole tree — see below)
   - Config-as-code path: `deploy/railway.app.json`
3. Set variables from `app.env.example`. Do **not** set any signing key; the
   service scans its own environment and refuses to boot if it finds one.
4. Generate a public domain for `mandatex-app` only. The verifier stays private.
5. Add the verifier service, then set
   `MANDATEX_VERIFIER_URL=http://mandatex-verifier.railway.internal:8080` on the
   app and redeploy.

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

Measured on the built image at idle: **23 MiB resident**. Two services at that
size is roughly 0.05 GB-month ≈ **$0.50/mo**, well inside the included credit.
The earlier estimate in `plan.md` §5.3 assumed ~150 MB per service; the real
figure is an order of magnitude lower because the image ships no framework and
Core's only runtime dependency is zod.

Load will raise this. The headroom before the $5 credit is exhausted is large.

## Blocked: the verifier half

`tools/marketplace-service` is currently a **library**, not a service — it
exports `evaluateAndAttestMarketplace` and friends, and has no `node:http`
listener, no `PORT` handling, and no entry point to containerize. There is
nothing to write a Dockerfile against yet.

That package is Codex-owned, and `plan.md` §5.1 ("what does `marketplace-service`
become?") is still open, so building an HTTP wrapper here would preempt an open
design question on someone else's path. The request is filed in `plan.md` §7.

What the verifier image will need, so it can be written the moment the surface
exists:

- `GET /v1/trust` returning `keyId`, `publicKeyFingerprintSha256`,
  `verifierPolicySha256`. **This is the lockstep mechanism** — the app polls it
  and goes `503` on mismatch. Without it the contract's lockstep requirement has
  no automated proof.
- A signing key read from an environment variable or Railway secret, never from
  the repository. The fixture key `fixture-insecure-do-not-deploy-1` is
  forgeable by anyone who can read this tree.
- `GET /healthz` for the deploy gate.
- Listen on `PORT`, bind `0.0.0.0`, handle SIGTERM.

## Security posture

| Property | Where enforced |
|---|---|
| App holds no signing key | Boot guard scans env by name **and** content; exits 78 |
| Forgeable fixture key never deployed | Not copied into the image, **and** refused at boot under `NODE_ENV=production` |
| Verifier not publicly reachable | No Railway domain generated for it; app reaches it over `*.railway.internal` |
| Plaintext internal traffic | Allowed only for `.internal` hosts, which Railway does not route externally. Public URLs must be https |
| Key rotation without app update | Caught by `/readyz` fingerprint comparison |
| Container runs unprivileged | `USER node` |

Plaintext `http://` to `*.railway.internal` is deliberate: Railway's private
network does not terminate TLS, and those names are not resolvable from outside
the project. The production https requirement is waived for that suffix only.
