# Deployment

Target: **Railway Hobby, $5/mo** — one project, three services.

```
project: mandatex
├── mandatex-verifier   holds the Ed25519 PRIVATE key, evaluates and signs
├── mandatex-app        pins only the PUBLIC key, verifies and serves the API
└── mandatex-ui         holds nothing; renders what the app returns
```

The verifier and app are two services, not one, because the verifier runtime *is*
the signer. A single process that both signs and verifies proves nothing — every
signature it checked would be one it could have produced itself. The v2 contract
requires the split, and requires proving both halves redeploy in lockstep before
submission rehearsal.

**The UI is outside that boundary in both directions**, which is why adding it costs
nothing in coordination. It holds no signing key *and* pins no trust: it has no
`MANDATEX_TRUST_*` variables at all, because it displays verdicts the app already
reached rather than reaching any itself. The lockstep pair remains strictly
verifier ↔ app. See [Why the UI is its own
service](#why-the-ui-is-its-own-service-and-not-a-second-process-in-the-app).

| File | Purpose |
|---|---|
| `app.Dockerfile` | Image for `mandatex-app`. Build context is the **repository root** |
| `railway.app.json` | Railway config-as-code for `mandatex-app` |
| `app.env.example` | Environment contract for `mandatex-app` |
| `verifier.Dockerfile` | Image for `mandatex-verifier`. Build context is the **repository root** |
| `railway.verifier.json` | Railway config-as-code for `mandatex-verifier` |
| `verifier.env.example` | Environment contract for `mandatex-verifier`, including key generation |
| `ui.Dockerfile` | Image for `mandatex-ui`. Build context is the **repository root**. Runtime stage carries no `node_modules` |
| `railway.ui.json` | Railway config-as-code for `mandatex-ui` |
| `ui.env.example` | Environment contract for `mandatex-ui` |
| `rehearse.mjs` | Boots the verifier and app as separate processes and checks the trust boundary |

---

## Status

| | |
|---|---|
| `mandatex-app` image | **builds and runs** — 353 MB. Boot guards fire, routes serve, SIGTERM exits 0 |
| `mandatex-verifier` image | **builds and runs** — 601 MB. Boot guards fire, key never appears in a response, SIGTERM exits 0 |
| `mandatex-ui` image | **builds and runs** — 347 MB, of which essentially all is the Node base image. Verified against the app over a private network: renders, `/healthz` and `/readyz` answer, four boot guards fire, SIGTERM exits 0, PID 1 is `node` |
| Lockstep proof | **exercised end to end.** `node deploy/rehearse.mjs` → 27/27 across two processes; also verified as two containers on a private network |
| Any service on Railway | not yet pushed |
| `POST /v1/evaluate` on the verifier | returns 503 until agent artifacts exist — see [What is still missing](#what-is-still-missing) |
| The deployed UI's content | **empty but honest** until those artifacts exist — see the same section |

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

### The UI

```bash
docker build -f deploy/ui.Dockerfile -t mandatex-ui .

# The UI needs an app to read. Give the app an .internal alias so the UI's
# production URL guard is satisfied without weakening it.
docker network create mx-net
docker run -d --name mx-app --network mx-net --network-alias mandatex-app.internal \
  -e MANDATEX_TRUST_KEY_ID=mandatex-verifier-1 \
  -e MANDATEX_TRUST_SPKI_DER_HEX=... \
  -e MANDATEX_TRUST_KEY_FINGERPRINT_SHA256=... \
  -e MANDATEX_TRUST_POLICY_SHA256=... \
  mandatex-app

docker run --rm --network mx-net -p 8081:8081 \
  -e MANDATEX_API_URL=http://mandatex-app.internal:8080 \
  mandatex-ui
```

Verified on this image, in two containers on a private network:

- `/healthz` → `200 {"status":"ok"}`; `/readyz` → `200 {"status":"ready"}`, having
  actually reached the app over `.internal`
- `GET /` → `200`, renders the mandate form
- in production it correctly reports *"No candidate attestations are available"*, and
  `POST /evaluate` answers `503 Unavailable`, because the app's `/v1/fixtures` is
  `404` there — see [What is still missing](#what-is-still-missing)
- no `MANDATEX_API_URL` → exits `78`
- `MANDATEX_SIGNING_KEY` set → exits `78`
- a PKCS#8 private key in a variable named `UI_THEME` → exits `78`
- `MANDATEX_API_URL=http://127.0.0.1:8080` → exits `78`, see below
- no `node_modules` and no `/srv/fixtures` in the image; runs as `uid=1000(node)`
- PID 1 is `node dist/server.js`; `docker stop` → `closed cleanly`, exit `0`

### Why the UI is its own service, and not a second process in the app

Mounting the UI into the `mandatex-app` container was the intended plan. It was
rejected on two concrete blockers, both measured rather than assumed:

**The UI refuses a loopback API URL in production.** Two processes in one container
must talk over loopback, and `MANDATEX_API_URL=http://127.0.0.1:8080` exits `78`:

```
MANDATEX_API_URL must be https in production unless it is a *.internal
private-network address, received http://127.0.0.1:8080
```

The waiver in `loadUiConfig` covers the `.internal` suffix and nothing else. Mounting
would mean widening a security guard to suit deployment convenience, which is the
wrong direction — the guard exists so that a plaintext hop is only ever possible on a
network that is not externally routable.

**Two node processes cannot both be PID 1.** Running a pair inside one container needs
a supervisor as PID 1 — a shell wrapper or an init like `tini`. Both break the property
that Railway's SIGTERM reaches the graceful-shutdown handler directly, which is exactly
what makes a redeploy clean rather than a SIGKILL. That property is load-bearing for the
lockstep pair and worth more than a saved service.

Against that, the cost of a third service turned out to be close to nothing: the UI has
**no trust pins**, so there is no third set of values to keep in lockstep, and it idles
at 18 MiB.

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
4. Read `publicKeySpkiDerHex` and `publicKeyFingerprintSha256` from the verifier's
   `GET /v1/trust` and set them as the app's `MANDATEX_TRUST_*` pins. Take them from
   the **running verifier**, not from what you believe you configured — that is what
   makes the pair actually locked together rather than nominally agreeing.
5. Set the app's remaining variables from `app.env.example`, including
   `MANDATEX_VERIFIER_URL=http://mandatex-verifier.railway.internal:8080`. Do
   **not** set any signing key on the app; it scans its own environment and refuses
   to boot if it finds one.
6. Generate a public domain for `mandatex-app`.
7. Check the app's `/readyz` is `200` with `checks.verifier.status = "ok"`. If it
   is `503 key_mismatch`, the pins are stale — step 4 was skipped or run against a
   previous verifier deploy.
8. Add a service named **`mandatex-ui`**, last, because it reads the app.
   - Root directory: `/`
   - Config-as-code path: `deploy/railway.ui.json`
   - Set `MANDATEX_API_URL=http://mandatex-app.railway.internal:8080` from
     `ui.env.example`. Set no trust pins and no key; it needs neither.
   - Generate a public domain for it. **This is the URL to give judges.**

Steps 1–7 are unchanged and must stay in that order: the app's pins come from the
running verifier, so the verifier has to exist first. The UI is appended rather than
inserted because it depends on the app answering, and it holds nothing that the other
two need.

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

**Each service's own `/healthz` is authoritative for its own deploy gate, and only
that.** All three expose one, and none of them should gate on another's:

| Service | `/healthz` means | `/readyz` means |
|---|---|---|
| `mandatex-verifier` | process is up | it can **sign** — 200 even with no agent configured |
| `mandatex-app` | process is up | the verifier's advertised key matches the app's pin |
| `mandatex-ui` | process is up | the app it reads is answering |

The UI's `/readyz` deliberately reports `degraded` when the app is unreachable, so an
API outage does not present as a UI bug. It is still not the deploy gate, for the same
deadlock reason: the UI is deployed last, and gating its first deploy on the app being
ready would couple three services into one failure.

## Getting a public URL with a Cloudflare Tunnel

The compose stack binds only `127.0.0.1:8090`, so something has to publish it. A
Cloudflare Tunnel is the least-moving-parts option and the one to reach for when
there is no domain, no working card, or no wish to open a firewall port:

- no DNS record to create and no certificate to obtain — the tunnel terminates TLS
  at Cloudflare's edge;
- **no inbound port at all**, because `cloudflared` dials outward. This sidesteps
  both the AWS security-group step and the Oracle double-firewall trap, where the
  VCN security list and the instance's local `iptables` must each be opened and
  people routinely open only the first;
- free, and it needs no payment method.

It also avoids the failure mode of the current agent hostname. `bnb-lp.172-104-171-139.nip.io`
is wildcard DNS that encodes the server's IP directly in the name: it publishes the
address, depends on a third party staying up, and reads as a development setup to
anyone who looks at it.

### Quick tunnel — for a first check

```bash
# with the stack already up, so there is something to proxy
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8090/   # expect 200

cloudflared tunnel --url http://127.0.0.1:8090
```

It prints a `https://<random>.trycloudflare.com` URL that works immediately.

**Do not submit that URL.** A quick tunnel's hostname is regenerated every restart,
so a reboot during judging silently invalidates whatever was submitted. Use it to
confirm the path works, then move to a named tunnel.

### Named tunnel — for anything judged

Needs a free Cloudflare account with a domain on it. The hostname is then stable
across restarts and the tunnel runs as a service.

```bash
cloudflared tunnel login                       # browser auth, selects the zone
cloudflared tunnel create mandatex             # writes ~/.cloudflared/<uuid>.json
cloudflared tunnel route dns mandatex mandatex.yourdomain.com
```

`~/.cloudflared/config.yml`:

```yaml
tunnel: mandatex
credentials-file: /home/USER/.cloudflared/<uuid>.json
ingress:
  - hostname: mandatex.yourdomain.com
    service: http://127.0.0.1:8090
  # Required: cloudflared refuses to start without a terminating catch-all.
  - service: http_status:404
```

Then install it so it survives a reboot — which is the whole point, since the
judging window is longer than one uptime:

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
systemctl status cloudflared --no-pager
```

### What the tunnel does not change

The trust boundary is unaffected. The tunnel publishes the **UI only**; the app and
the verifier stay on the private compose network, and the verifier still has no
`ports:` stanza, so the process holding the signing key remains unreachable from
outside the host regardless of what is tunnelled.

Security headers still come from the app rather than the edge — CSP,
`frame-ancestors`, `nosniff` and `referrer-policy` are set in `sendHtml`, so they
hold whether traffic arrives through a tunnel, an nginx proxy, or directly. HSTS is
the exception and belongs at whatever terminates TLS, which here is Cloudflare.

## Cost

Railway Hobby is $5/mo including $5 of usage credit, billed on **measured** RAM
at $10/GB/month — not allocated RAM, which is what makes it cheaper than Fly.io
for two mostly-idle Node services.

Measured in the running containers at idle:

| Service | Resident | Why |
|---|---|---|
| `mandatex-app` | **36 MiB** | No framework; Core's only runtime dependency is zod |
| `mandatex-verifier` | **81 MiB** | Carries `viem` and `@bnbagent/sdk` through `agent-supply-verifier` |
| `mandatex-ui` | **18 MiB** | The smallest of the three: its runtime stage has **no `node_modules` at all** |

Together ≈ **0.135 GB-month ≈ $1.35/mo** at idle, inside the included $5 credit. The UI
adds 18 MiB and about $0.18/mo, which is the whole cost of not mounting it.

Two corrections to earlier figures, both recorded rather than quietly replaced:
`plan.md` §5.3 originally assumed ~150 MB per service (≈$3/mo), which was too high;
the $0.50/mo figure that replaced it was measured on the **app alone** and applied
to both services, which was too low — the verifier is more than twice the app's
footprint because of its chain dependencies. The $1.17/mo figure that followed was
measured from the verifier and app actually running, and is superseded here only
because a third service now exists.

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

**So the deployed UI is empty until they exist, and says so.** `GET /v1/fixtures` on
the app is unconditionally disabled under `NODE_ENV=production` and the vectors are in
no production image, so the UI renders its mandate form with a *"No candidate
attestations are available"* banner and `POST /evaluate` answers `503`. Verified in the
built images. This is the correct behaviour for an interface that submits attestations
issued by the verifier and cannot mint them — but anyone opening the public URL before
artifacts exist should expect an honest empty state rather than assume a failed deploy.

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
| Container runs unprivileged | `USER node` on all three images |
| Verifier never echoes its key | Every response body checked against the real secret's four encodings before it reaches the socket |
| Verifier never logs its environment | Boot log names the key by id and public fingerprint only |
| Signing key absent from image layers | No `ARG`, no `COPY`, no default — env var only, at run time |
| UI holds no signing key | Boot guard scans env by name **and** content; exits 78 |
| UI decides no trust | It has no `MANDATEX_TRUST_*` variables, so "which signatures count" is decided in exactly one place |
| UI ships no dependencies | Runtime stage has no `node_modules`; the only non-relative import in its graph is `node:http`, so there is no third-party code in the public-facing container |
| UI renders no external resources | CSP is `default-src 'none'` with no `<script>` anywhere; zero external fonts or images. Graphics are inline SVG, so the only `w3.org` string in the output is an XML namespace, which is never fetched |

Plaintext `http://` to `*.railway.internal` is deliberate: Railway's private
network does not terminate TLS, and those names are not resolvable from outside
the project. The production https requirement is waived for that suffix only.
