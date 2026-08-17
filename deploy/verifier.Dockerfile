# syntax=docker/dockerfile:1

# Verifier API image — the SIGNING side of the trust boundary.
#
# BUILD CONTEXT IS THE REPOSITORY ROOT, not this directory:
#   docker build -f deploy/verifier.Dockerfile -t mandatex-verifier .
#
# Same reason as deploy/app.Dockerfile: the packages reference each other through
# relative `link:`/`file:` specifiers, so the image must reproduce the repository's
# layout under /srv for those to resolve. This image needs four packages rather
# than two, because the verifier sits on top of the whole supply stack:
#
#   marketplace-core        zod only
#   agent-supply-verifier   the heavy one — viem, @bnbagent/sdk
#   marketplace-service     links to both of the above; owns the signer
#   apps/verifier-api       this service
#
# They are built in that order so that a change to the service invalidates as few
# layers as possible; agent-supply-verifier's install is the expensive one.
#
# WHAT IS DELIBERATELY ABSENT: fixtures/attestations, exactly as in the app image.
# It matters more here. This process holds a real signing key, and the fixture
# directory contains a *private* seed; a container that has both is one bad
# environment variable away from signing with the forgeable key. The runtime
# refuses that key under NODE_ENV=production, but the material should not be in
# the image for that guard to be tested against.
#
# THE SIGNING KEY IS NEVER BAKED IN. It arrives only as the MANDATEX_SIGNING_KEY
# environment variable at run time, from the platform's secret store. There is no
# ARG, no COPY, and no default for it anywhere in this file — an image layer is
# permanent and readable by anyone who can pull the image.

# ── Build ────────────────────────────────────────────────────────────────────
FROM node:24-slim AS build

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable

WORKDIR /srv

# marketplace-core: smallest and slowest-moving, so it goes first.
COPY tools/marketplace-core/package.json tools/marketplace-core/pnpm-lock.yaml ./tools/marketplace-core/
RUN cd tools/marketplace-core && pnpm install --frozen-lockfile

COPY tools/marketplace-core/tsconfig.json ./tools/marketplace-core/
COPY tools/marketplace-core/src ./tools/marketplace-core/src
RUN cd tools/marketplace-core && pnpm build

# agent-supply-verifier: pulls viem and the BNB SDK. Its install is the layer
# worth protecting from invalidation, hence package.json + lock alone first.
COPY tools/agent-supply-verifier/package.json tools/agent-supply-verifier/pnpm-lock.yaml ./tools/agent-supply-verifier/
RUN cd tools/agent-supply-verifier && pnpm install --frozen-lockfile

COPY tools/agent-supply-verifier/tsconfig.json ./tools/agent-supply-verifier/
COPY tools/agent-supply-verifier/src ./tools/agent-supply-verifier/src
RUN cd tools/agent-supply-verifier && pnpm build

# marketplace-service: the signer. Depends on both packages above.
COPY tools/marketplace-service/package.json tools/marketplace-service/pnpm-lock.yaml ./tools/marketplace-service/
RUN cd tools/marketplace-service && pnpm install --frozen-lockfile

COPY tools/marketplace-service/tsconfig.json ./tools/marketplace-service/
COPY tools/marketplace-service/src ./tools/marketplace-service/src
RUN cd tools/marketplace-service && pnpm build

COPY apps/verifier-api/package.json apps/verifier-api/pnpm-lock.yaml ./apps/verifier-api/
RUN cd apps/verifier-api && pnpm install --frozen-lockfile

COPY apps/verifier-api/tsconfig.json ./apps/verifier-api/
COPY apps/verifier-api/src ./apps/verifier-api/src
RUN cd apps/verifier-api && pnpm build

# Drop devDependencies from every tree. typescript, tsx and @types/node are build
# tools; leaving them resident in the one container that holds a signing key is
# strictly worse than not.
RUN cd /srv/tools/marketplace-core      && pnpm prune --prod \
 && cd /srv/tools/agent-supply-verifier && pnpm prune --prod \
 && cd /srv/tools/marketplace-service   && pnpm prune --prod \
 && cd /srv/apps/verifier-api           && pnpm prune --prod

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM node:24-slim AS runtime

ENV NODE_ENV=production
ENV HOST=0.0.0.0

WORKDIR /srv/apps/verifier-api

COPY --from=build /srv/tools/marketplace-core/package.json       /srv/tools/marketplace-core/package.json
COPY --from=build /srv/tools/marketplace-core/dist               /srv/tools/marketplace-core/dist
COPY --from=build /srv/tools/marketplace-core/node_modules       /srv/tools/marketplace-core/node_modules
COPY --from=build /srv/tools/agent-supply-verifier/package.json  /srv/tools/agent-supply-verifier/package.json
COPY --from=build /srv/tools/agent-supply-verifier/dist          /srv/tools/agent-supply-verifier/dist
COPY --from=build /srv/tools/agent-supply-verifier/node_modules  /srv/tools/agent-supply-verifier/node_modules
COPY --from=build /srv/tools/marketplace-service/package.json    /srv/tools/marketplace-service/package.json
COPY --from=build /srv/tools/marketplace-service/dist            /srv/tools/marketplace-service/dist
COPY --from=build /srv/tools/marketplace-service/node_modules    /srv/tools/marketplace-service/node_modules
COPY --from=build /srv/apps/verifier-api/package.json            /srv/apps/verifier-api/package.json
COPY --from=build /srv/apps/verifier-api/dist                    /srv/apps/verifier-api/dist
COPY --from=build /srv/apps/verifier-api/node_modules            /srv/apps/verifier-api/node_modules

# Never run the signer as root. This is the process whose memory holds the private
# key; a root shell inside this container is the worst outcome in the system.
USER node

EXPOSE 8080

# No npm/pnpm wrapper: an init-less container should have node as PID 1 so
# Railway's SIGTERM on redeploy reaches the graceful-shutdown handler directly
# rather than dying in a package-manager shim.
CMD ["node", "dist/server.js"]
