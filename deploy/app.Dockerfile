# syntax=docker/dockerfile:1

# Marketplace API image.
#
# BUILD CONTEXT IS THE REPOSITORY ROOT, not this directory:
#   docker build -f deploy/app.Dockerfile -t mandatex-app .
#
# It has to be. `apps/marketplace-api` depends on Marketplace Core through
# `link:../../tools/marketplace-core`, so the image must reproduce the repository's
# relative layout for that link to resolve. Both packages therefore live under
# /srv at the same relative paths they occupy in the tree.
#
# WHAT IS DELIBERATELY ABSENT: fixtures/attestations. Those vectors are signed by
# a committed, publicly-forgeable Ed25519 seed, and the trust file next to them
# pins key id `fixture-insecure-do-not-deploy-1`. Not copying them means the
# forgeable key cannot be present in a deployed image even by accident — the
# runtime's boot guard against development keys becomes a second line of defence
# rather than the only one. Production trust must come from MANDATEX_TRUST_*.

# ── Build ────────────────────────────────────────────────────────────────────
FROM node:24-slim AS build

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable

WORKDIR /srv

# Core before the app: it is the slower-moving package, so a change to the app's
# source does not invalidate Core's install and build layers.
COPY tools/marketplace-core/package.json tools/marketplace-core/pnpm-lock.yaml ./tools/marketplace-core/
RUN cd tools/marketplace-core && pnpm install --frozen-lockfile

COPY tools/marketplace-core/tsconfig.json ./tools/marketplace-core/
COPY tools/marketplace-core/src ./tools/marketplace-core/src
RUN cd tools/marketplace-core && pnpm build

COPY apps/marketplace-api/package.json apps/marketplace-api/pnpm-lock.yaml ./apps/marketplace-api/
RUN cd apps/marketplace-api && pnpm install --frozen-lockfile

COPY apps/marketplace-api/tsconfig.json ./apps/marketplace-api/
COPY apps/marketplace-api/src ./apps/marketplace-api/src
RUN cd apps/marketplace-api && pnpm build

# Drop devDependencies from both trees. typescript, tsx and @types/node are build
# tools; leaving them resident inside the trust boundary buys nothing.
RUN cd tools/marketplace-core && pnpm prune --prod \
 && cd /srv/apps/marketplace-api && pnpm prune --prod

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM node:24-slim AS runtime

ENV NODE_ENV=production
ENV HOST=0.0.0.0

WORKDIR /srv/apps/marketplace-api

COPY --from=build /srv/tools/marketplace-core/package.json  /srv/tools/marketplace-core/package.json
COPY --from=build /srv/tools/marketplace-core/dist          /srv/tools/marketplace-core/dist
COPY --from=build /srv/tools/marketplace-core/node_modules   /srv/tools/marketplace-core/node_modules
COPY --from=build /srv/apps/marketplace-api/package.json    /srv/apps/marketplace-api/package.json
COPY --from=build /srv/apps/marketplace-api/dist            /srv/apps/marketplace-api/dist
COPY --from=build /srv/apps/marketplace-api/node_modules    /srv/apps/marketplace-api/node_modules

# Never run the evaluator as root. It holds no key, but it does hold the pin that
# decides which signatures count.
USER node

EXPOSE 8080

# No npm/pnpm wrapper: an init-less container should have node as PID 1 so
# Railway's SIGTERM on redeploy reaches the graceful-shutdown handler directly
# rather than dying in a package-manager shim.
CMD ["node", "dist/server.js"]
