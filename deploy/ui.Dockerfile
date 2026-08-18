# syntax=docker/dockerfile:1

# Marketplace UI image.
#
# BUILD CONTEXT IS THE REPOSITORY ROOT, not this directory:
#   docker build -f deploy/ui.Dockerfile -t mandatex-ui .
#
# Same reason as the sibling images: the packages reference each other through
# relative `link:` specifiers, so the build has to reproduce the repository's
# layout under /srv for those to resolve.
#
# THE RUNTIME STAGE CARRIES NO node_modules AT ALL.
#
# That is not an optimisation, it is a measured fact about this package. The only
# non-relative import anywhere in the runtime graph is `node:http`:
# `@mandatex/marketplace-api` appears in `src/api.ts` as `import type`, which TypeScript
# erases at compile time, and it is a devDependency used by the smoke suite to boot a
# real API. So the deployed artifact is Node plus six .js files. There is no install
# step between a judge clicking a link and seeing a page, and no dependency that can
# publish a compromised version between build and deploy.
#
# The build stage still needs the whole chain — marketplace-core, then
# marketplace-api, then this package — because `tsc` needs the *types* it erases.
#
# WHAT IS DELIBERATELY ABSENT: fixtures/attestations, as in both sibling images.
# This process holds no key and pins no trust, but the fixture directory contains a
# publicly-forgeable private seed and none of the three images should carry it.

# ── Build ────────────────────────────────────────────────────────────────────
FROM node:24-slim AS build

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable

WORKDIR /srv

# Core first: slowest-moving, so a UI change does not invalidate its layers.
COPY tools/marketplace-core/package.json tools/marketplace-core/pnpm-lock.yaml ./tools/marketplace-core/
RUN cd tools/marketplace-core && pnpm install --frozen-lockfile

COPY tools/marketplace-core/tsconfig.json ./tools/marketplace-core/
COPY tools/marketplace-core/src ./tools/marketplace-core/src
RUN cd tools/marketplace-core && pnpm build

# marketplace-api next: the UI imports its display types.
COPY apps/marketplace-api/package.json apps/marketplace-api/pnpm-lock.yaml ./apps/marketplace-api/
RUN cd apps/marketplace-api && pnpm install --frozen-lockfile

COPY apps/marketplace-api/tsconfig.json ./apps/marketplace-api/
COPY apps/marketplace-api/src ./apps/marketplace-api/src
RUN cd apps/marketplace-api && pnpm build

COPY apps/marketplace-ui/package.json apps/marketplace-ui/pnpm-lock.yaml ./apps/marketplace-ui/
RUN cd apps/marketplace-ui && pnpm install --frozen-lockfile

COPY apps/marketplace-ui/tsconfig.json ./apps/marketplace-ui/
COPY apps/marketplace-ui/src ./apps/marketplace-ui/src
RUN cd apps/marketplace-ui && pnpm build

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM node:24-slim AS runtime

ENV NODE_ENV=production
ENV HOST=0.0.0.0

WORKDIR /srv/apps/marketplace-ui

# dist and package.json only. Nothing else is reachable from dist/server.js.
COPY --from=build /srv/apps/marketplace-ui/package.json /srv/apps/marketplace-ui/package.json
COPY --from=build /srv/apps/marketplace-ui/dist         /srv/apps/marketplace-ui/dist

# This process renders untrusted strings into a document. It should be the least
# privileged thing in the project, and root inside it buys an attacker a shell in
# the one container that faces the public internet.
USER node

EXPOSE 8081

# No npm/pnpm wrapper: node is PID 1 so Railway's SIGTERM on redeploy reaches the
# graceful-shutdown handler directly rather than dying in a package-manager shim.
CMD ["node", "dist/server.js"]
