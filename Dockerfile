# syntax=docker/dockerfile:1.7
#
# HELIOS container images, from one Dockerfile:
#
#   runtime (default)  the web server (node server.js) and, with another
#                      command, the background worker (node worker.mjs).
#   tools              database migrations and the first-run seed.
#
# Both final images are distroless: no package manager, no shell in the
# runtime image (a minimal busybox one in tools, for its script), Debian 12
# underneath, an unprivileged user, and a read-only root filesystem friendly
# layout. Build stages use the full Node image, which brings OpenSSL and CA
# certificates without fetching anything from the OS's package mirrors.
#
# Builds for the machine it runs on (Apple Silicon or x86), or for both:
#   docker buildx build --platform linux/amd64,linux/arm64 --target runtime -t helios:1.0 .
#
# Behind a proxy that inspects TLS (common on company laptops), pass its CA
# certificate; it's mounted for the build only and never stored in a layer:
#   docker build --secret id=extra_ca,src=/path/to/proxy-ca.pem .

ARG NODE_IMAGE=node:22-bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/nodejs22-debian12:nonroot
ARG TOOLS_IMAGE=gcr.io/distroless/nodejs22-debian12:debug-nonroot

# ---------------------------------------------------------------- dependencies
FROM ${NODE_IMAGE} AS deps
ENV NEXT_TELEMETRY_DISABLED=1 \
    CHECKPOINT_DISABLE=1 \
    npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false
WORKDIR /app
COPY package.json package-lock.json ./
COPY prisma ./prisma
# Dependencies' install scripts don't run, except the three that fetch or
# check a binary HELIOS needs (Prisma's engines, esbuild).
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca npm_config_cafile=/run/secrets/extra_ca; fi; \
    npm ci --ignore-scripts \
 && npm rebuild @prisma/engines prisma esbuild \
 && npx prisma generate \
 # The engines under one name whatever the architecture, so the distroless
 # images can point Prisma straight at them (it otherwise probes the system
 # with a shell to pick one).
 && cp node_modules/.prisma/client/libquery_engine-*.so.node node_modules/.prisma/client/query-engine.so.node \
 && cp node_modules/@prisma/engines/schema-engine-* node_modules/@prisma/engines/schema-engine

# ---------------------------------------------------------------- build
FROM deps AS build
# The image's version: browsers holding pages from the previous version
# reload during a rolling update instead of mixing the two.
ARG HELIOS_DEPLOYMENT_ID=""
ENV HELIOS_DEPLOYMENT_ID=${HELIOS_DEPLOYMENT_ID}
COPY . .
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    npm run build \
 && npm run build:worker
# The standalone server serves its own static files; the worker sits beside it.
RUN cp -r public .next/standalone/public \
 && mkdir -p .next/standalone/.next/cache /out/var/lib/helios/archive \
 && cp -r .next/static .next/standalone/.next/static \
 && cp dist/worker.mjs .next/standalone/worker.mjs \
 && cp node_modules/.prisma/client/query-engine.so.node .next/standalone/node_modules/.prisma/client/query-engine.so.node

# ---------------------------------------------------------------- tools
FROM ${TOOLS_IMAGE} AS tools
WORKDIR /app
ENV NODE_ENV=production \
    HOME=/tmp \
    CHECKPOINT_DISABLE=1 \
    PRISMA_HIDE_UPDATE_MESSAGE=1 \
    PRISMA_QUERY_ENGINE_LIBRARY=/app/node_modules/.prisma/client/query-engine.so.node \
    PRISMA_SCHEMA_ENGINE_BINARY=/app/node_modules/@prisma/engines/schema-engine
COPY --from=deps --chown=root:root /app/node_modules ./node_modules
COPY --chown=root:root package.json tsconfig.json ./
COPY --chown=root:root prisma ./prisma
COPY --chown=root:root src ./src
COPY --chown=root:root deploy/db ./deploy/db
USER nonroot
# Migrations, then the app role's grants, then the seed (HELIOS_SEED=0 skips it).
ENTRYPOINT ["/busybox/sh", "/app/deploy/db/migrate.sh"]

# ---------------------------------------------------------------- runtime
FROM ${RUNTIME_IMAGE} AS runtime
LABEL org.opencontainers.image.title="HELIOS" \
      org.opencontainers.image.description="Managed detection and response platform" \
      org.opencontainers.image.source="https://github.com/dharani2d/helios"
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    PRISMA_QUERY_ENGINE_LIBRARY=/app/node_modules/.prisma/client/query-engine.so.node \
    HELIOS_JOBS=none
# Owned by root and read-only to the app: it can't change its own code.
COPY --from=build --chown=root:root /app/.next/standalone ./
# Writable by the app: Next's cache (mount an emptyDir or tmpfs over it on a
# read-only root) and the log archive (mount a volume).
COPY --from=build --chown=nonroot:nonroot /app/.next/standalone/.next/cache ./.next/cache
COPY --from=build --chown=nonroot:nonroot /out/var/lib/helios /var/lib/helios
USER nonroot
EXPOSE 3000
# The image's entrypoint is node. The worker runs ["worker.mjs"] with
# HELIOS_JOBS=core,ingest.
CMD ["server.js"]
