# syntax=docker.io/docker/dockerfile:1
#
#   docker buildx build --build-arg NEXT_PUBLIC_BACKEND_URL=https://<api host> -f frontend/Dockerfile frontend
#
# NEXT_PUBLIC_* values are inlined into the browser bundle at build time, so the API URL is required: an image built
# without it would send every browser to a default host. Optional: NEXT_PUBLIC_CBOM_NODE_IMAGE (the scan-node image
# shown in the deployment instructions; a registry customers can pull from; without it the UI
# offers the image file the server serves, zeroshield/cbom-scan-node:<version>) and
# NEXT_PUBLIC_BUILD_SHA (the git commit, shown as <meta name="zs-build">; build_images.sh passes it).
# Behind a TLS-intercepting proxy or with a private registry mirror: --build-arg NODE_BASE_IMAGE=<node:20-alpine
# image that trusts the proxy CA>.
ARG NODE_BASE_IMAGE=node:20-alpine

FROM ${NODE_BASE_IMAGE} AS base

# Install dependencies only when needed
FROM base AS deps
# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
RUN apk add --no-cache libc6-compat
WORKDIR /frontend

# Install dependencies based on the preferred package manager
COPY package.json yarn.lock* package-lock.json* pnpm-lock.yaml* .npmrc* ./
RUN \
  if [ -f yarn.lock ]; then yarn --frozen-lockfile; \
  elif [ -f package-lock.json ]; then npm ci; \
  elif [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm i --frozen-lockfile; \
  else echo "Lockfile not found." && exit 1; \
  fi


# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /frontend
COPY --from=deps /frontend/node_modules ./node_modules
COPY . .

ARG NEXT_PUBLIC_BACKEND_URL
ARG NEXT_PUBLIC_CBOM_NODE_IMAGE=
# Build identity (CB-03): the commit this frontend is built from, in every page's <meta name="zs-build">.
# build_images.sh fills it only with DSS_EXPOSE_BUILD=1 (local stack, lab, staging). `next build` compiles it in, so
# there every new commit re-runs the build (~4-8 min on 2 CPUs); a production build (empty value) reuses its cache.
ARG NEXT_PUBLIC_BUILD_SHA=
ENV NEXT_PUBLIC_BACKEND_URL=$NEXT_PUBLIC_BACKEND_URL \
    NEXT_PUBLIC_CBOM_NODE_IMAGE=$NEXT_PUBLIC_CBOM_NODE_IMAGE \
    NEXT_PUBLIC_BUILD_SHA=$NEXT_PUBLIC_BUILD_SHA

# No telemetry call during the build (air-gapped builders have no route to it anyway).
ENV NEXT_TELEMETRY_DISABLED=1

RUN case "$NEXT_PUBLIC_BACKEND_URL" in \
      http://?*|https://?*) echo "NEXT_PUBLIC_BACKEND_URL=$NEXT_PUBLIC_BACKEND_URL" ;; \
      *) echo "ERROR: build with --build-arg NEXT_PUBLIC_BACKEND_URL=https://<api host> (got '$NEXT_PUBLIC_BACKEND_URL')" >&2; exit 1 ;; \
    esac

RUN \
  if [ -f yarn.lock ]; then yarn run build; \
  elif [ -f package-lock.json ]; then npm run build; \
  elif [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm run build; \
  else echo "Lockfile not found." && exit 1; \
  fi

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /frontend

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /frontend/public ./public

# Automatically leverage output traces to reduce image size
# https://nextjs.org/docs/advanced-features/output-file-tracing
COPY --from=builder --chown=nextjs:nodejs /frontend/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /frontend/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000

ENV MODE=production
# server.js is created by next build from the standalone output
# https://nextjs.org/docs/pages/api-reference/config/next-config-js/output
ENV HOSTNAME="0.0.0.0"
CMD ["node", "server.js"]