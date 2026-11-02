# Build from the repository root (scripts/deploy/build_images.sh does exactly this):
#   docker buildx build --build-context migrations=prod_database_migrations -f backend/Dockerfile backend
#
# The Alembic bundle lives in prod_database_migrations/, outside this build context. The named context "migrations"
# replaces the stage of the same name below; without it the stage falls back to backend/_migrations (git-ignored,
# populated by e2e/scripts/build.sh). Either way only alembic.ini and migrations/ reach the image, never a .env, and a
# build with neither fails here instead of producing an image that cannot migrate.
#
# Behind a TLS-intercepting proxy or with a private registry mirror, pass a uv/python3.12 base that trusts the proxy
# CA: --build-arg UV_BASE_IMAGE=<image>.
ARG UV_BASE_IMAGE=ghcr.io/astral-sh/uv:python3.12-bookworm-slim

FROM scratch AS migrations
COPY _migrations /

# ============================================================
# Stage 1: Builder — install dependencies and compile bytecode
# ============================================================
FROM ${UV_BASE_IMAGE} AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_HTTP_TIMEOUT=180 \
    UV_HTTP_RETRIES=5 \
    PYTHONUNBUFFERED=1

WORKDIR /backend

# Install dependencies first (cached layer)
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

# Copy application source and install the project
COPY . /backend
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

# ============================================================
# Stage 2: Runtime — slim image with only what's needed
# ============================================================
FROM ${UV_BASE_IMAGE}

# `uv run` at start (entrypoint, alembic, gunicorn) must never resolve or download: the venv is complete from the
# build and an air-gapped site has no package index.
ENV IS_DOCKER_CONTAINER="True" \
    PYTHONPATH="/backend/.." \
    PYTHONUNBUFFERED=1 \
    UV_NO_SYNC=1 \
    UV_OFFLINE=1

WORKDIR /backend

# Copy the entire app + venv from builder
COPY --from=builder /backend /backend
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY --from=migrations /alembic.ini /prod_database_migrations/alembic.ini
COPY --from=migrations /migrations /prod_database_migrations/migrations
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uv", "run", "gunicorn", "main:app", "-k", "uvicorn.workers.UvicornWorker", "--workers", "9", "--bind", "0.0.0.0:8080", "--timeout", "120", "--graceful-timeout", "30", "--keep-alive", "5"]
