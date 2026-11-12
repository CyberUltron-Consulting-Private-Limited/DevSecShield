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
# Stage 1: deps — the virtualenv, from pyproject.toml + uv.lock only (never the source), bytecode compiled
# ============================================================
FROM ${UV_BASE_IMAGE} AS deps

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_HTTP_TIMEOUT=180 \
    UV_HTTP_RETRIES=5 \
    PYTHONUNBUFFERED=1

WORKDIR /backend

# pyproject.toml has no [build-system]: uv never installs the project itself, so this venv is the complete
# runtime environment and depends on nothing but these two files.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

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

# The venv is its own layer, then the source (.dockerignore keeps the context's .venv out). A release that changes
# only source reuses the venv layer and adds a small one. Round 5 (L1): one COPY of the builder's whole /backend
# put venv + source in a single layer, ~700 MB of new layer per release.
COPY --from=deps /backend/.venv /backend/.venv
COPY . /backend
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY --from=migrations /alembic.ini /prod_database_migrations/alembic.ini
COPY --from=migrations /migrations /prod_database_migrations/migrations
RUN chmod +x /docker-entrypoint.sh

# Build identity (CB-03): the commit this image was built from and its version string, reported by GET /health, the
# X-ZS-Build header and the CBOM exports (backend/utilities/build_info.py). scripts/deploy/build_images.sh passes both.
# Declared last, so a new commit with the same source reuses every layer above.
ARG DSS_BUILD_SHA=""
ARG DSS_BUILD_VERSION=""
ENV DSS_BUILD_SHA=${DSS_BUILD_SHA} \
    DSS_BUILD_VERSION=${DSS_BUILD_VERSION}

EXPOSE 8080

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uv", "run", "gunicorn", "main:app", "-k", "uvicorn.workers.UvicornWorker", "--workers", "9", "--bind", "0.0.0.0:8080", "--timeout", "120", "--graceful-timeout", "30", "--keep-alive", "5"]
