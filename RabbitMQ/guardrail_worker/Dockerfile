# ============================================================
# Stage 1: Builder — install dependencies and compile bytecode
# ============================================================
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON=3.12 \
    UV_PYTHON_PREFERENCE=only-system \
    UV_HTTP_TIMEOUT=180 \
    UV_HTTP_RETRIES=5 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install build-time system dependencies (regex, etc. need C compiler)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (cached layer)
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

# Copy application source and install
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

# ============================================================
# Stage 2: Runtime
# ============================================================
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV IS_DOCKER_CONTAINER="True" \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON=3.12 \
    UV_PYTHON_PREFERENCE=only-system

WORKDIR /app

COPY --from=builder /app /app

CMD ["uv", "run", "celery", "-A", "guardrail_worker", "worker", "-P", "prefork", "--loglevel=info", "--concurrency=2"]