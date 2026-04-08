# ============================================================
# Stage 1: Builder — install dependencies and compile bytecode
# ============================================================
FROM ghcr.io/astral-sh/uv:bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

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
FROM ghcr.io/astral-sh/uv:bookworm-slim

ENV IS_DOCKER_CONTAINER="True" \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /app /app

CMD ["uv", "run", "celery", "-A", "guardrail_worker", "worker", "-P", "prefork", "--loglevel=info", "--concurrency=2"]