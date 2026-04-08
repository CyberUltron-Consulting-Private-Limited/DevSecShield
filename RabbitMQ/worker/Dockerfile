# ============================================================
# Stage 1: Builder — install build tools, compile dependencies
# ============================================================
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON=3.12 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install build-time system dependencies (not carried to final image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev curl git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain (needed to compile tree-sitter, cryptography wheels)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Install dependencies first (cached layer — only rebuilds when lockfile changes)
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

# Copy application source and install the project
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

# ============================================================
# Stage 2: Runtime — minimal image with only what's needed
# ============================================================
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV PYTHONUNBUFFERED=1 \
    UV_PYTHON=3.12 \
    IS_DOCKER_CONTAINER="True" \
    LINUX_GITLEAKS="True"

WORKDIR /app

# Install only runtime system dependencies (no build-essential, no rust)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install grype (SBOM scanning — runtime binary)
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin

# Copy the entire app + venv from builder (includes compiled wheels)
COPY --from=builder /app /app

CMD ["uv", "run", "celery", "-A", "scan_worker", "worker", "-P", "threads", "--loglevel=info"]