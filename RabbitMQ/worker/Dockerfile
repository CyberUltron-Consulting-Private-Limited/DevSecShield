# ============================================================
# Stage 1: Builder — install build tools, compile dependencies
# ============================================================
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON=3.12 \
    UV_PYTHON_PREFERENCE=only-system \
    UV_HTTP_TIMEOUT=180 \
    UV_HTTP_RETRIES=5 \
    PYTHONUNBUFFERED=1

# Install build-time system dependencies (not carried to final image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev curl git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain (needed to compile tree-sitter, cryptography wheels)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Monorepo path dependency (clinithread-aibom → ../../aibom from worker dir)
COPY aibom /build/aibom
COPY RabbitMQ/worker/pyproject.toml RabbitMQ/worker/uv.lock /build/RabbitMQ/worker/
WORKDIR /build/RabbitMQ/worker

# Install dependencies first (cached layer — only rebuilds when lockfile changes)
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project

# Copy application source and install the project
COPY RabbitMQ/worker /build/RabbitMQ/worker
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

# ============================================================
# Stage 1b: Build cbomkit-theia from source (Go binary for CBOM scanning)
# ============================================================
FROM golang:1.26-bookworm AS cbomkit-builder

RUN git clone --depth 1 https://github.com/cbomkit/cbomkit-theia.git /tmp/cbomkit-theia \
    && cd /tmp/cbomkit-theia \
    && rm go.sum \
    && GONOSUMCHECK=* GONOSUMDB=* go mod tidy \
    && CGO_ENABLED=0 go build -o /usr/local/bin/cbomkit-theia .

# ============================================================
# Stage 2: Runtime — minimal image with only what's needed
# ============================================================
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV PYTHONUNBUFFERED=1 \
    UV_PYTHON=3.12 \
    UV_PYTHON_PREFERENCE=only-system \
    IS_DOCKER_CONTAINER="True" \
    LINUX_GITLEAKS="True"
    
WORKDIR /build/RabbitMQ/worker

# Install only runtime system dependencies (no build-essential, no rust)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install grype + syft (SBOM vuln + inventory — runtime binaries)
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin

# Install cbomkit-theia (CBOM binary/directory scanning)
COPY --from=cbomkit-builder /usr/local/bin/cbomkit-theia /usr/local/bin/cbomkit-theia


# Copy the entire app + venv from builder (includes compiled wheels)
COPY --from=builder /build/RabbitMQ/worker /build/RabbitMQ/worker
COPY --from=builder /build/aibom /build/aibom

CMD ["uv", "run", "celery", "-A", "scan_worker", "worker", "-P", "threads", "--loglevel=info"]