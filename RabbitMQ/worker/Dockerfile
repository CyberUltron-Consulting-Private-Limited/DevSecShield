# Base images. scripts/deploy/build_images.sh passes UV_BASE_IMAGE / GO_BASE_IMAGE when they are set: behind a
# TLS-intercepting proxy, bases that trust the proxy's CA (deploy/staging/README.md).
# Every third-party input of this image is pinned and verified (#69): base images by digest, cbomkit-theia by tag and
# commit with upstream's go.sum and the Go checksum database, rustup / grype / syft by version and SHA-256. To update
# one, change its version and its checksum together; a mismatch fails the build.
ARG UV_BASE_IMAGE=ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58
ARG GO_BASE_IMAGE=golang:1.26.10-bookworm@sha256:5de7c99eb78ca5e515a4c340235d0955ec5964a5071c492c15503d7c267da473

# ============================================================
# Stage 1: Builder — install build tools, compile dependencies
# ============================================================
FROM ${UV_BASE_IMAGE} AS builder

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

# Install Rust toolchain (needed to compile tree-sitter, cryptography wheels): rustup-init of a pinned version,
# checked against its SHA-256, installing a pinned toolchain (rustup verifies the toolchain's own checksums).
ARG TARGETARCH
ARG RUSTUP_VERSION=1.29.3
ARG RUSTUP_SHA256_AMD64=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
ARG RUSTUP_SHA256_ARM64=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282
ARG RUST_TOOLCHAIN=1.99.0
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) triple=x86_64-unknown-linux-gnu; sum="${RUSTUP_SHA256_AMD64}" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sum="${RUSTUP_SHA256_ARM64}" ;; \
      *) echo "no pinned rustup-init for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init"; \
    printf '%s  /tmp/rustup-init\n' "${sum}" > /tmp/rustup-init.sha256; \
    sha256sum -c /tmp/rustup-init.sha256; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"; \
    rm /tmp/rustup-init /tmp/rustup-init.sha256
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
FROM ${GO_BASE_IMAGE} AS cbomkit-builder

# A release tag, held to its commit (a moved tag fails the build). Upstream's go.sum is kept and read-only, and every
# module is checked against it and the Go checksum database (the default GOSUMDB). -trimpath / -buildvcs=false: two
# builds of the same commit give the same binary.
ARG CBOMKIT_THEIA_REF=v1.1.2
ARG CBOMKIT_THEIA_SHA=dcd95ac86d1cbe6e867ff3ee059b9ef77bac6a59
ENV GOFLAGS=-mod=readonly \
    CGO_ENABLED=0
RUN set -eu; \
    git clone --depth 1 --branch "${CBOMKIT_THEIA_REF}" https://github.com/cbomkit/cbomkit-theia.git /tmp/cbomkit-theia; \
    head="$(git -C /tmp/cbomkit-theia rev-parse HEAD)"; \
    if [ "${head}" != "${CBOMKIT_THEIA_SHA}" ]; then \
      echo "cbomkit-theia ${CBOMKIT_THEIA_REF} is ${head}, expected ${CBOMKIT_THEIA_SHA}" >&2; exit 1; \
    fi; \
    cd /tmp/cbomkit-theia; \
    go mod download; \
    go mod verify; \
    go build -trimpath -buildvcs=false -o /usr/local/bin/cbomkit-theia .

# ============================================================
# Stage 2: Runtime — minimal image with only what's needed
# ============================================================
FROM ${UV_BASE_IMAGE}

# UV_NO_SYNC / UV_OFFLINE: `uv run` at start must never resolve or download anything. The venv is complete from
# the build; an air-gapped site has no index to reach (found in the AWS lab: a worker restart with no internet
# path crash-looped trying to fetch wheels).
ENV PYTHONUNBUFFERED=1 \
    UV_NO_SYNC=1 \
    UV_OFFLINE=1 \
    UV_PYTHON=3.12 \
    UV_PYTHON_PREFERENCE=only-system \
    IS_DOCKER_CONTAINER="True" \
    LINUX_GITLEAKS="True"
    
WORKDIR /build/RabbitMQ/worker

# Install only runtime system dependencies (no build-essential, no rust)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install grype + syft (SBOM vuln + inventory — runtime binaries): pinned release archives, checked against the
# SHA-256 from each release's checksums file.
ARG TARGETARCH
ARG GRYPE_VERSION=0.121.2
ARG GRYPE_SHA256_AMD64=9c8965ced9df657e5e851c14021bae838802f711edd7a48f9bc3c923a8d28f12
ARG GRYPE_SHA256_ARM64=d7d2e160255b0f087280feabf6f213cf4c45d475690f3f1fe5dc336eb1037bf0
ARG SYFT_VERSION=1.57.0
ARG SYFT_SHA256_AMD64=9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704
ARG SYFT_SHA256_ARM64=410cbfa0ae0f63246bc0057843760b1de2833cd23919e025e368fd7681308cdb
RUN set -eu; \
    arch="${TARGETARCH:-amd64}"; \
    case "${arch}" in \
      amd64) grype_sum="${GRYPE_SHA256_AMD64}"; syft_sum="${SYFT_SHA256_AMD64}" ;; \
      arm64) grype_sum="${GRYPE_SHA256_ARM64}"; syft_sum="${SYFT_SHA256_ARM64}" ;; \
      *) echo "no pinned grype/syft for ${arch}" >&2; exit 1 ;; \
    esac; \
    get() { \
      file="${1}_${2}_linux_${arch}.tar.gz"; \
      curl -sSfL -o "/tmp/${file}" "https://github.com/anchore/${1}/releases/download/v${2}/${file}"; \
      printf '%s  /tmp/%s\n' "${3}" "${file}" > /tmp/download.sha256; \
      sha256sum -c /tmp/download.sha256; \
      tar -xzf "/tmp/${file}" -C /usr/local/bin "${1}"; \
      rm "/tmp/${file}" /tmp/download.sha256; \
    }; \
    get grype "${GRYPE_VERSION}" "${grype_sum}"; \
    get syft "${SYFT_VERSION}" "${syft_sum}"; \
    grype version; syft version

# Install cbomkit-theia (CBOM binary/directory scanning)
COPY --from=cbomkit-builder /usr/local/bin/cbomkit-theia /usr/local/bin/cbomkit-theia


# Copy the entire app + venv from builder (includes compiled wheels)
COPY --from=builder /build/RabbitMQ/worker /build/RabbitMQ/worker
COPY --from=builder /build/aibom /build/aibom

CMD ["uv", "run", "celery", "-A", "scan_worker", "worker", "-P", "threads", "--loglevel=info"]