# Base images. scripts/deploy/build_images.sh passes UV_BASE_IMAGE / GO_BASE_IMAGE when they are set: behind a
# TLS-intercepting proxy, bases that trust the proxy's CA (deploy/staging/README.md).
# Every third-party input of this image is pinned and verified (#69): base images by digest, cbomkit-theia by tag and
# commit with upstream's go.sum and the Go checksum database, rustup / grype / syft / Node.js by version and SHA-256,
# cdxgen and its npm dependencies by RabbitMQ/worker/tools/cdxgen/package-lock.json (sha512 integrity per package).
# To update one, change its version and its checksum together; a mismatch fails the build.
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
# Stage 1c: cdxgen (CycloneDX generator, SBOM inventory next to Syft)
# ============================================================
# Node.js from nodejs.org by version and SHA-256 (SHASUMS256.txt of the release); cdxgen and every dependency from the
# committed lockfile: npm ci refuses a package whose sha512 differs. --ignore-scripts: no install script runs;
# --omit=optional: cdxgen's optional native plugins are not needed to read manifests and lock files. The SBOM scan
# runs it with --no-install-deps (helpers/tools/sca_sbom_agent/cdxgen_run.py), so nothing is fetched at scan time.
FROM ${UV_BASE_IMAGE} AS cdxgen-builder
ARG TARGETARCH
ARG NODE_VERSION=24.22.3
ARG NODE_SHA256_AMD64=061ec3e3062115705b56b51fa9cc330ab50d34b6969387d4e4b1a50c6809acc2
ARG NODE_SHA256_ARM64=261af2af250dfd7e9f25cf151d1b2713a0adf8f10a9ad116c4947f68627affe8
# No apt step: the base image's Python fetches the archive (an HTTP error fails the step), sha256sum checks it.
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) narch=x64; sum="${NODE_SHA256_AMD64}" ;; \
      arm64) narch=arm64; sum="${NODE_SHA256_ARM64}" ;; \
      *) echo "no pinned Node.js for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    file="node-v${NODE_VERSION}-linux-${narch}.tar.gz"; \
    python3 -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' \
      "https://nodejs.org/dist/v${NODE_VERSION}/${file}" "/tmp/${file}"; \
    printf '%s  /tmp/%s\n' "${sum}" "${file}" > /tmp/node.sha256; \
    sha256sum -c /tmp/node.sha256; \
    mkdir -p /opt/node; \
    tar -xzf "/tmp/${file}" -C /opt/node --strip-components=1; \
    rm "/tmp/${file}" /tmp/node.sha256
ENV PATH="/opt/node/bin:${PATH}"
WORKDIR /opt/cdxgen
COPY RabbitMQ/worker/tools/cdxgen/package.json RabbitMQ/worker/tools/cdxgen/package-lock.json /opt/cdxgen/
# --use-system-ca: behind a TLS-intercepting proxy the base image's trust store holds the proxy CA (see UV_BASE_IMAGE).
# package.json "overrides" lift cdxgen's glob / minimatch / body-parser to releases with the advisories fixed
# (cdxgen output checked identical on peva3/SmarterRouter and ninedter/pcap-hunter).
RUN NODE_OPTIONS=--use-system-ca npm ci --omit=dev --omit=optional --ignore-scripts --no-audit --no-fund \
    && node node_modules/@cyclonedx/cdxgen/bin/cdxgen.js --version

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

# cdxgen (SBOM inventory): the Node.js runtime binary and the npm ci tree (no npm in the runtime image)
COPY --from=cdxgen-builder /opt/node/bin/node /usr/local/bin/node
COPY --from=cdxgen-builder /opt/cdxgen /opt/cdxgen
RUN ln -s /opt/cdxgen/node_modules/@cyclonedx/cdxgen/bin/cdxgen.js /usr/local/bin/cdxgen \
    && cdxgen --version

# Install cbomkit-theia (CBOM binary/directory scanning)
COPY --from=cbomkit-builder /usr/local/bin/cbomkit-theia /usr/local/bin/cbomkit-theia


# Copy the entire app + venv from builder (includes compiled wheels)
COPY --from=builder /build/RabbitMQ/worker /build/RabbitMQ/worker
COPY --from=builder /build/aibom /build/aibom
# The CBOM SSRF guard's address rule (#53): MCP and LLM scans check every address they connect to with the file the API
# runs. Standard library only; helpers/net/guard.py loads it from this path (the same path as in a checkout).
COPY backend/utilities/cbom_sources/address_rule.py /build/backend/utilities/cbom_sources/address_rule.py
# The SBOM scan resolves licences, authors and hashes once with the API's own files (sca_sbom_agent/registry_enrich.py
# loads them from these paths; standard library only): the package-registry lookup, the SPDX licence-id rules (they read
# /build/aibom/src/aibom/schemas/spdx.schema.json) and the licence risk categories the dashboard counts.
COPY backend/utilities/compliance/sbom_registry.py backend/utilities/compliance/spdx_license.py /build/backend/utilities/compliance/
COPY backend/utilities/dashboard/sbom_license.py /build/backend/utilities/dashboard/sbom_license.py

# Build identity: the SBOM's metadata.tools names DevSecShield with this version (sca_sbom_agent/merge_inventory.py).
# scripts/deploy/build_images.sh passes both, as for the backend. Declared last so a new commit reuses every layer.
ARG DSS_BUILD_SHA=""
ARG DSS_BUILD_VERSION=""
ENV DSS_BUILD_SHA=${DSS_BUILD_SHA} \
    DSS_BUILD_VERSION=${DSS_BUILD_VERSION}

# Build identity: the release the AI BOM / CBOM documents name as their tool version (aibom/src/aibom/emit/identity.py,
# "DevSecShield AI BOM <version>"). scripts/deploy/build_images.sh passes both, as for the backend. Declared last, so a
# new commit with the same source reuses every layer above.
ARG DSS_BUILD_SHA=""
ARG DSS_BUILD_VERSION=""
ENV DSS_BUILD_SHA=${DSS_BUILD_SHA} \
    DSS_BUILD_VERSION=${DSS_BUILD_VERSION}

CMD ["uv", "run", "celery", "-A", "scan_worker", "worker", "-P", "threads", "--loglevel=info"]