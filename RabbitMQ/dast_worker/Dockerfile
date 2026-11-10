# Base image of both stages. scripts/deploy/build_images.sh passes UV_BASE_IMAGE when it is set: behind a
# TLS-intercepting proxy, a base that trusts the proxy's CA (deploy/staging/README.md).
ARG UV_BASE_IMAGE=ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# ============================================================
# Stage 1: Builder — install dependencies and compile bytecode
# ============================================================
FROM ${UV_BASE_IMAGE} AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON=3.12 \
    UV_PYTHON_PREFERENCE=only-system \
    UV_HTTP_TIMEOUT=180 \
    UV_HTTP_RETRIES=5 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (cached layer)
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

# Copy application source and install
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

# Install Playwright browsers in builder
RUN uv run playwright install --with-deps chromium

# ============================================================
# Stage 2: Runtime
# ============================================================
FROM ${UV_BASE_IMAGE}

ENV IS_DOCKER_CONTAINER="True" \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON=3.12 \
    UV_PYTHON_PREFERENCE=only-system

WORKDIR /app

# Install nuclei directly from GitHub releases (no Homebrew needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip git tini \
    # Chromium/Playwright runtime dependencies
    libglib2.0-0 libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libgbm1 libasound2 \
    libpango-1.0-0 libcairo2 libx11-6 libxcomposite1 libxdamage1 \
    libxext6 libxfixes3 libxrandr2 fonts-liberation libx11-xcb1 \
    libxcursor1 libgtk-3-0 libpangocairo-1.0-0 libcairo-gobject2 \
    libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei binary directly (skip Homebrew entirely — saves ~500MB). A pinned release, checked against the
# release's own checksums file: the "latest" lookup through the unauthenticated GitHub API is rate-limited per address
# (60 requests an hour), and when it was refused the build downloaded an error page and failed with "not a zipfile".
ARG NUCLEI_VERSION=3.4.10
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then NUCLEI_ARCH="linux_amd64"; \
    elif [ "$ARCH" = "arm64" ]; then NUCLEI_ARCH="linux_arm64"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    base="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}" && \
    zip="nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip" && \
    curl -fsSL --retry 3 "${base}/${zip}" -o "/tmp/${zip}" && \
    curl -fsSL --retry 3 "${base}/nuclei_${NUCLEI_VERSION}_checksums.txt" -o /tmp/nuclei_checksums.txt && \
    (cd /tmp && grep " ${zip}\$" nuclei_checksums.txt | sha256sum -c -) && \
    unzip "/tmp/${zip}" -d /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm "/tmp/${zip}" /tmp/nuclei_checksums.txt

# Copy app + venv from builder
COPY --from=builder /app /app

# Copy Playwright browsers from builder
COPY --from=builder /root/.cache/ms-playwright /root/.cache/ms-playwright

# nuclei runs headless templates with -system-chrome (helpers/checks/nuclei/run_nuclei.py), which looks for
# `chromium` on PATH: point it at the Chromium above, so nothing is downloaded at run time (go-rod would otherwise
# fetch its own browser into /root/.cache/rod on first use).
RUN chrome="$(ls -d /root/.cache/ms-playwright/chromium-*/chrome-linux*/chrome | head -n 1)" && \
    test -x "${chrome}" && ln -s "${chrome}" /usr/local/bin/chromium && \
    test ! -e /root/.cache/rod

# tini as PID 1 reaps Nuclei/Chrome zombies that uv/celery will not.
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["uv", "run", "celery", "-A", "dast_worker", "worker", "-P", "threads", "--loglevel=info"]
