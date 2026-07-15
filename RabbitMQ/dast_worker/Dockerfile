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
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV IS_DOCKER_CONTAINER="True" \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON=3.12 \
    UV_PYTHON_PREFERENCE=only-system

WORKDIR /app

# Install nuclei directly from GitHub releases (no Homebrew needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip git \
    # Chromium/Playwright runtime dependencies
    libglib2.0-0 libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libgbm1 libasound2 \
    libpango-1.0-0 libcairo2 libx11-6 libxcomposite1 libxdamage1 \
    libxext6 libxfixes3 libxrandr2 fonts-liberation libx11-xcb1 \
    libxcursor1 libgtk-3-0 libpangocairo-1.0-0 libcairo-gobject2 \
    libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei binary directly (skip Homebrew entirely — saves ~500MB)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then NUCLEI_ARCH="linux_amd64"; \
    elif [ "$ARCH" = "arm64" ]; then NUCLEI_ARCH="linux_arm64"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/') && \
    curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip" -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Copy app + venv from builder
COPY --from=builder /app /app

# Copy Playwright browsers from builder
COPY --from=builder /root/.cache/ms-playwright /root/.cache/ms-playwright

CMD ["uv", "run", "celery", "-A", "dast_worker", "worker", "-P", "threads", "--loglevel=info"]