# ============================================================
# Stage 1: Builder — install dependencies and compile bytecode
# ============================================================
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
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
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV IS_DOCKER_CONTAINER="True" \
    PYTHONPATH="/backend/.." \
    PYTHONUNBUFFERED=1

WORKDIR /backend

# Copy the entire app + venv from builder
COPY --from=builder /backend /backend

EXPOSE 8080

CMD ["uv", "run", "gunicorn", "main:app", "-k", "uvicorn.workers.UvicornWorker", "--workers", "9", "--bind", "0.0.0.0:8080", "--timeout", "120", "--graceful-timeout", "30", "--keep-alive", "5"]