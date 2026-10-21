# E2E-only image: the product's REAL CBOM scanner, installed the way the scan worker has it (the
# `aibom` package as an EDITABLE install from source, with its dependencies pinned to aibom/uv.lock),
# run in a throw-away container.
#
# What runs here   aibom.integrations.cbom_devsecshield.scan_crypto_to_devsecshield(path, level=4),
#                  the function RabbitMQ/worker/scan_worker.py calls for a `cbom` scan.
# What does NOT    LLM calls, boto3, or any network access. The scan is deterministic pure Python,
#                  and docker-compose.e2e.yml runs this container with `network_mode: none` so a
#                  network attempt would fail loudly instead of passing silently.
#
# Why editable and not `pip install /src/aibom`: the worker consumes aibom as
# `clinithread-aibom = { path = "../../aibom", editable = true }` and keeps the source tree in its
# image, and building a wheel of this package currently fails with hatchling >= 1.2x ("A second file
# is being added to the wheel archive at the same path: aibom/dashboard/index.html", because
# pyproject.toml lists src/aibom in `packages` AND force-includes src/aibom/{schemas,dashboard}).
# aibom/ is not ours to change, so this image mirrors what production actually does.
#
# Build (scripts/build.sh runs this; the context is aibom/, filtered by the sibling
# aibom-scan.Dockerfile.dockerignore allowlist):
#   docker buildx build --builder dss-fast --platform linux/amd64 --provenance=false --sbom=false \
#     --load -t dss-e2e/aibom-scan:local -f e2e/docker/aibom-scan.Dockerfile aibom

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt
COPY . /opt/aibom

# Dependency pins = `uv export --frozen --no-dev --no-emit-project --no-hashes` of aibom/uv.lock, so
# the container resolves the same versions as the worker and the host aibom/.venv (the seed step
# compares a container scan against a host scan byte for byte). scripts/build.sh warns when this
# list drifts from the lock; regenerate it from the lock when that happens.
COPY <<'PINS' /tmp/constraints.txt
annotated-doc==0.0.4
annotated-types==0.7.0
attrs==26.1.0
colorama==0.4.6 ; sys_platform == 'win32'
jsonschema==4.26.0
jsonschema-specifications==2025.9.1
markdown-it-py==4.2.0
mdurl==0.1.2
pydantic==2.13.4
pydantic-core==2.46.4
pygments==2.20.0
pyyaml==6.0.3
referencing==0.37.0
rich==15.0.0
rpds-py==2026.5.1
shellingham==1.5.4
typer==0.26.7
typing-extensions==4.15.0
typing-inspection==0.4.2
PINS

# Byte-compile the sources now: the runtime container has a read-only root filesystem and
# PYTHONDONTWRITEBYTECODE=1, so nothing could be cached at run time.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install -c /tmp/constraints.txt -e /opt/aibom \
 && /opt/venv/bin/python -m compileall -q /opt/aibom/src \
 && /opt/venv/bin/python -c "import aibom, aibom.integrations.cbom_devsecshield"

FROM python:3.12-slim

LABEL com.dss-e2e="1" \
      org.opencontainers.image.title="dss-e2e aibom-scan" \
      org.opencontainers.image.description="Real aibom CBOM scanner for the dss-e2e proof harness (offline, deterministic, no LLM)"

RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin e2e

# The editable install's .pth file points at /opt/aibom/src, so both trees keep these exact paths.
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/aibom /opt/aibom

# HOME and PYTHONDONTWRITEBYTECODE keep the container usable with a read-only root filesystem and an
# arbitrary --user (docker-compose.e2e.yml runs it as the host uid:gid so files written to the
# bind-mounted .work/out are owned by the invoking user).
ENV PATH="/opt/venv/bin:${PATH}" \
    HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /work
USER 10001:10001
CMD ["python", "-c", "import aibom; print('aibom-scan image ready')"]
