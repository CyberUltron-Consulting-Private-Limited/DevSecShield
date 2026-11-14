# ZeroShield CBOM scan node.
#   docker build -t zeroshield/cbom-scan-node:1.0.0 scan_node/
#   scripts/release/scan_node_image.sh build 1.0.0    (also writes the docker-save archive customers load offline)
# Behind a TLS-intercepting proxy, build from a base image that already trusts the proxy CA:
#   docker build --network host --build-arg BASE_IMAGE=<base with CA> --build-arg HTTPS_PROXY=... scan_node/
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ZS_STATE_DIR=/var/lib/zs-node

# openssl (s_client) does the full TLS handshakes; python:3.12-slim already ships OpenSSL 3.5 (ML-KEM groups).
RUN command -v openssl >/dev/null || { apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*; }

WORKDIR /opt/zs-scan-node
# requirements.lock pins every package, transitive ones included, with sha256 hashes; pip refuses anything else.
# It must match requirements.txt: after editing requirements.txt run scripts/release/scan_node_image.sh lock.
COPY requirements.txt requirements.lock ./
RUN python - <<'PY'
import re, sys

def pins(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        m = re.match(r"([A-Za-z0-9_.-]+)(\[[^\]]*\])?==([^\s;\\]+)", line.strip())
        if m:
            out[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = m.group(3)
    return out

want, have = pins("requirements.txt"), pins("requirements.lock")
stale = sorted(f"{name}=={version}" for name, version in want.items() if have.get(name) != version)
if stale:
    sys.exit("requirements.lock does not match requirements.txt for " + ", ".join(stale)
             + ": run scripts/release/scan_node_image.sh lock")
print(f"requirements.lock covers requirements.txt ({len(have)} pinned packages)")
PY
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock && pip check

COPY zs_scan_node ./zs_scan_node

# Build identity (CB-03): the commit this image was built from and its release version. The node reports
# <version>+<12-character commit> to ZeroShield (enrolment, heartbeat, results, User-Agent).
# scripts/release/scan_node_image.sh passes both. Declared after the code layer, so a new commit with the same code
# reuses every layer above.
ARG ZS_NODE_BUILD=""
ARG ZS_NODE_VERSION=""
ENV ZS_NODE_BUILD=${ZS_NODE_BUILD} \
    ZS_NODE_VERSION=${ZS_NODE_VERSION}

RUN useradd --system --uid 10001 --home-dir /var/lib/zs-node --shell /usr/sbin/nologin zsnode \
 && mkdir -p /var/lib/zs-node && chown zsnode:zsnode /var/lib/zs-node && chmod 0700 /var/lib/zs-node
USER 10001
VOLUME ["/var/lib/zs-node"]

# Healthy = the agent's heartbeat loop is turning: it touches $ZS_STATE_DIR/alive on every pass (at most 60 s apart),
# so a stuck agent turns unhealthy although its process still exists. A node that is not yet enrolled is unhealthy.
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s \
  CMD python -c "import os,sys,time; p=os.path.join(os.environ.get('ZS_STATE_DIR','/var/lib/zs-node'),'alive'); sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p)<180 else 1)"

ENTRYPOINT ["python", "-m", "zs_scan_node"]
