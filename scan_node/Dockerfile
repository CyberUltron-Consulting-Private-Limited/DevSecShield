# ZeroShield CBOM scan node.
#   docker build -t registry.zeroshield.ai/cbom/scan-node:1.0 scan_node/
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
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY zs_scan_node ./zs_scan_node

RUN useradd --system --uid 10001 --home-dir /var/lib/zs-node --shell /usr/sbin/nologin zsnode \
 && mkdir -p /var/lib/zs-node && chown zsnode:zsnode /var/lib/zs-node && chmod 0700 /var/lib/zs-node
USER 10001
VOLUME ["/var/lib/zs-node"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD python -c "import os,sys; sys.exit(0 if os.path.exists('/var/lib/zs-node/state.json') else 1)"

ENTRYPOINT ["python", "-m", "zs_scan_node"]
