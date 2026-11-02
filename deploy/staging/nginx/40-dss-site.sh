#!/bin/sh
# Run by the nginx image entrypoint (/docker-entrypoint.d) before nginx starts. Writes the site configuration:
# TLS when both certificate files are mounted at /etc/nginx/certs, plain HTTP otherwise.
set -eu
certs=/etc/nginx/certs
if [ -s "$certs/fullchain.pem" ] && [ -s "$certs/privkey.pem" ]; then
  mode=https
else
  mode=http
fi
: "${FRONTEND_HOST:?FRONTEND_HOST is not set}"
: "${API_HOST:?API_HOST is not set}"
# Scan-node client certificates (mTLS) on the API host when their CA is mounted next to the server certificate.
DSS_NODE_MTLS=""
if [ "$mode" = https ] && [ -s "$certs/node-client-ca.pem" ]; then
  DSS_NODE_MTLS="ssl_client_certificate $certs/node-client-ca.pem; ssl_verify_client optional; ssl_verify_depth 2;"
fi
export DSS_NODE_MTLS
# shellcheck disable=SC2016 # the variable list is for envsubst, not the shell
envsubst '${FRONTEND_HOST} ${API_HOST} ${DSS_NODE_MTLS}' <"/etc/dss-nginx/${mode}.conf.template" \
  >/etc/nginx/conf.d/default.conf
echo "40-dss-site.sh: serving ${FRONTEND_HOST} and ${API_HOST} over ${mode}${DSS_NODE_MTLS:+ (scan-node client certificates checked)}"
