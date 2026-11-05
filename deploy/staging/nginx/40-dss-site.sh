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
# Behind a TLS-terminating load balancer: DSS_REAL_IP_FROM lists its addresses or networks (space or comma
# separated). nginx then takes the client address from the X-Forwarded-For header, trusting only those senders.
# Empty: off. 0.0.0.0/0 or ::/0 would let any client choose its own address, so a /0 is refused.
DSS_REAL_IP=""
real_ip_sources=""
nl='
'
set -f # no globbing of the list
for source in $(printf '%s' "${DSS_REAL_IP_FROM:-}" | tr ',' ' '); do
  case "$source" in
  */0 | *[!0-9A-Fa-f:./]*)
    echo "40-dss-site.sh: DSS_REAL_IP_FROM entry '$source' is not a specific IP address or network" >&2
    exit 1
    ;;
  esac
  DSS_REAL_IP="${DSS_REAL_IP}set_real_ip_from ${source};${nl}"
  real_ip_sources="${real_ip_sources:+$real_ip_sources }${source}"
done
set +f
if [ -n "$DSS_REAL_IP" ]; then
  DSS_REAL_IP="${DSS_REAL_IP}real_ip_header X-Forwarded-For;${nl}real_ip_recursive on;"
fi
export DSS_REAL_IP
# shellcheck disable=SC2016 # the variable list is for envsubst, not the shell
envsubst '${FRONTEND_HOST} ${API_HOST} ${DSS_NODE_MTLS} ${DSS_REAL_IP}' <"/etc/dss-nginx/${mode}.conf.template" \
  >/etc/nginx/conf.d/default.conf
echo "40-dss-site.sh: serving ${FRONTEND_HOST} and ${API_HOST} over ${mode}${DSS_NODE_MTLS:+ (scan-node client certificates checked)}${real_ip_sources:+ (client address from X-Forwarded-For set by ${real_ip_sources})}"
