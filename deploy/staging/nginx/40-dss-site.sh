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
# shellcheck disable=SC2016 # the variable list is for envsubst, not the shell
envsubst '${FRONTEND_HOST} ${API_HOST}' <"/etc/dss-nginx/${mode}.conf.template" >/etc/nginx/conf.d/default.conf
echo "40-dss-site.sh: serving ${FRONTEND_HOST} and ${API_HOST} over ${mode}"
