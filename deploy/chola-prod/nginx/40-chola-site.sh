#!/bin/sh
# Run by the nginx image entrypoint (/docker-entrypoint.d) before nginx starts: writes /etc/nginx/conf.d/default.conf
# from site.conf.template for the Chola production site (deploy/chola-prod/README.md).
#
# TLS ends at the ALB, which forwards plain HTTP to port 80. DSS_REAL_IP_FROM (required) lists the ALB subnets, space or
# comma separated: nginx then believes X-Forwarded-For (client address, right-most untrusted entry) and
# X-Forwarded-Proto only from those senders. A /0, a host name or anything that is not an address is refused, so nginx
# does not start rather than trusting every client.
set -eu
: "${FRONTEND_HOST:?FRONTEND_HOST is not set}"
: "${API_HOST:?API_HOST is not set}"
: "${DSS_REAL_IP_FROM:?DSS_REAL_IP_FROM is not set (the ALB subnets)}"

nl='
'
DSS_REAL_IP=""
DSS_ALB_GEO=""
sources=""
set -f # no globbing of the list
refuse() {
  echo "40-chola-site.sh: DSS_REAL_IP_FROM entry '$1' $2" >&2
  exit 1
}
for source in $(printf '%s' "${DSS_REAL_IP_FROM}" | tr ',' ' '); do
  case "${source}" in
  *[!0-9A-Fa-f:./]* | "" | */*/*) refuse "${source}" "is not an IP address or network" ;;
  esac
  addr=${source%%/*}
  case "${addr}" in
  *:*) family=6 min=16 max=128 ;;
  *.*.*.*) family=4 min=8 max=32 ;;
  *) refuse "${source}" "is not an IP address or network" ;;
  esac
  # the unspecified address in any spelling (0.0.0.0, 0.00.0.0, ::, 0::0) is "every client"
  case "$(printf '%s' "${addr}" | tr -d '0.:')" in
  "") refuse "${source}" "is the unspecified address" ;;
  esac
  if [ "${family}" = 4 ]; then
    printf '%s' "${addr}" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || refuse "${source}" "is not an IPv4 address"
  fi
  case "${source}" in
  */*)
    prefix=${source#*/}
    case "${prefix}" in "" | *[!0-9]*) refuse "${source}" "has no numeric prefix length" ;; esac
    # 0, 00, 7 ...: anything shorter than /8 (IPv4) or /16 (IPv6) trusts most of the Internet
    prefix=$(printf '%s' "${prefix}" | sed 's/^0*//')
    prefix=${prefix:-0}
    { [ "${#prefix}" -le 3 ] && [ "${prefix}" -ge "${min}" ] && [ "${prefix}" -le "${max}" ]; } ||
      refuse "${source}" "has a prefix length outside /${min}../${max} (IPv${family})"
    ;;
  esac
  DSS_REAL_IP="${DSS_REAL_IP}set_real_ip_from ${source};${nl}"
  DSS_ALB_GEO="${DSS_ALB_GEO}    ${source} 1;${nl}"
  sources="${sources:+${sources} }${source}"
done
set +f
[ -n "${sources}" ] || { echo "40-chola-site.sh: DSS_REAL_IP_FROM lists no address" >&2; exit 1; }
DSS_REAL_IP="${DSS_REAL_IP}real_ip_header X-Forwarded-For;${nl}real_ip_recursive on;"
export DSS_REAL_IP DSS_ALB_GEO
# shellcheck disable=SC2016 # the variable list is for envsubst, not the shell
envsubst '${FRONTEND_HOST} ${API_HOST} ${DSS_REAL_IP} ${DSS_ALB_GEO}' </etc/dss-nginx/site.conf.template \
  >/etc/nginx/conf.d/default.conf
echo "40-chola-site.sh: serving ${FRONTEND_HOST} and ${API_HOST} over HTTP behind the ALB (client address and scheme from X-Forwarded-* set by ${sources})"
