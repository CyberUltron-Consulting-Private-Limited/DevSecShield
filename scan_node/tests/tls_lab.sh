#!/bin/sh
# TLS prober fidelity lab (CB-12): real TLS, non-TLS and PostgreSQL servers in Docker for tests/test_tls_fidelity_live.py.
# Every expected value the live test checks is written HERE, from the configuration given to each server (never from
# the product): tests read it from $ZS_TLS_LAB/expected.json.
#
#   .10 sni-only    nginx: handshakes without SNI are rejected (ssl_reject_handshake); vhost sni.cb12.lab
#   .11 full-suite  nginx: TLS 1.0-1.3, ALL:@SECLEVEL=0, every TLS 1.3 suite, 6 groups, RSA + ECDSA certificates
#   .12 closes      socat: accepts TCP and closes at once (not TLS)
#   .13 http        socat: answers every connection with an HTTP/1.1 400 (not TLS)
#   .14 alert-only  openssl s_server: TLS 1.2 only, PSK suites only, no PSK: every handshake ends in an alert
#   .15 pg-tls      postgres (15) with ssl=on, ssl_min_protocol_version=TLSv1.2 (accepts TLS 1.2 and 1.3)
#
# Usage: scan_node/tests/tls_lab.sh up|down|test [python]. Needs Docker and the CB-02 lab images (target: OpenSSL 3.5,
# nginx, socat; tools: nmap): `python3 e2e/cbom/lab/gen.py build` builds them as cb02-lab/target:dev and
# cb02-lab/tools:dev; override with ZS_TLS_LAB_IMAGE / ZS_TLS_LAB_TOOLS.
# Keys and passwords are generated at run time into the work directory and removed by `down`.
set -eu
CMD=${1:-test}
PY=${2:-python}
IMAGE=${ZS_TLS_LAB_IMAGE:-cb02-lab/target:dev}
TOOLS=${ZS_TLS_LAB_TOOLS:-cb02-lab/tools:dev}  # nmap ssl-enum-ciphers: the independent check of the full-suite server
PG_IMAGE=${ZS_TLS_LAB_PG_IMAGE:-postgres:15-alpine}
NET=cb12-tls-lab
SUBNET=${ZS_TLS_LAB_SUBNET:-10.232.12.0/24}
PREFIX=$(echo "$SUBNET" | sed 's#\.0/24$##')
WORK=${ZS_TLS_LAB:-${TMPDIR:-/tmp}/cb12-tls-lab}
NAMES="cb12-sni cb12-full cb12-close cb12-http cb12-alert cb12-pg"

down() {
  for n in $NAMES; do docker rm -f "$n" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}

cert() {  # cert <dir> <name> <key spec rsa:2048|ec:P-256> <CN> [SAN names...]
  dir=$1; name=$2; spec=$3; cn=$4; shift 4
  san=$(printf 'DNS:%s,' "$cn" "$@" | sed 's/,$//')
  case "$spec" in
    rsa:*) openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${spec#rsa:}" -out "$dir/$name.key" 2>/dev/null ;;
    ec:*) openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${spec#ec:}" -out "$dir/$name.key" 2>/dev/null ;;
  esac
  openssl req -x509 -new -key "$dir/$name.key" -subj "/CN=$cn" -addext "subjectAltName=$san" -days 30 \
    -sha256 -out "$dir/$name.crt" 2>/dev/null
  chmod 0644 "$dir/$name.key" "$dir/$name.crt"
}

nginx_head() {  # nginx_head <protocols>
  cat <<EOF
worker_processes 1;
pid /tmp/nginx.pid;
error_log stderr notice;
events { worker_connections 256; }
http {
  access_log off;
  client_body_temp_path /tmp/nb; proxy_temp_path /tmp/np; fastcgi_temp_path /tmp/nf;
  uwsgi_temp_path /tmp/nu; scgi_temp_path /tmp/ns;
  ssl_protocols $1;
EOF
}

up() {
  down
  mkdir -p "$WORK/sni" "$WORK/full" "$WORK/alert" "$WORK/pg"
  chmod 0755 "$WORK" "$WORK"/*
  docker network create --subnet "$SUBNET" "$NET" >/dev/null

  # .10 SNI-only
  cert "$WORK/sni" leaf rsa:2048 sni.cb12.lab
  { nginx_head "TLSv1.2 TLSv1.3"
    cat <<'EOF'
  ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
  ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384;
  ssl_ecdh_curve X25519:secp256r1;
  server { listen 443 ssl default_server; ssl_reject_handshake on; }
  server { listen 443 ssl; server_name sni.cb12.lab;
           ssl_certificate /lab/leaf.crt; ssl_certificate_key /lab/leaf.key; return 200 "sni\n"; }
}
EOF
  } > "$WORK/sni/nginx.conf"
  docker run -d --name cb12-sni --network "$NET" --ip "$PREFIX.10" --network-alias sni.cb12.lab \
    -v "$WORK/sni:/lab:ro" --entrypoint nginx "$IMAGE" -g 'daemon off;' -c /lab/nginx.conf >/dev/null

  # .11 full suite: TLS 1.0-1.3, every suite OpenSSL 3.5 has at @SECLEVEL=0, RSA and ECDSA certificates
  cert "$WORK/full" rsa rsa:2048 full.cb12.lab
  cert "$WORK/full" ec ec:P-256 full.cb12.lab
  { nginx_head "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
    cat <<'EOF'
  ssl_ciphers 'ALL:@SECLEVEL=0';
  ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256;
  ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1:secp384r1:secp521r1:X448;
  server { listen 443 ssl default_server; server_name _;
           ssl_certificate /lab/rsa.crt; ssl_certificate_key /lab/rsa.key;
           ssl_certificate /lab/ec.crt; ssl_certificate_key /lab/ec.key; return 200 "full\n"; }
}
EOF
  } > "$WORK/full/nginx.conf"
  docker run -d --name cb12-full --network "$NET" --ip "$PREFIX.11" -v "$WORK/full:/lab:ro" \
    --entrypoint nginx "$IMAGE" -g 'daemon off;' -c /lab/nginx.conf >/dev/null

  # .12 / .13 not TLS
  docker run -d --name cb12-close --network "$NET" --ip "$PREFIX.12" --entrypoint socat "$IMAGE" \
    TCP-LISTEN:443,fork,reuseaddr EXEC:/bin/true >/dev/null
  docker run -d --name cb12-http --network "$NET" --ip "$PREFIX.13" --entrypoint socat "$IMAGE" \
    TCP-LISTEN:443,fork,reuseaddr 'SYSTEM:printf "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"' >/dev/null

  # .14 TLS, but nothing a client can negotiate: PSK suites only and no PSK
  cert "$WORK/alert" leaf rsa:2048 alert.cb12.lab
  docker run -d --name cb12-alert --network "$NET" --ip "$PREFIX.14" -v "$WORK/alert:/lab:ro" --entrypoint openssl \
    "$IMAGE" s_server -accept 443 -cert /lab/leaf.crt -key /lab/leaf.key -tls1_2 -cipher 'PSK:@SECLEVEL=0' -quiet \
    >/dev/null

  # .15 PostgreSQL with TLS 1.2 and 1.3
  cert "$WORK/pg" server rsa:2048 pg.cb12.lab
  PGPASS=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
  printf '%s' "$PGPASS" > "$WORK/pg/superpass"
  chmod 0600 "$WORK/pg/superpass"
  docker run -d --name cb12-pg --network "$NET" --ip "$PREFIX.15" -e POSTGRES_PASSWORD="$PGPASS" \
    -v "$WORK/pg/server.crt:/lab/server.crt:ro" -v "$WORK/pg/server.key:/lab/server.key.src:ro" \
    --entrypoint sh "$PG_IMAGE" -c 'install -o postgres -m 0600 /lab/server.key.src /tmp/server.key &&
      exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/lab/server.crt -c ssl_key_file=/tmp/server.key \
        -c ssl_min_protocol_version=TLSv1.2' >/dev/null

  # the expected values, from the configuration above (the OpenSSL 3.5 expansion of the full-suite cipher string is
  # recorded too, so the expected suite list is the server's own library's answer, not the product's)
  FULL12=$(docker run --rm --entrypoint openssl "$IMAGE" ciphers -tls1_2 -stdname 'ALL:@SECLEVEL=0' \
    | awk '{print $1}' | grep -v '^TLS_AES\|^TLS_CHACHA' | sort | tr '\n' ' ')
  sleep 2
  docker run --rm --network "$NET" --entrypoint nmap "$TOOLS" -Pn -p 443 --script ssl-enum-ciphers -oX - \
    "$PREFIX.11" > "$WORK/nmap-full-suite.xml" 2>/dev/null || echo "nmap self-check unavailable ($TOOLS)"
  "${PY}" - "$WORK" "$PREFIX" "$FULL12" <<'EOF'
import json, sys
import xml.etree.ElementTree as ET
work, prefix, full12 = sys.argv[1], sys.argv[2], sys.argv[3].split()
nmap = {}
try:
    for script in ET.parse(f"{work}/nmap-full-suite.xml").getroot().iter("script"):
        for ver in script.findall("table"):
            names = [e.text for c in ver.findall("table[@key='ciphers']") for s in c.findall("table")
                     for e in s.findall("elem[@key='name']")]
            # nmap names TLS 1.3 suites TLS_AKE_WITH_<cipher>; the IANA name is TLS_<cipher>
            nmap[ver.get("key")] = sorted(n.replace("TLS_AKE_WITH_", "TLS_") for n in names)
except (OSError, ET.ParseError):
    pass
tls13_all = ["TLS_AES_128_CCM_8_SHA256", "TLS_AES_128_CCM_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
             "TLS_CHACHA20_POLY1305_SHA256"]
expected = {
    "sni-only": {"ip": f"{prefix}.10", "port": 443, "sni": "sni.cb12.lab", "versions": ["TLSv1.2", "TLSv1.3"],
                 "suites": {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
                            "TLSv1.3": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]},
                 "groups": ["secp256r1", "x25519"], "leaf_cn": "sni.cb12.lab"},
    "full-suite": {"ip": f"{prefix}.11", "port": 443, "versions": ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
                   "tls12_suites_openssl_all": sorted(full12), "tls13_suites": tls13_all,
                   "groups": ["X25519MLKEM768", "secp256r1", "secp384r1", "secp521r1", "x25519", "x448"],
                   "certificates": ["RSA", "EC"], "nmap_suites": nmap},
    "closes": {"ip": f"{prefix}.12", "port": 443, "tls": False},
    "http": {"ip": f"{prefix}.13", "port": 443, "tls": False},
    "alert-only": {"ip": f"{prefix}.14", "port": 443, "tls": True, "negotiable": False},
    "pg-tls": {"ip": f"{prefix}.15", "port": 5432, "versions": ["TLSv1.2", "TLSv1.3"]},
}
json.dump(expected, open(f"{work}/expected.json", "w"), indent=1, sort_keys=True)
EOF
  i=0
  until docker exec cb12-pg pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "postgres did not start"; exit 1; }; sleep 1
  done
  echo "lab up: $WORK/expected.json"
}

case "$CMD" in
  up) up ;;
  down) down ;;
  test)
    trap down EXIT
    up
    cd "$(dirname "$0")/.."
    ZS_TLS_LAB="$WORK" "$PY" -m pytest -q -p no:cacheprovider -rA tests/test_tls_fidelity_live.py ;;
  *) echo "usage: $0 up|down|test [python]"; exit 2 ;;
esac
