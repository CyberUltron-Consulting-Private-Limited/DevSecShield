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
#   .16 mysql-hardened  mysql (8.4), max_connect_errors=10, host cache on (the package default; the image's own
#                   my.cnf turns it off, which would hide the blocking): 10 unfinished connections block a client
#   .17 sni-close   nginx stream ssl_preread (Envoy/Istio style): sni.cb12.lab is passed to .10; a hello without
#                   it (or with another name) is closed without a byte, no alert
#   .18 tarpit      socat: accepts TCP and never answers
#   .19 mysql-default   mysql (8.4), stock max_connect_errors (100), host cache on
#
# Scale bench (`bench-up` after `up`; scan_node/scripts/bench_tls_scale.py): .100-.117 "typical" nginx (TLS 1.2 + 1.3,
# Mozilla intermediate suites) and .118-.124 "permissive" nginx (the full-suite configuration), each on ports 443,
# 8443, 9443 and 10443: 100 TLS endpoints on the lab /24, the other addresses silent.  `bench-down` removes them.
#
# Usage: scan_node/tests/tls_lab.sh up|down|test|bench-up|bench-down [python]. Needs Docker and the CB-02 lab images (target: OpenSSL 3.5,
# nginx, socat; tools: nmap): `python3 e2e/cbom/lab/gen.py build` builds them as cb02-lab/target:dev and
# cb02-lab/tools:dev; override with ZS_TLS_LAB_IMAGE / ZS_TLS_LAB_TOOLS.
# Keys and passwords are generated at run time into the work directory and removed by `down`.
set -eu
CMD=${1:-test}
PY=${2:-python}
IMAGE=${ZS_TLS_LAB_IMAGE:-cb02-lab/target:dev}
TOOLS=${ZS_TLS_LAB_TOOLS:-cb02-lab/tools:dev}  # nmap ssl-enum-ciphers: the independent check of the full-suite server
NGINX_IMAGE=${ZS_TLS_LAB_NGINX_IMAGE:-nginx:1.27-alpine}  # stream + ssl_preread built in
MYSQL_IMAGE=${ZS_TLS_LAB_MYSQL_IMAGE:-mysql:8.4}
PG_IMAGE=${ZS_TLS_LAB_PG_IMAGE:-postgres:15-alpine}
NET=cb12-tls-lab
SUBNET=${ZS_TLS_LAB_SUBNET:-10.232.12.0/24}
PREFIX=$(echo "$SUBNET" | sed 's#\.0/24$##')
WORK=${ZS_TLS_LAB:-${TMPDIR:-/tmp}/cb12-tls-lab}
NAMES="cb12-sni cb12-full cb12-close cb12-http cb12-alert cb12-pg cb12-mysql cb12-sniclose cb12-tarpit cb12-mysqldef"

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
  mkdir -p "$WORK/sni" "$WORK/full" "$WORK/alert" "$WORK/pg" "$WORK/mysql" "$WORK/sniclose"
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

  # .16 / .19 MySQL 8.4 with the host cache on; a read-only scan user that must use TLS
  MYPASS=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
  SCANPASS=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
  printf '%s' "$MYPASS" > "$WORK/mysql/rootpass"
  printf '%s' "$SCANPASS" > "$WORK/mysql/scanpass"
  chmod 0600 "$WORK/mysql/rootpass" "$WORK/mysql/scanpass"
  printf '[mysqld]\ndatadir=/var/lib/mysql\nsocket=/var/run/mysqld/mysqld.sock\nsecure-file-priv=/var/lib/mysql-files\nuser=mysql\npid-file=/var/run/mysqld/mysqld.pid\n[client]\nsocket=/var/run/mysqld/mysqld.sock\n' \
    > "$WORK/mysql/my.cnf"
  printf "CREATE USER 'scan'@'%%' IDENTIFIED BY '%s' REQUIRE SSL;\nGRANT SELECT ON *.* TO 'scan'@'%%';\n" "$SCANPASS" \
    > "$WORK/mysql/init.sql"
  chmod 0644 "$WORK/mysql/my.cnf" "$WORK/mysql/init.sql"
  docker run -d --name cb12-mysql --network "$NET" --ip "$PREFIX.16" -e MYSQL_ROOT_PASSWORD="$MYPASS" \
    -v "$WORK/mysql/my.cnf:/etc/my.cnf:ro" -v "$WORK/mysql/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" \
    "$MYSQL_IMAGE" --max-connect-errors=10 >/dev/null
  docker run -d --name cb12-mysqldef --network "$NET" --ip "$PREFIX.19" -e MYSQL_ROOT_PASSWORD="$MYPASS" \
    -v "$WORK/mysql/my.cnf:/etc/my.cnf:ro" -v "$WORK/mysql/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" \
    "$MYSQL_IMAGE" >/dev/null
  # mysql_sql.sh <container> <sql>: root SQL inside a lab container (the tests read the server's own counters)
  printf '#!/bin/sh\nexec docker exec -e MYSQL_PWD="$(cat %s/mysql/rootpass)" "$1" mysql -uroot -N -B -e "$2"\n' "$WORK" \
    > "$WORK/mysql_sql.sh"
  chmod 0700 "$WORK/mysql_sql.sh"

  # .17 SNI-only, closes without an alert (no default filter chain): nginx stream + ssl_preread
  printf 'worker_processes 1;\npid /tmp/nginx.pid;\nerror_log stderr notice;\nevents { worker_connections 256; }\nstream {\n  map $ssl_preread_server_name $up { sni.cb12.lab %s.10:443; default 127.0.0.1:9; }\n  server { listen 443; ssl_preread on; proxy_pass $up; proxy_connect_timeout 2s; }\n}\n' "$PREFIX" \
    > "$WORK/sniclose/nginx.conf"
  docker run -d --name cb12-sniclose --network "$NET" --ip "$PREFIX.17" -v "$WORK/sniclose:/lab:ro" \
    --entrypoint nginx "$NGINX_IMAGE" -g 'daemon off;' -c /lab/nginx.conf >/dev/null

  # .18 tarpit: TCP accepted, never a byte back
  docker run -d --name cb12-tarpit --network "$NET" --ip "$PREFIX.18" --entrypoint socat "$IMAGE" \
    TCP-LISTEN:443,fork,reuseaddr SYSTEM:'sleep 600' >/dev/null

  # the expected values, from the configuration above (the OpenSSL 3.5 expansion of the full-suite cipher string is
  # recorded too, so the expected suite list is the server's own library's answer, not the product's)
  FULL12=$(docker run --rm --entrypoint openssl "$IMAGE" ciphers -tls1_2 -stdname 'ALL:@SECLEVEL=0' \
    | awk '{print $1}' | grep -v '^TLS_AES\|^TLS_CHACHA' | sort | tr '\n' ' ')
  sleep 2
  if command -v nmap >/dev/null 2>&1; then  # the host's nmap reaches the lab bridge as well
    nmap -Pn -p 443 --script ssl-enum-ciphers -oX - "$PREFIX.11" > "$WORK/nmap-full-suite.xml" 2>/dev/null
  else
    docker run --rm --network "$NET" --entrypoint nmap "$TOOLS" -Pn -p 443 --script ssl-enum-ciphers -oX - \
      "$PREFIX.11" > "$WORK/nmap-full-suite.xml" 2>/dev/null || echo "nmap self-check unavailable ($TOOLS)"
  fi
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
    # MySQL 8.4 accepts TLS 1.2 and 1.3 by default (tls_version); the scan user must use TLS
    "mysql-hardened": {"ip": f"{prefix}.16", "port": 3306, "container": "cb12-mysql", "max_connect_errors": 10,
                       "versions": ["TLSv1.2", "TLSv1.3"], "login": "scan", "ca": "mysql/ca.pem"},
    "mysql-default": {"ip": f"{prefix}.19", "port": 3306, "container": "cb12-mysqldef", "max_connect_errors": 100,
                      "versions": ["TLSv1.2", "TLSv1.3"], "login": "scan", "ca": "mysql/ca-default.pem"},
    "sni-close": {"ip": f"{prefix}.17", "port": 443, "sni": "sni.cb12.lab", "versions": ["TLSv1.2", "TLSv1.3"],
                  "suites": {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
                             "TLSv1.3": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]}},
    "tarpit": {"ip": f"{prefix}.18", "port": 443},
}
json.dump(expected, open(f"{work}/expected.json", "w"), indent=1, sort_keys=True)
EOF
  i=0
  until docker exec cb12-pg pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "postgres did not start"; exit 1; }; sleep 1
  done
  for name in cb12-mysql cb12-mysqldef; do
    i=0
    until docker logs "$name" 2>&1 | grep -q "ready for connections. Version: .* port: 3306" && \
          "$WORK/mysql_sql.sh" "$name" "select 1" >/dev/null 2>&1; do
      i=$((i + 1)); [ "$i" -lt 120 ] || { echo "$name did not start"; exit 1; }; sleep 2
    done
  done
  docker exec cb12-mysql cat /var/lib/mysql/ca.pem > "$WORK/mysql/ca.pem"
  docker exec cb12-mysqldef cat /var/lib/mysql/ca.pem > "$WORK/mysql/ca-default.pem"
  # self-check of the lab, not the product: 10 unfinished connections block a client at max_connect_errors=10
  docker run --rm --network "$NET" --ip "$PREFIX.30" --entrypoint sh "$IMAGE" -c \
    "for i in 1 2 3 4 5 6 7 8 9 10; do socat -u OPEN:/dev/null TCP:$PREFIX.16:3306 2>/dev/null; done" || true
  sleep 1
  "$WORK/mysql_sql.sh" cb12-mysql "select IP, SUM_CONNECT_ERRORS from performance_schema.host_cache" \
    > "$WORK/mysql/self-check.txt"
  "$WORK/mysql_sql.sh" cb12-mysql "truncate table performance_schema.host_cache"
  echo "lab up: $WORK/expected.json"
}

bench_down() {
  for i in $(seq 100 124); do docker rm -f "cb12-bench-$i" >/dev/null 2>&1 || true; done
}

bench_up() {
  bench_down
  mkdir -p "$WORK/bench"
  cp "$WORK/full/rsa.crt" "$WORK/full/rsa.key" "$WORK/bench/"
  for kind in typical full; do
    { nginx_head "TLSv1.2 TLSv1.3"
      if [ "$kind" = typical ]; then
        echo "  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305';"
        echo "  ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1:secp384r1;"
      else
        echo "  ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;"
        echo "  ssl_ciphers 'ALL:@SECLEVEL=0';"
        echo "  ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256;"
        echo "  ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1:secp384r1:secp521r1:X448;"
      fi
      echo "  server { listen 443 ssl; listen 8443 ssl; listen 9443 ssl; listen 10443 ssl; server_name _;"
      echo "           ssl_certificate /lab/rsa.crt; ssl_certificate_key /lab/rsa.key; return 200 \"$kind\\n\"; }"
      echo "}"
    } > "$WORK/bench/$kind.conf"
  done
  # the permissive file names ssl_protocols twice (nginx_head and the line above): keep the last one only
  awk '/ssl_protocols/ {n++; if (n == 1) next} {print}' "$WORK/bench/full.conf" > "$WORK/bench/full.conf.tmp"
  mv "$WORK/bench/full.conf.tmp" "$WORK/bench/full.conf"
  chmod 0644 "$WORK/bench/"*
  for i in $(seq 100 124); do
    kind=typical; [ "$i" -ge 118 ] && kind=full
    docker run -d --name "cb12-bench-$i" --network "$NET" --ip "$PREFIX.$i" -v "$WORK/bench:/lab:ro" \
      --entrypoint nginx "$IMAGE" -g 'daemon off;' -c "/lab/$kind.conf" >/dev/null
  done
  echo "bench up: 18 typical + 7 permissive hosts x 4 ports on $PREFIX.100-124"
}

case "$CMD" in
  up) up ;;
  bench-up) bench_up ;;
  bench-down) bench_down ;;
  down) bench_down; down ;;
  test)
    trap down EXIT
    up
    cd "$(dirname "$0")/.."
    ZS_TLS_LAB="$WORK" "$PY" -m pytest -q -p no:cacheprovider -rA tests/test_tls_fidelity_live.py ;;
  *) echo "usage: $0 up|down|test|bench-up|bench-down [python]"; exit 2 ;;
esac
