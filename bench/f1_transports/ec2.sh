#!/usr/bin/env bash
# F1.3 scale proof on one sandbox EC2 (Amazon Linux 2023, x86_64), driven over SSM by ec2_driver.py.
#
#   ec2.sh setup            docker, uv + Python 3.12, the scan-node venv (hash-locked), base images
#   ec2.sh build            the zs-collect binary + an UNSIGNED manifest (it is signed off the box), lab images
#   ec2.sh live N M         live.py with N targets (salt-ssh + AWX) and M salt-minions; report in $ROOT/out/live
#   ec2.sh host-release     install the signed release on this host (/opt/zeroshield/zs-collect) + zs-cbom + sudoers
#   ec2.sh direct NONCE     run the launcher on this host directly (the reference for the SSM proof)
#   ec2.sh summary          one JSON line per transport
#
# $ROOT (/opt/f13) holds the source tree shipped from the workstation (scan_node/, bench/f1_transports/) and release/.
# No secret is shipped: the release is signed on the workstation; the lab's keys and passwords are generated here.
set -euo pipefail
ROOT=${F13_ROOT:-/opt/f13}
export PATH=/usr/local/bin:/root/.local/bin:$PATH
PY=$ROOT/venv/bin/python
ECR=public.ecr.aws/docker/library
DEBIAN=$ECR/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
PYIMG=$ECR/python:3.12-slim-bullseye@sha256:411fa4dcfdce7e7a3057c45662beba9dcd4fa36b2e50a2bfcd6c9333e59bf0db
cmd=${1:?setup|build|live|host-release|direct|summary}; shift || true
cd "$ROOT"

case $cmd in
setup)
  dnf install -y -q docker tar gzip python3-pip openssl >/dev/null
  systemctl start docker
  python3 -m pip install -q uv
  uv python install 3.12 >/dev/null
  uv venv -q -p 3.12 "$ROOT/venv"
  uv pip install -q --python "$ROOT/venv" --require-hashes --no-deps -r scan_node/requirements.lock
  docker pull -q "$DEBIAN" >/dev/null && docker pull -q "$PYIMG" >/dev/null
  echo "setup ok: $($PY --version), $(docker --version | cut -d, -f1), $(nproc) vCPU, $(free -g | awk '/Mem/{print $2}') GB"
  ;;
build)
  mkdir -p "$ROOT/release"
  # build.sh signs only when SIGNING_KEY is set; it is not, here: the manifest is signed off the box
  git_commit=${F13_GIT_COMMIT:?}
  (cd scan_node && BASE_IMAGE=$PYIMG docker build -q --platform linux/amd64 -f zs_collect/Dockerfile.build \
      -t zs-collect-build:f13 --build-arg BASE_IMAGE=$PYIMG . >/dev/null)
  cid=$(docker create zs-collect-build:f13)
  docker cp "$cid:/build/dist/zs-collect" "$ROOT/release/zs-collect-1.0.0-linux-amd64" && docker rm -f "$cid" >/dev/null
  chmod 0755 "$ROOT/release/zs-collect-1.0.0-linux-amd64"
  $PY scan_node/zs_collect/release.py manifest --version 1.0.0 --git-commit "$git_commit" \
      --out "$ROOT/release/zs-collect-1.0.0.manifest.json" "$ROOT"/release/zs-collect-1.0.0-linux-amd64 >/dev/null
  $PY bench/f1_transports/parity.py --release-dir "$ROOT/release" --build-only --base-image "$DEBIAN" >/dev/null
  $PY bench/f1_transports/live.py --release-dir "$ROOT/release" --build-only >/dev/null
  echo "MANIFEST_B64 $(base64 -w0 "$ROOT/release/zs-collect-1.0.0.manifest.json")"
  docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -E 'f1-3|zs-collect' | tr '\n' ' '
  ;;
live)
  n=${1:-200}; m=${2:-20}
  rm -rf "$ROOT/out/live"
  $PY bench/f1_transports/live.py --release-dir "$ROOT/release" --targets "$n" --minions "$m" --awx-forks 50 \
      --ssh-max-procs 50 --out "$ROOT/out/live" > "$ROOT/out-live.log" 2>&1 || true
  tail -12 "$ROOT/out-live.log" | cut -c1-400
  ;;
host-release)
  install -d -m 0755 /opt/zeroshield/zs-collect
  install -m 0755 "$ROOT/release/zs-collect-1.0.0-linux-amd64" /opt/zeroshield/zs-collect/
  install -m 0644 "$ROOT/release/zs-collect-1.0.0.manifest.json" "$ROOT/release/zs-collect-1.0.0.manifest.json.sig" \
      /opt/zeroshield/zs-collect/
  id zs-cbom >/dev/null 2>&1 || useradd --system --shell /bin/bash --create-home zs-cbom
  $PY -c 'import sys; sys.path.insert(0, "scan_node"); from zs_scan_node import commands as C; print(C.sudoers_file("zs-cbom"), end="")' \
      > /etc/sudoers.d/zs-cbom
  chmod 0440 /etc/sudoers.d/zs-cbom && visudo -cf /etc/sudoers.d/zs-cbom >/dev/null
  $PY scan_node/zs_collect/release.py verify --public scan_node/zs_collect/zs-release-ed25519.pub \
      --files /opt/zeroshield/zs-collect /opt/zeroshield/zs-collect/zs-collect-1.0.0.manifest.json
  $PY scan_node/zs_collect/release.py wrapper --public scan_node/zs_collect/zs-release-ed25519.pub \
      --out "$ROOT/zs-collect-run.sh" /opt/zeroshield/zs-collect/zs-collect-1.0.0.manifest.json >/dev/null
  echo "host release ok; openssl $(openssl version | cut -d' ' -f2)"
  ;;
direct)
  nonce=${1:?nonce}
  sh "$ROOT/zs-collect-run.sh" --nonce "$nonce" --tier 2 --label "${2:-127.0.0.1}" --output chunks > "$ROOT/out-direct.txt"
  echo "DIRECT $(wc -c < "$ROOT/out-direct.txt") bytes"; cat "$ROOT/out-direct.txt"
  ;;
summary)
  $PY - "$ROOT/out/live/report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(json.dumps({"targets": r["targets"], "minions": r["minions"], "start_s": r.get("start_seconds"),
                  "failures": r.get("failures"), "sha256": r.get("zs_collect_sha256")}))
for name, v in r["results"].items():
    out = {k: v.get(k) for k in ("seconds", "summary", "hosts", "hosts_with_empty_diff", "assets", "emulator_stats")}
    bad = [row for row in v.get("rows") or [] if row["diff"]][:3]
    print(json.dumps({"transport": name, **out, "first_bad": bad}))
PY
  ;;
*) echo "unknown command $cmd" >&2; exit 2 ;;
esac
