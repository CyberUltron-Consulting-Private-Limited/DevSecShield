"""The scan node from the public registry on staging (deploy/staging/README.md, "Public registry"): `staging.sh deploy`
points the Add scan node wizard at GHCR (CBOM_NODE_IMAGE_REF = devsecshield-scan-node:<version>, the release, never a
moving tag; CBOM_NODE_CHART_REF = oci://.../charts/cbom-scan-node:<version> only once the chart can be pulled without a
login) while CBOM_NODE_REGISTRY_PUBLIC=1 (the default of a push deploy: the image package is public). 0 clears both;
never given, the host's own values are left alone; a rollback follows the switch kept in .env.
Run against the real staging.sh on a stubbed host (test_deploy_staging_script.Host)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from test_deploy_staging_script import BASH, ROOT, Host, failed, ok

pytestmark = pytest.mark.skipif(BASH is None or shutil.which("sha256sum") is None, reason="needs bash and sha256sum")

A, B = "0123456789ab", "abcdef012345"
GHCR = "ghcr.io/cyberultron-consulting-private-limited"


def env_values(host: Host) -> dict[str, str]:
    out = {}
    for line in (host.root / "deploy/staging/.env").read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def with_manifest(host: Host, tag: str, version: str = "1.0.0", under: str = "deploy/staging/node-artifacts") -> Path:
    d = host.root / under / tag if tag else host.root / under
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_text(json.dumps({"files": {}, "image_ref": f"localhost/zeroshield/cbom-scan-node:{version}",
                                                 "version": version}, indent=2, sort_keys=True) + "\n")
    chart = d / f"cbom-scan-node-{version}.tgz"  # the downloaded chart (node_artifacts.py)
    chart.write_bytes(f"chart {version} of {tag}".encode())
    return chart


# curl on the host: GHCR's anonymous token API and manifests, the rest to the harness's own stub (health checks).
# Images are public unless $FAKE_IMAGE_PUBLIC=0, charts unless $FAKE_CHART_PUBLIC=0. A chart's manifest names, as its
# chart content layer, the sha256 of the downloaded chart of that version ($FAKE_CHART_SHA instead, when set): what
# GHCR serves when the GHCR chart is the downloaded file (#361).
GHCR_CURL = r'''#!/usr/bin/env bash
out=""; prev=""
for a in "$@"; do [ "$prev" = -o ] && out=$a; prev=$a; done
for a in "$@"; do case "$a" in
  https://ghcr.io/token*) echo "$a" >> "$(dirname "$0")/ghcr.log"; printf '{"token":"anonTESTONLY"}'; exit 0;;
  https://ghcr.io/v2/*/charts/*/manifests/*) echo "$a $*" >> "$(dirname "$0")/ghcr.log"
    [ "${FAKE_CHART_PUBLIC:-1}" = 1 ] || { echo "curl: (22) 401" >&2; exit 22; }
    version=${a##*/}
    sha=${FAKE_CHART_SHA:-}
    if [ -z "$sha" ]; then
      f=$(ls "$(dirname "$0")"/../deploy/staging/node-artifacts/*/cbom-scan-node-"$version".tgz \
             "$(dirname "$0")"/../deploy/staging/images/node-artifacts/cbom-scan-node-"$version".tgz 2>/dev/null | head -n 1)
      [ -n "$f" ] && sha=$(sha256sum "$f" | cut -d' ' -f1)
    fi
    body='{"schemaVersion":2,"config":{"mediaType":"application/vnd.cncf.helm.config.v1+json","digest":"sha256:'$(printf 'c%.0s' $(seq 64))'","size":1},"layers":[{"mediaType":"application/vnd.cncf.helm.chart.content.v1.tar+gzip","digest":"sha256:'${sha:-none}'","size":9}]}'
    if [ -n "$out" ] && [ "$out" != /dev/null ]; then printf '%s' "$body" > "$out"; fi
    exit 0;;
  https://ghcr.io/v2/*/manifests/*) echo "$a $*" >> "$(dirname "$0")/ghcr.log"
    [ "${FAKE_IMAGE_PUBLIC:-1}" = 1 ] || { echo "curl: (22) 401" >&2; exit 22; }
    if [ -n "$out" ] && [ "$out" != /dev/null ]; then printf '{}' > "$out"; fi
    exit 0;;
esac; done
exec "$(dirname "$0")/curl.harness" "$@"
'''


@pytest.fixture
def host(tmp_path):
    h = Host(tmp_path, {A: ["r1"], B: ["r1"], "custom-tag": ["r1"]})
    (h.root / "bin/curl").rename(h.root / "bin/curl.harness")
    (h.root / "bin/curl").write_text(GHCR_CURL)
    (h.root / "bin/curl").chmod(0o755)
    with_manifest(h, A)
    with_manifest(h, B, "1.1.0")
    return h


def test_public_sets_the_ghcr_image_of_the_deployed_commit_and_its_chart(host):
    proc = ok(host.ship(A, env={"CBOM_NODE_REGISTRY_PUBLIC": "1"}))
    v = env_values(host)
    assert v["CBOM_NODE_IMAGE_REF"] == f"{GHCR}/devsecshield-scan-node:1.0.0"  # the release, never a moving tag
    assert v["CBOM_NODE_CHART_REF"] == f"oci://{GHCR}/charts/cbom-scan-node:1.0.0"
    assert v["CBOM_NODE_REGISTRY_PUBLIC"] == "1"
    assert f"scan node registry refs: {GHCR}/devsecshield-scan-node:1.0.0" in proc.stdout
    # the backend reads exactly these (compose interpolates them from .env)
    compose = (ROOT / "deploy/staging/docker-compose.yml").read_text()
    backend = compose.split("\n  backend:\n", 1)[1].split("\n  cbom-cloud-worker:", 1)[0]
    assert "CBOM_NODE_IMAGE_REF: ${CBOM_NODE_IMAGE_REF:-}" in backend and "CBOM_NODE_CHART_REF: ${CBOM_NODE_CHART_REF:-}" in backend


def test_a_chart_nobody_can_pull_yet_is_not_offered_but_the_image_is(host):
    proc = ok(host.ship(A, env={"CBOM_NODE_REGISTRY_PUBLIC": "1", "FAKE_CHART_PUBLIC": "0"}))
    v = env_values(host)
    assert v["CBOM_NODE_IMAGE_REF"] == f"{GHCR}/devsecshield-scan-node:1.0.0" and v["CBOM_NODE_CHART_REF"] == ""
    assert "cannot be pulled without a login" in proc.stdout
    log = (host.root / "bin/ghcr.log").read_text()
    assert f"https://ghcr.io/token?scope=repository:{GHCR.split('/', 1)[1]}/charts/cbom-scan-node:pull" in log
    assert f"https://ghcr.io/v2/{GHCR.split('/', 1)[1]}/charts/cbom-scan-node/manifests/1.0.0" in log
    assert "Bearer anonTESTONLY" in log  # the anonymous token, no credential of ours
    assert "anonTESTONLY" not in proc.stdout + proc.stderr


def test_an_image_not_released_yet_is_never_offered(host):
    # #361: a docker pull of a version publish-ghcr.yml has not written (or a private package) is not offered
    proc = ok(host.ship(A, env={"CBOM_NODE_REGISTRY_PUBLIC": "1", "FAKE_IMAGE_PUBLIC": "0"}))
    v = env_values(host)
    assert v["CBOM_NODE_IMAGE_REF"] == "" and v["CBOM_NODE_CHART_REF"] == ""
    assert f"{GHCR}/devsecshield-scan-node:1.0.0 cannot be pulled without a login" in proc.stdout


def test_a_ghcr_chart_that_is_not_the_downloaded_chart_is_never_offered(host):
    # #361: the GHCR chart 1.0.0 (README with api.zeroshield.ai) and the downloaded cbom-scan-node-1.0.0.tgz were two
    # different files; the wizard then installs the downloaded chart with the GHCR image instead
    proc = ok(host.ship(A, env={"CBOM_NODE_REGISTRY_PUBLIC": "1", "FAKE_CHART_SHA": "0" * 64}))
    v = env_values(host)
    assert v["CBOM_NODE_IMAGE_REF"] == f"{GHCR}/devsecshield-scan-node:1.0.0" and v["CBOM_NODE_CHART_REF"] == ""
    assert "is not the downloaded chart cbom-scan-node-1.0.0.tgz" in proc.stdout
    assert "one version must name one file" in proc.stdout


def test_wait_node_release_checks_the_ghcr_chart_is_the_download(host):
    chart = with_manifest(host, "", "1.0.4", under="deploy/staging/images/node-artifacts")
    proc = ok(host.staging("wait-node-release", "--timeout", "0"))
    assert "scan node 1.0.4 is released" in proc.stdout and "the downloaded chart byte for byte" in proc.stdout
    assert __import__("hashlib").sha256(chart.read_bytes()).hexdigest() in proc.stdout
    proc = host.staging("wait-node-release", "--timeout", "0", env={"FAKE_CHART_SHA": "1" * 64})
    assert proc.returncode == 1 and "one version must name one file" in proc.stdout
    proc = host.staging("wait-node-release", "--timeout", "0", env={"FAKE_IMAGE_PUBLIC": "0"})
    assert proc.returncode == 3 and "is not pullable" in proc.stdout
    proc = host.staging("wait-node-release", "--timeout", "1", env={"FAKE_CHART_PUBLIC": "0", "STAGING_WAIT_STEP": "1"})
    assert proc.returncode == 3  # the chart never became pullable: waited, then gave up


def test_the_push_deploy_waits_for_its_release_and_builds_the_downloads_as_released():
    wf = (ROOT / ".github/workflows/deploy-staging.yml").read_text()
    wait = wf.split("      - name: Wait for the scan node release (GHCR)\n", 1)[1].split("\n      - name:", 1)[0]
    assert "if: github.event_name == 'push' && (vars.CBOM_NODE_REGISTRY_PUBLIC || '1') != '0'" in wait
    assert "continue-on-error: true" in wait and "scripts/deploy/staging.sh wait-node-release" in wait
    assert wf.index("name: Wait for the scan node release") < wf.index("name: Copy and deploy")
    downloads = wf.split("      - name: Scan node downloads\n", 1)[1].split("\n      - uses:", 1)[0]
    assert "CBOM_NODE_VERSION=$(python3 -I .github/ci/node_version.py --rev HEAD)" in downloads
    assert 'export SCAN_NODE_IMAGE="ghcr.io/${OWNER,,}/devsecshield-scan-node"' in downloads
    build = wf.split("  build:\n", 1)[1].split("\n  deploy:\n", 1)[0]
    assert "          fetch-depth: 0\n          filter: blob:none\n" in build


def test_not_public_clears_both_so_no_pull_is_ever_offered(host):
    ok(host.ship(A, env={"CBOM_NODE_REGISTRY_PUBLIC": "1"}))
    ok(host.ship(B, env={"CBOM_NODE_REGISTRY_PUBLIC": "0"}))
    v = env_values(host)
    assert v["CBOM_NODE_IMAGE_REF"] == "" and v["CBOM_NODE_CHART_REF"] == "" and v["CBOM_NODE_REGISTRY_PUBLIC"] == "0"
    # anything but 1 is "not public"
    ok(host.ship(A, env={"CBOM_NODE_REGISTRY_PUBLIC": "yes"}))
    assert env_values(host)["CBOM_NODE_IMAGE_REF"] == ""


def test_never_given_leaves_the_hosts_own_values_alone(host):
    env = host.root / "deploy/staging/.env"
    env.write_text(env.read_text() + "CBOM_NODE_IMAGE_REF=registry.bank.example/zs/cbom-scan-node:1.0.0\n")
    ok(host.ship(A))
    v = env_values(host)
    assert v["CBOM_NODE_IMAGE_REF"] == "registry.bank.example/zs/cbom-scan-node:1.0.0"
    assert "CBOM_NODE_CHART_REF" not in v and "CBOM_NODE_REGISTRY_PUBLIC" not in v


def test_the_switch_is_kept_so_the_next_deploy_and_a_rollback_follow_it(host):
    ok(host.ship(A, env={"CBOM_NODE_REGISTRY_PUBLIC": "1"}))
    with_manifest(host, B, "1.1.0")  # pushed with B (retention removed the copy the fixture made)
    ok(host.ship(B))  # no switch given: .env's 1 is kept, and the refs follow the new tag and its version
    v = env_values(host)
    assert v["CBOM_NODE_IMAGE_REF"] == f"{GHCR}/devsecshield-scan-node:1.1.0"
    assert v["CBOM_NODE_CHART_REF"] == f"oci://{GHCR}/charts/cbom-scan-node:1.1.0"
    ok(host.staging("rollback"))
    v = env_values(host)
    assert v["DSS_TAG"] == A and v["CBOM_NODE_IMAGE_REF"] == f"{GHCR}/devsecshield-scan-node:1.0.0"
    assert v["CBOM_NODE_CHART_REF"] == f"oci://{GHCR}/charts/cbom-scan-node:1.0.0"


def test_without_a_version_a_tag_that_is_not_a_commit_gets_no_registry_image(host):
    proc = ok(host.ship("custom-tag", env={"CBOM_NODE_REGISTRY_PUBLIC": "1"}))
    v = env_values(host)
    assert v["CBOM_NODE_IMAGE_REF"] == "" and v["CBOM_NODE_CHART_REF"] == ""
    assert "is not a 12-character commit" in proc.stdout


def test_no_downloads_manifest_means_the_commits_immutable_image_and_no_chart(host):
    shutil.rmtree(host.root / "deploy/staging/node-artifacts" / A)
    ok(host.ship(A, env={"CBOM_NODE_REGISTRY_PUBLIC": "1"}))
    v = env_values(host)
    assert v["CBOM_NODE_IMAGE_REF"] == f"{GHCR}/devsecshield-scan-node:staging-{A}" and v["CBOM_NODE_CHART_REF"] == ""


def test_another_registry_and_a_bad_one(host):
    ok(host.ship(A, env={"CBOM_NODE_REGISTRY_PUBLIC": "1", "CBOM_NODE_REGISTRY": "ghcr.io/acme"}))
    assert env_values(host)["CBOM_NODE_IMAGE_REF"] == "ghcr.io/acme/devsecshield-scan-node:1.0.0"
    proc = failed(host.ship(B, env={"CBOM_NODE_REGISTRY_PUBLIC": "1", "CBOM_NODE_REGISTRY": "ghcr.io/x|rm -rf /"}))
    assert "CBOM_NODE_REGISTRY" in proc.stderr


def test_the_workflow_turns_it_on_by_default_for_push_deploys_only_and_passes_only_0_or_1():
    import os
    import subprocess
    import tempfile
    import textwrap
    from pathlib import Path

    wf = (ROOT / ".github/workflows/deploy-staging.yml").read_text()
    step = wf.split("      - name: Copy and deploy\n", 1)[1].split("\n      - name:", 1)[0]
    assert "NODE_REGISTRY_PUBLIC: ${{ vars.CBOM_NODE_REGISTRY_PUBLIC }}" in step
    assert "EVENT: ${{ github.event_name }}" in step
    script = textwrap.dedent(step.split("        run: |\n", 1)[1])
    with tempfile.TemporaryDirectory() as d:
        fake = Path(d) / "scripts/deploy/staging.sh"
        fake.parent.mkdir(parents=True)
        fake.write_text('#!/usr/bin/env bash\necho "public=${CBOM_NODE_REGISTRY_PUBLIC-unset}"\n')
        fake.chmod(0o755)
        # public by default (the packages are public): unset is 1 on a push; 0 turns it off; manual runs never
        for var, event, want in (("1", "push", "public=1"), ("1", "workflow_dispatch", "public=0"), ("0", "push", "public=0"),
                                 ("", "push", "public=1"), ("", "workflow_dispatch", "public=0"), ("true", "push", None)):
            p = subprocess.run(["bash", "-e", "-c", script], cwd=d, capture_output=True, text=True, timeout=30,
                               env={"PATH": os.environ["PATH"], "HOME": d, "NODE_REGISTRY_PUBLIC": var, "EVENT": event,
                                    "STAGING_SSH_TARGET": "x@y", "STAGING_DIR": "/opt/x"})
            if want is None:
                assert p.returncode != 0 and "must be 0 or 1" in p.stdout, p.stdout
            else:
                assert p.returncode == 0 and p.stdout.strip() == want, (var, event, p.stdout, p.stderr)


def test_push_forwards_only_a_0_or_1_and_a_checked_registry_to_the_host():
    script = (ROOT / "scripts/deploy/staging.sh").read_text()
    push = script.split("cmd_push() {", 1)[1].split("\n}\n", 1)[0]
    assert '[[ "${CBOM_NODE_REGISTRY_PUBLIC}" =~ ^[01]$ ]] || die' in push
    assert """remote_env+=" CBOM_NODE_REGISTRY_PUBLIC='${CBOM_NODE_REGISTRY_PUBLIC}'\"""" in push
