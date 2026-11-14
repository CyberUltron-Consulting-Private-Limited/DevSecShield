"""Staging QA B6-1 (14 Nov 2026): scan nodes could not show they were out of date.

Every staging node and the published downloads said node_version "1.0.0" while staging-lab-node still ran pre-#234
test_range code (job 265 probed .1-.5), so node-side fixes were invisible and nothing told anyone to update.  Root
causes: (1) the server ships a node build (its downloads) but recorded only the version, "1.0.0", never the commit the
image was built from, so it had nothing to compare a node with; (2) nothing compared: the Scan nodes tab printed the
reported string.  The node itself already reports ``<version>+<12-character commit>`` when its image carries one
(CB-03), and only ``<version>`` when it was built by hand or before build ids existed (the lab node).

Now: ``staging.sh node-artifacts`` reads the commit the node image was labelled with and ``node_artifacts.py --build``
writes it into manifest.json; the downloads listing names it (``build``, ``node_build``); every node in the API carries
``node_build`` and ``update`` (``node_release.node_update``); old nodes without a build id still enrol and heartbeat.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_cbom_sources_api import api, enroll_node, world  # noqa: F401  (fixtures)

from backend.utilities.cbom_sources import node_release as NR

ROOT = Path(__file__).resolve().parents[2]
SHA = "5d41b4cc9a1f2e3d4c5b6a79881726354a5b6c7d"
OTHER = "0123456789abcdef0123456789abcdef01234567"


# ------------------------------------------------------------------------------------------------ the comparison
@pytest.mark.parametrize("reported, server, build, state, reason", [
    # the staging lab node: 1.0.0 with no build id, the server ships 1.0.0 built from SHA
    ("1.0.0", "1.0.0", SHA, "update_available", "no_build_id"),
    (f"1.0.0+{SHA[:12]}", "1.0.0", SHA, "current", "same_build"),
    (f"1.0.0+{OTHER[:12]}", "1.0.0", SHA, "update_available", "different_build"),
    (f"1.0.0+{SHA[:12]}", "1.1.0", SHA, "update_available", "older_version"),
    ("1.0.0", "1.0.10", None, "update_available", "older_version"),  # numeric, not text order
    ("2.0.0-rc.1", "2.0.0", SHA, "update_available", "older_version"),  # a pre-release is before its release
    (f"1.2.0+{OTHER[:12]}", "1.1.0", SHA, "newer", "newer_version"),
    ("1.0.0", "1.0.0", None, "current", "same_version"),  # the server ships no build id: versions only
    ("1.0.0", None, None, "unknown", "no_server_build"),  # this server ships no node downloads
    (None, "1.0.0", SHA, "unknown", "not_reported"),  # never enrolled
    ("garbage; rm", "1.0.0", SHA, "unknown", "not_reported"),
    ("1.0", "1.0.0", SHA, "update_available", "no_build_id"),  # 1.0 == 1.0.0
    ("cloud-worker-1.0", "1.0.0", SHA, "unknown", "not_reported"),
])
def test_node_update_states(reported, server, build, state, reason):
    got = NR.node_update(reported, server, build)
    assert (got["state"], got["reason"]) == (state, reason), got
    assert got["server_build"] == (None if not server else f"{server}+{build[:12]}" if build else server)
    assert (got["message"] is not None) == (state in ("update_available", "newer"))


@pytest.mark.parametrize("reported, server, state, reason", [
    # review of PR #286: a core longer than 3 parts compared an int with the pre-release tuple (TypeError)
    ("1.2.3.4", "1.2.3", "newer", "newer_version"),
    ("1.2.3", "1.2.3.4", "update_available", "older_version"),
    ("1.2.3.0", "1.2.3", "update_available", "no_build_id"),  # 1.2.3.0 == 1.2.3, so the build id decides
    ("1.2.3-rc.1", "1.2.3.4", "update_available", "older_version"),
    ("1.2.3.4-rc.1", "1.2.3", "newer", "newer_version"),
    ("1.2.3.4.5.6.7.8.9.1", "1.2.3", "newer", "newer_version"),  # the longest version a node can report (19)
    ("1.2.3", "1.2.3.4.5.6.7.8.9.1", "update_available", "older_version"),
    ("9999999999999999999", "1.0.0", "newer", "newer_version"),
    ("1.0.0-1", "1.0.0-a", "update_available", "older_version"),  # numeric pre-release parts sort first
    ("1.0.0-a.1", "1.0.0-a", "newer", "newer_version"),
    ("1.0.0", "garbage", "update_available", "different_version"),  # not semver-like: just "not the same"
    ("", "1.0.0", "unknown", "not_reported"),
    ("   ", "1.0.0", "unknown", "not_reported"),
    ("1.٢.3", "1.2.3", "unknown", "not_reported"),  # non-ASCII digits are not a node version
    ("1.0.0\u200b", "1.0.0", "unknown", "not_reported"),
    ("1.2.3" + "0" * 40, "1.2.3", "unknown", "not_reported"),  # longer than a node can report
])
def test_node_update_never_raises_on_odd_versions(reported, server, state, reason):
    got = NR.node_update(reported, server, SHA)
    assert (got["state"], got["reason"]) == (state, reason), got


def test_node_update_total_over_every_pair():
    """Any two versions (node and server, either order) give a state, never an exception."""
    versions = ["1", "1.0", "1.0.0", "1.0.0.0", "1.2.3.4", "1.2.3.4.5", "0.9", "10.0.0", "1.0.0-rc", "1.0.0-rc.1",
                "1.0.0-1", "1.0.0-rc-1", "1.2.3.4-1.a", "2.0.0-0.a.1", "1.0.0-a.b.c.1", "x", "", "1..2", "1.0.0-",
                "1.٢", "١", "1.0.0+abc", f"1.0.0+{SHA[:12]}", "9" * 19, "1." * 9 + "1"]
    for a in versions:
        for b in versions:
            got = NR.node_update(a, b, SHA)
            assert got["state"] in ("current", "update_available", "newer", "unknown"), (a, b, got)
            assert NR._compare(a, b) in (-1, 0, 1, None), (a, b)


def test_the_lab_node_message_says_what_is_missing():
    msg = NR.node_update("1.0.0", "1.0.0", SHA)["message"]
    assert msg == ("Runs 1.0.0 with no build id (an image built by hand or before build ids existed), so it is older "
                   f"than the server's node build 1.0.0+{SHA[:12]}.")


def test_parse_reported_is_the_node_s_own_format():
    """scan_node/zs_scan_node reported_version(): <version>[+<12 hex>], version per _VERSION."""
    assert NR.parse_reported(f"1.0.0+{SHA[:12]}") == ("1.0.0", SHA[:12])
    assert NR.parse_reported("2.0.0-rc.1") == ("2.0.0-rc.1", None)
    assert NR.parse_reported(f"1.0.0+{SHA[:11]}") == (None, None)
    node = (ROOT / "scan_node/zs_scan_node/__init__.py").read_text()
    assert '_VERSION = re.compile(r"[0-9][0-9A-Za-z.-]{0,18}")' in node
    assert "[0-9][0-9A-Za-z.-]{0,18}" in NR._REPORTED.pattern


# ------------------------------------------------------------------------------------------------ the manifest
def _make(out: Path, *extra: str) -> subprocess.CompletedProcess:
    out.mkdir(parents=True, exist_ok=True)
    (out / "scan-node-1.0.0.tar.gz").write_bytes(b"image" * 100)
    return subprocess.run([sys.executable, "-I", str(ROOT / "scripts/release/node_artifacts.py"), "--version", "1.0.0",
                           "--image-ref", "localhost/zeroshield/cbom-scan-node:1.0.0", "--out", str(out), *extra],
                          capture_output=True, text=True, timeout=60, check=False)


def test_node_artifacts_records_the_image_s_commit(tmp_path):
    done = _make(tmp_path / "a", "--build", SHA.upper())
    assert done.returncode == 0, done.stderr
    assert json.loads((tmp_path / "a/manifest.json").read_text())["build"] == SHA
    done = _make(tmp_path / "b")  # no commit (a dirty build): recorded as none, the downloads still ship
    assert done.returncode == 0, done.stderr
    assert json.loads((tmp_path / "b/manifest.json").read_text())["build"] is None
    bad = _make(tmp_path / "c", "--build", SHA[:12])
    assert bad.returncode != 0 and "40-character commit" in bad.stderr


FAKE_DOCKER = r"""#!/usr/bin/env python3
import json, os, sys
state = os.environ["FAKE_DOCKER_STATE"]
with open(state + ".log", "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if args[:2] == ["buildx", "build"]:
    for i, a in enumerate(args):
        if a == "--label" and args[i + 1].startswith("org.opencontainers.image.revision="):
            open(state, "w").write(args[i + 1].split("=", 1)[1])
elif args[:2] == ["image", "inspect"]:
    print(open(state).read() if os.path.exists(state) else "")
sys.exit(0)
"""


@pytest.mark.skipif(shutil.which("bash") is None or shutil.which("git") is None, reason="needs bash, git")
@pytest.mark.parametrize("dirty", [False, True])
def test_staging_node_artifacts_ships_the_commit_the_image_reports(tmp_path, dirty):
    """staging.sh node-artifacts -> scan_node_image.sh build (labels the image with its commit) -> the manifest's build
    is that label, so the server compares nodes with exactly what it ships; a dirty tree's image claims no commit."""
    repo = tmp_path / "repo"
    for rel in ("scripts/deploy/staging.sh", "scripts/release/scan_node_image.sh", "scripts/release/node_artifacts.py",
                "scan_node/zs_scan_node/__init__.py", ".gitignore"):
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, repo / rel)
    for rel in ("deploy/helm/cbom-scan-node", "deploy/node-images"):
        shutil.copytree(ROOT / rel, repo / rel)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path), "FAKE_DOCKER_STATE": str(tmp_path / "rev"),
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
           "GIT_CONFIG_GLOBAL": "/dev/null"}
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True)
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, env=env, capture_output=True,
                          text=True).stdout.strip()
    if dirty:
        (repo / "scan_node/zs_scan_node/x.py").write_text("x = 1\n")
    proc = subprocess.run([str(repo / "scripts/deploy/staging.sh"), "node-artifacts"], env=env, capture_output=True, check=False,
                          text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    manifest = json.loads((repo / "deploy/staging/images/node-artifacts/manifest.json").read_text())
    assert manifest["version"] == "1.0.0"
    if dirty:
        assert manifest["build"] is None and "carries no commit" in proc.stdout + proc.stderr
    else:
        assert manifest["build"] == head


# ------------------------------------------------------------------------------------------------ the API
@pytest.fixture()
def shipped(tmp_path, monkeypatch):
    d = tmp_path / "node-artifacts"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps({"version": "1.0.0", "build": SHA, "files": {}}))
    monkeypatch.setenv("CBOM_NODE_ARTIFACT_DIR", str(d))
    return d


def _node(api, node_id):  # noqa: F811
    return next(n for n in api("GET", "/1/cbom/sources/nodes").json()["nodes"] if n["id"] == node_id)


def test_scan_nodes_say_which_node_needs_an_update(api, world, shipped):  # noqa: F811
    lab, lab_token, _ = enroll_node(api, name="staging-lab-node")
    fresh, fresh_token, _ = enroll_node(api, name="staging-hsm-node")
    # the lab node: an image without a build id; still accepted (older nodes keep working)
    hb = api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": lab_token}, json={"version": "1.0.0"})
    assert hb.status_code == 200, hb.text
    hb = api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": fresh_token},
             json={"version": f"1.0.0+{SHA[:12]}"})
    assert hb.status_code == 200, hb.text

    old = _node(api, lab)
    assert old["node_version"] == "1.0.0" and old["node_build"] is None
    assert old["update"]["state"] == "update_available" and old["update"]["reason"] == "no_build_id"
    assert old["update"]["server_build"] == f"1.0.0+{SHA[:12]}"
    assert "older than the server's node build" in old["update"]["message"]
    new = _node(api, fresh)
    assert new["node_build"] == SHA[:12] and new["update"]["state"] == "current"
    # the single-node route says the same
    assert api("GET", f"/1/cbom/sources/nodes/{lab}").json()["node"]["update"]["state"] == "update_available"

    # the lab node updated: same container state, new image -> current on its next heartbeat
    api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": lab_token}, json={"version": f"1.0.0+{SHA[:12]}"})
    assert _node(api, lab)["update"]["state"] == "current"

    # a new server build (the next deploy rewrites the manifest): both are now behind, no restart of the API needed
    (shipped / "manifest.json").write_text(json.dumps({"version": "1.0.0", "build": OTHER, "files": {}}))
    os.utime(shipped / "manifest.json", ns=(1, 1))  # a different mtime even within the same clock tick
    assert {_node(api, n)["update"]["reason"] for n in (lab, fresh)} == {"different_build"}


def test_a_four_part_node_version_does_not_take_the_list_down(api, world, shipped):  # noqa: F811
    """Review of PR #286: node_version is node-controlled text; "1.2.3.4" against a server build 1.2.3 500'd GET /nodes
    for the whole team."""
    (shipped / "manifest.json").write_text(json.dumps({"version": "1.2.3", "build": SHA, "files": {}}))
    odd, odd_token, _ = enroll_node(api, name="four-part")
    plain, plain_token, _ = enroll_node(api, name="plain")
    hb = api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": odd_token}, json={"version": "1.2.3.4"})
    assert hb.status_code == 200, hb.text
    api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": plain_token}, json={"version": "1.0.0"})
    listed = api("GET", "/1/cbom/sources/nodes")
    assert listed.status_code == 200, listed.text
    by_id = {n["id"]: n for n in listed.json()["nodes"]}
    assert by_id[odd]["update"]["state"] == "newer" and by_id[odd]["node_version"] == "1.2.3.4"
    assert by_id[plain]["update"]["reason"] == "older_version"
    assert api("GET", f"/1/cbom/sources/nodes/{odd}").status_code == 200


def test_a_comparison_error_is_unknown_not_a_500(api, world, shipped, monkeypatch):  # noqa: F811
    """Whatever goes wrong comparing one node, the list still answers and that node says "unknown"."""
    from backend.utilities.cbom_sources import serialize

    def boom(*_a, **_k):
        raise TypeError("'>' not supported between instances of 'int' and 'tuple'")

    node_id, token, _ = enroll_node(api)
    api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": token}, json={"version": "1.0.0"})
    monkeypatch.setattr(serialize, "node_update", boom)
    listed = api("GET", "/1/cbom/sources/nodes")
    assert listed.status_code == 200, listed.text
    assert _node(api, node_id)["update"] == {"state": "unknown", "reason": "compare_failed", "message": None,
                                             "server_build": f"1.0.0+{SHA[:12]}"}


def test_the_manifest_is_read_once_per_list(api, world, shipped, monkeypatch):  # noqa: F811
    """Review nit on PR #286: one server_release() per GET /nodes, not one per node."""
    from backend.routers import cbom_sources as router
    from backend.utilities.cbom_sources import serialize

    for i in range(4):
        enroll_node(api, name=f"n{i}")
    calls = []

    def counted():
        calls.append(1)
        return NR.server_release()

    monkeypatch.setattr(serialize, "server_release", counted)
    monkeypatch.setattr(router, "server_release", counted)
    nodes = api("GET", "/1/cbom/sources/nodes").json()["nodes"]
    assert len(nodes) >= 4 and len(calls) == 1
    assert {n["update"]["server_build"] for n in nodes} == {f"1.0.0+{SHA[:12]}"}


def test_without_node_downloads_nothing_is_claimed(api, world, monkeypatch):  # noqa: F811
    monkeypatch.delenv("CBOM_NODE_ARTIFACT_DIR", raising=False)
    node_id, token, _ = enroll_node(api)
    api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": token}, json={"version": "1.0.0"})
    assert _node(api, node_id)["update"] == {"state": "unknown", "reason": "no_server_build", "message": None,
                                             "server_build": None}


def test_downloads_listing_names_the_build(api, world, shipped):  # noqa: F811
    body = api("GET", "/1/cbom/node-artifacts", "bob").json()
    assert body["version"] == "1.0.0" and body["build"] == SHA and body["node_build"] == f"1.0.0+{SHA[:12]}"
    (shipped / "manifest.json").write_text(json.dumps({"version": "1.0.0", "build": "not-a-commit", "files": {}}))
    body = api("GET", "/1/cbom/node-artifacts", "bob").json()
    assert body["build"] is None and body["node_build"] == "1.0.0"
