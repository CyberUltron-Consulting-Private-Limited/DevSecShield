"""Issue #197: the Add scan node wizard installed a stale scan node image.

Staging (build 6a6ef42, 14 Nov) offered GHCR ``devsecshield-scan-node:1.0.0``: written once (2 Nov) and kept while
every later build also said 1.0.0, so nodes installed from it did not sign requests, ignored ZS_CA_FILE and never
wrote the ``alive`` file the Helm chart's readiness probe reads (pod 0/1 Ready).  #377 (#361) made every node-changing
promotion a new release 1.0.N, so a published version names one node; what was still missing is a check of the image
the wizard offers against the release this server ships, before anyone installs it.

Pinned here: ``node_release.image_freshness`` (the shared contract contracts/cbom/node_image_freshness.json, also read
by the frontend: the same version is current, 1.0.0 never is), the downloads listing names it for the registry image
(``pull_image_freshness``), and the chart's readiness probe reads exactly the file the current agent writes, within the
age the image HEALTHCHECK allows.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from backend.routers import cbom_node_artifacts as NA
from backend.utilities.cbom_sources import node_release as NR
from test_cbom_sources_api import api, world  # noqa: F401  (fixtures)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / "contracts/cbom/node_image_freshness.json").read_text())
SERVER = CONTRACT["server_build"]


def _build(value):
    return SERVER if value == "SERVER" else value


@pytest.mark.parametrize("case", CONTRACT["cases"], ids=[c["ref"] + "@" + str(c["server_version"]) for c in CONTRACT["cases"]])
def test_image_freshness_contract(case):
    got = NR.image_freshness(case["ref"], case["server_version"], _build(case["server_build"]))
    assert (got["state"], got["reason"]) == (case["state"], case["reason"]), got
    stale = got["state"] in CONTRACT["stale_states"]
    # a stale or moving image always says why; a current one says nothing
    assert (got["message"] is not None) == (stale or got["state"] == "moving"), got
    if got["message"]:
        assert case["ref"] in got["message"]


def test_the_stale_states_are_the_backends():
    assert tuple(CONTRACT["stale_states"]) == NR.STALE_IMAGE_STATES


def test_no_reference_no_verdict():
    assert NR.image_freshness(None, "1.1.0", SERVER) is None and NR.image_freshness("  ", "1.1.0", SERVER) is None


def test_the_frozen_staging_tag_of_issue_197_is_never_current():
    """The exact image staging offered: :1.0.0, while the server's downloads also said 1.0.0 (before release versions)."""
    got = NR.image_freshness("ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node:1.0.0", "1.0.0", SERVER)
    assert got["state"] == "unverified" and "1.0.0" in got["message"] and "before release versions" in got["message"]
    assert NR.image_freshness("registry.zeroshield.ai/cbom/scan-node:1.0", "1.0.4", SERVER)["state"] == "moving"
    # the #377 scheme: the release the server ships is current whichever commit built the GHCR copy
    assert NR.image_freshness("ghcr.io/o/devsecshield-scan-node:1.0.4", "1.0.4", CONTRACT["server_build"])["state"] == "current"


# ------------------------------------------------------------------------------------------------ the listing
def _manifest(tmp_path, monkeypatch, build=SERVER, version="1.0.4"):
    d = tmp_path / "node-artifacts"
    d.mkdir(exist_ok=True)
    body = {"version": version, "image_ref": f"localhost/zeroshield/cbom-scan-node:{version}", "files": {}}
    if build:
        body["build"] = build
    (d / "manifest.json").write_text(json.dumps(body))
    monkeypatch.setenv("CBOM_NODE_ARTIFACT_DIR", str(d))
    return d


@pytest.mark.parametrize("ref, state", [
    ("ghcr.io/o/devsecshield-scan-node:1.0.0", "outdated"),
    ("ghcr.io/o/devsecshield-scan-node:1.0.3", "outdated"),
    ("ghcr.io/o/devsecshield-scan-node:1.0.4", "current"),
    (f"ghcr.io/o/devsecshield-scan-node:staging-{SERVER[:12]}", "current"),
    ("ghcr.io/o/devsecshield-scan-node:staging", "moving"),
])
def test_listing_says_whether_the_registry_image_is_this_servers_build(api, world, tmp_path, monkeypatch, ref, state):  # noqa: F811
    _manifest(tmp_path, monkeypatch)
    monkeypatch.setenv("CBOM_NODE_IMAGE_REF", ref)
    body = api("GET", "/1/cbom/node-artifacts", "bob").json()
    assert body["pull_image_ref"] == ref and body["node_build"] == f"1.0.4+{SERVER[:12]}"
    fresh = body["pull_image_freshness"]
    assert fresh["state"] == state and fresh["server_build"] == f"1.0.4+{SERVER[:12]}" and fresh["tag"] == ref.rsplit(":", 1)[1]


def test_listing_without_a_registry_image_has_no_verdict(api, world, tmp_path, monkeypatch):  # noqa: F811
    _manifest(tmp_path, monkeypatch)
    monkeypatch.delenv("CBOM_NODE_IMAGE_REF", raising=False)
    body = api("GET", "/1/cbom/node-artifacts").json()
    assert body["pull_image_ref"] is None and body["pull_image_freshness"] is None


def test_listing_follows_a_new_manifest(tmp_path, monkeypatch):
    """A deploy (or rollback) replaces the downloads: the verdict is read again from the new manifest."""
    monkeypatch.setenv("CBOM_NODE_IMAGE_REF", f"ghcr.io/o/devsecshield-scan-node:staging-{SERVER[:12]}")
    _manifest(tmp_path, monkeypatch)
    assert NA.listing()["pull_image_freshness"]["state"] == "current"
    _manifest(tmp_path, monkeypatch, build="0123456789abcdef0123456789abcdef01234567")
    assert NA.listing()["pull_image_freshness"]["state"] == "unverified"  # another commit: not provably this release
    _manifest(tmp_path, monkeypatch, version="1.0.5")
    monkeypatch.setenv("CBOM_NODE_IMAGE_REF", "ghcr.io/o/devsecshield-scan-node:1.0.4")
    assert NA.listing()["pull_image_freshness"]["state"] == "outdated"  # a rollback forward: the old pin is refused


# ------------------------------------------------------------------------------------------------ Helm readiness
def test_the_charts_readiness_probe_reads_the_file_the_agent_writes():
    """The probe must pass for a current node: the same file (ALIVE_FILE in ZS_STATE_DIR, the image's default and
    the chart's mount), the same age as the image HEALTHCHECK, and the agent refreshes it well within that age."""
    helpers = (ROOT / "deploy/helm/cbom-scan-node/templates/_helpers.tpl").read_text()
    dockerfile = (ROOT / "scan_node/Dockerfile").read_text()
    agent = (ROOT / "scan_node/zs_scan_node/agent.py").read_text()
    alive = re.search(r'(?m)^ALIVE_FILE = "([^"]+)"', agent).group(1)
    probe = re.search(r"readinessProbe:\n  exec:\n    command: \[(.*)\]", helpers).group(1)
    check = re.search(r'CMD python -c "(.*)"', dockerfile).group(1)
    for text in (probe, check):
        assert f"os.environ.get('ZS_STATE_DIR','/var/lib/zs-node'),'{alive}'" in text, text
        assert "<180" in text, text
    assert "ZS_STATE_DIR=/var/lib/zs-node" in dockerfile
    assert "- name: ZS_STATE_DIR\n  value: /var/lib/zs-node\n" in helpers  # the chart's commonEnv, the probe's directory
    for template in ("deployment.yaml", "daemonset.yaml"):
        body = (ROOT / "deploy/helm/cbom-scan-node/templates" / template).read_text()
        assert 'include "cbom-scan-node.readiness"' in body and "mountPath: /var/lib/zs-node" in body, template
        assert "ZS_STATE_DIR" not in body, f"{template} moves the state directory away from the probe's"
    # the heartbeat loop touches it on every pass, and again at most every 60 s while it waits out a longer
    # server interval (protocol 2, up to MAX_HEARTBEAT_SECONDS). The image HEALTHCHECK fails after 180 s.
    assert "self.mark_alive()" in agent and "min(left, 60)" in agent and "MAX_HEARTBEAT_SECONDS" in agent
