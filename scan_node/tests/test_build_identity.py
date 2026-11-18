"""CB-03: the node image carries the commit it was built from (ZS_NODE_BUILD) and the release version
(ZS_NODE_VERSION, both from scripts/release/scan_node_image.sh) and reports ``<version>+<12-character commit>``
(semver build metadata; fits the server's 32-character node_version) in the enrolment, every heartbeat, every job
result, the User-Agent and the start-up log line."""
import pytest

import zs_scan_node
from zs_scan_node import api as node_api

from test_agent import _agent, _job, _listener, _wait, server  # noqa: F401  (fixture)

SHA = "83b570bed86212e3afed395be942df57b8dc3df5"
V = zs_scan_node.VERSION


def test_version_constant():
    """The release a source build reports. The regex and the 32-character column stay as they are."""
    assert V == "1.0.1"
    assert zs_scan_node._VERSION.pattern == r"[0-9][0-9A-Za-z.-]{0,18}"
    assert zs_scan_node._VERSION.fullmatch(V)
    assert len(f"{V}+{SHA[:12]}") <= 32


@pytest.mark.parametrize("raw, expected", [
    (SHA, f"{V}+{SHA[:12]}"), (SHA.upper(), f"{V}+{SHA[:12]}"), (f" {SHA}\n", f"{V}+{SHA[:12]}"),
    ("", V), (None, V), ("unknown", V), (SHA[:12], V), (SHA + "a", V),
    ("1.0.0; rm -rf /", V),
])
def test_reported_version(monkeypatch, raw, expected):
    monkeypatch.delenv("ZS_NODE_VERSION", raising=False)
    if raw is None:
        monkeypatch.delenv("ZS_NODE_BUILD", raising=False)
    else:
        monkeypatch.setenv("ZS_NODE_BUILD", raw)
    assert zs_scan_node.reported_version() == expected
    assert len(zs_scan_node.reported_version()) <= 32  # backend CbomScanNode.node_version is String(32)
    assert zs_scan_node.node_build() == (SHA if expected != V else None)


@pytest.mark.parametrize("version, expected", [
    ("1.1.0", "1.1.0"), ("1.1", "1.1"), ("2.0.0-rc.1", "2.0.0-rc.1"), ("", V), ("v1.1", V),
    ("1.1_beta", V), ("1" + ".0" * 10, V), ("1.1; rm", V),
])
def test_release_version_from_the_image(monkeypatch, version, expected):
    """scan_node_image.sh build <version> bakes ZS_NODE_VERSION: a 1.1.0 image reports 1.1.0, not the constant."""
    monkeypatch.setenv("ZS_NODE_BUILD", SHA)
    monkeypatch.setenv("ZS_NODE_VERSION", version)
    assert zs_scan_node.reported_version() == f"{expected}+{SHA[:12]}"
    assert len(zs_scan_node.reported_version()) <= 32


def test_enrolment_heartbeat_result_and_user_agent_carry_the_build(server, tmp_path, monkeypatch, capsys):  # noqa: F811
    api, url = server
    monkeypatch.setenv("ZS_NODE_BUILD", SHA)
    monkeypatch.delenv("ZS_NODE_VERSION", raising=False)
    ag = _agent(tmp_path, url, monkeypatch)
    assert ag.api.client.headers["User-Agent"] == f"zs-scan-node/{V}+{SHA[:12]}"
    ag.ensure_enrolled()
    assert api.enroll_bodies[-1]["version"] == f"{V}+{SHA[:12]}"
    ag.heartbeat_once()
    assert api.heartbeats[-1]["version"] == f"{V}+{SHA[:12]}"
    srv, port = _listener()  # one job through to its result
    ag.start_job(_job(51, port))
    assert _wait(lambda: 51 in api.results)
    assert api.results[51]["result"]["node_version"] == f"{V}+{SHA[:12]}"
    ag.shutdown.set()
    srv.close()


def test_start_up_log_names_version_and_build(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ZS_NODE_BUILD", SHA)
    monkeypatch.delenv("ZS_NODE_VERSION", raising=False)
    monkeypatch.setenv("ZS_API_URL", "https://zeroshield.example")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    from zs_scan_node import agent as A

    ag = A.Agent()
    ag.log_start()
    line = capsys.readouterr().out.strip().splitlines()[-1]
    assert "scan node starting" in line and f"version={V}+{SHA[:12]}" in line and f"build={SHA}" in line


def test_user_agent_without_a_build_is_unchanged(monkeypatch):
    monkeypatch.delenv("ZS_NODE_BUILD", raising=False)
    monkeypatch.delenv("ZS_NODE_VERSION", raising=False)
    client = node_api.Api("https://zeroshield.example", None)
    assert client.client.headers["User-Agent"] == f"zs-scan-node/{V}"
