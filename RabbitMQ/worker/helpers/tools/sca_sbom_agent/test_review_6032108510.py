"""Review 6032108510 (PR #489, second review) fixes in the scan worker.

* B-1  public-registry lookups are opt-in (``DSS_SBOM_REGISTRY=1``): by default the worker makes no egress and no
       scan waits on a registry; ``dss:registry`` says off / on / unreachable.
* M-2  a lock or pin replaces a range guess only when the pinned version satisfies the guess's constraint
       (pcap-hunter: ``requirements-docs.txt`` pillow>=10.0,<13.0 next to a lock pinning pillow==13.0.0).
* m2   a finding on a guessed version reads "≥ 10.0 (range …)" and is marked unverified in its title and dependency.
* m4   hostile SPDX: wrong-typed fields do not crash, packages without an SPDXID are kept and reported, and edge
       de-duplication is linear.
* m6   whether the LLM enrichment ran is stamped in the SBOM (``dss:llm_enrichment``).
"""
from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[4]
if str(_REPO_ROOT / "aibom" / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "aibom" / "src"))


def _props(item):
    return {p["name"]: p["value"] for p in item.get("properties") or []}


# ----------------------------------------------------------------------------------------------------------- B-1
def test_registry_is_off_unless_opted_in(monkeypatch):
    from helpers.tools.sca_sbom_agent import registry_enrich

    reg = registry_enrich.backend_module("registry")
    monkeypatch.delenv("DSS_SBOM_REGISTRY", raising=False)
    monkeypatch.setattr(reg, "_network_allowed", lambda: True)  # even outside pytest's own guard

    def boom(*_a):
        raise AssertionError("a registry lookup was made although DSS_SBOM_REGISTRY is unset")

    monkeypatch.setattr(reg, "lookup_package", boom)
    comps = [{"name": "flask", "version": "0.12.2", "purl": "pkg:pypi/flask@0.12.2"}]
    stats = registry_enrich.resolve_components(comps, budget_s=30)
    assert stats["registry"] == "off" and stats["looked_up"] == 0
    assert registry_enrich.registry_note(stats).startswith("off")
    for value in ("0", "", "true", "yes", "on"):
        monkeypatch.setenv("DSS_SBOM_REGISTRY", value)
        assert registry_enrich.resolve_components(list(comps), budget_s=30)["registry"] == "off"


def _blackhole() -> int:
    """A proxy that accepts connections and never answers (a firewall that drops the replies)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    held = []

    def run():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            held.append(conn)

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def test_registry_behind_a_dropping_firewall_is_bounded_and_reported_unreachable(monkeypatch):
    from helpers.tools.sca_sbom_agent import registry_enrich

    port = _blackhole()
    for var in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        monkeypatch.setenv(var, f"http://127.0.0.1:{port}")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    reg = registry_enrich.backend_module("registry")
    reg._fetch.cache_clear()
    comps = [{"name": f"p{i}", "version": "1.0", "purl": f"pkg:pypi/p{i}@1.0"} for i in range(4)]
    # the default: no call at all, so no wait
    monkeypatch.delenv("DSS_SBOM_REGISTRY", raising=False)
    started = time.monotonic()
    assert registry_enrich.resolve_components([dict(c) for c in comps], budget_s=30)["registry"] == "off"
    assert time.monotonic() - started < 1.0
    # opted in: bounded by the budget, and the document says the registry was unreachable
    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(reg, "_network_allowed", lambda: True)
    started = time.monotonic()
    stats = registry_enrich.resolve_components([dict(c) for c in comps], budget_s=2)
    assert time.monotonic() - started < 4.0
    assert stats["registry"] == "unreachable" and stats["resolved"] == 0
    assert registry_enrich.registry_note(stats).startswith("unreachable: 0/4 resolved")


def test_a_failed_lookup_is_not_cached(monkeypatch):
    from helpers.tools.sca_sbom_agent import registry_enrich

    reg = registry_enrich.backend_module("registry")
    reg._fetch.cache_clear()
    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(reg, "_network_allowed", lambda: True)
    answers = iter([None, {"license": "MIT", "author": "a", "hash": ("SHA-256", "ab" * 32)}])
    calls = []

    def native(eco, name, version):
        calls.append(name)
        return next(answers, None)

    monkeypatch.setattr(reg, "_from_native", native)
    monkeypatch.setattr(reg, "_from_deps_dev", lambda *a: None)
    assert reg.lookup_package("pypi", "blip", "1.0") is None  # a network blip
    assert reg.lookup_package("pypi", "blip", "1.0")["license"] == "MIT"  # retried, not remembered as a failure
    assert reg.lookup_package("pypi", "blip", "1.0")["license"] == "MIT"  # an answer is cached
    assert calls == ["blip", "blip"]


# ----------------------------------------------------------------------------------------------------------- M-2
def test_a_lock_outside_the_range_does_not_replace_the_guess():
    """pcap-hunter: requirements-docs.txt pillow>=10.0,<13.0 (no lock) and requirements.lock pillow==13.0.0 (for
    requirements-runtime.txt pillow>=13,<14). 13.0.0 cannot be the docs' pillow: both components stay."""
    from helpers.tools.sca_sbom_agent.merge_inventory import merge_cdx_components, prefer_pinned

    guess = {"components": [{"name": "pillow", "version": "10.0", "purl": "pkg:pypi/pillow@10.0",
                             "evidence": {"occurrences": [{"location": "/requirements-docs.txt"}]}},
                            {"name": "scapy", "version": "2.6", "purl": "pkg:pypi/scapy@2.6",
                             "evidence": {"occurrences": [{"location": "/requirements-runtime.txt"}]}}]}
    lock = {"components": [{"name": "pillow", "version": "13.0.0", "purl": "pkg:pypi/pillow@13.0.0",
                            "properties": [{"name": "dss:version_source", "value": "lock_file"}]},
                           {"name": "scapy", "version": "2.8.0", "purl": "pkg:pypi/scapy@2.8.0",
                            "properties": [{"name": "dss:version_source", "value": "lock_file"}]}]}
    comps = merge_cdx_components(guess, lock)
    constraints = {"pkg:pypi/pillow@10.0": ">=10.0,<13.0", "pkg:pypi/scapy@2.6": ">=2.6,<3"}
    kept, left, dropped = prefer_pinned(comps, constraints)
    purls = {c["purl"] for c in kept}
    assert "pkg:pypi/pillow@10.0" in purls and "pkg:pypi/pillow@13.0.0" in purls  # 13.0.0 is outside <13.0
    assert left == {"pkg:pypi/pillow@10.0": ">=10.0,<13.0"}  # still a guess: unverified
    assert dropped == ["pkg:pypi/scapy@2.6"]  # 2.8.0 satisfies >=2.6,<3: the lock wins
    pillow13 = next(c for c in kept if c["purl"] == "pkg:pypi/pillow@13.0.0")
    assert "/requirements-docs.txt" not in json.dumps(pillow13)


def test_the_three_pillow_advisories_stay_as_unverified_findings():
    """The docs' pillow 10.0 guess keeps its Grype matches (as unverified), as with the lock files removed."""
    from helpers.tools.sca_sbom_agent.grype_findings import finding_rows

    def match(vid, sev):
        return {"vulnerability": {"id": vid, "severity": sev, "fix": {"state": "fixed", "versions": ["10.3.0"]}},
                "artifact": {"name": "pillow", "version": "10.0", "purl": "pkg:pypi/pillow@10.0"}}

    doc = {"matches": [match("GHSA-3f63-hfp8-52jq", "Critical"), match("GHSA-44wm-f244-xhp3", "High"),
                       match("GHSA-j7hp-h8jx-5ppr", "High")]}
    rows = finding_rows(doc, guessed_versions={"pkg:pypi/pillow@10.0": ">=10.0,<13.0"})
    assert {r["vuln_id"] for r in rows} == {"GHSA-3f63-hfp8-52jq", "GHSA-44wm-f244-xhp3", "GHSA-j7hp-h8jx-5ppr"}
    for row in rows:  # m2: never reads as a pin
        assert row["version_guessed_from"] == ">=10.0,<13.0"
        assert "≥ 10.0 (range >=10.0,<13.0)" in row["title"] and "unverified" in row["title"]
        assert row["dependency"] == "pillow (≥ 10.0, range >=10.0,<13.0)"
        assert row["purl"] == "pkg:pypi/pillow@10.0"


# ----------------------------------------------------------------------------------------------------------- m4
def test_hostile_spdx_fields_do_not_crash_and_id_less_packages_are_kept():
    from helpers.tools.sca_sbom_agent.spdx_convert import spdx_to_cyclonedx

    doc = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "creationInfo": "x", "documentDescribes": 5,
           "packages": [{"name": "a", "versionInfo": 1, "externalRefs": 4, "checksums": "x", "supplier": 7},
                        {"name": "b", "SPDXID": "SPDXRef-b", "versionInfo": "2"}, 5, "junk"],
           "relationships": 7}
    out = spdx_to_cyclonedx(doc)
    names = sorted(c["name"] for c in out["components"])
    assert names == ["a", "b"]
    props = _props(out["metadata"])
    assert props["dss:spdx_packages_without_id"] == "1"
    assert props["dss:spdx_invalid_entries"] == "2"
    with pytest.raises(ValueError):
        spdx_to_cyclonedx({"spdxVersion": "SPDX-2.3", "packages": "nope"})


def test_spdx_edge_dedupe_is_linear():
    from helpers.tools.sca_sbom_agent.spdx_convert import spdx_to_cyclonedx

    n = 40_000
    pkgs = [{"SPDXID": "SPDXRef-root", "name": "root"}] + [{"SPDXID": f"SPDXRef-p{i}", "name": f"p{i}",
                                                            "versionInfo": "1"} for i in range(n)]
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-root", "relationshipType": "DESCRIBES"}]
    rels += [{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": f"SPDXRef-p{i}", "relationshipType": "DEPENDS_ON"}
             for i in range(n)] * 2  # every edge twice
    started = time.monotonic()
    out = spdx_to_cyclonedx({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": pkgs,
                             "relationships": rels})
    assert time.monotonic() - started < 3.0  # was 6.6 s for 40k edges (quadratic list membership)
    root = out["metadata"]["component"]["bom-ref"]
    assert len(next(d for d in out["dependencies"] if d["ref"] == root)["dependsOn"]) == n


def test_offline_scan_states_its_licence_and_hash_coverage(monkeypatch):
    """M-1: an SBOM built without the registries says how many components lack a licence / hash, and why."""
    from helpers.tools.sca_sbom_agent.test_review_6028132826 import _scan_repo

    agent = _scan_repo(monkeypatch)
    props = _props(agent.sbom_json["metadata"])
    total = len(agent.sbom_json["components"])
    licensed = sum(1 for c in agent.sbom_json["components"] if c.get("licenses"))
    assert props["dss:licence_coverage"] == f"{licensed}/{total}" and licensed < total
    assert props["dss:hash_coverage"] == f"0/{total}"
    assert "registry lookups are off" in props["dss:coverage_note"]
    assert "not assessed" in props["dss:coverage_note"]


# ----------------------------------------------------------------------------------------------------------- m6
def test_llm_enrichment_state_is_stamped_in_the_sbom(monkeypatch):
    from helpers.tools.sca_sbom_agent.test_review_6028132826 import _scan_repo

    agent = _scan_repo(monkeypatch)
    assert _props(agent.sbom_json["metadata"])["dss:llm_enrichment"] == "disabled"


def test_an_upload_with_no_readable_package_is_an_empty_scan_not_a_grype_error(tmp_path, monkeypatch):
    """m4: ``{"name": {...}}`` packages convert to 0 components; Grype used to be run on the raw SPDX upload and
    fail with "unable to decode sbom". Now the scan completes empty and says what it could not read."""
    from helpers.tools.sca_sbom_agent import main as agent_main

    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "x",
                                "packages": [{"SPDXID": "SPDXRef-a", "name": {"x": 1}, "versionInfo": [1, 2]}]}))
    monkeypatch.setattr(agent_main, "run_sbom_scan", lambda **kw: (_ for _ in ()).throw(AssertionError(kw)))
    agent = agent_main.SCASBOMAgent.__new__(agent_main.SCASBOMAgent)
    agent.directory, agent.sbom_json_file, agent.state_update_writer = None, str(path), None
    agent.vulnerabilities, agent.vulnerability_rows, agent.inventory_rows = None, [], []
    agent.bom_properties, agent.sbom_json, agent.repo_info = {}, None, {}
    agent.analyze_sbom_file()
    assert agent.sbom_json["components"] == [] and agent.vulnerability_rows == []
    props = {p["name"]: p["value"] for p in agent.sbom_json["metadata"]["properties"]}
    assert props["dss:spdx_invalid_entries"] == "1"
