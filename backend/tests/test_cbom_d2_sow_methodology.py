"""D2 Discovery Methodology and Evidence Plan against the SOW (FIX-D1, audit-D "D2").

Failing first on dev 214d3ca1e (audit-D, staging team 1: 57 scans, 56 of them CBOM Sources collections, 212 endpoints
probed): the document had no agentless / agent / read-only API method, no L1-L4 source table, no collector, Q0,
evidence-chain or data-protection section; section 10 said "No live-network discovery: TLS endpoints ... are not
probed" while the disclaimer said 212 endpoints were probed (cut mid-word at 600 characters); Appendix A listed 3 of 57
scans and none of the 56 collections; the Document ID said "D03". ``cbom_methodology_text`` and
``cbom_sources.methodology_facts`` did not exist.

The views here are the committed code-scan fixture folded by the real aggregator (the harness of
``test_cbom_deliverable_methodology.py``), with CBOM Sources collections, the team's collection set-up and its open
Q0 gaps added the way ``load_team_cbom_view`` adds them.  Contract tests pin the authored tables to the product
(``kinds.KINDS``, ``provenance``, ``qgrade.REASONS``, ``agility.CLASSES``, ``evidence.CONFIDENCE``).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import re
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_deliverable_methodology as H  # noqa: E402  (the PDF reader and the folded fixture)

from backend.utilities.dashboard.cbom_team_rollup import CollectionAgg  # noqa: E402
from backend.utilities.pdf import cbom_methodology_text as M  # noqa: E402
from backend.utilities.pdf.cbom_methodology_pdf import build_pdf  # noqa: E402

UTC = dt.timezone.utc
# staging team 1's shape (audit-D): 56 collections over 15 kinds, 212 endpoints probed
SHAPE = (("linux_servers", 8, 0), ("windows_servers", 4, 0), ("kubernetes", 6, 4), ("database", 6, 0),
         ("aws_account", 3, 0), ("azure_subscription", 2, 0), ("gcp_project", 1, 0), ("oci_tenancy", 1, 0),
         ("key_manager", 3, 0), ("ca_connector", 4, 0), ("idp", 5, 0), ("network_range", 8, 200),
         ("appliance", 3, 8), ("container_images", 1, 0), ("host_agent", 1, 0))
VARIANTS = {"database:postgres": 3, "database:mysql": 2, "database:mssql": 1, "key_manager:pkcs11": 2,
            "key_manager:kmip": 1, "ca_connector:vault": 1, "ca_connector:adcs": 1, "ca_connector:ejbca": 1,
            "ca_connector:aws_private_ca": 1, "idp:entra_id": 2, "idp:okta": 1, "idp:keycloak": 1, "idp:adfs": 1,
            "appliance:fortios": 1, "appliance:cisco_ios": 1, "appliance:panos": 1}


def _collections() -> tuple[CollectionAgg, ...]:
    out, i = [], 0
    base = dt.datetime(2026, 10, 18, 10, 0, tzinfo=UTC)
    for kind, n, probes in SHAPE:
        for j in range(n):
            i += 1
            out.append(CollectionAgg(
                key=f"sources:uid{i:03d}", label=f"Sources run #{40 + i % 13} · {kind}-{j}",
                source_name=f"{kind.replace('_', '-')}-{j}", source_kind=kind, run_id=40 + i % 13, job_id=500 + i,
                observed_at=base + dt.timedelta(minutes=i), asset_count=10 + i,
                endpoints_probed=probes // n + (1 if j < probes % n else 0)))
    return tuple(out)


def _facts(collections, *, ports=("ike", "rdp", "ssh", "starttls-smtp", "tls", "opcua", "modbus")) -> dict:
    by_uid, pool = {}, [v for v, n in VARIANTS.items() for _ in range(n)]
    for c in collections:
        for v in list(pool):
            if v.split(":")[0] == c.source_kind:
                by_uid[c.key.split(":", 1)[1]] = v
                pool.remove(v)
                break
    by_kind = {kind: {"configured": n, "enabled": n} for kind, n, _p in SHAPE}
    by_kind["active_directory"] = {"configured": 1, "enabled": 1}
    return {"sources": {"by_kind": by_kind, "variants": dict(VARIANTS), "variant_by_uid": by_uid,
                        "total": sum(v["configured"] for v in by_kind.values())},
            "settings": {"settings_default": False, "port_protocols": sorted(ports), "window_hours": 35,
                         "window_timezone": "Asia/Kolkata", "require_signed_nodes": True, "stop_all_network": False,
                         "rate_conn_per_s": 20, "rate_parallel_per_server": 2, "rate_handshakes_per_endpoint": 128,
                         "never_scan_entries": 3, "mosca_set": True},
            "nodes": {"agentless": 2, "agent": 1, "signing": 3, "legacy": 0},
            "schedules": {"total": 1, "enabled": 0}, "runs": {"total": 57, "scheduled": 1, "manual": 56}}


def sources_view(**facts_kw):
    view = dataclasses.replace(H.fold(), collections=_collections())
    view.methodology = _facts(view.collections, **facts_kw)
    view.register = {"summary": {"q0_gaps_open": {"coverage_gap": 14, "evidence_e0": 3, "source_not_read": 6}}}
    return view


@pytest.fixture(scope="module")
def sview():
    return sources_view()


@pytest.fixture(scope="module")
def spdf(sview) -> bytes:
    return build_pdf(sview)


@pytest.fixture(scope="module")
def stext(spdf) -> str:
    return H.body_text(spdf)


def _norm(text: str) -> str:
    return H.norm(text)


# ----------------------------------------------------------------------------- identity
def test_document_id_is_the_sow_identifier_d2(sview, spdf):
    assert f"CBOM-D2-T1-20261019-{sview.fingerprint[:8]}" in H.full_text(spdf)
    assert "CBOM-D03-" not in H.full_text(spdf)


# ----------------------------------------------------------------------------- section 2: methods and Table 4
def test_three_collection_methods_are_described(stext):
    two = H.section(stext, 2)
    for name, how, _sources, safeguards in M.METHOD_ROWS:
        assert _norm(f"{name} {how}") in two, name
        assert _norm(safeguards) in two
    assert "outbound HTTPS" in two and "Ed25519" in two and "list" in two


def test_every_sow_table4_source_type_is_listed_with_its_status(stext):
    two = H.section(stext, 2)
    assert len(M.SOW_SOURCE_TYPES) == 45
    for spec in M.SOW_SOURCE_TYPES:
        assert _norm(f"{spec.layer} {spec.label} {spec.method}") in two, spec.label
    rows = {  # (status, sources of the type, collected in this edition)
        "Linux servers (SSH)": "Configured 8 8",
        "Host agent": "Configured 1 1",
        "Active Directory (LDAPS)": "Configured 1 0",
        "Oracle": "Not configured 0 0",
        "Redis": "Not configured 0 0",
        "HSMs (PKCS#11)": "Configured 2 2",
        "Sectigo": "Not configured 0 0",
        "Modbus OT endpoints (port check only)": "Configured 8 8",
        "Cisco ASA (SSH)": "Not configured 0 0",
        "Git repositories (GitHub, GitLab, Bitbucket) or uploaded archives": "Configured 7 7",
    }
    for label, cells in rows.items():
        spec = next(s for s in M.SOW_SOURCE_TYPES if s.label == label)
        assert _norm(f"{spec.layer} {label} {spec.method} {cells}") in two, label
    assert "Configured for this team: 57 CBOM Sources sources of 16 kinds, 2 agentless scan nodes and 1 " \
           "agent-mode node; this edition holds 56 complete collections" in two


def test_a_port_the_team_does_not_probe_is_not_configured():
    text = H.section(H.body_text(build_pdf(sources_view(ports=("tls", "ssh")))), 2)
    assert "L4 Modbus OT endpoints (port check only) Agentless Not configured (port not in the probe list) 8 0" in text
    assert "L4 SSH services Agentless Configured 8 8" in text


def test_without_the_setup_the_table_says_not_loaded_never_not_configured(sview):
    view = dataclasses.replace(sview)
    view.methodology = None
    two = H.section(H.body_text(build_pdf(view)), 2)
    assert "L2 Linux servers (SSH) Agentless Not loaded — 8" in two
    assert "was not loaded for this edition" in two
    assert "L1 Git repositories (GitHub, GitLab, Bitbucket) or uploaded archives Agentless Configured 7 7" in two


# ----------------------------------------------------------------------------- section 3: collectors
def test_every_collector_kind_is_described_and_out_of_sow_kinds_are_marked(stext):
    three = H.section(stext, 3)
    for spec in M.COLLECTORS:
        assert _norm(f"{spec.layer} {spec.label}") in three, spec.kind
        assert _norm(spec.never) in three, spec.kind
    assert "L4 Network ranges and endpoints" in three and "8 / 200 ep." in three
    assert "(outside SOW, 7.2)" in three and _norm(M.OUT_OF_SOW_NOTE) in three


def test_collectors_are_pinned_to_the_kinds_registry_and_its_provenance_methods():
    from backend.utilities.cbom_sources.kinds import KINDS
    from backend.utilities.cbom_sources.provenance import kind_provenance

    assert {spec.kind for spec in M.COLLECTORS} == set(KINDS)  # a new collector cannot ship without its D2 row
    method = {"agentless": M.AGENTLESS, "agent": M.AGENT, "api": M.API}
    for spec in M.COLLECTORS:
        assert spec.method == method[kind_provenance(spec.kind).method], spec.kind
    for kind in ("ct_logs", "awx_hosts", "salt_hosts", "ssm_hosts"):  # SOW 7.2 exclusions
        assert M.COLLECTOR_BY_KIND[kind].in_sow is False


def test_active_directory_row_matches_whether_the_product_collects_it():
    """The D2 row must say what the product does: while the kind is not collectable it says there is no directory
    collector; the day a release collects it (FIX-B3's LDAPS collector), this test asks for the row to be rewritten."""
    from backend.utilities.cbom_sources.kinds import KINDS

    collectable = KINDS["active_directory"].collectable(None)
    assert ("no directory collector" in M.COLLECTOR_BY_KIND["active_directory"].reads) is (not collectable)


def test_sow_rows_name_only_real_kinds_and_variants():
    from backend.utilities.cbom_sources import kinds as K

    literals = {
        "database": set(K.DatabaseConfig.model_fields["engine"].annotation.__args__),
        "key_manager": {"pkcs11", "kmip"},
        "ca_connector": set(K.CaConnectorConfig.model_fields["provider"].annotation.__args__),
        "idp": set(K.IdpConfig.model_fields["provider"].annotation.__args__),
        "appliance": set(K.ApplianceConfig.model_fields["vendor"].annotation.__args__),
    }
    from backend.utilities.cbom_sources.settings import PORT_PROTOCOLS

    for spec in M.SOW_SOURCE_TYPES:
        assert set(spec.kinds) <= set(K.KINDS), spec.label
        for variant in spec.variants:
            kind, value = variant.split(":")
            assert value in literals[kind], variant
        assert set(spec.ports) <= set(PORT_PROTOCOLS), spec.label


# ----------------------------------------------------------------------------- section 6: classification
def test_classification_names_the_standards_q_grades_q0_reasons_and_fix_classes(stext):
    six = H.section(stext, 6)
    for token in ("FIPS 203", "FIPS 204", "FIPS 205", "CNSA 2.0", "SP 800-131A", "CycloneDX 1.6",
                  "related-crypto-material", "Q0 Unknown", "Mosca", "business criticality", "internet exposure"):
        assert token in six, token
    assert _norm(M.Q0_POLICY) in six
    for code, text in M.Q0_REASONS:
        assert code in six and _norm(text) in six, code
    assert "coverage_gap A check, target or address range was not read. 14" in six  # live open count
    assert "mosca_missing Quantum-vulnerable, and the team's Mosca X, Y or Z is not set. 0" in six
    for cls, sow, _text in M.FIX_CLASSES:
        assert f"{cls} {sow}" in six


def test_q0_reasons_fix_classes_and_evidence_levels_are_pinned_to_the_product():
    from backend.utilities.cbom_sources import agility, evidence, qgrade

    assert [code for code, _t in M.Q0_REASONS] == [c for c, r in qgrade.REASONS.items() if r["grade"] == "Q0"]
    for code, text in M.Q0_REASONS:
        assert text.rstrip(".") == qgrade.REASONS[code]["text"], code
    assert [c for c, _s, _t in M.FIX_CLASSES] == list(agility.CLASSES)
    assert sorted(level for level, _t in M.EVIDENCE_LEVELS) == sorted(evidence.CONFIDENCE)
    assert evidence.EVIDENCE_MAX_AGE_DAYS == 365 and "365 days" in dict(M.EVIDENCE_LEVELS)["E0"]
    assert [g.split()[0] for g, _t in M.Q_GRADE_ROWS] == ["Q1", "Q2", "Q3", "Q4", "Q0"]
    assert set(qgrade.GRADES) == {g.split()[0] for g, _t in M.Q_GRADE_ROWS}


def test_without_the_register_open_counts_are_not_invented(sview):
    view = dataclasses.replace(sview)
    view.register = None
    six = H.section(H.body_text(build_pdf(view)), 6)
    assert "coverage_gap A check, target or address range was not read. —" in six
    assert "open Q0 counts are not shown" in six


# ----------------------------------------------------------------------------- sections 7-9
def test_evidence_model_signing_fingerprints_and_signed_deliverables(stext):
    seven = H.section(stext, 7)
    for step, text in M.EVIDENCE_CHAIN:
        assert _norm(f"{step} {text}") in seven, step
    assert "Scan nodes: 3 enrolled with an Ed25519 request-signing key, 0 without (legacy); unsigned nodes are " \
           "refused (require signed nodes: on)." in seven
    assert "evidence pack" in seven and "drift file" in seven and "verify" in seven


def test_data_protection_states_metadata_only_tls_least_privilege_rbac_and_audit(stext):
    eight = H.section(stext, 8)
    for line in M.DATA_PROTECTION:
        assert _norm(line) in eight
    for token in ("Metadata only", "never read or exported", "TLS", "Least privilege", "RBAC", "audit log"):
        assert token in eight, token


def test_scan_windows_ot_safety_modbus_port_check_and_live_settings(stext):
    nine = H.section(stext, 9)
    assert _norm(M.OT_SAFETY_TEXT) in nine and "no Modbus request is sent" in nine
    assert "scan window 35 of 168 hours a week open (Asia/Kolkata)" in nine
    assert "OT probe protocols modbus, opcua" in nine
    assert "57 runs so far (1 scheduled, 56 manual)" in nine


# ----------------------------------------------------------------------------- section 13: evidence plan
def test_evidence_plan_covers_d1_to_d14_in_order(stext):
    plan = H.section(stext, 13)
    ids = [row[0] for row in M.EVIDENCE_PLAN]
    assert ids == [f"D{i}" for i in range(1, 15)]
    positions = []
    for sow, name, produced, _evidence in M.EVIDENCE_PLAN:
        assert _norm(f"{sow} {name}") in plan, sow
        positions.append(plan.index(_norm(f"{sow} {name}")))
    assert positions == sorted(positions)


# ----------------------------------------------------------------------------- the contradiction (audit-D)
def test_no_sentence_denies_what_the_runs_did(sview, spdf, stext):
    everything = H.full_text(spdf)
    for denial in ("No live-network discovery", "not probed", "Static analysis only", "running systems are not",
                   "No key service was collected"):
        assert denial not in everything, denial
    sixteen = H.section(stext, 16)
    assert _norm(M.LIMIT_CUSTODY) in sixteen and _norm(M.LIMIT_MODBUS) in sixteen
    five = H.section(stext, 5)  # the manual checklist drops what the collections read
    assert "Live TLS endpoints Negotiated" not in five
    assert "212 endpoints were probed by CBOM Sources collections" in five
    assert _norm(M.MANUAL_KEY_CUSTODY_COLLECTED) in five


def test_limits_follow_run_coverage():
    base = H.fold()
    assert M.method_limits(base)[:3] == (M.LIMIT_STATIC_ONLY, M.LIMIT_NO_PROBES, M.LIMIT_NO_KEY_SERVICES)
    only_cloud = dataclasses.replace(base, collections=tuple(c for c in _collections() if c.source_kind == "aws_account"))
    limits = M.method_limits(only_cloud)
    assert M.LIMIT_STATIC_ONLY not in limits and M.LIMIT_NO_PROBES in limits and M.LIMIT_NO_HOSTS in limits
    assert M.LIMIT_NO_KEY_SERVICES not in limits


def test_disclaimer_is_whole_and_true_for_the_edition(spdf):
    everything = H.full_text(spdf)
    sentence = M.method_scope_sentence(sources_view())
    assert len(sentence) < 600 and _norm(sentence) in everything
    assert "56 CBOM Sources collections" in sentence and "212 endpoints probed" in sentence
    assert "liv…" not in everything


# ----------------------------------------------------------------------------- appendix: every run in scope
def test_appendix_lists_every_collection_with_its_run(stext):
    appendix = H.appendix(stext)
    rows = re.findall(r"#(\d+) ([a-z0-9-]+-\d+) ", appendix)
    names = {name for _run, name in rows}
    for c in _collections():
        assert c.source_name in names, c.source_name
    assert len([c for c in _collections()]) == 56
    assert "network-range-0 Network ranges and endpoints L4 Agentless 2026-10-18" in appendix


def test_same_view_builds_byte_identical_pdf(sview, spdf):
    assert build_pdf(sview) == spdf


# ----------------------------------------------------------------------------- the live facts loader
def test_methodology_facts_load_counts_one_team_and_never_reads_secrets(tmp_path):
    from sqlalchemy import create_engine
    from sqlmodel import SQLModel

    from backend.new_models import (CbomCollectionRun, CbomCollectionSchedule, CbomCollectionSettings,
                                    CbomCollectionSource, CbomScanNode, Team)
    from backend.utilities.cbom_sources import methodology_facts as F

    engine = create_engine(f"sqlite:///{tmp_path / 'f.db'}")
    SQLModel.metadata.create_all(engine)
    now = dt.datetime(2026, 11, 23, 10, 0)
    with Session(engine) as s:
        for tid in (1, 2):
            s.add(Team(id=tid, name=f"t{tid}"))
        s.commit()

        def src(team, kind, name, config, enabled=True):
            s.add(CbomCollectionSource(team_id=team, owner_user_id=1, kind=kind, name=name, name_lower=name,
                                       enabled=enabled, config=config, secret_encrypted="SECRET-CANARY"))
        src(1, "database", "pg", {"engine": "postgres"})
        src(1, "database", "my", {"engine": "mysql"}, enabled=False)
        src(1, "key_manager", "hsm", {"provider": "pkcs11"})
        src(1, "network_range", "dmz", {"cidr": "10.0.0.0/24"})
        src(2, "database", "other", {"engine": "oracle"})
        s.add(CbomCollectionSettings(team_id=1, aws_external_id="zs-ext", ports=[{"port": 502, "protocol": "modbus"},
                                                                                 {"port": 443, "protocol": "tls"}],
                                     scan_window=[[True] * 24] + [[False] * 24] * 6, require_signed_nodes=True,
                                     network_exclusions=[{"value": "10.0.0.5"}]))
        s.add(CbomScanNode(team_id=1, owner_user_id=1, name="n1", mode="agentless", signing_public_key="k", enrolled_at=now))
        s.add(CbomScanNode(team_id=1, owner_user_id=1, name="n2", mode="agent", enrolled_at=now))
        s.add(CbomScanNode(team_id=1, owner_user_id=1, name="n3", mode="agentless"))  # never enrolled
        s.add(CbomCollectionSchedule(team_id=1, owner_user_id=1, name="nightly", enabled=False))
        for i, (trigger, sid) in enumerate((("manual", None), ("scheduled", 1), ("manual", None))):
            s.add(CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"r{i}", trigger=trigger,
                                    schedule_id=sid))
        s.add(CbomCollectionRun(team_id=2, owner_user_id=1, client_request_id="other", trigger="scheduled"))
        s.commit()
        facts = F.load(s, 1)
    assert facts["sources"]["by_kind"] == {"database": {"configured": 2, "enabled": 1},
                                           "key_manager": {"configured": 1, "enabled": 1},
                                           "network_range": {"configured": 1, "enabled": 1}}
    assert facts["sources"]["variants"] == {"database:mysql": 1, "database:postgres": 1, "key_manager:pkcs11": 1}
    assert facts["sources"]["total"] == 4 and len(facts["sources"]["variant_by_uid"]) == 3
    st = facts["settings"]
    assert st["port_protocols"] == ["modbus", "tls"] and st["window_hours"] == 24 and st["require_signed_nodes"]
    assert st["never_scan_entries"] == 1 and st["settings_default"] is False
    assert facts["nodes"] == {"agentless": 1, "agent": 1, "signing": 1, "legacy": 1}
    assert facts["schedules"] == {"total": 1, "enabled": 0}
    assert facts["runs"] == {"total": 3, "scheduled": 1, "manual": 2}
    assert "SECRET-CANARY" not in repr(facts)
    with Session(engine) as s:  # a team that never opened CBOM Sources: product defaults, no row created
        empty = F.load(s, 2)
        assert empty["settings"]["settings_default"] is True and empty["settings"]["window_hours"] == 35
        assert s.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == 2)).first() is None
    engine.dispose()
