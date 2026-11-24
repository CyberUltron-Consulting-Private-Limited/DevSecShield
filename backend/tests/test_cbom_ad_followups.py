"""#488 follow-ups (review 6031264030) on the backend: D6 reads the Active Directory / Kerberos posture, a segment
whose nodes are all too old says so, and the Kerberos encryption-type order lives in one table.

Before: ``posture_mapper.posture_fact`` ended in an unconditional ``return _cloud_ca(...)``, so adding the two AD asset
types to ``_LANES`` alone would have printed every Kerberos account as a private CA; D6 showed no AD row at all.  A
segment-routed AD source whose segment had only pre-AD nodes was queued and waited out the 7 d queue TTL in silence.

Oracle: literals from the fixture (``support/sources_every_type.py``, "Corp Active Directory"), never the renderer.
"""

from __future__ import annotations

import ast
import datetime as dt
import sys
from pathlib import Path

import pytest
from sqlmodel import Session

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests.support import sources_every_type as FX  # noqa: E402
from backend.utilities.cbom_sources import posture_mapper as M  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView, merge_collections  # noqa: E402
from backend.utilities.pdf import cbom_data_at_rest_pdf as d9  # noqa: E402
from backend.utilities.pdf import cbom_infra_posture_pdf as d6  # noqa: E402
from backend.utilities.pdf.cbom_deliverable_common import get_deliverable_styles  # noqa: E402
from test_cbom_sources_posture_d6_d9_d10 import cell_text, iter_tables, kpi_cards, rows_under  # noqa: E402

NOW = dt.datetime(2026, 11, 23, 12, 0, tzinfo=dt.UTC)
WIDTH = 720.0
AD_SOURCE = "Corp Active Directory"
AD_LABEL = f"Sources run #52 · {AD_SOURCE}"


def _view(sources=None) -> TeamCbomView:
    base = TeamCbomView(team_id=1, team_name="Bank One", generated_at=NOW, as_of=NOW.date(), fingerprint="adfu0001")
    if sources is None:
        rows, collections = FX.build()
    else:
        saved = FX.SOURCES
        FX.SOURCES = sources
        try:
            rows, collections = FX.build()
        finally:
            FX.SOURCES = saved
    return merge_collections(base, rows, collections)


@pytest.fixture(scope="module")
def view() -> TeamCbomView:
    return _view()


@pytest.fixture(scope="module")
def view_without_ad() -> TeamCbomView:
    return _view({k: v for k, v in FX.SOURCES.items() if k != AD_SOURCE})


def _story(module, view):
    return module.build_story(view, get_deliverable_styles(), WIDTH)


# ----------------------------------------------------------------------------------------------- the mapper
def test_every_lane_reaches_its_own_branch_and_nothing_falls_through_to_cloud_ca():
    """Review point 1: a type added to ``_LANES`` without its own branch silently became a private CA."""
    assert {"kerberos_account", "ad_domain"} <= M.MAPPED_TYPES
    assert M._LANES["kerberos_account"] == M._LANES["ad_domain"] == "sources_identity"
    from backend.utilities.pdf import cbom_posture_text as text

    assert text.KERBEROS_KINDS == M.KERBEROS_KINDS  # D6 keeps its own copy (the PDF import allow-list)
    sample = {}
    for _s, _k, _r, asset in FX.assets():
        sample.setdefault(asset["type"], asset["facts"])
    for node_type in M._LANES:
        # a collected shape where the fixture has one (database_config without a self-managed engine is None by
        # design: a cloud parameter group's storage row is the store), else no facts at all
        fact = M.posture_fact(node_type, sample.get(node_type, {}), fact_id="x")
        assert fact is not None, node_type
        if node_type == "cloud_ca":
            assert (fact["kind"], fact["native_type"]) == ("certificate_policy", "Private CA")
            continue
        assert fact["kind"] != "certificate_policy" and fact["native_type"] != "Private CA", node_type
        if node_type in FX.MAPPED_KIND:
            assert fact["kind"] == FX.MAPPED_KIND[node_type], node_type


def _asset(name):
    return next(a for s, _k, _r, a in FX.assets() if s == AD_SOURCE and a["name"] == name)


def test_a_kerberos_account_is_a_fact_with_its_strongest_key_type_and_no_at_rest_verdict():
    legacy = _asset("svc-legacy")
    fact = M.posture_fact("kerberos_account", legacy["facts"], fact_id="k", name="svc-legacy",
                          location=legacy["location"], algorithm=None, impact="High",
                          finding_codes=["KERBEROS_DES_ENABLED", "KERBEROS_RC4_ENABLED"], source_label=AD_LABEL,
                          source_kind="active_directory")
    assert fact["kind"] == "kerberos_account" and fact["lane"] == "sources_identity"
    assert fact["provider"] == "self_hosted" and fact["native_type"] == "Service account"
    # the strongest key type from the enctypes (not the stored ``algorithm``: rows from before #488 M4 had the weakest)
    assert fact["key_algorithm"] == "RC4-HMAC"
    assert fact["enc_types"] == "DES-CBC-CRC, DES-CBC-MD5, RC4-HMAC" and fact["enc_types_source"] == "attribute"
    assert fact["verdict"] is None and "layers" not in fact and "at_rest" not in fact
    sql = M.posture_fact("kerberos_account", _asset("svc-sql")["facts"], fact_id="s", name="svc-sql")
    assert (sql["key_algorithm"], sql["enc_types"], sql["dc_default"]) == ("", "", True)
    assert M.posture_fact("kerberos_account", _asset("DC1$")["facts"], fact_id="d")["key_algorithm"] == (
        "AES256-CTS-HMAC-SHA1-96")
    domain = M.posture_fact("ad_domain", _asset("corp.test")["facts"], fact_id="a", name="corp.test")
    assert domain["kind"] == "ad_domain" and domain["verdict"] is None
    assert domain["domain_functional_level_name"] == "Windows Server 2008 R2"
    assert domain["krbtgt_password_last_set"] == "2025-01-01T00:00:00Z"
    assert domain["accounts"]["service_account_rc4_only"] == 1
    assert domain["dc_operating_systems"] == ["Windows Server 2016 Datacenter 10.0 (14393)"]


def test_the_kerberos_enctype_order_is_one_table_on_both_sides():
    """n-4: the scan node's bit table (strongest first = its key types, highest bit first) and the backend's
    KERBEROS_ENCTYPES must name the same key types in the same order, or ``algorithm`` and ``algorithmRef`` drift."""
    from backend.utilities.cbom_sources.classify_ext.ad import KERBEROS_ENCTYPES

    source = (_REPO_ROOT / "scan_node/zs_scan_node/collectors/active_directory.py").read_text()
    values = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in ("ENCTYPE_BITS", "ENCTYPE_FLAGS"):
            values[node.targets[0].id] = node.value
    bits = ast.literal_eval(values["ENCTYPE_BITS"])
    flags = ast.literal_eval(values["ENCTYPE_FLAGS"].args[0])  # frozenset({...})
    strongest_first = [name for bit, name in reversed(bits) if bit not in flags]
    assert strongest_first == list(KERBEROS_ENCTYPES)


# ----------------------------------------------------------------------------------------------- D6
def test_d6_prints_the_kerberos_and_ad_register(view):
    body = _story(d6, view)
    rows = rows_under(body, "Domain")
    by_check = {row["Check"]: row for row in rows if row["Domain"] == "corp.test"}
    assert list(by_check) == ["Domain functional level", "krbtgt key age", "Accounts with RC4 only",
                              "Accounts on the DC default", "LDAPS TLS posture"]
    assert by_check["Domain functional level"]["Reading"] == "Windows Server 2008 R2 (level 4)"
    assert "AD_FUNCTIONAL_LEVEL_LEGACY" in by_check["Domain functional level"]["Finding codes"]
    assert by_check["krbtgt key age"]["Reading"] == "691 days (last set 2025-01-01)"
    assert by_check["krbtgt key age"]["Finding codes"] == "KRBTGT_KEY_OLD"
    assert by_check["Accounts with RC4 only"]["Reading"] == "1: svc-rc4only"
    assert by_check["Accounts with RC4 only"]["Finding codes"] == "KERBEROS_RC4_ONLY"
    # 2 service accounts listed by name, 4 computers counted by the collector and not listed (krbtgt is judged by the
    # functional level and its key age, never by the DC default)
    assert by_check["Accounts on the DC default"]["Reading"] == "6: svc-sql, svc-zero and 4 more not listed"
    assert by_check["Accounts on the DC default"]["Finding codes"] == "KERBEROS_ENCTYPES_DEFAULT"
    ldaps = by_check["LDAPS TLS posture"]
    assert ldaps["Reading"].startswith("dc1.corp.test:636: TLS 1.0 to TLS 1.3")
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in ldaps["Reading"] and "SOW D7" in ldaps["Reading"]
    assert all(row["Source"] == AD_LABEL for row in rows)


def test_d6_kpis_move_by_exactly_the_ad_facts_and_d9_is_unchanged(view, view_without_ad):
    with_ad, without = kpi_cards(_story(d6, view)), kpi_cards(_story(d6, view_without_ad))
    assert int(with_ad["Facts"]) - int(without["Facts"]) == 7  # corp.test + the 6 account rows; LDAPS is D7's
    ad_facts = [f for f in d6.scope_facts(view) if f.get("kind") in ("kerberos_account", "ad_domain")]
    assert len(ad_facts) == 7 and {f["source"] for f in ad_facts} == {AD_LABEL}
    for card in ("Encrypted (declared)", "Encrypted (provider default)", "Not encrypted", "Unknown", "KMS keys"):
        assert with_ad[card] == without[card], card  # verdict None: the at-rest KPIs do not move
    findings = rows_under(_story(d6, view), "Label")
    for band in ("High", "Medium", "Low"):
        listed = sum(int(row["Count"]) for row in findings if row["Impact"] == band)
        assert with_ad[f"Findings {band}"] == str(listed), band
    labels = {row["Label"] for row in findings}
    assert len(labels) == len(findings)
    codes = {c for f in ad_facts for c in f["finding_codes"]}
    assert codes == {"AD_FUNCTIONAL_LEVEL_LEGACY", "KRBTGT_KEY_OLD", "KERBEROS_RC4_ONLY", "KERBEROS_RC4_ENABLED",
                     "KERBEROS_DES_ENABLED", "KERBEROS_ENCTYPES_DEFAULT"}
    # D9 (at rest) reads none of it
    d9_with, d9_without = _story(d9, view), _story(d9, view_without_ad)
    cards_with, cards_without = kpi_cards(d9_with), kpi_cards(d9_without)
    assert (cards_with.pop("Sources"), cards_without.pop("Sources")) == ("17/17", "16/16")  # one more source
    assert cards_with == cards_without
    for table_with, table_without in zip(_registers(d9_with), _registers(d9_without), strict=True):
        assert table_with == table_without


def _registers(story):
    """Every table's text except the source-status register and the Sources card (one more source)."""
    out = []
    for table in iter_tables(story):
        cells = [[cell_text(c) for c in row] for row in table._cellvalues]
        if cells and cells[0] and cells[0][0] in ("Source", "Sources"):  # source status; the Sources KPI card
            continue
        out.append(cells)
    return out


def test_d6_limits_say_the_dc_default_is_not_readable_over_ldap(view, view_without_ad):
    from backend.utilities.pdf import cbom_posture_text as text

    def limits(story):
        return " ".join(cell_text(f) if hasattr(f, "text") else "" for f in story)

    assert text.KERBEROS_DC_DEFAULT_LIMIT in limits(_story(d6, view))
    assert text.KERBEROS_DC_DEFAULT_LIMIT not in limits(_story(d6, view_without_ad))


# ----------------------------------------------------------------------------------------------- planning (n-3)
from test_cbom_sources_api import PASSWORD, api, world  # noqa: E402,F401


def _segment_world(engine, versions: dict[str, list[str]]) -> int:
    from backend.new_models import CbomCollectionSource, CbomScanNode
    from backend.utilities.cbom_sources.kinds import KINDS

    cfg = KINDS["active_directory"].model.model_validate(
        {"targets": ["dc01.corp.example"], "credential_type": "password", "login_user": "svc@corp.example",
         "window": "any"})
    with Session(engine) as s:
        for i, (version, collectors) in enumerate(versions.items()):
            s.add(CbomScanNode(team_id=1, owner_user_id=1, name=f"dmz-{i}", segment="DMZ",
                               node_token_hash=f"{i:064d}", signing_public_key="k" * 44, node_version=version,
                               capabilities={"collectors": collectors}))
        src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="active_directory", name="corp-ad-dmz",
                                   name_lower="corp-ad-dmz", node_id=None, node_segment="DMZ",
                                   config=cfg.model_dump(mode="json"), last_test_status="passed")
        s.add(src)
        s.commit()
        return int(src.id)


def test_n3_a_segment_whose_nodes_all_lack_the_ad_collector_says_update_a_node(api, world):  # noqa: F811
    engine, _ = world
    src = _segment_world(engine, {"1.0.6": ["linux_ssh", "network_tls"], "1.0.2": ["linux_ssh"]})
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    item = next(i for i in est["skipped"] if i["source_id"] == src)
    assert item["reason"].startswith("Needs a scan node with Active Directory support: no scan node of segment DMZ "
                                     "has it"), item["reason"]
    assert "dmz-0 runs 1.0.6" in item["reason"] and "dmz-1 runs 1.0.2" in item["reason"]
    assert "after 1.0.6" in item["reason"]


def test_n3_one_capable_member_is_enough_and_the_source_is_queued(api, world):  # noqa: F811
    engine, _ = world
    src = _segment_world(engine, {"1.0.6": ["linux_ssh"], "1.0.7": ["linux_ssh", "ad_ldaps"]})
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    assert not any(i["source_id"] == src for i in est["skipped"]), est["skipped"]
    assert any(i["source_id"] == src and i["status"] == "queued" for i in est["items"])
