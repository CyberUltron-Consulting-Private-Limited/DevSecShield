"""Staging QA round 2 (lane Q4) on SOW D12, D13, S1 and S3, and lane Q1's Q1-08 (fix/cbom-register-roadmap-qa2).

* M1   D13 first-found / fix-by dates never move between renders: a certificate one source reads at two places has ONE
       estate observation; the other place is dated from the estate's de-duplicated identity or its earliest stored
       observation, never from the collection being rendered.
* M2   D13: the card, section 3, the collected-infrastructure section and the waves count one population; symmetric
       and algorithm-less assets are not planned; "Distinct kinds" is not 0 when every asset is collected.
* M3   the SOW class (deprecated / quantum-broken / weakened / quantum-safe / unknown / not applicable) in the D12 PDF
       and the CSV, the same label; RSA-1024, Triple DES, SHA-1 read "deprecated", with "also quantum-broken".
* M4   one population reconciliation (``cbom_sources.reconciliation``) printed by D1, D12, D13, D14 and the dashboard;
       Q1-08: the dashboard is folded from the same team roll-up (a superseded code scan is history).
* m1 m2 m3 m4 m6 m8 m10 m12 m14 (see each test).
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlmodel import Session, select

_BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND / "tests"))

from test_cbom_cb20_estate import NOW, World, _sqlite, cert  # noqa: E402
from test_cbom_deliverable_pqc_roadmap import pdf_full_text  # noqa: E402
from test_cicd_cbom_gate import (  # noqa: E402, F401  (the hosted-gate route fixture)
    _post,
    ci,
)

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomEstateObservation,
    Scan,
)
from backend.utilities.cbom_sources import qgrade as QG  # noqa: E402
from backend.utilities.cbom_sources import reconciliation as RECON  # noqa: E402
from backend.utilities.cbom_sources import risk_register as REG  # noqa: E402
from backend.utilities.cbom_sources import sow_class as SC  # noqa: E402
from backend.utilities.cbom_sources import waves as W  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    TeamCbomView,
    load_team_cbom_view,
)
from backend.utilities.pdf import cbom_deliverable_common as common  # noqa: E402
from backend.utilities.pdf import cbom_pqc_roadmap_pdf as roadmap  # noqa: E402
from backend.utilities.pdf import cbom_risk_register_pdf as RPDF  # noqa: E402
from backend.utilities.pdf.cbom_deliverables import DELIVERABLES  # noqa: E402

UTC = dt.timezone.utc
SERIAL = "7A:B1:9C:00:12:7B:3E:55:90:AB:CD:EF:01:99"
NOT_AFTER = "2028-01-31T00:00:00Z"
CERT_FACTS = {"serial": SERIAL, "not_after": NOT_AFTER, "fingerprint_sha256": "9f" * 32,
              "subject": "CN=lab-mssql", "issuer": "CN=lab-mssql", "key_alg": "RSA", "key_size": 1024}
SECOND_DAY = dt.timedelta(days=10)


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _mssql_cert(location: str) -> dict:
    row = cert("lab-mssql:1433", location, **CERT_FACTS)
    return {**row, "name": "CN=lab-mssql", "qv": True, "impact": "High",
            "codes": ["WEAK_KEY_SIZE", "QUANTUM_VULNERABLE"]}


def _shift(engine, run_id: int, delta: dt.timedelta) -> None:
    """Move a World run (its rows and jobs) ``delta`` later: a collection on another day."""
    with Session(engine) as s:
        for row in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all():
            row.created_at = row.created_at + delta
            s.add(row)
        for job in s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).all():
            job.finished_at = (job.finished_at or job.created_at or NOW) + delta
            s.add(job)
        run = s.get(CbomCollectionRun, run_id)
        run.finished_at = (run.finished_at or NOW) + delta
        s.add(run)
        s.commit()


# ============================================================================ M1
@pytest.fixture()
def two_collections(tmp_path):
    """One certificate the lab-mssql source reads in two databases (master and msdb), collected on two days."""
    w = World(_sqlite(tmp_path / "m1.db"))
    sid = w.source("database", "lab-mssql")
    rows = [_mssql_cert("lab-mssql:1433/master"), _mssql_cert("lab-mssql:1433/msdb")]
    first = w.run({sid: {"rows": rows}})
    w.finalise(first)
    second = w.run({sid: {"rows": rows}})
    _shift(w.engine, second, SECOND_DAY)
    w.finalise(second)
    return w, second


def test_m1_the_estate_keeps_one_observation_for_the_two_places(two_collections):
    w, _second = two_collections
    with Session(w.engine) as s:
        assert len(s.exec(select(CbomEstateObservation)).all()) == 1  # why one place had no observation key


def test_m1_both_places_are_first_found_on_the_first_collection_at_any_now(two_collections):
    w, second = two_collections
    first_day = (NOW + dt.timedelta(hours=1)).date().isoformat()
    seen = []
    for now in (dt.date(2026, 11, 30), dt.date(2027, 9, 1)):  # two renders, months apart
        with Session(w.engine) as s:
            items = W.node_items(s, 1, s.get(CbomCollectionRun, second), as_of=now)
        by_place = {i["label"].rsplit("/", 1)[-1]: i for i in items}
        assert set(by_place) == {"master", "msdb"}
        assert {i["first_seen_on"] for i in items} == {first_day}, items  # never the second collection's day
        assert {i["found_on"] for i in items} == {first_day}
        seen.append({k: (v["first_seen_on"], v["fix_by"], v["pq_by"]) for k, v in by_place.items()})
    assert seen[0] == seen[1]
    assert seen[0]["master"] == seen[0]["msdb"]


def test_m1_d13_prints_the_same_found_and_fix_dates_on_two_days(two_collections):
    w, _second = two_collections
    texts = []
    for now in (dt.datetime(2026, 11, 30, 9, tzinfo=UTC), dt.datetime(2026, 12, 20, 9, tzinfo=UTC)):
        view = load_team_cbom_view(w.engine, 1, now=now)
        texts.append(_squash(pdf_full_text(roadmap.build_pdf(view))))
    founds = [sorted(re.findall(r"fix \(proposed\) found (\d{4}-\d{2}-\d{2})", t)) for t in texts]
    assert founds[0] == founds[1] and founds[0] and set(founds[0]) == {(NOW + dt.timedelta(hours=1)).date().isoformat()}
    fixes = [sorted(re.findall(r"(\d{4}-\d{2}-\d{2}) fix \(proposed\)", t)) for t in texts]
    assert fixes[0] == fixes[1] and fixes[0]


def test_m1_a_row_the_estate_never_recorded_is_its_own_first_observation(tmp_path):
    w = World(_sqlite(tmp_path / "m1b.db"))
    sid = w.source("database", "db")
    run = w.run({sid: {"rows": [_mssql_cert("db:1433/master")]}})  # not finalised: no estate yet
    with Session(w.engine) as s:
        (item,) = W.node_items(s, 1, s.get(CbomCollectionRun, run), as_of=dt.date(2026, 12, 1))
    assert item["first_seen_on"] == (NOW + dt.timedelta(hours=1)).date().isoformat()


# ============================================================================ the seeded team (M2, M3, M4)
def _code_scan(engine, scan_id: int, created: dt.datetime, rows: list[dict]) -> None:
    with Session(engine) as s:
        s.add(Scan(id=scan_id, team_id=1, owner_user_id=1, scan_type="cbom", title="pay", scan_status="success",
                   scan_metadata={"repo_url": "https://github.com/acme/pay", "branch": "main"}, created_at=created,
                   last_updated=created, scan_data={"results": rows}))
        s.commit()


def _code_row(title: str, bom_ref: str, qv: bool | None, impact: str = "High", codes=("QUANTUM_VULNERABLE",)) -> dict:
    return {"title": title, "algorithm_name": title.split("-")[0], "asset_type": "algorithm", "algorithm_type": "pke",
            "location": f"src/{bom_ref}.py:1", "bom_ref": bom_ref, "impact": impact, "key_size": 1024,
            "finding_codes": list(codes), "quantum_vulnerable": qv, "quantum_safe": None if qv is None else not qv}


def _endpoint() -> dict:
    return {"type": "tls_endpoint", "target": "pay.example.com", "location": "pay.example.com:443", "name": "TLS",
            "algorithm": "ECDHE-RSA", "qv": True, "impact": "High", "codes": ["PROTO_TLS10", "QUANTUM_VULNERABLE"],
            "facts": {"protocol": "TLSv1.0", "negotiated_group": "secp256r1", "port": 443}}


@pytest.fixture()
def team(tmp_path):
    return seed_team(tmp_path / "team.db")


def seed_team(db: Path) -> World:
    """The seeded team: lab-mssql (one RSA-1024 certificate in two databases), aws-prod (Triple DES, AES-128 marked
    quantum-vulnerable, an RSA-2048 signing key, a policy with no algorithm), two network probes of one endpoint, and
    one repository scanned twice (the first scan superseded)."""
    w = World(_sqlite(db))
    db = w.source("database", "lab-mssql")
    aws = w.source("aws_account", "aws-prod")
    net_a = w.source("network_range", "dmz-a")  # two probes of one public endpoint: one occurrence in each source,
    net_b = w.source("network_range", "dmz-b")  # one estate asset
    w.finalise(w.run({
        db: {"rows": [_mssql_cert("lab-mssql:1433/master"), _mssql_cert("lab-mssql:1433/msdb")]},
        aws: {"rows": [
            {"type": "managed_key", "target": "arn:aws:kms:ap-south-1:1:key/a", "location": "kms", "name": "legacy-3des",
             "algorithm": "DES-EDE3", "qv": None, "impact": "High", "codes": ["WEAK_ALGORITHM"], "facts": {}},
            {"type": "managed_key", "target": "arn:aws:kms:ap-south-1:1:key/b", "location": "kms", "name": "aes-128",
             "algorithm": "AES", "qv": True, "impact": "Low", "codes": ["QUANTUM_VULNERABLE"],
             "facts": {"key_size": 128}},
            {"type": "kms_key", "target": "arn:aws:kms:ap-south-1:1:key/c", "location": "kms", "name": "signer",
             "algorithm": "RSA_2048", "qv": True, "impact": None, "codes": ["QUANTUM_VULNERABLE"],
             "facts": {"key_spec": "RSA_2048", "key_usage": "SIGN_VERIFY"}},
            {"type": "appliance_config", "target": "fw-1", "location": "fw-1#policy", "name": "unknown policy",
             "algorithm": None, "qv": True, "impact": None, "codes": ["QUANTUM_VULNERABLE"], "facts": {}},
        ]},
        net_a: {"rows": [_endpoint()]},
        net_b: {"rows": [_endpoint()]},
    }))
    # Q1-08: the repository was scanned twice; the documents count the latest scan only
    _code_scan(w.engine, 901, dt.datetime(2026, 11, 1, 9), [_code_row("RSA-1024", "rsa", True),  # noqa: DTZ001
                                                            _code_row("RSA-512", "old", True)])
    _code_scan(w.engine, 902, dt.datetime(2026, 11, 10, 9), [_code_row("RSA-1024", "rsa", True)])  # noqa: DTZ001
    return w


def _view(w: World, now: dt.datetime | None = None) -> TeamCbomView:
    return load_team_cbom_view(w.engine, 1, now=now or dt.datetime(2026, 11, 20, 9, tzinfo=UTC))


def _text(slug: str, view: TeamCbomView) -> str:
    return _squash(pdf_full_text(DELIVERABLES[slug].build(view)))


# ============================================================================ M2
def test_m2_d13_counts_one_population_and_never_plans_symmetric_or_algorithm_less_assets(team):
    view = _view(team)
    pop = view.remediation["population"]
    assert pop["symmetric"] == 1 and pop["no_algorithm"] == 1  # the AES-128 key, the policy with no algorithm
    rows = roadmap._roadmap_assets(view)
    planned = roadmap.planned_count(view, rows)
    q = RECON.quantum_counts(view)
    assert planned == q["planned"] == len(rows) + pop["sources_planned"]
    assert q["occurrences"] == view.pqc_vulnerable == q["planned"] + q["symmetric"] + q["no_algorithm"] + q["code_other"]
    node_rows = view.remediation["node_rows"]
    assert len(node_rows) == pop["sources_planned"]
    assert all(W.plan_exclusion(r["pq_usage"]) is None for r in node_rows)
    text = _text("pqc-migration-roadmap", view)
    assert f"Quantum-vulnerable {planned} public-key assets planned" in text
    section3 = text[text.index("NIST post-quantum targets by function"):]
    section3 = section3[:section3.index("Per-asset roadmap") if "Per-asset roadmap" in section3 else 3000]
    assert "Symmetric encryption" not in section3 and "not derivable" not in section3
    assert "Not listed: 1 symmetric or hash asset(s) and 1 with no algorithm recorded" in text
    assert "Distinct kinds 0" not in text


def test_m2_distinct_kinds_counts_collected_assets_when_the_code_scans_have_none(team):
    view = _view(team)
    view.assets = tuple(a for a in view.assets if a.source_key.startswith("sources:"))
    assert roadmap.distinct_kinds(view, []) >= 2  # RSA 1024 (the certificate) and the RSA_2048 KMS key


def test_m2_section_4_heading_says_what_it_means():
    from backend.utilities.pdf import cbom_deliverable_text as authored

    assert authored.PQC_NO_VULNERABLE_CODE_TITLE == "Code scans: no quantum-vulnerable public-key algorithm to plan"
    assert "{count}" in authored.PQC_NO_VULNERABLE_CODE_TEXT


# ============================================================================ M3
@pytest.mark.parametrize("grade, reason, disallowed, expected", [
    ("Q2", "deprecated", False, SC.DEPRECATED),  # RSA-1024 of unknown exposure (the disallowed cap)
    ("Q1", "deprecated_internet", False, SC.DEPRECATED),
    ("Q1", "qv_exceeds_anchor", True, SC.DEPRECATED),  # an RSA-1024 CA: the cap keeps Q1, the class says deprecated
    ("Q1", "qv_exceeds_anchor", False, SC.BROKEN),  # an RSA-2048 CA
    ("Q2", "qv_exceeds", False, SC.BROKEN),
    ("Q2", "qv_fallback_exceeds", False, SC.BROKEN),
    ("Q3", "grover_weakened", False, SC.WEAKENED),
    ("Q4", "pq_observed", False, SC.SAFE),
    ("Q3", "pq_attested_e1", False, SC.SAFE),
    ("Q0", "unknown_verdict", False, SC.UNKNOWN),
    ("Q0", "not_correlated", True, SC.UNKNOWN),
    (None, "not_applicable", False, SC.NOT_APPLICABLE),
])
def test_m3_sow_class_follows_the_grade(grade, reason, disallowed, expected):
    assert SC.sow_class(grade, reason, disallowed) == expected
    assert SC.sow_class(grade, reason, lambda: disallowed) == expected


def test_m3_every_qg1_reason_has_a_sow_class():
    for code, meta in QG.REASONS.items():
        label = SC.sow_class(meta["grade"], code)
        assert label in SC.CLASSES, code
        if meta["grade"] in ("Q1", "Q2", "Q3", "Q4"):
            assert label in SC.GRADED_CLASSES, code  # a graded row is never "unknown"


def test_m3_csv_and_pdf_print_the_same_class_and_both_facts(team):
    view = _view(team)
    with Session(team.engine) as s:
        items = REG.list_register(s, 1, {}, after=None, limit=500, detail=True, now=dt.datetime(2026, 11, 20))["items"]  # noqa: DTZ001
    by_label = {i["label"].split(" · ")[0]: i for i in items}
    rsa = next(i for k, i in by_label.items() if k.startswith("CN=lab-mssql"))
    des = by_label["legacy-3des"]
    assert (rsa["sow_class"], rsa["also_quantum_broken"]) == ("deprecated", "yes")  # RSA-1024: both facts
    assert (des["sow_class"], des["also_quantum_broken"]) == ("deprecated", "no")
    csv_text = b"".join(REG.csv_rows(team.engine, 1, {}, now=dt.datetime(2026, 11, 20))).decode("utf-8-sig")  # noqa: DTZ001
    header = csv_text.splitlines()[0].split(",")
    assert header[header.index("sow_class") + 1] == "also_quantum_broken" and "pqc_class" in header
    rows = [dict(zip(header, line.split(","))) for line in csv_text.splitlines()[1:]]
    assert {r["sow_class"] for r in rows} <= set(SC.CLASSES)
    summary = view.register["summary"]
    assert sum(summary["sow_classes"].values()) == summary["total"]
    assert summary["sow_classes"]["deprecated"] == sum(1 for r in rows if r["sow_class"] == "deprecated")
    pdf = _text("quantum-risk-register", view)
    assert "deprecated also quantum-broken" in pdf  # the cell's two lines
    assert "SOW class" in pdf and pdf.count("deprecated") >= 3  # QA2: the word never appeared


def test_m3_anchor_reason_counts_move_to_deprecated_when_the_row_is_disallowed():
    groups = [("Q1", "qv_exceeds_anchor", "RSA", "present", 3), ("Q2", "deprecated", "RSA", "present", 2),
              ("Q2", "qv_exceeds", "RSA", "present", 4), (None, "not_applicable", None, "present", 1)]
    counts = SC.counts(groups, anchors_disallowed=1)
    assert counts[SC.DEPRECATED] == 3 and counts[SC.BROKEN] == 6 and counts[SC.NOT_APPLICABLE] == 1
    assert sum(counts.values()) == 10


# ============================================================================ m6
def test_m6_a_disallowed_key_is_never_graded_better_than_a_quantum_vulnerable_one_in_the_same_role():
    def g(anchor: bool, exposure: str, disallowed: bool):
        return QG.grade(QG.GradeInput(item="asset", cls="quantum-vulnerable", fallback=False, exposure=exposure,
                                      anchor=anchor, x=7, y=5, z=9, provenance="observed", disallowed=disallowed))
    rank = {"Q1": 1, "Q2": 2, "Q3": 3, "Q4": 4}
    for anchor in (False, True):
        for exposure in ("internet", "internal", "unknown"):
            weak, strong = g(anchor, exposure, True), g(anchor, exposure, False)
            assert rank[weak.q_grade] <= rank[strong.q_grade], (anchor, exposure)
    assert g(False, "unknown", True).q_grade == "Q2" and g(True, "internal", False).q_grade == "Q1"
    assert "How grades compare" in RPDF.GRADE_COMPARE_NOTE and "RSA-1024" in RPDF.GRADE_COMPARE_NOTE


# ============================================================================ M4 / Q1-08
def test_m4_every_document_prints_the_same_reconciliation(team):
    view = _view(team)
    lines = RECON.lines(RECON.from_view(view))
    assert [ln.split(".")[0] for ln in lines] == [str(i) for i in range(1, len(lines) + 1)]
    for slug in ("scope-baseline-register", "quantum-risk-register", "pqc-migration-roadmap", "board-executive-report"):
        text = _text(slug, view)
        assert "Population reconciliation" in text, slug
        for line in lines:
            assert _squash(line) in text, (slug, line)


def test_m4_the_chain_adds_up_and_names_every_bucket(team):
    view = _view(team)
    pop = RECON.from_view(view)
    r = RECON.register_numbers(pop.register)
    assert pop.occurrences == pop.sources_occurrences + pop.code_occurrences
    # the certificate both lab-mssql places hold is counted once; the endpoint both probes read is one occurrence in
    # each source and one register asset; the code scan counts once (its latest scan)
    assert (pop.collected, pop.sources_occurrences, pop.code_occurrences) == (8, 7, 1)
    assert r["graded"] + r["q0"] + r["none"] == r["total"]
    assert sum(r[c] for c in SC.GRADED_CLASSES) == r["graded"]
    text = " ".join(RECON.lines(pop))
    for bucket in ("code-scan occurrence", "of an estate asset already counted", "no latest collection holds",
                   "quantum-broken", "deprecated", "Q0 Unknown", "no grade", "symmetric or hash",
                   "with no algorithm recorded"):
        assert bucket in text, bucket
    assert "8 run assets minus 1 observation of an asset another source also observed" in text
    assert "minus 1 CBOM Sources occurrence of an estate asset already counted" in text
    assert f"= {r['total']} distinct assets in the Quantum Risk Register (D12)" in text and r["total"] == 6


def _dashboard(team: World, monkeypatch, now: dt.datetime) -> dict:
    from backend.utilities.cbom_sources.collections_view import load_sources_result
    from backend.utilities.dashboard import scan_list

    monkeypatch.setattr(scan_list, "get_findings_for_scan_id", lambda **_kw: [])
    with Session(team.engine) as s:
        scans = s.exec(select(Scan).where(Scan.team_id == 1)).all()
        sources = load_sources_result(s, 1, now)
        summary = REG.summary(s, 1, now.replace(tzinfo=None))
        return scan_list.generate_cbom_dashboard_data(list(scans), sources, team_id=1, register_summary=summary,
                                                      now=now)


def test_q1_08_the_dashboard_counts_what_the_documents_count(team, monkeypatch):
    now = dt.datetime(2026, 11, 20, 9, tzinfo=UTC)
    view = _view(team, now)
    board = _dashboard(team, monkeypatch, now)
    card = board["card_data"]
    assert card["total_crypto_assets"] == view.asset_occurrences == 8  # scan 901 (superseded) is history
    assert card["total_quantum_vulnerable"] == view.pqc_vulnerable
    assert card["quantum_readiness_score"] == (view.readiness_pct or 0.0)
    steps = {s["key"]: s for s in board["population"]["steps"]}
    doc = {s["key"]: s for s in RECON.steps(RECON.from_view(view))}
    for key in ("run_assets", "occurrences", "register", "classes"):
        assert steps[key]["value"] == doc[key]["value"], key
        assert steps[key]["text"].split(". ", 1)[1] == doc[key]["text"].split(". ", 1)[1], key
    assert steps["dashboard_card"]["value"] == card["total_crypto_assets"]
    assert "counts 8: the same occurrences" in steps["dashboard_card"]["text"]


# ============================================================================ m1 (D13 code signing)
def test_m1_d13_names_the_cnsa_code_signing_target(team):
    line = roadmap.code_signing_line()
    assert "LMS" in line and "XMSS" in line and "ML-DSA-87" in line
    assert _squash(line) in _text("pqc-migration-roadmap", _view(team))


# ============================================================================ m2 (Document ID)
def test_m2_a_change_only_another_document_prints_keeps_this_documents_id(team):
    view = _view(team)
    ids = {n: common.document_id(view, n) for n in (2, 10, 12, 13, 14)}
    view.methodology = {**(view.methodology or {}), "runs": {"total": 99, "scheduled": 0, "manual": 99}}
    view.vendors = ({"name": "HSM vendor", "status": "overdue"},)
    after = {n: common.document_id(view, n) for n in (2, 10, 12, 13, 14)}
    assert after[12] == ids[12] and after[13] == ids[13] and after[14] == ids[14]
    assert after[2] != ids[2] and after[10] != ids[10]  # their own content changed
    view.grade_inputs = {"digest": "ffff", "model_version": "x"}
    assert common.document_id(view, 12) != ids[12]  # a change D12 prints still moves its ID


def test_m2_the_same_content_gives_the_same_id_in_two_loads(team):
    a, b = _view(team), _view(team, dt.datetime(2026, 11, 20, 17, tzinfo=UTC))
    for n in (1, 12, 13, 14):
        assert common.document_id(a, n) == common.document_id(b, n)


# ============================================================================ m3 m4 m8 (D12 layout)
def test_m3_section_f_title_says_it_is_capped():
    reg = {"assets": [{}] * 2000, "assets_total": 2058}
    assert RPDF.assets_title(reg) == ("F. Assets with their grade: the first 2,000 of 2,058 rows, worst first "
                                      "(58 omitted; the register CSV holds every row)")
    assert RPDF.assets_title({"assets": [{}] * 3, "assets_total": 3}) == "F. Every asset with its grade"


def test_m4_repeated_scope_gaps_name_their_check_or_fold():
    base = {"reason": "coverage_gap", "sub_reason": None, "item_kind": "scope", "title": "azure:3f8e",
            "source_name": "Azure tenant", "opened_at": "2026-11-18T04:02:50Z", "age_days": 6}
    gaps = [{**base, "detail": {"check": "key vault zslabkv02 secrets", "status": "blocked_by_firewall",
                                "detail": "ForbiddenByFirewall"}},
            {**base, "detail": {"check": "sql servers in subscription 3f8e", "status": "not_found"}},
            {**base, "detail": {"check": "target", "status": "error", "detail": "storage: not_found"}},
            {**base, "detail": {"check": "target", "status": "error", "detail": "storage: not_found"}}]
    rows = RPDF.gap_rows(gaps)
    assert len(rows) == 3
    items = [r[3] for r in rows]
    assert any("key vault zslabkv02 secrets" in i for i in items) and any("sql servers" in i for i in items)
    assert any("identical gaps" in i for i in items)
    assert rows[0][1].startswith("blocked by firewall")


def test_m8_the_asset_column_is_wide_enough_and_addresses_break_only_at_punctuation():
    assert 720 - sum(RPDF._ASSET_FIXED) >= 150  # was 66 pt: 235 pages of 2-4 rows for team 1
    owner = RPDF._ASSET_FIXED[-1]
    for line in RPDF.breakable("priya.sharma-pki@cholamandalam.example.com", owner).split("\n"):
        assert line[-1:] in ("@", ".", "-") or line.endswith("com"), line  # never mid-word


# ============================================================================ m10 m12 (CI/CD)
def test_m12_a_dispatch_failure_is_logged_with_its_reason_and_no_secret():
    from fastapi import HTTPException

    from backend.routers import cicd as router
    from backend.utilities.db.s3_utils import StorageUnavailable

    stored = []
    logs = SimpleNamespace(insert_one=lambda doc: stored.append(dict(doc)) or SimpleNamespace(inserted_id="x1"))
    assert router.log_dispatch_failure(logs, 7, StorageUnavailable("InvalidAccessKeyId"), True) == "x1"
    (doc,) = stored
    assert doc["status"] == "failure" and doc["credits_consumed"] is None and doc["ci_cd_integration_id"] == 7
    assert doc["error"].startswith("HTTP 503: File storage is unavailable (the storage credentials were rejected)")
    assert "No credits were charged." in doc["error"]
    assert "AKIA" not in doc["error"]
    secret = RuntimeError("aws_secret_access_key=abc123 leaked")
    router.log_dispatch_failure(logs, 7, secret, True)
    assert "abc123" not in stored[-1]["error"] and "RuntimeError" in stored[-1]["error"]
    assert router.dispatch_failure_reason(HTTPException(status_code=400, detail="bad")) == "HTTP 400: bad"


@pytest.fixture()
def failing_ci(ci, monkeypatch):  # noqa: F811
    from backend.utilities.db.s3_utils import StorageUnavailable

    async def _start(**_kw):
        raise StorageUnavailable("InvalidAccessKeyId")

    monkeypatch.setattr("backend.routers.cicd.start_cicd_scan_and_update_db", _start)
    monkeypatch.setattr("backend.utilities.team.credits.refund_credits_to_team", lambda **_kw: None)
    return ci


def test_m12_a_hosted_gate_503_is_in_the_delivery_log(failing_ci):
    http, _state, logs, auth_as = failing_ci
    auth_as("cbom")
    response = _post(http, "cbom")
    assert response.status_code == 503
    (doc,) = logs.docs.values()
    assert doc["status"] == "failure" and "storage credentials were rejected" in doc["error"]
    assert doc["credits_consumed"] is None


def test_m10_integration_times_are_utc_with_z():
    from backend.utilities.cbom_sources.common import iso_z

    assert iso_z(dt.datetime(2026, 11, 24, 5, 48)) == "2026-11-24T05:48:00Z"  # noqa: DTZ001
    source = (_BACKEND / "routers" / "cicd.py").read_text()
    assert source.count('"created_at": iso_z(integration.created_at)') == 2


# ============================================================================ m14 (OSCAL)
def test_m14_oscal_has_risks_from_findings_and_a_real_assessment_plan():
    from backend.utilities.cbom_sources import drift as D
    from backend.utilities.integrations import oscal as OSCAL

    view = D.View(identity="i", key="k1", label="RSA-1024 · api", asset_type="algorithm",
                  codes=frozenset({"WEAK_KEY_SIZE", "QUANTUM_VULNERABLE"}), impact="High", quantum_vulnerable=True,
                  finding=True, judged=True, extra={"target": "api", "location": "src/a.py"})
    doc = OSCAL.assessment_results(team_id=1, anchor="run-1", title="Run 1", namespace="node",
                                   start=dt.datetime(2026, 11, 24, 5, tzinfo=UTC), end=None,
                                   views=[("api source", view)], kb_version="kb", description="Run 1 scope",
                                   team=None)
    assert OSCAL.validate(doc) == []
    ar = doc["assessment-results"]
    result = ar["results"][0]
    risks = {r["uuid"]: r for r in result["risks"]}
    assert len(risks) == len({p["value"] for f in result["findings"] for p in f["props"] if p["name"] == "finding-code"})
    assert all(r["status"] == "open" and r["related-observations"] for r in risks.values())
    assert all(f["related-risks"][0]["risk-uuid"] in risks for f in result["findings"])
    href = ar["import-ap"]["href"]
    assert href.startswith("#") and "urn:" not in href
    (resource,) = [r for r in ar["back-matter"]["resources"] if r["uuid"] == href[1:]]
    plan = json.loads(base64.b64decode(resource["base64"]["value"]))
    assert OSCAL.validate_plan(plan) == []
    ap = plan["assessment-plan"]
    assert ap["import-ssp"]["href"][1:] in {r["uuid"] for r in ap["back-matter"]["resources"]}
    assert ap["reviewed-controls"] == {**ap["reviewed-controls"],
                                       "control-selections": result["reviewed-controls"]["control-selections"]}
    again = OSCAL.assessment_results(team_id=1, anchor="run-1", title="Run 1", namespace="node",
                                     start=dt.datetime(2026, 11, 24, 5, tzinfo=UTC), end=None,
                                     views=[("api source", view)], kb_version="kb", description="Run 1 scope",
                                     team=None)
    assert again["assessment-results"]["back-matter"] == ar["back-matter"]  # byte-stable for one run
