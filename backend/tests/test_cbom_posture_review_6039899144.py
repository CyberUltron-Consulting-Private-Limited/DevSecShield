"""Review 6039899144 of PR #499 (D6-D10 staging QA round 2), every finding at its root cause.

B1   Rule P: the run's assets API, posture, heat map and results were folded (one resource counted once), but the CBOM
     Scans table / ``GET /runs`` (``run_list.asset_counts`` / ``grouped_counts``), the CycloneDX export, the
     remediation waves (and the run's tickets) and the parity page still counted both jobs' rows: 458 for 229.
M1   ``sni not in base`` was a substring test: ``api.example.com:443`` with SNI ``example.com`` was the endpoint with
     no SNI, and ``10.0.0.15:443`` with SNI ``10.0.0.1`` too.
M2   ``"/subscriptions/" in where`` / ``startswith("projects/")`` made file paths cloud ids (two hosts merged), and a
     private address or "localhost" carried no network scope (two sites' 10.0.0.5:22 merged).
M4   A newer collection that read nothing (status success, outcome failed) replaced the source's last read: D8 and the
     certificate hygiene list dropped every certificate (15 -> 0).
m1   D7 rubric cells were cut at 300 characters.  m3: Q3-10 layout had no failing-first tests.  m4: a reader stack
     without acm:GetCertificate made every AWS run "partial".  m5: the run fold was recomputed on every request.
m7   Host names were compared with their case.

M3 / m2 (SSL 3 + CBC caps at C, rubric wording) are tested in ``test_cbom_posture_qa2.py`` next to the other grade
rules, and in ``test_cbom_d7_d8_network_certs.py::test_grade_caps``.

Fixtures: ``fixtures/cbom_sources_two_aws_roles.json`` (staging run #57: two IAM roles reading one account, 229
resources each) stored in SQLite by ``test_cbom_posture_qa2_run._store``; oracles are literals counted from the JSON.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    Team,
)
from backend.tests.support import two_aws_roles as AWS2  # noqa: E402
from backend.tests.test_cbom_posture_qa2_run import DONE, UNIQUE, _store  # noqa: E402
from backend.tests.test_cbom_sources_posture_d6_d9_d10 import kpi_cards, rows_under, story  # noqa: E402
from backend.utilities.cbom_sources import resource_identity as RI  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView, merge_collections  # noqa: E402

RESOURCES = sum(UNIQUE.values())  # 229: one source's unique resources (both jobs read every one)
CERTIFICATES = 15  # D8's unique certificates of one role's read (the review's probe: "15 -> 0")
NOW = dt.datetime(2026, 11, 24, 6, 0, tzinfo=dt.timezone.utc)


@pytest.fixture()
def engine(tmp_path):
    getattr(RI, "clear_cache", lambda: None)()  # (absent before review 6039899144 m5)
    engine = create_engine(f"sqlite:///{tmp_path / 'r6039899144.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    yield engine
    getattr(RI, "clear_cache", lambda: None)()  # (absent before review 6039899144 m5)


# ------------------------------------------------------------------------------------------------ B1 Rule P
def test_scans_table_and_get_runs_count_each_resource_once(engine):
    """The CBOM Scans row and Review & Run (``GET /runs``) read ``asset_counts``; staging run #57 printed 458."""
    from backend.utilities.cbom_sources import run_list as RL

    run_id = _store(engine)
    with Session(engine) as s:
        assert RL.asset_counts(s, 1, [run_id]) == {run_id: RESOURCES}  # dev / 77deca1c: 458
        counts = RL.grouped_counts(s, 1, [run_id])[run_id]
        risk = counts["risk_data"]
        severities = sum(risk[k] for k in ("total_critical", "total_high", "total_medium", "total_low",
                                           "total_informational"))
        assert counts["asset_count"] == severities == RESOURCES
        listed = __import__("backend.utilities.cbom_sources.inventory", fromlist=["x"]).list_assets(
            s, team_id=1, run_id=run_id, page_size=1000)
        assert listed["all_total"] == counts["asset_count"]  # Rule P: the list and the table agree
        assert risk["total_quantum_vulnerable"] == sum(1 for i in listed["items"] if i["quantum_vulnerable"])


def test_a_run_with_one_job_is_counted_without_a_fold(engine):
    from backend.utilities.cbom_sources import run_list as RL

    run_id = _store(engine, only=(520,))
    with Session(engine) as s:
        assert RL.folded_out(s, 1, [run_id]) == []
        assert RL.asset_counts(s, 1, [run_id]) == {run_id: RESOURCES}


def test_export_has_one_component_per_resource_and_agrees_with_itself(engine):
    """``zs:asset_count`` was 458 next to ``zs:run_asset_count`` 229 and class counts summing to 229."""
    from backend.utilities.cbom_sources import inventory as INV

    run_id = _store(engine)
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        doc = INV.cyclonedx(s, run, dt.datetime(2026, 11, 24, 7, 0))
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        assets = [c for c in doc["components"] if str(c.get("bom-ref", "")).startswith("zs-asset-")]
        assert len(assets) == RESOURCES
        assert props["zs:asset_count"] == props["zs:run_asset_count"] == str(RESOURCES)
        classes = sum(int(v) for k, v in props.items() if k.startswith("zs:pqc_class_count:"))
        assert classes == RESOURCES
        kept = {int(c["bom-ref"].split("-")[-1]) for c in assets}
        fold = RI.run_fold(s, 1, run_id)
        assert not kept & set(fold.dropped) and set(fold.dropped.values()) <= kept


def test_waves_and_parity_plan_each_resource_once(engine):
    from backend.utilities.cbom_sources import run_parity as RP
    from backend.utilities.cbom_sources import waves as WAVES

    run_id = _store(engine)
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        items = WAVES.node_items(s, 1, run)
        assert len(items) == RESOURCES  # the waves page and run_tickets' whole-run selection (dev: 458)
        dropped = RI.run_fold(s, 1, run_id).dropped
        assert not {i["asset_id"] for i in items} & set(dropped)
        # ids a caller names are its own choice (a ticket for a listed row is never refused)
        some = sorted(dropped)[:2]
        assert {i["asset_id"] for i in WAVES.node_items(s, 1, run, asset_ids=some)} == set(some)
        assert RP._gather(s, run, 1, dt.datetime(2026, 11, 24, 7, 0))["total"] == RESOURCES


# ------------------------------------------------------------------------------------------------ M1 / m7 endpoints
@pytest.mark.parametrize("a,b,same", [
    (("api.example.com:443", {"sni": "example.com"}), ("api.example.com:443", {}), False),
    (("api.example.com:443", {"sni": "example.com"}), ("api.example.com:443", {"sni": "api.example.com"}), False),
    (("api.example.com:443", {"sni": "api.example.com"}), ("api.example.com:443", {}), True),  # SNI = host
    (("10.0.0.15:443", {"sni": "10.0.0.1"}), ("10.0.0.15:443", {}), False),
    (("API.Example.com:443", {}), ("api.example.com:443", {}), True),  # m7: DNS names are case-insensitive
    (("api.example.com:443", {"sni": "API.example.com."}), ("api.example.com:443", {}), True),
    (("[2001:DB8::1]:443", {}), ("[2001:db8::1]:443", {}), True),
])
def test_endpoint_identity_compares_the_sni_with_the_host_exactly(a, b, same):
    key = lambda loc, facts: RI.resource_identity("tls_endpoint", "x", loc, facts)  # noqa: E731
    assert (key(*a) == key(*b)) is same


def test_d7_prints_the_sni_unless_it_is_the_host():
    from types import SimpleNamespace

    from backend.utilities.cbom_sources import network_estate as NE

    def item(location, sni=None):
        return SimpleNamespace(row={"location": location}, facts={"sni": sni} if sni else {}, target=None,
                               collection=SimpleNamespace(network_scope="", machine_scope=""))

    assert NE.endpoint_key(item("api.example.com:443#tls", "example.com")) == "api.example.com:443/example.com"
    assert NE.endpoint_key(item("api.example.com:443", "API.example.com")) == "api.example.com:443"
    assert NE.endpoint_key(item("10.0.0.15:443", "10.0.0.1")) == "10.0.0.15:443/10.0.0.1"


# ------------------------------------------------------------------------------------------------ M2 identities
def test_cloud_resource_ids_are_anchored():
    assert not RI.cloud_resource_id("/srv/billing/subscriptions/key.pem")
    assert not RI.cloud_resource_id("projects/billing/key.pem")
    assert not RI.cloud_resource_id("/etc/pki/kv1.vault.azure.net.pem")
    assert RI.cloud_resource_id("/subscriptions/0000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1")
    assert RI.cloud_resource_id("projects/p-1/locations/global/keyRings/r/cryptoKeys/k")
    assert RI.cloud_resource_id("//storage.googleapis.com/projects/_/buckets/b")
    assert RI.cloud_resource_id("https://kv1.vault.azure.net/keys/a")
    assert RI.cloud_resource_id("arn:aws:kms:ap-south-1:444455556666:key/1")
    # the two hosts of the review keep two identities
    a = RI.resource_identity("key_file", "web01", "/srv/billing/subscriptions/key.pem")
    b = RI.resource_identity("key_file", "web02", "/srv/billing/subscriptions/key.pem")
    assert a != b


@pytest.mark.parametrize("host,scope", [
    ("10.0.0.5", "network"), ("192.168.1.1", "network"), ("100.64.0.9", "network"), ("fe80::1", "network"),
    ("fd00::5", "network"), ("web01", "network"), ("printer.local", "network"), ("db.corp.internal", "network"),
    ("127.0.0.1", "machine"), ("::1", "machine"), ("localhost", "machine"), ("LOCALHOST", "machine"),
    ("8.8.8.8", ""), ("api.example.com", ""), ("aws:444455556666", ""), ("Lab network", ""),
])
def test_host_scope(host, scope):
    assert RI.host_scope(host) == scope


def test_private_endpoints_carry_the_network_scope_and_loopback_the_machine():
    ssh = lambda net, machine="": RI.resource_identity("ssh_endpoint", "", "10.0.0.5:22",  # noqa: E731
                                                       network=net, machine=machine)
    assert ssh("segment:dc1") != ssh("segment:dc2")
    assert ssh("segment:dc1", "node:1") == ssh("segment:dc1", "node:2")  # one segment is one network
    public = lambda net: RI.resource_identity("tls_endpoint", "", "8.8.8.8:443", network=net)  # noqa: E731
    assert public("segment:dc1") == public("segment:dc2")  # a public address is one host everywhere
    local = lambda machine: RI.resource_identity("disk_encryption", "localhost", "/dev/sda2",  # noqa: E731
                                                 network="segment:dc1", machine=machine)
    assert local("node:1") != local("node:2")  # two hosts' "localhost" are two machines, even in one segment


def _network_run(engine, segments: tuple[str, str]) -> int:
    """Two network-range sources whose jobs ran in ``segments`` and both read ``10.0.0.5:22``."""
    with Session(engine) as s:
        s.add(Team(id=1, name="Sites", credit_balance=0.0))
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="sites", status="done")
        s.add(run)
        s.commit()
        for n, segment in enumerate(segments):
            src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="network_range", name=f"site {n}",
                                       name_lower=f"site {n}", source_uid=f"site{n}", node_segment=segment)
            s.add(src)
            s.commit()
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                                    outcome="ok", attempts=1, node_segment=segment,
                                    finished_at=dt.datetime(2026, 11, 24, 5, n),
                                    params={"source_uid": f"site{n}", "source_name": f"site {n}"})
            s.add(job)
            s.commit()
            s.add(CbomCollectedAsset(team_id=1, run_id=run.id, job_id=job.id, source_id=src.id, attempt=1,
                                     asset_key=f"k{n}", asset_type="ssh_endpoint", cdx_type="protocol",
                                     target="10.0.0.5", location="10.0.0.5:22", name="ssh", facts={}))
            s.commit()
        return int(run.id)


def test_two_sites_reading_one_private_address_are_two_resources(engine):
    from backend.utilities.cbom_sources import run_list as RL

    run_id = _network_run(engine, ("dc1", "dc2"))
    with Session(engine) as s:
        assert RI.run_fold(s, 1, run_id).dropped == {}
        assert RL.asset_counts(s, 1, [run_id]) == {run_id: 2}


def test_one_segment_reading_one_private_address_twice_is_one_resource(engine):
    run_id = _network_run(engine, ("dc1", "dc1"))
    with Session(engine) as s:
        assert len(RI.run_fold(s, 1, run_id).dropped) == 1


def test_team_view_and_d7_keep_two_sites_apart():
    from backend.utilities.cbom_sources import network_estate as NE
    from backend.utilities.cbom_sources.collections_view import link_resources

    rows, collections = AWS2.build()
    probe = next(r for r in rows if r.node_type == "kms_key")
    sites = [dataclasses.replace(c, network_scope=f"segment:dc{i}", machine_scope=f"node:{i}")
             for i, c in enumerate(collections[:2])]
    made = []
    for site in sites:
        made.append(dataclasses.replace(probe, row={**probe.row, "location": "10.0.0.5:443"}, node_type="tls_endpoint",
                                        identity=f"node|{site.source_ref}|ep", collection=site,
                                        facts={"versions": {"TLSv1.3": True}}))
    link_resources(made)
    assert made[0].identity != made[1].identity
    observed = NE.dedupe(made)
    assert len(observed) == 2 and len({o.key for o in observed}) == 2
    assert {o.key for o in observed} == {"10.0.0.5:443 (segment dc0)", "10.0.0.5:443 (segment dc1)"}
    same = [dataclasses.replace(m, collection=dataclasses.replace(m.collection, network_scope="segment:dc0"))
            for m in made]
    assert len(NE.dedupe(same)) == 1 and NE.dedupe(same)[0].key == "10.0.0.5:443"


# ------------------------------------------------------------------------------------------------ M4 an empty newer read
def _add_failed_newer(engine) -> tuple[int, int]:
    """A newer run of the stored source whose job finished "success" but read nothing (outcome failed, no rows)."""
    with Session(engine) as s:
        src = s.exec(select(CbomCollectionSource)).one()
        at = DONE[521] + dt.timedelta(hours=1)
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="empty", status="done", finished_at=at)
        s.add(run)
        s.commit()
        job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                                outcome="failed", attempts=1, asset_count=0, finished_at=at,
                                params={"source_uid": src.source_uid, "source_name": src.name},
                                result={"counts": {"ok": 0, "partial": 0, "failed": 1, "skipped": 0}})
        s.add(job)
        s.commit()
        return int(run.id), int(job.id)


def test_a_newer_collection_that_read_nothing_keeps_every_certificate(engine):
    from backend.utilities.cbom_sources import cert_hygiene as HY
    from backend.utilities.cbom_sources import collections_view as CV

    run_id = _store(engine, only=(520,))
    with Session(engine) as s:
        before = len(HY.build(s, 1, now=NOW).certs)
    assert before == CERTIFICATES
    _run_id, empty_id = _add_failed_newer(engine)
    with Session(engine) as s:
        assert len(HY.build(s, 1, now=NOW).certs) == before  # 77deca1c: 0 (the empty job was the "latest")
        (collection,) = CV.load_sources_result(s, 1, now=NOW).collections
        assert collection.run_id == run_id and collection.newer_attempt_job_id == empty_id
        assert collection.newer_attempt_at is not None
        assert [j.id for j in CV.latest_jobs(s, 1)] == [collection.job_id]


def test_a_source_that_never_read_anything_keeps_its_newest_job(engine):
    from backend.utilities.cbom_sources import collections_view as CV

    with Session(engine) as s:
        s.add(Team(id=1, name="T", credit_balance=0.0))
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="r", status="done")
        src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="network_range", name="lab", name_lower="lab",
                                   source_uid="lab")
        s.add(run)
        s.add(src)
        s.commit()
        for minute in (1, 2):
            s.add(CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                                    outcome="failed", attempts=1, finished_at=dt.datetime(2026, 11, 24, 5, minute),
                                    params={"source_uid": "lab"}))
        s.commit()
        (pair,) = CV.latest_collections(s, 1)
        assert pair[0].finished_at == dt.datetime(2026, 11, 24, 5, 2) and pair[1] is None


def test_d2_and_d8_say_the_newest_collection_read_nothing(engine):
    from backend.utilities.dashboard.cbom_team_rollup import load_core_view, newer_attempt_note
    from backend.utilities.pdf import cbom_cert_register_pdf as d8
    from backend.utilities.pdf import cbom_methodology_pdf as d2

    _store(engine, only=(520,))
    _add_failed_newer(engine)
    with Session(engine) as s:
        view = load_core_view(s, 1, now=NOW)
    (collection,) = view.collections
    note = newer_attempt_note(collection)
    assert note == "newest collection read nothing on 2026-11-24; last read 2026-11-24"
    assert note in d2._collection_row(collection)[4]
    from backend.utilities.cbom_sources.cert_estate import unique_certificates

    assert note in d8._scope_note(unique_certificates(view), view)
    assert "counts the Sources estate store" not in d8._scope_note(unique_certificates(view), view)


# ------------------------------------------------------------------------------------------------ m1 rubric cells
def test_rubric_rows_are_never_cut():
    from reportlab.platypus import Table

    from backend.tests.test_cbom_sources_posture_d6_d9_d10 import cell_text
    from backend.utilities.cbom_sources import network_estate as NE
    from backend.utilities.pdf import cbom_network_tls_pdf as d7
    from backend.utilities.pdf.cbom_deliverable_common import get_deliverable_styles

    assert max(len(rule) for _part, rule in NE.RUBRIC) <= d7.RUBRIC_CELL_LIMIT
    flows = d7._grade_rubric(get_deliverable_styles(), 500)
    table = next(f for f in flows if isinstance(f, Table))
    printed = [cell_text(row[1]) for row in table._cellvalues[1:]]
    for (_part, rule), shown in zip(NE.RUBRIC, printed, strict=True):
        assert shown.rstrip().endswith(rule.rstrip()[-25:]), (rule[-40:], shown[-60:])
        assert "…" not in shown


# ------------------------------------------------------------------------------------------------ m3 Q3-10 layout
def test_dense_table_widens_a_column_narrower_than_its_header_word():
    from reportlab.pdfbase.pdfmetrics import stringWidth

    from backend.utilities.pdf.cbom_deliverable_common import _shared_styles, dense_table

    table = dense_table(["#", "Classification", "Location"], [["1", "secret", "/srv/x"]], [14, 30, 300])
    style = _shared_styles()["dense_header"]
    assert table._colWidths[1] >= stringWidth("Classification", style.fontName, style.fontSize)
    assert sum(table._colWidths) == pytest.approx(344)  # the total never changes


def test_disclaimer_keeps_a_long_method_sentence_whole():
    from backend.tests.test_cbom_sources_posture_d6_d9_d10 import cell_text
    from backend.utilities.pdf.cbom_deliverable_common import _disclaimer_box, get_deliverable_styles

    sentence = ("The collections named here were read " + "and so on " * 100 + "is not proof that the end is here.")
    assert 1000 < len(sentence) < 1600
    box = _disclaimer_box(get_deliverable_styles(), 500, [sentence])
    text = " ".join(cell_text(row[0]) for row in box._cellvalues)
    assert "is not proof that the end is here." in text


def test_d9_kubernetes_card_is_a_count():
    from backend.utilities.pdf import cbom_data_at_rest_pdf as d9

    empty = TeamCbomView(team_id=1, team_name="S", generated_at=NOW, as_of=NOW.date(), fingerprint="m3m3m3m3")
    assert kpi_cards(story(d9, empty))["Kubernetes secrets"] == "0"  # was "no cluster configuratio..."


def test_d6_key_register_prints_words_not_api_enums():
    from backend.utilities.pdf import cbom_infra_posture_pdf as d6

    empty = TeamCbomView(team_id=1, team_name="S", generated_at=NOW, as_of=NOW.date(), fingerprint="m3m3m3m4")
    rows = rows_under(story(d6, merge_collections(empty, *AWS2.build())), "Key")
    assert {r["Provider"] for r in rows} == {"AWS"}
    assert {"RSA 2048", "ECC NIST P-256", "HMAC 256", "ML-DSA-65", "symmetric default"} == {r["Key type"] for r in rows}
    assert {"sign / verify", "encrypt / decrypt", "MAC generate / verify"} == {r["Usage"] for r in rows}
    assert {"enabled", "pending import (no key material)"} == {r["State"] for r in rows}
    printed = " ".join(r[c] for r in rows for c in ("Provider", "Key type", "Usage", "State"))
    for enum in ("RSA_2048", "SIGN_VERIFY", "PendingImport", "ECC_NIST_P256", "ML_DSA_65", "aws"):
        assert enum not in printed


# ------------------------------------------------------------------------------------------------ m4 reader stack
def test_a_reader_stack_without_get_certificate_does_not_make_the_run_partial():
    from backend.utilities.cbom_sources import aws_collect as AC

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_cbom_aws_cb33 import ACM_PREFIX, Plan, _body_pem, _cert_detail, _cert_summary, run

    plan = Plan()
    plan.acm = [("list_certificates", {"CertificateSummaryList": [_cert_summary(n) for n in (1, 2)]}, None),
                ("describe_certificate", _cert_detail(1), {"CertificateArn": f"{ACM_PREFIX}c1"}),
                ("describe_certificate", _cert_detail(2), {"CertificateArn": f"{ACM_PREFIX}c2"}),
                ("get_certificate", {"Certificate": _body_pem()}, {"CertificateArn": f"{ACM_PREFIX}c1"}),
                ("get_certificate", "AccessDeniedException", {"CertificateArn": f"{ACM_PREFIX}c2"})]
    _services, found, _rows = run(plan)
    (gap,) = [a for a in found if a["type"] == "coverage" and "#body" in a["location"]]
    assert gap["facts"]["incomplete"] is True and gap["facts"][AC.TEMPLATE_UPDATE] == "acm:GetCertificate"
    assert "update it to the current template" in gap["facts"]["detail"]
    tally = AC._GapTally(lambda _a: None)
    tally(gap)
    assert tally.gaps == 0  # shown, never "partial"
    other = {"type": "coverage", "location": "arn:aws:kms:x#rotation", "facts": {"status": "denied"}}
    tally(other)
    assert tally.gaps == 1  # any other denial still is


# ------------------------------------------------------------------------------------------------ m5 the fold is cached
def test_the_run_fold_is_computed_once_for_the_same_rows_and_jobs(engine, monkeypatch):
    run_id = _store(engine)
    calls = []
    real = RI._run_fold
    monkeypatch.setattr(RI, "_run_fold", lambda *a, **k: calls.append(1) or real(*a, **k))
    for _ in range(3):
        with Session(engine) as s:
            assert len(RI.run_fold(s, 1, run_id).dropped) == RESOURCES
    assert len(calls) == 1
    with Session(engine) as s:  # a deleted source re-ranks the fold: a new key
        s.delete(s.exec(select(CbomCollectionSource).where(CbomCollectionSource.name == "aws-pca-test")).one())
        s.commit()
        fold = RI.run_fold(s, 1, run_id)
    assert len(calls) == 2 and len(fold.dropped) == RESOURCES
