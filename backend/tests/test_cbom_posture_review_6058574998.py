"""Review 6058574998 of PR #499 (round 3), every finding at its root cause.

F1  A URL or host:port target was never network-scoped: two Kubernetes clusters at ``https://127.0.0.1:6443`` or
    ``https://kubernetes.default.svc`` folded each other's ``default/...`` secrets.  Targets are parsed first, ``*.svc``
    / ``*.cluster.local`` names are local, and every Kubernetes asset is one resource per cluster read.
F2  The kept row was the job that finished last, so the resource's remediation key (waves, Jira dedup, the team
    view's remediation status) flipped run to run.  The oldest source is now kept, and a plan or ticket held on
    another source's copy of the resource follows it.
F3  ``enrichment_only`` coverage rows (an ACM body not read) are notes in ``_GapTally``, ``inventory.job_reads`` and
    ``qgrade.coverage_kind``, whatever the body error.
F4  D7's "Caps and trust" and "Source" cells were cut at 300 characters.
F5  Unsegmented scan nodes are separate networks; link-local addresses are one machine; ::ffff: is its IPv4.
F6  IDEA is a 64-bit block cipher (C with TLS 1.1+), EDH- names are forward secret, a malformed HSTS is invalid.
F7  The job window no longer pushes a source's last real read out.

Fixture: ``fixtures/cbom_sources_two_aws_roles.json`` (staging run #57, two IAM roles reading one account).
"""
from __future__ import annotations

import datetime as dt
import hashlib
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
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomRemediationAssignment,
    Team,
)
from backend.tests.support import two_aws_roles as AWS2  # noqa: E402
from backend.utilities.cbom_sources import classify as C  # noqa: E402
from backend.utilities.cbom_sources import resource_identity as RI  # noqa: E402

T0 = dt.datetime(2026, 11, 24, 5, 0)


@pytest.fixture()
def engine(tmp_path):
    RI.clear_cache()
    engine = create_engine(f"sqlite:///{tmp_path / 'r6058574998.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    yield engine
    RI.clear_cache()


def _team(s) -> None:
    s.add(Team(id=1, name="Staging", credit_balance=0.0))
    s.commit()


def _source(s, name: str, kind: str, uid: str) -> CbomCollectionSource:
    src = CbomCollectionSource(team_id=1, owner_user_id=1, kind=kind, name=name, name_lower=name.lower(),
                               source_uid=uid)
    s.add(src)
    s.commit()
    return src


def _job(s, run, src, finished, **kw) -> CbomCollectionJob:
    job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                            outcome=kw.pop("outcome", "ok"), attempts=1, finished_at=finished,
                            params={"source_uid": src.source_uid, "source_name": src.name}, **kw)
    s.add(job)
    s.commit()
    return job


def _asset(s, run, job, src, item) -> None:
    judged = C.classify(item["type"], item.get("algorithm"), item.get("key_size"), item.get("protocol"),
                        item["facts"], T0)
    s.add(CbomCollectedAsset(
        team_id=1, run_id=run.id, job_id=job.id, source_id=src.id, attempt=1,
        asset_key=hashlib.sha256(f"{src.source_uid}|{item['type']}|{item['location']}".encode()).hexdigest(),
        asset_type=item["type"], cdx_type=judged["cdx_type"], target=item.get("target"), location=item["location"],
        name=item.get("name"), algorithm=item.get("algorithm"), key_size=item.get("key_size"),
        protocol=item.get("protocol"), quantum_vulnerable=judged["quantum_vulnerable"], impact=judged["impact"],
        finding=judged["finding"], finding_codes=judged["finding_codes"], facts=item["facts"], created_at=job.finished_at))


# ------------------------------------------------------------------------------------------------ F1 Kubernetes
@pytest.mark.parametrize("target,scope", [
    ("https://127.0.0.1:6443", "machine"), ("https://10.0.0.1:6443", "network"), ("10.0.0.5:5432", "network"),
    ("https://kubernetes.default.svc", "network"), ("kubernetes.default", "network"),
    ("db.prod.svc.cluster.local", "network"), ("https://api.prod.example.com:6443", ""), ("aws:444455556666", ""),
])
def test_url_and_host_port_targets_are_judged_by_their_host(target, scope):
    assert RI.host_scope(target) == scope


def test_two_clusters_at_one_api_url_keep_their_own_secrets():
    key = lambda cluster, machine: RI.resource_identity(  # noqa: E731
        "k8s_tls_secret", "https://127.0.0.1:6443", "default/secret/tls", network="segment:", machine=machine,
        cluster=cluster)
    assert key("kind-a", "node:1") != key("kind-b", "node:1")  # two clusters, one node
    assert key("kind-a", "node:1") != key("kind-a", "node:2")  # loopback is the reading machine
    svc = lambda cluster: RI.resource_identity("k8s_ingress_tls", "https://kubernetes.default.svc",  # noqa: E731
                                               "shop/ingress/web", network="segment:dc1", cluster=cluster)
    assert svc("prod") != svc("stage")


def test_two_in_cluster_readers_are_two_resources_in_a_run(engine):
    from backend.utilities.cbom_sources import run_list as RL

    with Session(engine) as s:
        _team(s)
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="k8s", status="done")
        s.add(run)
        s.commit()
        for n, name in enumerate(("cluster prod", "cluster stage")):
            src = _source(s, name, "kubernetes", f"k8s{n}")
            job = _job(s, run, src, T0 + dt.timedelta(minutes=n))
            s.add(CbomCollectedAsset(team_id=1, run_id=run.id, job_id=job.id, source_id=src.id, attempt=1,
                                     asset_key=f"k{n}", asset_type="k8s_tls_secret", cdx_type="related-crypto-material",
                                     target="https://kubernetes.default.svc", location="default/secret/tls",
                                     name="tls", facts={}))
            s.commit()
        assert RI.run_fold(s, 1, run.id).dropped == {}  # before: one row of the two
        assert RL.asset_counts(s, 1, [run.id]) == {run.id: 2}


# ------------------------------------------------------------------------------------------------ F2 stable kept row
def _two_runs(engine) -> tuple[int, int, int, int]:
    """Two sources (A created first) reading one account in two runs; run 1: B finishes last, run 2: A finishes last.
    Returns (run 1, run 2, source A id, source B id)."""
    with Session(engine) as s:
        _team(s)
        a = _source(s, "role A (oldest)", "aws_account", "srcA")
        b = _source(s, "role B", "aws_account", "srcB")
        runs = []
        for n, (a_at, b_at) in enumerate(((T0, T0 + dt.timedelta(seconds=30)),
                                           (T0 + dt.timedelta(days=1, seconds=30), T0 + dt.timedelta(days=1)))):
            run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"r{n}", status="done")
            s.add(run)
            s.commit()
            jobs = {520: (_job(s, run, a, a_at), a), 521: (_job(s, run, b, b_at), b)}
            for item in AWS2.items():
                job, src = jobs[item["job_id"]]
                _asset(s, run, job, src, item)
            s.commit()
            runs.append(int(run.id))
        return runs[0], runs[1], int(a.id), int(b.id)


def test_the_remediation_key_does_not_flip_with_the_finish_order(engine):
    """The kept row follows the newest read (review 6060688856 M1); the key a plan or ticket is written to is the
    resource's group key, whichever row is shown."""
    from backend.utilities.cbom_sources import waves as WAVES

    first, second, _a, _b = _two_runs(engine)
    with Session(engine) as s:
        keys, shown = [], []
        for run_id in (first, second):
            items = WAVES.node_items(s, 1, s.get(CbomCollectionRun, run_id))
            assert len(items) == 229
            shown.append({i["source_name"] for i in items})
            keys.append({i["label"]: i["asset_key"] for i in items if i["type"] == "kms_key"})
            assert all(i["asset_key"] == i["group_key"] for i in items if i["type"] == "kms_key")
        assert shown == [{"role B"}, {"role A (oldest)"}]  # the newest read of each run is shown
        assert keys[0] == keys[1]


def test_a_plan_on_another_sources_copy_follows_the_resource(engine):
    """Assignments made before this fix sit on whichever source's row was kept then (here B's)."""
    from backend.utilities.cbom_sources import identity as ID
    from backend.utilities.cbom_sources import waves as WAVES

    first, second, _a, b_id = _two_runs(engine)
    with Session(engine) as s:
        row = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == first,
                                                      CbomCollectedAsset.source_id == b_id,
                                                      CbomCollectedAsset.asset_type == "kms_key")).first()
        b_key = ID.stable_key("node", "srcB", ID.node_identity(row))
        s.add(CbomRemediationAssignment(team_id=1, asset_key=b_key, source_ref="srcB", status="in_progress", wave=1,
                                        ticket_key="SEC-7", ticket_url="https://jira.example/browse/SEC-7"))
        s.commit()
        item = next(i for i in WAVES.node_items(s, 1, s.get(CbomCollectionRun, second))
                    if i["type"] == "kms_key" and i["label"] == ID.node_label(row))
        assert item["source_name"] == "role A (oldest)"  # run 2: A finished last
        assert item["asset_key"] == b_key  # the plan's own key: a change edits that record
        assert item["assignment"]["status"] == "in_progress" and item["assignment"]["ticket_key"] == "SEC-7"


def test_create_tickets_twice_across_runs_makes_one_jira_issue(engine, monkeypatch):
    from backend.utilities.cbom_sources import run_tickets as RT
    from backend.utilities.cbom_sources import waves as WAVES

    first, second, _a, _b = _two_runs(engine)
    created: list[dict] = []

    def fake_create(**kw):
        created.append(kw)
        return {"key": f"SEC-{len(created)}"}

    monkeypatch.setattr(RT.JIRA, "create_issue_in_project", fake_create)
    monkeypatch.setattr(RT.JIRA, "find_issue_by_label", lambda *a, **k: None)
    monkeypatch.setattr(RT, "_jira_creds", lambda team: ("qa@example.com", "token", "https://jira.example"))
    with Session(engine) as s:
        s.add(CbomCollectionSettings(team_id=1, aws_external_id="x" * 32, jira_project_key="SEC"))
        s.commit()

    def kms_finding(run_id):
        with Session(engine) as s:
            items = WAVES.node_items(s, 1, s.get(CbomCollectionRun, run_id))
        return next(i for i in items if i["type"] == "kms_key" and RT.is_ticketable(i))

    one = kms_finding(first)
    out1 = RT.create_tickets(engine, 1, 1, first, RT.TicketBody(asset_ids=[one["asset_id"]]))
    assert [c["ticket_key"] for c in out1["created"]] == ["SEC-1"]
    with Session(engine) as s:
        two = next(i for i in WAVES.node_items(s, 1, s.get(CbomCollectionRun, second)) if i["label"] == one["label"])
    out2 = RT.create_tickets(engine, 1, 1, second, RT.TicketBody(asset_ids=[two["asset_id"]]))
    assert out2["created"] == [] and [e["ticket_key"] for e in out2["existing"]] == ["SEC-1"]
    assert len(created) == 1  # one Jira issue for one KMS key, whichever role finished last


# ------------------------------------------------------------------------------------------------ F3 enrichment notes
def test_an_enrichment_row_is_a_note_everywhere(engine):
    from backend.utilities.cbom_sources import aws_collect as AC
    from backend.utilities.cbom_sources import inventory as INV
    from backend.utilities.cbom_sources.common import ENRICHMENT_ONLY
    from backend.utilities.cbom_sources.qgrade import coverage_kind

    for status in ("denied", "error", "throttled"):
        facts = {"status": status, "incomplete": True, ENRICHMENT_ONLY: "certificate body (SHA-256 thumbprint)"}
        assert coverage_kind(facts) == "enrichment"
        tally = AC._GapTally(lambda _a: None)
        tally({"type": "coverage", "location": "arn:aws:acm:x:1:certificate/c#body", "facts": facts})
        assert tally.gaps == 0
    assert coverage_kind({"status": "denied"}) == "gap"
    with Session(engine) as s:
        _team(s)
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="n", status="done")
        s.add(run)
        s.commit()
        src = _source(s, "aws", "aws_account", "aws1")
        job = _job(s, run, src, T0)
        for n, extra in enumerate(({ENRICHMENT_ONLY: "certificate body"}, {})):
            s.add(CbomCollectedAsset(team_id=1, run_id=run.id, job_id=job.id, source_id=src.id, attempt=1,
                                     asset_key=f"c{n}", asset_type="coverage", cdx_type="data",
                                     target="aws:1", location=f"arn:aws:acm:x:1:certificate/c{n}#body",
                                     facts={"status": "error", "check": "acm body", **extra}))
        s.commit()
        reads = INV.job_reads(s, [job])
        assert reads[job.id][1] == 1  # the plain error is one gap, the note none


def test_any_acm_body_error_is_a_note_not_a_partial_run():
    from backend.utilities.cbom_sources import aws_collect as AC
    from backend.utilities.cbom_sources.common import ENRICHMENT_ONLY

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_cbom_aws_cb33 import ACM_PREFIX, Plan, _body_pem, _cert_detail, _cert_summary, run

    plan = Plan()
    plan.acm = [("list_certificates", {"CertificateSummaryList": [_cert_summary(n) for n in (1, 2)]}, None),
                ("describe_certificate", _cert_detail(1, Status="REVOKED"), {"CertificateArn": f"{ACM_PREFIX}c1"}),
                ("describe_certificate", _cert_detail(2, Status="INACTIVE"), {"CertificateArn": f"{ACM_PREFIX}c2"}),
                ("get_certificate", {"Certificate": _body_pem()}, {"CertificateArn": f"{ACM_PREFIX}c1"}),
                ("get_certificate", "ResourceNotFoundException", {"CertificateArn": f"{ACM_PREFIX}c2"})]
    _services, found, _rows = run(plan)
    (gap,) = [a for a in found if a["type"] == "coverage" and "#body" in a["location"]]
    assert gap["facts"][ENRICHMENT_ONLY] and AC.TEMPLATE_UPDATE not in gap["facts"]
    tally = AC._GapTally(lambda _a: None)
    tally(gap)
    assert tally.gaps == 0


# ------------------------------------------------------------------------------------------------ F4 D7 grade cells
def test_d7_grade_reasons_and_sources_are_never_cut():
    from types import SimpleNamespace

    from reportlab.platypus import Table

    from backend.tests.test_cbom_sources_posture_d6_d9_d10 import cell_text
    from backend.utilities.cbom_sources import network_estate as NE
    from backend.utilities.pdf import cbom_network_tls_pdf as d7
    from backend.utilities.pdf.cbom_deliverable_common import get_deliverable_styles

    versions = {v: True for v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")}
    suites = ["TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
              "TLS_DH_anon_WITH_AES_128_CBC_SHA"]
    facts = {"versions": versions, "cipher_suites": {"TLSv1.0": [{"name": n} for n in suites]},
             "server_temp_key": "DH, 1024 bits",
             "leaf": {"key_alg": "RSA", "key_size": 1024, "sig_alg": "md5WithRSAEncryption", "self_signed": True,
                      "not_after": "2020-01-01T00:00:00Z"}}
    grade = NE.grade_tls(facts, dt.date(2026, 11, 24))
    reasons = "; ".join(grade.reasons)
    assert len(reasons) > 300
    also = tuple(f"Lab network site {n:02d} with a long source name" for n in range(8))
    observed = SimpleNamespace(facts=facts, source="Lab appliances scanner", also_seen=also, item=SimpleNamespace(row={}))
    endpoint = SimpleNamespace(key="10.9.9.9:443", service="tls", grade=grade, groups=(), not_read=(),
                               observed=observed)
    flows = d7._grades(SimpleNamespace(tls=[endpoint]), get_deliverable_styles(), 700)
    table = next(f for f in flows if isinstance(f, Table))
    heads = [cell_text(c) for c in table._cellvalues[0]]
    row = dict(zip(heads, (cell_text(c) for c in table._cellvalues[1]), strict=True))
    assert row["Caps and trust"].rstrip().endswith(reasons[-30:]) and "…" not in row["Caps and trust"]
    assert row["Source"].rstrip().endswith(also[-1] + ")") and "…" not in row["Source"]


# ------------------------------------------------------------------------------------------------ F5 scopes
def test_unsegmented_nodes_are_separate_networks_and_node_less_jobs_their_source():
    from types import SimpleNamespace

    def job(node_id=None, segment=None):
        return SimpleNamespace(params={}, node_segment=segment, node_id=node_id)

    assert RI.job_scope(job(1), None, "s1") == ("node:1", "node:1")
    assert RI.job_scope(job(2), None, "s2") == ("node:2", "node:2")  # never one shared default network
    assert RI.job_scope(job(1, "DC1"), None, "s1") == ("segment:dc1", "node:1")
    assert RI.job_scope(job(), None, "s9") == ("source:s9", "source:s9")
    ssh = lambda j, ref: RI.resource_identity("ssh_endpoint", "", "10.0.0.5:22",  # noqa: E731
                                              **dict(zip(("network", "machine"), RI.job_scope(j, None, ref))))
    assert ssh(job(1), "a") != ssh(job(2), "b")
    assert ssh(job(1, "dc1"), "a") == ssh(job(2, "dc1"), "b")


@pytest.mark.parametrize("host,scope", [("169.254.169.254", "machine"), ("fe80::1", "machine"),
                                        ("::ffff:10.0.0.5", "network"), ("::ffff:8.8.8.8", "")])
def test_link_local_is_one_machine_and_mapped_addresses_are_ipv4(host, scope):
    assert RI.host_scope(host) == scope


def test_an_ipv4_mapped_endpoint_is_its_ipv4_endpoint():
    a = RI.resource_identity("tls_endpoint", "", "[::ffff:10.0.0.5]:443", network="segment:a")
    assert a == RI.resource_identity("tls_endpoint", "", "10.0.0.5:443", network="segment:a")


def test_d7_rubric_states_the_identity_rules():
    from backend.utilities.cbom_sources import network_estate as NE

    text = " ".join(rule for part, rule in NE.RUBRIC if part == "Divergence")
    assert "once by DNS name and once by IP address is two rows" in text
    assert "split-horizon name is one row" in text and "else per scan node, else per source" in text


# ------------------------------------------------------------------------------------------------ F6 grade details
def _g(versions, suites, **extra):
    from backend.utilities.cbom_sources import network_estate as NE

    facts = {"versions": {v: (v in versions) for v in ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")},
             "cipher_suites": {v: [{"name": n} for n in names] for v, names in suites.items()},
             "cipher_suites_complete": {v: True for v in suites},
             "negotiated_group": "x25519",
             "leaf": {"key_alg": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption",
                      "not_after": "2030-01-01T00:00:00Z"}, **extra}
    return NE.grade_tls(facts, dt.date(2026, 11, 24))


GCM = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"


def test_idea_is_a_64_bit_block_cipher():
    graded = _g(["TLSv1.2"], {"TLSv1.2": [GCM, "TLS_RSA_WITH_IDEA_CBC_SHA"]})
    assert graded.letter == "C" and any("64-bit block" in c for c in graded.caps)  # before: A-


def test_edh_names_are_forward_secret():
    graded = _g(["TLSv1.2"], {"TLSv1.2": ["EDH-RSA-AES256-GCM-SHA384"]})
    assert not any("no forward secrecy" in c for c in graded.caps)


def test_a_malformed_hsts_is_invalid_not_unrecorded():
    modern = (["TLSv1.2", "TLSv1.3"], {"TLSv1.2": [GCM], "TLSv1.3": ["TLS_AES_256_GCM_SHA384"]})
    assert _g(*modern, hsts_max_age="soon").text == "A-"  # before: A (as if not read)
    assert "HSTS max-age invalid" in _g(*modern, hsts_max_age="soon").warnings
    assert _g(*modern, hsts_max_age="31536000").text == "A+"  # a whole number written as text is that number
    assert _g(*modern).text == "A"  # not read: neither A+ nor A-


# ------------------------------------------------------------------------------------------------ F7 the job window
def test_a_long_run_of_empty_attempts_keeps_the_last_real_read(engine):
    from backend.utilities.cbom_sources import collections_view as CV

    with Session(engine) as s:
        _team(s)
        src = _source(s, "files", "linux_servers", "files1")
        real_run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="real", status="done")
        s.add(real_run)
        s.commit()
        real = _job(s, real_run, src, T0)
        for n in range(12):  # a window of 10 holds only empty attempts
            empty_run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"e{n}", status="done")
            s.add(empty_run)
            s.commit()
            _job(s, empty_run, src, T0 + dt.timedelta(hours=n + 1), outcome="failed")
        ((job, newer),) = CV.latest_collections(s, 1, limit=10)
        assert job.id == real.id  # before: the newest empty attempt (the M4 symptom again)
        assert newer is not None and newer.finished_at == T0 + dt.timedelta(hours=12)
