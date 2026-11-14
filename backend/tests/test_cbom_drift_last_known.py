"""CB-33 PR-0: drift compares against the LAST KNOWN state of each asset, not the newest run's partial view.

A collection with coverage gaps (a key whose DescribeKey or rotation status was throttled, a host that did not
answer) is comparable: what it did not read is "not read", never removed or resolved.  Before this change that run
then became the next run's baseline, silently lacking what it had not read, so the next clean run reported the
unread key as a NEW asset with its findings OPENED again, and a key deleted or fixed while unread was never reported
at all (CB-33 DA RC-4; reviews cx3 S1, cx4).  Now an asset absent under a gap at every newer level, and the findings
of a listed asset under an incomplete gap, are carried from the newest earlier comparable job that read them, each
older level judged by the current rules (DA-2b), the walk going on only past real (not ``by_choice``) gaps (DA-2c),
and events, the run's "not read" list and Compare share one baseline (DA-2a).

The introduced-fact guard (DA-2e, RC-5): a fact a collector starts sending (``drift.INTRODUCED_FACTS``) that makes a
finding vanish is a "collector change", listed apart in Compare, never a resolved event.

Every test states what it gives on dev c75aec146 (before this change).  Synthetic rows, stored as ``add_assets``
stores them; the real ``record_run_drift`` / ``run_not_read`` / ``run_diff``.

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_drift_last_known.py
"""
from __future__ import annotations

import ast
import datetime as dt
import re
import sys
from pathlib import Path
from typing import Any

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
    CbomDriftEvent,
    Team,
)
from backend.utilities.cbom_sources import classify as C  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402

ACCT = "111122223333"
LABEL = f"aws:{ACCT}"
KMS = f"arn:aws:kms:us-east-1:{ACCT}:key/"
ACM = f"arn:aws:acm:us-east-1:{ACCT}:certificate/"
T0 = dt.datetime(2026, 11, 1, 6, 0, 0)
OLD = {"kb_version": "2026.01.01.1", "classifier_version": "rules-000000000000"}


def current() -> dict[str, str]:
    return {"kb_version": crypto_kb.version(), "classifier_version": C.CLASSIFIER_VERSION}


# ----------------------------------------------------------------------------- assets, shaped as aws_collect sends them
def key(kid: str, *, rotation: bool | None = False, spec: str = "SYMMETRIC_DEFAULT", **extra: Any) -> dict[str, Any]:
    arn = KMS + kid
    return {"type": "kms_key", "target": LABEL, "location": arn, "name": kid, "algorithm": spec,
            "key_size": 256 if spec == "SYMMETRIC_DEFAULT" else 2048,
            "facts": {"key_spec": spec, "key_usage": "ENCRYPT_DECRYPT", "key_manager": "CUSTOMER",
                      "key_state": "Enabled", "origin": "AWS_KMS", "multi_region": False, "rotation_enabled": rotation,
                      "signing_algorithms": None, "identity": arn, **extra}}


def cert(cid: str, *, in_use: bool = False, aws_type: str = "AMAZON_ISSUED", **extra: Any) -> dict[str, Any]:
    arn = ACM + cid
    return {"type": "certificate", "target": LABEL, "location": arn, "name": f"{cid}.example.com", "algorithm": "RSA",
            "key_size": 2048,
            "facts": {"subject": f"CN={cid}.example.com", "issuer": "CN=Amazon RSA 2048 M02", "serial": cid,
                      "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-06-01T00:00:00Z",
                      "sig_alg": "SHA256WITHRSA", "key_alg": "RSA", "key_size": 2048, "san": [], "status": "ISSUED",
                      "aws_type": aws_type, "in_use": in_use, "in_use_by": [], "renewal_eligibility": "ELIGIBLE",
                      "source": "aws", "identity": arn, **extra}}


def gap(where: str, check: str, *, scope: list[str] | None, incomplete: bool = False, by_choice: bool = False,
        status: str = "throttled", target: str = LABEL) -> dict[str, Any]:
    facts: dict[str, Any] = {"check": check, "status": status, "detail": f"{check}: {status}"}
    if scope is not None:
        facts["scope"] = scope
    if incomplete:
        facts["incomplete"] = True
    if by_choice:
        facts["by_choice"] = True
    return {"type": "coverage", "target": target, "location": where, "name": check, "facts": facts}


def describe_throttled(kid: str) -> dict[str, Any]:
    return gap(f"{KMS}{kid}#metadata", f"kms key {kid} metadata", scope=[KMS + kid])


def rotation_throttled(kid: str) -> dict[str, Any]:
    return gap(f"{KMS}{kid}#rotation", f"kms key {kid} rotation status", scope=[KMS + kid], incomplete=True)


GLUE_OFF = gap(f"arn:aws:glue:us-east-1:{ACCT}:connection#option-off", "glue connections in us-east-1",
               scope=[f"arn:aws:glue:us-east-1:{ACCT}:connection/"], by_choice=True, status="not_read")


def tls(ip: str) -> dict[str, Any]:
    where = f"{ip}:443"
    return {"type": "tls_endpoint", "target": ip, "location": where, "name": f"HTTPS {where}", "protocol": "TLSv1.2",
            "facts": {"tls": True, "service": "tls", "negotiated_version": "TLSv1.2",
                      "versions": {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True,
                                   "TLSv1.3": False}}}


# ----------------------------------------------------------------------------- a source and its runs, stored for real
class Chain:
    """One source collected run after run; each run is stored as ``add_assets`` / ``finish_job`` store it."""

    def __init__(self, engine, kind: str = "aws"):
        self.engine = engine
        self.at = T0
        with Session(engine) as s:
            src = CbomCollectionSource(team_id=1, owner_user_id=1, kind=kind, name=f"{kind}-src", name_lower=f"{kind}-src")
            s.add(src)
            s.commit()
            s.refresh(src)
            self.source_id = src.id

    def run(self, assets: list[dict[str, Any]], *, versions: dict[str, str] | None = None) -> int:
        self.at += dt.timedelta(days=1)
        versions = versions or current()
        gaps = [a for a in assets if a["type"] == "coverage" and not a["facts"].get("by_choice")]
        counts = {"total": 1, "ok": 0 if gaps else 1, "partial": 1 if gaps else 0, "failed": 0, "skipped": 0}
        with Session(self.engine) as s:
            run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"r{self.at:%j%H%M%S}",
                                    status="partial" if gaps else "done", created_at=self.at,
                                    finished_at=self.at + dt.timedelta(minutes=5), **versions)
            s.add(run)
            s.commit()
            s.refresh(run)
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=self.source_id, kind="collect",
                                    status="success", attempts=1, outcome="partial" if gaps else "ok",
                                    result={"counts": counts, "asset_count": len(assets)}, asset_count=len(assets),
                                    created_at=self.at, finished_at=self.at)
            s.add(job)
            s.commit()
            s.refresh(job)
            for a in assets:
                facts = a.get("facts") or {}
                verdict = C.classify(a["type"], a.get("algorithm"), a.get("key_size"), a.get("protocol"), facts,
                                     self.at)
                s.add(CbomCollectedAsset(
                    team_id=1, run_id=run.id, job_id=job.id, source_id=self.source_id, attempt=1,
                    asset_key=J._asset_key(a["type"], a["target"], a["location"], facts, a.get("name")),
                    asset_type=a["type"], cdx_type=verdict["cdx_type"], target=a["target"], location=a["location"],
                    name=a.get("name"), algorithm=a.get("algorithm"), key_size=a.get("key_size"),
                    protocol=a.get("protocol"), quantum_vulnerable=verdict["quantum_vulnerable"],
                    impact=verdict["impact"], finding_codes=verdict["finding_codes"], finding=verdict["finding"],
                    facts=facts, created_at=self.at))
            s.commit()
            return run.id

    def record(self, run_id: int) -> list[tuple[str, str | None, str | None]]:
        """Record the run's drift; its events as (kind, asset location, code)."""
        with Session(self.engine) as s:
            run = s.get(CbomCollectionRun, run_id)
            D.record_run_drift(s, run, self.at + dt.timedelta(hours=1))
            s.commit()
            return events(s, run_id)

    def diff(self, run_id: int, against: int | None = None) -> dict[str, Any]:
        with Session(self.engine) as s:
            run = s.get(CbomCollectionRun, run_id)
            base = s.get(CbomCollectionRun, against) if against else D.previous_comparable_run(s, run)
            return D.run_diff(s, run, base)

    def not_read(self, run_id: int) -> list[dict[str, Any]]:
        with Session(self.engine) as s:
            return D.run_not_read(s, s.get(CbomCollectionRun, run_id))


def events(s: Session, run_id: int) -> list[tuple[str, str | None, str | None]]:
    rows = s.exec(select(CbomDriftEvent).where(CbomDriftEvent.run_id == run_id)).all()
    return sorted((e.kind, (e.detail or {}).get("location"), e.code) for e in rows if e.kind != "cert_expiring")


def diff_events(diff: dict[str, Any]) -> list[tuple[str, str | None, str | None]]:
    """What ``record_run_drift`` would record for this comparison, from Compare's lists."""
    out = [("new_asset", d.get("location"), None) for d in diff["added"]]
    out += [("removed_asset", d.get("location"), None) for d in diff["removed"]]
    out += [("cert_renewed", d.get("location"), None) for d in diff["changed"] if d.get("renewed")]
    out += [("opened", d.get("location"), d["code"]) for d in diff["opened"]]
    out += [("resolved", d.get("location"), d["code"]) for d in diff["resolved"]]
    return sorted(out)


def assert_events_agree_with_compare(chain: Chain, run_id: int) -> None:
    """D10: the events of a run and Compare against the default baseline are one comparison."""
    with Session(chain.engine) as s:
        recorded = events(s, run_id)
    assert diff_events(chain.diff(run_id)) == recorded


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'drift.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        s.add(Team(id=1, name="Bank One", credit_balance=10.0))
        s.commit()
    return eng


@pytest.fixture()
def emitted(monkeypatch):
    """The ``scan_finished`` summaries handed to integrations."""
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(D, "_emit_finished", lambda _s, _t, _now, **fields: seen.append(fields))
    return seen


RSA = "rsa-1"  # an asymmetric key: quantum-vulnerable, so it moves readiness


def estate() -> list[dict[str, Any]]:
    return [key("k1"), key("k2"), key("k3", rotation=True), key(RSA, spec="RSA_2048", rotation=None)]


# ----------------------------------------------------------------------------- D1: the next clean run
def test_d1_a_clean_run_after_a_throttled_one_opens_nothing_and_compare_agrees(engine, emitted):
    """dev: run3 ``new_asset`` k1 and rsa-1, ``opened`` k1 and k2 KMS_NO_ROTATION (cx3 T, T2)."""
    ch = Chain(engine)
    r1 = ch.run(estate())
    assert ch.record(r1) == []
    r2 = ch.run([key("k2", rotation=None), key("k3", rotation=True), describe_throttled("k1"),
                 rotation_throttled("k2"), describe_throttled(RSA)])
    assert ch.record(r2) == []  # not read, never removed or resolved (dev already did this)
    assert sorted(d["location"] for d in ch.not_read(r2)) == [KMS + "k1", KMS + "k2", KMS + RSA]
    r3 = ch.run(estate())
    assert ch.record(r3) == []
    diff = ch.diff(r3, r2)
    assert diff["added"] == [] and diff["opened"] == [] and diff["resolved"] == []
    assert diff["readiness"]["delta"] == 0.0
    # the throttled run itself: an unread asymmetric key does not move readiness
    assert ch.diff(r2, r1)["readiness"]["delta"] == 0.0
    assert ch.diff(r2, r1)["readiness"]["carried_unread"] == 2  # k1 and rsa-1 at their last known verdict
    for run_id in (r2, r3):
        assert_events_agree_with_compare(ch, run_id)


# ----------------------------------------------------------------------------- D2: transitions while unread
def test_d2_a_key_deleted_or_fixed_while_unread_is_reported_at_the_next_read(engine, emitted):
    """dev: nothing, ever (cx3 L / L2): the incident for a deleted or fixed key stays open."""
    ch = Chain(engine)
    ch.record(ch.run([key("k1"), key("k2")]))
    ch.record(ch.run([key("k2", rotation=None), describe_throttled("k1"), rotation_throttled("k2")]))
    r3 = ch.run([key("k2", rotation=True)])  # k1 deleted, k2's rotation switched on, both while unread
    assert ch.record(r3) == [("removed_asset", KMS + "k1", None), ("resolved", KMS + "k1", "KMS_NO_ROTATION"),
                             ("resolved", KMS + "k2", "KMS_NO_ROTATION")]
    assert_events_agree_with_compare(ch, r3)


def test_d2b_unread_for_several_runs_is_carried_across_every_one(engine, emitted):
    ch = Chain(engine)
    ch.record(ch.run([key("k1"), key("k2")]))
    for _ in range(3):
        assert ch.record(ch.run([key("k2"), describe_throttled("k1")])) == []
    r5 = ch.run([key("k2")])  # k1 deleted
    assert ch.record(r5) == [("removed_asset", KMS + "k1", None), ("resolved", KMS + "k1", "KMS_NO_ROTATION")]


# ----------------------------------------------------------------------------- D3: control
def test_d3_control_a_real_removal_beside_a_gap_is_reported_once(engine, emitted):
    ch = Chain(engine)
    ch.record(ch.run([key("k1"), key("k5")]))
    r2 = ch.run([key("k5", rotation=None), rotation_throttled("k5")])  # k1 really deleted
    assert ch.record(r2) == [("removed_asset", KMS + "k1", None), ("resolved", KMS + "k1", "KMS_NO_ROTATION")]
    r3 = ch.run([key("k5")])
    assert ch.record(r3) == []  # neither removed again nor k5 opened again
    assert_events_agree_with_compare(ch, r3)


# ----------------------------------------------------------------------------- D4: carried views use current rules
def _private_rule(monkeypatch) -> None:
    """A rule change like PR-B's: a PRIVATE certificate is no longer CERT_UNUSED."""
    real = C.classify

    def patched(asset_type, algorithm, key_size, protocol, facts, now=None):
        verdict = real(asset_type, algorithm, key_size, protocol, facts, now)
        if asset_type == "certificate" and (facts or {}).get("aws_type") == "PRIVATE":
            codes = [c for c in verdict["finding_codes"] if c != "CERT_UNUSED"]
            verdict = {**verdict, "finding_codes": codes, "finding": verdict["finding"] if codes else None,
                       "impact": verdict["impact"] if codes else None}
        return verdict

    monkeypatch.setattr(C, "classify", patched)


def test_d4_a_carried_view_is_judged_by_the_current_rules_not_its_own(engine, emitted, monkeypatch):
    """Scenario V.  dev: run3 ``new_asset`` P1; cx3's sketch: ``resolved P1 CERT_UNUSED`` (a false resolved)."""
    ch = Chain(engine)
    ch.record(ch.run([cert("p1", aws_type="PRIVATE"), cert("i1")], versions=OLD))  # old rules: P1 CERT_UNUSED
    _private_rule(monkeypatch)
    r2 = ch.run([cert("i1"), gap(f"{ACM}p1#metadata", "acm certificate p1", scope=[ACM + "p1"])])
    ch.record(r2)
    r3 = ch.run([cert("p1", aws_type="PRIVATE"), cert("i1")])
    assert ch.record(r3) == []
    assert_events_agree_with_compare(ch, r3)


# ----------------------------------------------------------------------------- D5: the walk stays short
def test_d5_a_history_of_by_choice_gaps_loads_two_jobs(engine, emitted, monkeypatch):
    """DA-2c: the Glue ``by_choice`` row is on every AWS job; the walk must not follow it."""
    ch = Chain(engine)
    for _ in range(6):
        last = ch.run([key("k1"), GLUE_OFF])
    loads: list[int] = []
    real = D._job_assets
    monkeypatch.setattr(D, "_job_assets", lambda s, job: loads.append(job.id) or real(s, job))
    ch.record(last)
    assert len(loads) <= 2


def test_d5b_older_levels_load_only_what_the_baseline_gaps_cover(engine, emitted, monkeypatch):
    """Review #132 blocker: the walk loaded every row of up to 20 older jobs.  Now only the baseline job is read in
    full (as on dev); an older job gives only its coverage rows and the rows the baseline's gaps could cover."""
    ch = Chain(engine)
    many = [key(f"m{i}", rotation=True) for i in range(200)]
    ch.run([key("k1"), key("k2"), *many])
    for _ in range(D.CARRY_LEVELS + 5):
        last = ch.run([key("k2"), describe_throttled("k1"), *many])
    full: list[int] = []
    older: list[int] = []
    real_full, real_older = D._job_assets, D._level_rows
    monkeypatch.setattr(D, "_job_assets", lambda s, job: full.append(job.id) or real_full(s, job))
    monkeypatch.setattr(D, "_level_rows", lambda s, jobs, cond: (lambda rows: older.append(
        (len(jobs), sum(len(r) for r in rows.values()))) or rows)(real_older(s, jobs, cond)))
    ch.record(last)
    assert len(full) == 2  # the run's own job and its baseline job, as on dev
    # one query over the older jobs; each gives its gap row (and k1's row where it was read): never 200 keys
    (jobs, loaded), = older
    assert jobs == D.CARRY_LEVELS - 1 and loaded <= 2 * jobs


def test_d5c_the_walk_stops_when_older_gaps_cannot_overlap_the_baselines(engine, emitted, monkeypatch):
    ch = Chain(engine)
    ch.run([key("k1"), key("k2")])
    for _ in range(5):
        ch.run([key("k1"), key("k2"), describe_throttled("k9")])  # an older gap elsewhere
    ch.run([key("k2"), describe_throttled("k1")])  # the baseline job: its gap covers k1 only
    last = ch.run([key("k1"), key("k2")])
    levels: list[int] = []
    real = D._level
    monkeypatch.setattr(D, "_level", lambda s, job, rows=None: levels.append(job.id) or real(s, job, rows))
    assert ch.record(last) == []  # k1 carried from the level before the baseline, which read it
    assert len(levels) == 2  # the baseline job and one older level: the k9 gaps cannot cover what k1's does


def test_a_carried_event_names_the_run_that_last_read_the_asset(engine, emitted):
    """Review #132 major: VEX builds a BOM-Link from baseline_run_id + asset_id, so they must name the same run."""
    ch = Chain(engine)
    r1 = ch.run([key("k1"), key("k2")])
    ch.record(r1)
    ch.record(ch.run([key("k2"), describe_throttled("k1")]))
    r3 = ch.run([key("k2")])
    ch.record(r3)
    with Session(engine) as s:
        resolved = s.exec(select(CbomDriftEvent).where(CbomDriftEvent.run_id == r3,
                                                       CbomDriftEvent.kind == "resolved")).one()
        row = s.get(CbomCollectedAsset, resolved.detail["asset_id"])
        assert resolved.baseline_run_id == r1 == row.run_id
        assert resolved.detail["last_read_run_id"] == r1


# ----------------------------------------------------------------------------- D6: deploy straddle (ST-1)
def test_d6_a_run_judged_after_a_deploy_but_labelled_before_it_is_a_rule_change(engine, emitted, monkeypatch):
    """DA-1: run2 was queued (labelled) under the old rules and classified under the new ones."""
    ch = Chain(engine)
    ch.record(ch.run([cert("p1", aws_type="PRIVATE")], versions=OLD))
    _private_rule(monkeypatch)
    r2 = ch.run([cert("p1", aws_type="PRIVATE")], versions=OLD)
    assert ch.record(r2) == []
    diff = ch.diff(r2)
    assert diff["resolved"] == [] and [(r["code"], r["direction"]) for r in diff["rule_changes"]] == [
        ("CERT_UNUSED", "resolved")]


# ----------------------------------------------------------------------------- D7: introduced-fact guard
def _exported_rule(monkeypatch) -> None:
    """A rule like PR-B's: an exported certificate is not CERT_UNUSED (its key is used outside AWS)."""
    real = C.classify

    def patched(asset_type, algorithm, key_size, protocol, facts, now=None):
        verdict = real(asset_type, algorithm, key_size, protocol, facts, now)
        if asset_type == "certificate" and (facts or {}).get("exported") is True:
            codes = [c for c in verdict["finding_codes"] if c != "CERT_UNUSED"]
            verdict = {**verdict, "finding_codes": codes, "finding": verdict["finding"] if codes else None,
                       "impact": verdict["impact"] if codes else None}
        return verdict

    monkeypatch.setattr(C, "classify", patched)


def test_d7_a_finding_hidden_by_a_newly_sent_fact_is_a_collector_change_not_resolved(engine, emitted, monkeypatch):
    """DA-1 X1.  dev: ``resolved X1 CERT_UNUSED`` (the certificate did not change; the collector did)."""
    _exported_rule(monkeypatch)
    ch = Chain(engine)
    ch.record(ch.run([cert("x1"), cert("c2", exported=False)]))  # x1 stored before the collector sent ``exported``
    r2 = ch.run([cert("x1", exported=True), cert("c2", exported=False, in_use=True)])
    assert ch.record(r2) == [("resolved", ACM + "c2", "CERT_UNUSED")]  # c2: both sides know; attaching it fixed it
    diff = ch.diff(r2)
    assert [(d["location"], d["code"]) for d in diff["collector_changes"]] == [(ACM + "x1", "CERT_UNUSED")]
    assert diff["collector_changes"][0]["label_change"] == "collector change"
    assert diff["counts"]["collector_changes"] == 1
    assert not any(k in diff["collector_changes"][0] for k in ("introduced", "inputs", "fact_keys"))
    assert_events_agree_with_compare(ch, r2)
    r3 = ch.run([cert("x1", exported=True, in_use=True), cert("c2", exported=False, in_use=True)])
    assert ch.record(r3) == []  # both sides now carry the fact: nothing to guard, nothing changed


def test_d7b_the_guard_only_withholds_what_the_new_fact_explains(engine, emitted, monkeypatch):
    """The certificate was ALSO attached in the same run: CERT_UNUSED would be gone without the new fact too."""
    _exported_rule(monkeypatch)
    ch = Chain(engine)
    ch.record(ch.run([cert("x1")]))
    r2 = ch.run([cert("x1", exported=True, in_use=True)])
    assert ch.record(r2) == [("resolved", ACM + "x1", "CERT_UNUSED")]
    assert ch.diff(r2)["collector_changes"] == []


def test_d7c_codes_carried_through_an_incomplete_gap_keep_the_guard(engine, emitted, monkeypatch):
    """Review #132 minor: the codes came from a level without the fact, so the fact is still introduced."""
    _exported_rule(monkeypatch)
    ch = Chain(engine)
    ch.record(ch.run([cert("x1")]))
    partly = gap(f"{ACM}x1#settings", "acm certificate x1 settings", scope=[ACM + "x1"], incomplete=True)
    assert ch.record(ch.run([cert("x1", exported=True), partly])) == []
    r3 = ch.run([cert("x1", exported=True)])
    assert ch.record(r3) == []
    assert [d["code"] for d in ch.diff(r3)["collector_changes"]] == ["CERT_UNUSED"]


def test_introduced_facts_are_the_facts_cb33_adds_and_rules_may_suppress_on():
    assert {"exported", "key_pair_origin"} <= set(D.INTRODUCED_FACTS)


# Facts the AWS collector sent before CB-33 (dev c75aec146, ``aws_collect.py``), per asset type a rule may suppress on.
# A rule that makes a finding vanish because of a fact NOT in this list reads something the stored baselines lack,
# so drift would read the first run with the fact as "resolved": the fact must be in ``drift.INTRODUCED_FACTS``.
_AWS_FACTS_BEFORE_CB33 = {
    "kms_key": set(key("x")["facts"]),
    "certificate": set(cert("x")["facts"]),
}
# Read by the rules before CB-33 for other collectors' rows (a certificate OID, a CA bundle summary); the AWS collector
# never sends them, so no AWS row gains one and drift never compares a row with one against a row without.
_READ_BEFORE_CB33_NEVER_SENT_BY_AWS = {"key_alg_oid", "trust_store"}
_SAMPLES = [key("s1"), key("s2", rotation=True), cert("s3"), cert("s4", aws_type="IMPORTED"),
            cert("s5", aws_type="PRIVATE"), cert("s6", in_use=True)]
_PROBES = (True, False, "ACME", "PRIVATE", "EXTERNAL", "AWS_KMS", "Disabled", "PendingImport", "ISSUED",
           "PENDING_VALIDATION", "MULTI_REGION", "REPLICA", "ENABLED", "DISABLED", "AMAZON_ISSUED", 0, 365)


def _classifier_fact_names() -> set[str]:
    """Every string literal the rules look up with ``.get("…")`` / ``["…"]`` (classify.py and classify_ext)."""
    folder = Path(C.__file__).parent
    files = [folder / "classify.py", *sorted((folder / "classify_ext").glob("*.py"))]
    names: set[str] = set()
    for path in files:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "get" and node.args \
                    and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                names.add(node.args[0].value)
            elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) \
                    and isinstance(node.slice.value, str):
                names.add(node.slice.value)
    return {n for n in names if re.fullmatch(r"[a-z][a-z0-9_]*", n)}


def test_a_rule_that_suppresses_a_finding_on_a_new_aws_fact_must_list_it_as_introduced():
    """DA §5.1 3: fails when a rule makes an AWS finding vanish on a fact the collector did not send before CB-33,
    unless the fact is in ``drift.INTRODUCED_FACTS`` (so drift reads that first run as a collector change)."""
    offenders: dict[str, list[str]] = {}
    for sample in _SAMPLES:
        kind, facts = sample["type"], sample["facts"]
        base = set(C.classify(kind, sample["algorithm"], sample["key_size"], None, facts, T0)["finding_codes"])
        if not base:
            continue
        for name in sorted(_classifier_fact_names() - _AWS_FACTS_BEFORE_CB33[kind] - set(D.INTRODUCED_FACTS)
                           - _READ_BEFORE_CB33_NEVER_SENT_BY_AWS):
            for value in _PROBES:
                codes = set(C.classify(kind, sample["algorithm"], sample["key_size"], None, {**facts, name: value},
                                       T0)["finding_codes"])
                if base - codes:
                    offenders.setdefault(name, []).append(f"{kind} {sample['location'][-2:]}={value!r}: "
                                                          f"{sorted(base - codes)}")
    assert offenders == {}


# ----------------------------------------------------------------------------- D8: a node target
def test_d8_a_network_target_down_for_one_run_is_not_new_when_it_answers_again(engine, emitted):
    """dev: run3 ``new_asset`` 10.9.0.5:443 with its findings ``opened`` again."""
    ch = Chain(engine, kind="network")
    ch.record(ch.run([tls("10.9.0.5"), tls("10.9.0.6")]))
    down = gap("10.9.0.5#no answer", "no answer", scope=None, status="unreachable", target="10.9.0.5")
    assert ch.record(ch.run([tls("10.9.0.6"), down])) == []
    r3 = ch.run([tls("10.9.0.5"), tls("10.9.0.6")])
    assert ch.record(r3) == []
    assert_events_agree_with_compare(ch, r3)


# ----------------------------------------------------------------------------- D9: scan_finished
def test_d9_scan_finished_says_what_was_not_read_and_which_sources_were_partial(engine, emitted):
    """F2: integrations got "0 resolved" and could not tell it from "nothing was read".  dev: neither field."""
    ch = Chain(engine)
    ch.record(ch.run([key("k1"), key("k2")]))
    ch.record(ch.run([key("k2", rotation=None), describe_throttled("k1"), rotation_throttled("k2")]))
    summary = emitted[-1]["summary"]
    assert summary["not_read"] == 2 and summary["partial_sources"] == 1
    ch.record(ch.run([key("k1"), key("k2")]))
    assert emitted[-1]["summary"]["not_read"] == 0 and emitted[-1]["summary"]["partial_sources"] == 0


# ----------------------------------------------------------------------------- unchanged behaviour
def test_without_gaps_nothing_changes(engine, emitted):
    """No gap anywhere: the comparison is the newest complete run, exactly as before."""
    ch = Chain(engine)
    ch.record(ch.run([key("k1"), key("k2")]))
    r2 = ch.run([key("k2", rotation=True), key("k4")])
    assert ch.record(r2) == [("new_asset", KMS + "k4", None), ("opened", KMS + "k4", "KMS_NO_ROTATION"),
                             ("removed_asset", KMS + "k1", None), ("resolved", KMS + "k1", "KMS_NO_ROTATION"),
                             ("resolved", KMS + "k2", "KMS_NO_ROTATION")]
    assert_events_agree_with_compare(ch, r2)


def test_a_by_choice_gap_carries_nothing(engine, emitted):
    """An option the customer switched off is their choice: what it hides is not carried run after run."""
    ch = Chain(engine)
    glue = {"type": "glue_connection", "target": LABEL, "location": f"arn:aws:glue:us-east-1:{ACCT}:connection/c1",
            "name": "c1", "facts": {"ssl_required": False}}
    ch.record(ch.run([key("k1"), glue]))
    ch.record(ch.run([key("k1"), GLUE_OFF, rotation_throttled("k1")]))
    r3 = ch.run([key("k1"), GLUE_OFF])
    ch.record(r3)
    assert ch.not_read(r3) == []  # not carried into r3's baseline: the option is off, nothing to say "not read"
