"""F-1: the views judge each library version's dates once, not twice per library row.

``classify.shown`` (run posture, the asset list, the asset panel, heat map, waves, export) asks the knowledge base for
a library row's upstream end of life on the run day and today. Before F-1 every call scanned every CVE range of the
library again (2 x rows x ranges per view). These tests count that work, so they do not depend on wall time, and
prove the memo cannot outlive the knowledge base it was computed from.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import sys
from pathlib import Path

import pytest
from sqlalchemy import insert
from sqlmodel import Session, SQLModel, create_engine, select

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun,  # noqa: E402
                                CbomCollectionSource, Team)
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources import inventory as INV  # noqa: E402
from backend.utilities.cbom_sources import posture as P  # noqa: E402
from backend.utilities.cbom_sources.classify import classify, shown  # noqa: E402

RUN_DAY = dt.datetime(2026, 8, 1, 9, 0)  # before OpenSSL 3.0's end of life (2026-09-07)
TODAY = dt.datetime(2026, 11, 14, 9, 0)  # after it: the 3.0 rows are judged differently today
VERSIONS = [("openssl", "3.0.2-0ubuntu1.15"), ("libssl3", "3.0.13-0ubuntu3.4"), ("openssl", "3.5.4"),
            ("openssh-server", "1:9.6p1-3ubuntu13.5")]
ROWS_PER_VERSION = 30


@pytest.fixture(autouse=True)
def _builtin_kb(monkeypatch):
    for name in ("CBOM_KB_BUNDLE", "CBOM_KB_BUNDLE_SIG", "CBOM_KB_PUBKEYS"):
        monkeypatch.delenv(name, raising=False)
    clear = crypto_kb.load.cache_clear  # a test may patch ``load``; the monkeypatch is undone after this fixture
    clear()
    yield
    clear()


@pytest.fixture
def run(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'f1.db'}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="f1", credit_balance=0.0))
        src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="linux_servers", name="f1", name_lower="f1")
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="f1", status="finished")
        s.add(src)
        s.add(run)
        s.commit()
        job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                                outcome="ok", params={"source_uid": src.source_uid, "metadata": {}})
        s.add(job)
        s.commit()
        rows = []
        for i in range(ROWS_PER_VERSION * len(VERSIONS)):
            package, version = VERSIONS[i % len(VERSIONS)]
            facts = {"name": package, "version": version, "source": "package"}
            v = classify("crypto_library", None, None, None, facts, RUN_DAY)
            rows.append({"team_id": 1, "run_id": run.id, "job_id": job.id, "source_id": src.id, "attempt": 1,
                         "asset_key": hashlib.sha256(str(i).encode()).hexdigest(), "asset_type": "crypto_library",
                         "cdx_type": v["cdx_type"], "target": f"10.0.0.{i}", "location": f"package:{package}:{i}",
                         "name": package, "algorithm": None, "key_size": None, "protocol": None,
                         "quantum_vulnerable": v["quantum_vulnerable"], "impact": v["impact"],
                         "finding_codes": v["finding_codes"], "finding": v["finding"], "facts": facts,
                         "created_at": RUN_DAY})
        s.execute(insert(CbomCollectedAsset), rows)
        s.commit()
        yield engine, run.id


@pytest.fixture
def range_checks(monkeypatch):
    """Counts the CVE-range comparisons, the work F-1 found repeated per row. A fresh KB first: seeding the run
    judged the same versions, and nothing it left behind may be counted as free."""
    crypto_kb.load.cache_clear()
    calls = {"n": 0}
    real = crypto_kb._in_range

    def counted(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(crypto_kb, "_in_range", counted)
    return calls


def _ranges(package: str) -> int:
    return len(crypto_kb.load()["libraries"][crypto_kb.library_for(package)].get("ranges") or [])


def _once_per_version() -> int:
    """Range checks when each distinct (package, version) is judged once."""
    return sum(_ranges(p) for p, _v in VERSIONS)


def test_run_posture_checks_each_library_version_once_not_per_row(run, range_checks):
    engine, run_id = run
    with Session(engine) as s:
        out = P.run_posture(s, team_id=1, run_id=run_id, risk_model=None)
    assert out["assets"] == ROWS_PER_VERSION * len(VERSIONS)
    # dev: 2 x 120 rows x the library's ranges (~93k); judged once per distinct version: ~800
    assert 0 < range_checks["n"] <= _once_per_version()


def test_asset_list_and_detail_check_each_library_version_once(run, range_checks):
    engine, run_id = run
    with Session(engine) as s:
        listed = INV.list_assets(s, team_id=1, run_id=run_id, page=1, page_size=200, now=TODAY)
        for item in listed["items"][:20]:
            P.asset_detail(s.get(CbomCollectedAsset, item["id"]), None, today=TODAY.date())
    assert listed["total"] == ROWS_PER_VERSION * len(VERSIONS)
    assert 0 < range_checks["n"] <= _once_per_version()


def test_the_views_judge_the_same_as_without_the_memo(run, monkeypatch):
    """Every row's shown(), the posture and the asset panel are identical with the memo emptied before each call."""
    engine, run_id = run
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all()
        memo = [shown(r, TODAY) for r in rows]
        detail = [P.asset_detail(r, None, today=TODAY.date()) for r in rows[:8]]
        cold = []
        for r in rows:
            monkeypatch.setattr(crypto_kb, "_library_memo", (None, {}))
            cold.append(shown(r, TODAY))
        cold_detail = []
        for r in rows[:8]:
            monkeypatch.setattr(crypto_kb, "_library_memo", (None, {}))
            cold_detail.append(P.asset_detail(r, None, today=TODAY.date()))
    assert memo == cold and detail == cold_detail
    # the dated case is exercised: OpenSSL 3.0 passed end of life between the run day and today
    changed = [v for v in memo if v["as_of_run"]]
    assert len(changed) == 2 * ROWS_PER_VERSION and all("LIB_EOL" in v["finding_codes"] for v in changed)


def test_the_memo_follows_a_knowledge_base_swap(monkeypatch):
    """A KB swapped in the same process (signed bundle, cache_clear, patched load) is never answered from the old
    KB's memo, even when both carry the same kb_version; swapping back answers from the first KB again."""
    builtin = crypto_kb.load()
    first = crypto_kb.library_status("openssl", "3.0.2-0ubuntu1.15", today=TODAY.date())
    assert first["eol"]["date"] == builtin["libraries"]["openssl"]["eol"]["3.0"]
    assert first["eol"]["passed"] is True

    later = copy.deepcopy(builtin)  # same kb_version, different content
    later["libraries"]["openssl"]["eol"]["3.0"] = "2030-01-01"
    later["libraries"]["openssl"]["ranges"] = []
    monkeypatch.setattr(crypto_kb, "load", lambda: later)
    swapped = crypto_kb.library_status("openssl", "3.0.2-0ubuntu1.15", today=TODAY.date())
    assert swapped["eol"] == {**first["eol"], "date": "2030-01-01", "passed": False}
    assert swapped["cves"] == [] and first["cves"]

    monkeypatch.setattr(crypto_kb, "load", lambda: builtin)
    assert crypto_kb.library_status("openssl", "3.0.2-0ubuntu1.15", today=TODAY.date()) == first


def test_the_memo_hands_out_copies_and_stays_bounded(monkeypatch):
    a = crypto_kb.library_status("openssl", "3.0.2-0ubuntu1.15", today=TODAY.date())
    a["cves"].append("CVE-0000-0000")
    a["eol"]["sources"].append("tampered")
    a["eol"]["passed"] = False
    b = crypto_kb.library_status("openssl", "3.0.2-0ubuntu1.15", today=TODAY.date())
    assert "CVE-0000-0000" not in b["cves"] and "tampered" not in b["eol"]["sources"] and b["eol"]["passed"] is True
    # the date is applied per call, never memoised
    assert crypto_kb.library_status("openssl", "3.0.2-0ubuntu1.15", today=dt.date(2026, 1, 1))["eol"]["passed"] is False
    assert crypto_kb.library_status("zlib1g", "1.2.13") is None and crypto_kb.library_status("openssl", "") is None

    monkeypatch.setattr(crypto_kb, "_LIBRARY_MEMO_MAX", 16)
    for i in range(100):
        crypto_kb.library_status("openssl", f"3.0.{i}")
    assert len(crypto_kb._library_memo[1]) <= 16
    assert crypto_kb.library_status("openssl", "3.0.99", today=TODAY.date())["upstream_version"] == "3.0.99"

