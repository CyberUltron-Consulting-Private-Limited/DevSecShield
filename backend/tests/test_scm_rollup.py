"""F3: de-duplication and roll-up of findings across repositories (backend/utilities/scm/rollup.py).

The same issue in many repositories is one roll-up finding with a repository count; a rescan replaces that
repository's occurrences; a finding left in no repository is resolved, and re-opened when it comes back.
"""
from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "scm-test-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "scm-test-refresh")
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode())

from sqlmodel import Session, select  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_scm_queue as _q  # noqa: E402

from backend.utilities.scm import rollup as R  # noqa: E402
from backend.utilities.scm.models import ScmFinding, ScmFindingOccurrence  # noqa: E402

engine, make_world = _q.engine, _q.make_world  # fixture and world builder of the queue tests
T0 = dt.datetime(2026, 11, 11, 12, 0)


def lodash(location="package-lock.json"):
    return {"dependency": "lodash@4.17.15", "title": "Prototype pollution", "impact": "high",
            "cves": ["CVE-2020-8203"], "location": location}


def sbom(*rows):
    return {"results": list(rows)}


def test_fingerprints_are_location_free_and_product_specific():
    a, _t, _f = R.describe("sbom_sca", lodash("a/package-lock.json"))
    b, _t, _f = R.describe("sbom_sca", lodash("b/yarn.lock"))
    c, _t, _f = R.describe("sbom_sca", {**lodash(), "cves": ["CVE-2021-23337"]})
    assert a == b and a != c
    assert R.describe("sbom_sca", {**lodash(), "cves": ["cve-2020-8203"]})[0] == a  # CVE case does not matter
    iac1 = R.describe("iac", {"title": "S3 bucket without encryption", "category": "Encryption", "location": "a.tf"})
    iac2 = R.describe("iac", {"title": "S3  bucket WITHOUT encryption", "category": "encryption", "location": "b.tf"})
    assert iac1[0] == iac2[0]
    cb1 = R.describe("cbom", {"asset_type": "algorithm", "algorithm_name": "RSA-1024", "finding_codes": ["WEAK_KEY"],
                              "location": "x.py:10"})
    cb2 = R.describe("cbom", {"asset_type": "algorithm", "algorithm_name": "RSA-1024", "finding_codes": ["WEAK_KEY"],
                              "location": "y.java:3"})
    assert cb1[0] == cb2[0] and cb1[2]["finding_codes"] == ["WEAK_KEY"]
    assert R.describe("sast", {"title": "SQL injection"})[0] != R.describe("iac", {"title": "SQL injection"})[0]


def test_result_shapes_match_what_create_findings_stores():
    sast = {"results": [{"logical_component_title": "login", "vulnerabilities": [{"title": "SQLi", "impact": "high"},
                                                                                 {"title": "XSS", "impact": "low"}]}]}
    assert [f["title"] for f in R.iter_findings("sast", sast)] == ["SQLi", "XSS"]
    cbom = {"results": [{"title": "AES-GCM", "finding_codes": [], "asset_type": "algorithm"},  # clean inventory row
                        {"title": "RSA-1024", "finding_codes": ["WEAK_KEY"], "asset_type": "algorithm"}]}
    assert [f["title"] for f in R.iter_findings("cbom", cbom)] == ["RSA-1024"]
    assert list(R.iter_findings("iac", {"results": "not a list"})) == []
    assert list(R.iter_findings("sbom_sca", None)) == []
    assert [f["title"] for f in R.iter_findings("sbom_sca", sbom({"dependency": "x@1"}))] == ["x@1"]


def test_same_issue_in_many_repositories_is_one_finding(engine):
    ids = make_world(engine, repos_per_team={1: 5, 2: 1})
    repos = ids["repos"][1]
    with Session(engine) as s:
        for i, repo in enumerate(repos):
            rows = [lodash(f"svc-{i}/package-lock.json")]
            if i < 2:
                rows.append({"dependency": "log4j-core@2.14.1", "title": "Log4Shell", "impact": "critical",
                             "cves": ["CVE-2021-44228"]})
            R.fold_scan(s, team_id=1, repo_id=repo, product="sbom_sca", scan_id=100 + i, scan_data=sbom(*rows), now=T0)
        # another team's identical finding is its own roll-up row
        R.fold_scan(s, team_id=2, repo_id=ids["repos"][2][0], product="sbom_sca", scan_id=200, scan_data=sbom(lodash()),
                    now=T0)
        s.commit()
        team1 = {f.title: f for f in s.exec(select(ScmFinding).where(ScmFinding.team_id == 1)).all()}
    assert set(team1) == {"Prototype pollution (lodash@4.17.15)", "Log4Shell (log4j-core@2.14.1)"}
    assert (team1["Prototype pollution (lodash@4.17.15)"].repo_count,
            team1["Prototype pollution (lodash@4.17.15)"].occurrence_count) == (5, 5)
    assert team1["Log4Shell (log4j-core@2.14.1)"].repo_count == 2
    assert team1["Log4Shell (log4j-core@2.14.1)"].severity == "critical"
    assert team1["Log4Shell (log4j-core@2.14.1)"].key_fields["cves"] == ["CVE-2021-44228"]
    # 7 occurrences across 5 repositories de-duplicate to 2 findings


def test_rescan_replaces_occurrences_resolves_and_reopens(engine):
    ids = make_world(engine, repos_per_team={1: 3})
    a, b, c = ids["repos"][1]
    with Session(engine) as s:
        for repo in (a, b, c):
            R.fold_scan(s, team_id=1, repo_id=repo, product="sbom_sca", scan_id=1, scan_data=sbom(lodash(), lodash("x")),
                        now=T0)
        s.commit()
        finding = s.exec(select(ScmFinding)).one()
        assert (finding.repo_count, finding.occurrence_count) == (3, 6)
        # repo a upgraded lodash: its occurrence goes, the others stay
        R.fold_scan(s, team_id=1, repo_id=a, product="sbom_sca", scan_id=2, scan_data=sbom(), now=T0)
        s.commit()
        s.refresh(finding)
        assert (finding.repo_count, finding.occurrence_count, finding.resolved_at) == (2, 4, None)
        # an IaC scan of b does not touch b's SBOM occurrences
        R.fold_scan(s, team_id=1, repo_id=b, product="iac", scan_id=3, scan_data={"results": []}, now=T0)
        s.commit()
        s.refresh(finding)
        assert finding.repo_count == 2
        later = T0 + dt.timedelta(days=1)
        for repo in (b, c):
            R.fold_scan(s, team_id=1, repo_id=repo, product="sbom_sca", scan_id=4, scan_data=sbom(), now=later)
        s.commit()
        s.refresh(finding)
        assert finding.repo_count == 0 and finding.resolved_at == later
        R.fold_scan(s, team_id=1, repo_id=c, product="sbom_sca", scan_id=5, scan_data=sbom(lodash()), now=later)
        s.commit()
        s.refresh(finding)
        assert finding.repo_count == 1 and finding.resolved_at is None
        R.forget_repo(s, c, later)
        s.commit()
        s.refresh(finding)
        assert finding.repo_count == 0 and finding.resolved_at is not None
        assert s.exec(select(ScmFindingOccurrence)).all() == []


def test_fold_is_idempotent(engine):
    ids = make_world(engine, repos_per_team={1: 1})
    repo = ids["repos"][1][0]
    with Session(engine) as s:
        for _ in range(3):
            assert R.fold_scan(s, team_id=1, repo_id=repo, product="sbom_sca", scan_id=9,
                               scan_data=sbom(lodash(), lodash("y")), now=T0) == 2
            s.commit()
        assert len(s.exec(select(ScmFinding)).all()) == 1
        occ = s.exec(select(ScmFindingOccurrence)).one()
        assert occ.count == 2 and occ.locations == ["package-lock.json", "y"]


@pytest.mark.parametrize("impact,expected", [("CRITICAL", "critical"), ("High", "high"), (None, "low"),
                                             ("informational", "info"), ("bogus", "low")])
def test_severity_normalisation(impact, expected):
    assert R.severity_of({"impact": impact}) == expected
