"""SOW D12 Quantum Risk Register grades (audit A-03): quantum-vulnerable assets are graded even when the team has
not set Mosca X/Y/Z, on documented defaults marked "default assumptions", and an SP 800-131A disallowed algorithm
(Triple DES, DES, RC4, MD5 ...) gets a grade of its own instead of "no grade".

* Defaults: X = the source's data lifetime, else the team's X, else 7 years (10 for a high / critical source);
  Y 5 years; Z 10 years (FORMULA_TEXT "Inputs"). ``explain["assumed"]`` names the inputs a default filled, and
  ``RowGrade.q_assumed`` / ``fields()["q_assumed"]`` mark the grade.
* The pure function keeps Q0 ``mosca_missing`` for a caller that passes unset inputs (rules 7-8).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_d12_grades.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from backend.utilities.cbom_sources import qgrade as QG


def _ctx(*, x=None, y=None, z=None, source_x=None, criticality=None, exposure=None):
    job = QG._JobInfo(x=source_x, exposure=exposure, segment=None, source_uid="src-1", source_id=1,
                      source_name="lab", network=False, criticality=criticality)
    return QG.GradeContext(team_x=x, y=y, z=z, jobs={1: job}, run=None, job_rows=[], sources={})


def _row(asset_type="certificate", algorithm="RSA", qv=True, facts=None, key_size=2048, target="10.0.0.5:443"):
    return SimpleNamespace(id=1, job_id=1, asset_type=asset_type, algorithm=algorithm, key_size=key_size,
                           quantum_vulnerable=qv, facts=facts or {}, target=target, location="", protocol=None)


@pytest.mark.parametrize("explain", [True, False])
def test_a_quantum_vulnerable_asset_is_graded_on_defaults_when_mosca_is_unset(explain):
    out = _ctx(exposure="internal").grade_row(_row(), [], explain=explain)
    # 7 + 5 > 10: the data outlives the default horizon -> Q2 internal (was Q0 mosca_missing)
    assert (out.q_grade, out.q_reason) == ("Q2", "qv_exceeds")
    assert out.q_assumed is True and out.fields()["q_assumed"] is True
    assert out.explain["assumed"] == ["x", "y", "z"]
    assert out.q_item_key is None


def test_internet_exposure_on_defaults_is_q1():
    out = _ctx(exposure="internet").grade_row(_row(), [], explain=True)
    assert (out.q_grade, out.q_reason) == ("Q1", "qv_exceeds_internet")
    assert (out.explain["x"], out.explain["y"], out.explain["z"]) == (QG.DEFAULT_X, QG.DEFAULT_Y, QG.DEFAULT_Z)
    assert out.explain["x_basis"] == "default" and out.explain["y_basis"] == out.explain["z_basis"] == "default"
    assert out.explain["inequality"] == "7 + 5 > 10"


def test_the_source_data_lifetime_and_criticality_drive_the_default():
    crit = _ctx(criticality="critical", exposure="internal").grade_row(_row(), [], explain=True)
    assert crit.explain["x"] == QG.DEFAULT_X_CRITICAL and crit.explain["criticality"] == "critical"
    src = _ctx(source_x=1, exposure="internal").grade_row(_row(), [], explain=True)
    assert src.explain["x"] == 1 and src.explain["x_basis"] == "source" and src.explain["assumed"] == ["y", "z"]
    assert (src.q_grade, src.q_reason) == ("Q3", "qv_within")  # 1 + 5 <= 10


def test_the_teams_inputs_win_and_then_nothing_is_assumed():
    out = _ctx(x=2, y=2, z=20, exposure="internal").grade_row(_row(), [], explain=True)
    assert (out.q_grade, out.q_reason) == ("Q3", "qv_within")
    assert out.q_assumed is False and out.explain["assumed"] == []


def test_a_safe_or_not_applicable_asset_never_reads_a_default():
    out = _ctx().grade_row(_row(asset_type="storage_encryption", algorithm="AES-256", qv=None, key_size=256), [],
                           explain=False)
    assert out.q_grade is None and out.q_reason == "not_applicable" and out.q_assumed is False


@pytest.mark.parametrize("algorithm", ["DES-EDE3", "TRIPLE_DES_3KEY", "RC4", "DES"])
@pytest.mark.parametrize("explain", [True, False])
def test_sp800_131a_disallowed_algorithms_get_the_deprecated_class_and_a_grade(algorithm, explain):
    row = _row(asset_type="managed_key", algorithm=algorithm, qv=None, key_size=None, target="lab-mssql:1433")
    out = _ctx(exposure="internal").grade_row(row, [], explain=explain)
    assert (out.q_grade, out.q_reason) == ("Q2", "deprecated")
    if explain:
        assert out.explain["class"] == "deprecated"
    internet = _ctx(exposure="internet").grade_row(row, [], explain=explain)
    assert (internet.q_grade, internet.q_reason) == ("Q1", "deprecated_internet")


def test_the_pure_function_keeps_q0_with_a_reason_for_unset_inputs():
    out = QG.grade(QG.GradeInput(cls="quantum-vulnerable", x=None, y=5, z=10))
    assert (out.q_grade, out.q_reason) == ("Q0", "mosca_missing")
    assert QG.grade(QG.GradeInput(cls="deprecated", exposure="unknown")).q_grade == "Q2"


def test_the_formula_text_documents_the_defaults_and_the_deprecated_rules():
    text = QG.FORMULA_TEXT
    assert "default: 7 years, 10 when the source's business criticality is high or critical" in text
    assert "Y 5 years; Z 10 years" in text and "default assumptions" in text
    assert '-> Q2 "deprecated"' in text and '-> Q1 "deprecated_internet"' in text
    assert QG.REASONS["deprecated"]["grade"] == "Q2" and QG.REASONS["deprecated_internet"]["grade"] == "Q1"
