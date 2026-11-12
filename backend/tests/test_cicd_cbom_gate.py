"""CB-30: the CBOM policy gate on the hosted CI path (POST /cicd/cbom/scan).

A customer pipeline uploads its tree with the team's CI/CD key and must be able to fail on the answer. The verdict
follows the code-scan CLI's gate (``aibom cbom`` exits 1 on ``aibom.cbom.gate.FAIL_CODES``), decided from the
run-object rows the hosted path already returns. Expected verdicts come from NIST SP 800-131A Rev. 2 (RSA keys
below 2048 bits are disallowed for digital signature generation and key establishment; RSA >= 2048 and AES-GCM
are acceptable) and from the CLI's documented exit code, never from a product view.

Run (repo root): cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_cicd_cbom_gate.py -q
The cross-lane test calls aibom/.venv/bin/python (the backend CI job installs it).
"""
from __future__ import annotations

import ast
import json
import os
import pathlib
import subprocess
import sys
import types

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("JWT_SECRET_KEY", "cb30-cicd-gate-test-secret-not-for-prod")

from backend.new_models import CicdIntegration, Team, User  # noqa: E402
from backend.utilities.cicd import cbom_gate  # noqa: E402
from backend.utilities.cicd.auth import get_user_and_integration_id  # noqa: E402
from backend.main import app  # noqa: E402

ENGINE_GATE = ROOT / "aibom/src/aibom/cbom/gate.py"
AIBOM_PY = ROOT / "aibom/.venv/bin/python"


def _engine_fail_codes() -> set[str]:
    """``FAIL_CODES`` read from the engine's source (the backend image does not ship the aibom package)."""
    tree = ast.parse(ENGINE_GATE.read_text(encoding="utf-8"))
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "FAIL_CODES" for t in node.targets):
            call = node.value
            assert isinstance(call, ast.Call) and getattr(call.func, "id", "") == "frozenset"
            items = call.args[0].elts
            return {item.value if isinstance(item, ast.Constant) else constants[item.id] for item in items}
    raise AssertionError(f"FAIL_CODES not found in {ENGINE_GATE}")


# ------------------------------------------------------------------------------------------------- the policy itself
def test_fail_codes_are_the_engine_gate():
    engine = _engine_fail_codes()
    assert {"WEAK_ALGORITHM", "WEAK_KEY_SIZE", "HARDCODED_KEY", "VULNERABLE_CRYPTO_LIBRARY"} <= engine
    assert set(cbom_gate.FAIL_CODES) == engine


def _row(title: str, codes: list[str], location: str = "app/keys.py", line: int | None = 5, impact: str | None = "High"):
    return {"title": title, "finding_codes": codes, "location": location, "line": line, "impact": impact,
            "bom_ref": f"ref-{title}"}


def test_a_high_finding_fails_the_gate():
    run = {"results": [_row("AES-GCM", []), _row("RSA-1024", ["QUANTUM_VULNERABLE", "WEAK_ALGORITHM"])]}
    gate = cbom_gate.evaluate(run)
    assert gate["verdict"] == "fail"
    assert cbom_gate.gate_failed(gate) is True
    assert gate["failing_count"] == 1
    assert gate["failing"] == [{"codes": ["WEAK_ALGORITHM"], "title": "RSA-1024", "location": "app/keys.py",
                                "line": 5, "impact": "High"}]
    assert gate["fail_codes"] == sorted(cbom_gate.FAIL_CODES)
    assert "WEAK_ALGORITHM" in gate["reason"]


@pytest.mark.parametrize("codes", [[], ["QUANTUM_VULNERABLE"], ["CUSTOM_CRYPTO"], ["CERT_EXPIRED"]])
def test_findings_outside_the_policy_pass(codes):
    # The CLI reports quantum-vulnerable and custom-crypto findings without failing the build (gate.py docstring).
    gate = cbom_gate.evaluate({"results": [_row("RSA-3072", codes)]})
    assert gate["verdict"] == "pass"
    assert cbom_gate.gate_failed(gate) is False
    assert gate["failing"] == [] and gate["failing_count"] == 0


def test_an_empty_inventory_passes():
    assert cbom_gate.evaluate({"results": []})["verdict"] == "pass"


@pytest.mark.parametrize("run", [None, [], "x", {}, {"results": None}, {"results": {"a": 1}}])
def test_no_result_fails_closed(run):
    gate = cbom_gate.evaluate(run)
    assert gate["verdict"] == "no_result"
    assert cbom_gate.gate_failed(gate) is True
    assert gate["failing"] == []


def test_the_reason_tells_a_timeout_from_an_unreadable_result():
    # None: poll_for_results gave up (running the job again can help); anything else arrived but cannot be read.
    timed_out = cbom_gate.evaluate(None)["reason"]
    assert "within the time limit" in timed_out and "again" in timed_out
    for run in ([], "x", {}, {"results": None}, {"results": {"a": 1}}):
        reason = cbom_gate.evaluate(run)["reason"]
        assert "could not be read" in reason and "time limit" not in reason, run


def test_malformed_rows_are_skipped_not_fatal():
    run = {"results": ["junk", None, {"finding_codes": None}, {"finding_codes": "WEAK_ALGORITHM"},
                       _row("DES", ["WEAK_ALGORITHM"], line=None, impact=None)]}
    gate = cbom_gate.evaluate(run)
    assert gate["verdict"] == "fail"
    assert gate["failing_count"] == 1
    assert gate["failing"][0]["title"] == "DES" and gate["failing"][0]["line"] is None


@pytest.mark.parametrize(("rows", "truncated"), [(cbom_gate.MAX_LISTED, False), (cbom_gate.MAX_LISTED + 1, True)])
def test_the_cap_boundary(rows, truncated):
    gate = cbom_gate.evaluate({"results": [_row(f"DES-{i}", ["WEAK_ALGORITHM"]) for i in range(rows)]})
    assert gate["failing_count"] == rows
    assert len(gate["failing"]) == cbom_gate.MAX_LISTED
    assert gate["truncated"] is truncated


def test_the_failing_list_is_capped_and_says_so():
    rows = [_row(f"DES-{i}", ["WEAK_ALGORITHM"]) for i in range(cbom_gate.MAX_LISTED + 7)]
    gate = cbom_gate.evaluate({"results": rows})
    assert gate["failing_count"] == cbom_gate.MAX_LISTED + 7
    assert len(gate["failing"]) == cbom_gate.MAX_LISTED
    assert gate["truncated"] is True
    json.dumps(gate)  # stored in Mongo and returned as JSON


# ------------------------------------------------------------------------------------------------ the hosted route
class _Logs:
    def __init__(self):
        self.docs: dict[str, dict] = {}

    def insert_one(self, doc):
        oid = "6553f0e0a0b0c0d0e0f00001"
        self.docs[oid] = dict(doc)
        return types.SimpleNamespace(inserted_id=oid)

    def update_one(self, flt, update):
        doc = self.docs[str(flt["_id"])]
        doc.update(update.get("$set", {}))
        return types.SimpleNamespace(matched_count=1)


@pytest.fixture()
def ci(monkeypatch: pytest.MonkeyPatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    monkeypatch.setattr("backend.get_db.get_db", lambda: eng)
    monkeypatch.setattr("backend.routers.cicd.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.cicd.auth.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.team.credits.get_db", lambda: eng)
    logs = _Logs()
    monkeypatch.setattr("backend.routers.cicd.get_mongo_client_db", lambda: {"cicd_logs": logs})
    monkeypatch.setattr("backend.routers.cicd.get_celery_app", lambda: object())
    monkeypatch.setattr("backend.routers.cicd.deduct_credits_from_team", lambda **_kw: None)

    async def _estimate(**_kw):
        return 1.0

    async def _start(**_kw):
        return ("task-cb30", "pending")

    monkeypatch.setattr("backend.routers.cicd.estimate_cicd_scan", _estimate)
    monkeypatch.setattr("backend.routers.cicd.start_cicd_scan_and_update_db", _start)
    state: dict = {"run": None}

    async def _poll(task_id, celery_app, collection, log_id):
        collection.update_one({"_id": log_id}, {"$set": {"results": state["run"], "status": "success"}})
        return state["run"]

    monkeypatch.setattr("backend.routers.cicd.poll_for_results", _poll)

    with Session(eng) as session:
        team = Team(name="t", credit_balance=50.0)
        session.add(team)
        session.commit()
        session.refresh(team)
        user = User(email="ci@example.com", password="x", first_name="c", last_name="i", default_team_id=team.id)
        session.add(user)
        session.commit()
        session.refresh(user)
        integrations = {}
        for kind in ("cbom", "sast"):
            integ = CicdIntegration(team_id=team.id, owner_user_id=user.id, api_key=f"hashed-{kind}",
                                    title=f"ci-{kind}", scan_type=kind,
                                    scan_settings={"sast": {"app_lang": "python"}} if kind == "sast" else {})
            session.add(integ)
            session.commit()
            session.refresh(integ)
            integrations[kind] = integ.id
        ids = {"team_id": team.id, "user_id": user.id, **integrations}

    def auth_as(kind: str):
        app.dependency_overrides[get_user_and_integration_id] = lambda: {
            "user_id": ids["user_id"], "integration_id": ids[kind], "team_id": ids["team_id"], "scan_type": kind}

    yield TestClient(app), state, logs, auth_as
    app.dependency_overrides.clear()


def _post(http: TestClient, kind: str):
    return http.post(f"/cicd/{kind}/scan", files={"zip_file": ("project.zip", b"PK\x03\x04-not-read-here", "application/zip")})


def test_route_fails_the_gate_on_a_high_finding_and_stores_the_verdict(ci):
    http, state, logs, auth_as = ci
    auth_as("cbom")
    state["run"] = {"results": [_row("RSA-1024", ["QUANTUM_VULNERABLE", "WEAK_ALGORITHM"])], "cbom_json": {}}
    response = _post(http, "cbom")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["gate_failed"] is True
    assert body["gate"]["verdict"] == "fail"
    assert body["gate"]["failing"][0]["codes"] == ["WEAK_ALGORITHM"]
    stored = logs.docs[body["cicd_log_id"]]
    assert stored["gate"] == body["gate"]  # the log records what the pipeline was told
    # the shape the customer templates test (FastAPI's compact JSON)
    assert '"gate_failed":true' in response.text


def test_route_passes_the_gate_on_a_clean_tree(ci):
    http, state, logs, auth_as = ci
    auth_as("cbom")
    state["run"] = {"results": [_row("RSA-3072", ["QUANTUM_VULNERABLE"]), _row("AES-GCM", [])], "cbom_json": {}}
    response = _post(http, "cbom")
    body = response.json()
    assert response.status_code == 200
    assert body["gate_failed"] is False and body["gate"]["verdict"] == "pass"
    assert '"gate_failed":false' in response.text
    assert logs.docs[body["cicd_log_id"]]["gate"]["verdict"] == "pass"


def test_route_fails_closed_when_no_result_arrives_in_time(ci):
    http, state, logs, auth_as = ci
    auth_as("cbom")
    state["run"] = None  # poll_for_results gives up after its 20 x 10 s window and returns None
    response = _post(http, "cbom")
    body = response.json()
    assert response.status_code == 200
    assert body["gate_failed"] is True
    assert body["gate"]["verdict"] == "no_result"
    assert logs.docs[body["cicd_log_id"]]["gate"]["verdict"] == "no_result"


def test_the_pipeline_gets_its_verdict_when_storing_it_fails(ci):
    http, state, logs, auth_as = ci
    auth_as("cbom")
    state["run"] = {"results": [_row("RSA-1024", ["WEAK_ALGORITHM"])], "cbom_json": {}}
    real_update = logs.update_one

    def flaky(flt, update):
        if "gate" in update.get("$set", {}):
            raise RuntimeError("mongo went away")
        return real_update(flt, update)

    logs.update_one = flaky
    response = _post(http, "cbom")
    assert response.status_code == 200, response.text
    assert response.json()["gate_failed"] is True
    assert "gate" not in logs.docs[response.json()["cicd_log_id"]]


def test_other_scan_types_get_no_cbom_verdict(ci):
    http, state, logs, auth_as = ci
    auth_as("sast")
    state["run"] = {"results": [{"title": "sql injection", "impact": "High"}]}
    response = _post(http, "sast")
    body = response.json()
    assert response.status_code == 200, response.text
    assert "gate_failed" not in body and "gate" not in body
    assert "gate" not in logs.docs[body["cicd_log_id"]]


def test_integration_logs_carry_the_stored_verdict_and_never_invent_one(ci, monkeypatch):
    http, state, logs, auth_as = ci
    auth_as("cbom")
    state["run"] = {"results": [_row("RSA-1024", ["WEAK_ALGORITHM"])], "cbom_json": {}}
    posted = _post(http, "cbom").json()
    # a log written before the gate existed: same results, no stored verdict
    logs.docs["6553f0e0a0b0c0d0e0f00002"] = {**logs.docs[posted["cicd_log_id"]], "gate": None}
    logs.docs["6553f0e0a0b0c0d0e0f00002"].pop("gate")
    from backend.routers import cicd as router

    class _Cursor(list):
        def sort(self, *_a, **_k):
            return self

        def limit(self, *_a):
            return self

        def skip(self, *_a):
            return self

    def _find(_flt):
        return _Cursor({"_id": oid, **doc} for oid, doc in logs.docs.items())

    logs.find = _find
    monkeypatch.setattr(router, "get_user_from_header_or_raise_exception",
                        lambda *_a, **_k: _async(types.SimpleNamespace(id=1)))
    monkeypatch.setattr(router, "check_if_user_is_in_team", lambda *_a, **_k: None)
    monkeypatch.setattr(router, "project_cbom_ci_page", lambda _run: None)
    monkeypatch.setattr(router, "get_cicd_vuln_chart_data", lambda **_k: {})
    with Session(router.get_db()) as session:
        integ = session.exec(__import__("sqlmodel").select(CicdIntegration).where(CicdIntegration.scan_type == "cbom")).first()
        team_id, integ_id = integ.team_id, integ.id
    response = http.get(f"/{team_id}/cicd/integration/{integ_id}", headers={"Authorization": "Bearer x"})
    assert response.status_code == 200, response.text
    by_id = {log["id"]: log for log in response.json()["logs"]}
    assert by_id[posted["cicd_log_id"]]["gate"]["verdict"] == "fail"
    assert by_id["6553f0e0a0b0c0d0e0f00002"]["gate"] is None


async def _coro(value):
    return value


def _async(value):
    return _coro(value)


# ---------------------------------------------------------------- cross-lane: the real engine, the hosted verdict, the CLI
_RSA_1024 = """from cryptography.hazmat.primitives.asymmetric import rsa


def make_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
"""
_CLEAN = """import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def make_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def seal(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)
"""
_HOSTED_RUN = r"""
import json, sys
from pathlib import Path
from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield
Path(sys.argv[2]).write_text(json.dumps(scan_crypto_to_devsecshield(sys.argv[1], level=4)), encoding="utf-8")
"""


@pytest.mark.parametrize(("source", "sp800_131a_fails"), [(_RSA_1024, True), (_CLEAN, False)], ids=["rsa1024", "clean"])
def test_hosted_verdict_matches_sp800_131a_and_the_cli(tmp_path, source, sp800_131a_fails):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "keys.py").write_text(source, encoding="utf-8")
    dest = tmp_path / "run.json"
    # the run-object exactly as the worker builds it for POST /cicd/cbom/scan (scan_worker.cbom -> CBOMAgent.scan)
    subprocess.run([str(AIBOM_PY), "-c", _HOSTED_RUN, str(tree), str(dest)], cwd=ROOT / "aibom", check=True,
                   capture_output=True, text=True, timeout=300)
    gate = cbom_gate.evaluate(json.loads(dest.read_text(encoding="utf-8")))
    assert cbom_gate.gate_failed(gate) is sp800_131a_fails
    cli = subprocess.run([str(AIBOM_PY), "-m", "aibom.cli", "cbom", str(tree), "-o", str(tmp_path / "bom.json")],
                         cwd=ROOT / "aibom", capture_output=True, text=True, timeout=300)
    assert cli.returncode == (1 if sp800_131a_fails else 0), cli.stderr
    if sp800_131a_fails:
        assert gate["failing"] and gate["failing"][0]["location"].endswith("keys.py")
