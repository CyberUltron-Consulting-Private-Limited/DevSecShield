"""
Integration regression tests for CBOM + AI-BOM API hardening (cross-tenant IDOR,
0-10 risk scale, finding idempotency, auth).

Requires the local backend running on :8081 with the seeded demo data
(user cbom-demo@cyberultron.com, team 1, a success CBOM scan + AI-BOM scan).
Tests SELF-SKIP if the backend is unreachable. JWTs are signed with the exported JWT_SECRET_KEY.

Run from backend:  uv run pytest tests/test_bom_api_regressions.py -q
"""
import json
import os
import urllib.error
import urllib.request

import pytest

from backend.tests.support.live_backend import mint_token, require_live_backend

BASE = os.getenv("REGRESSION_BASE_URL", "http://localhost:8081")
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(autouse=True, scope="module")
def _live_backend():
    """Skip the module cleanly unless the backend is up and accepts tokens signed with the exported secret."""
    require_live_backend(BASE, DEMO, 1)


def _token(sub):
    return mint_token(sub)


def _req(method, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except OSError:  # URLError, or a server on that port that is not the API (it resets the connection)
        pytest.skip("backend not reachable on " + BASE)


DEMO = "cbom-demo@cyberultron.com"
ATTACKER = "attacker@evil.com"  # member of a different team (seeded earlier) or unknown subject


def _first_success_scan(scan_type):
    st, d = _req("GET", f"/1/{scan_type}/scans", _token(DEMO))
    if st != 200:
        pytest.skip(f"no access to {scan_type} scans (status {st})")
    for s in d.get("scans_list_data", []):
        if s.get("scan_status") == "success":
            return s["id"]
    pytest.skip(f"no success {scan_type} scan seeded")


@pytest.mark.parametrize("scan_type", ["cbom", "ai_bom"])
def test_auth_required(scan_type):
    st, _ = _req("GET", f"/1/{scan_type}/scans")
    assert st == 401


@pytest.mark.parametrize("scan_type", ["cbom", "ai_bom"])
def test_foreign_team_forbidden(scan_type):
    st, _ = _req("GET", f"/999/{scan_type}/scans", _token(DEMO))
    assert st in (403, 404)


@pytest.mark.parametrize("scan_type", ["cbom", "ai_bom"])
def test_bad_scan_id_validation(scan_type):
    st, _ = _req("GET", f"/1/{scan_type}/scan/abc", _token(DEMO))
    assert st == 422


@pytest.mark.parametrize("scan_type", ["cbom", "ai_bom"])
def test_risk_score_is_0_to_10_scale(scan_type):
    sid = _first_success_scan(scan_type)
    st, d = _req("GET", f"/1/{scan_type}/scan/{sid}", _token(DEMO))
    assert st == 200
    for f in d.get("findings") or []:
        rs = f.get("risk_score")
        if rs is None:
            continue
        assert 0 <= rs <= 10, f"risk_score {rs} out of 0-10 range"
        if (f.get("impact") or "").lower() == "high":
            assert rs == 7, f"High impact must map to 7 on 0-10 scale, got {rs}"


@pytest.mark.parametrize("scan_type", ["cbom", "ai_bom"])
def test_finding_toggle_cross_tenant_idor_closed(scan_type):
    """An attacker (different/unknown team) must NOT be able to toggle a victim finding by ObjectId."""
    sid = _first_success_scan(scan_type)
    st, d = _req("GET", f"/1/{scan_type}/scan/{sid}", _token(DEMO))
    findings = d.get("findings") or []
    if not findings:
        pytest.skip("no findings to test IDOR")
    victim_fid = findings[0]["id"]
    before = findings[0].get("status")
    # attacker uses their own team context (3) + the victim finding id
    st2, resp = _req("POST", f"/3/{scan_type}/scan/9999/finding", _token(ATTACKER),
                     {"finding_id": victim_fid, "state": "ignored"})
    assert st2 in (403, 404), f"IDOR not closed: attacker got {st2} {resp}"
    # confirm victim unchanged
    st3, d3 = _req("GET", f"/1/{scan_type}/scan/{sid}", _token(DEMO))
    after = next((f.get("status") for f in (d3.get("findings") or []) if f["id"] == victim_fid), None)
    assert after == before, "victim finding was mutated cross-tenant"


@pytest.mark.parametrize("scan_type", ["cbom", "ai_bom"])
def test_finding_count_idempotent_on_repoll(scan_type):
    sid = _first_success_scan(scan_type)
    counts = []
    for _ in range(3):
        st, d = _req("GET", f"/1/{scan_type}/scan/{sid}", _token(DEMO))
        assert st == 200
        counts.append(len(d.get("findings") or []))
    assert len(set(counts)) == 1, f"finding count changed across re-polls: {counts}"
