"""
End-to-end AI BOM test — the full click-to-result path through the platform's
NORMAL mechanism: create -> estimate -> start (the same API the UI calls), then
AWAIT the terminal job state via the status endpoint and assert the results-page
payload (findings + dashboard + the AI-BOM governance data the charts render).

Mirrors test_bom_api_regressions.py: live API, self-skips if the backend is
unreachable, JWT minted from backend/.env. Requires the Celery worker consuming
scan_worker_queue. Run from backend:  uv run pytest tests/test_ai_bom_e2e.py -q

Waiting is CONDITION-BASED (skill-condition-based-waiting): the poll loop returns
the instant a terminal state (success/failure) is observed and FAILS on a
deadline — it never sleeps a fixed, assumed scan duration. The platform exposes
no completion event (poll-driven by contract), so polling-until-condition is the
correct way to await the terminal state.
"""
import datetime
import json
import os
import re
import time
import urllib.error
import urllib.request

import pytest

BASE = os.getenv("REGRESSION_BASE_URL", "http://localhost:8081")
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEAM = int(os.getenv("AIBOM_E2E_TEAM", "4"))
USER = os.getenv("AIBOM_E2E_USER", "aibom-demo@local.test")
REPO = os.getenv("AIBOM_E2E_REPO", "https://github.com/openai/openai-python")
PAYLOAD = json.dumps(
    {
        "ai_bom": {
            "repo_context": {"mode": "github", "repo_url": REPO, "branch": "main", "PAT": ""},
            "zip_file_used": False,
            "ai_bom_file_used": False,
            "scan_binaries": False,
        }
    }
)


def _env():
    env, path = {}, os.path.join(BACKEND_DIR, ".env")
    if not os.path.exists(path):
        return env
    for line in open(path):
        m = re.match(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$", line.strip())
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if v and v[0] in "\"'":
            q = v[0]
            v = v[1:]
            v = v[: v.index(q)] if q in v else v
        else:
            v = v.split("#")[0].strip()
        if v:
            env[k] = v
    return env


def _token(sub):
    import jwt as jwtlib

    secret = _env().get("JWT_SECRET_KEY")
    if not secret:
        pytest.skip("JWT_SECRET_KEY not available")
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    return jwtlib.encode({"exp": exp, "sub": sub}, secret, algorithm="HS256")


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
    except urllib.error.URLError:
        pytest.skip("backend not reachable on " + BASE)


def _post_multipart(path, token, field, value):
    boundary = "----aibomE2Eboundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"\r\n\r\n'
        f"{value}\r\n--{boundary}--\r\n"
    ).encode()
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Authorization": f"Bearer {token}",
    }
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except urllib.error.URLError:
        pytest.skip("backend not reachable on " + BASE)


def _await_terminal(token, sid, deadline_s=300):
    """Return (status, body) as soon as the job is terminal; fail on deadline."""
    end = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < end:
        st, d = _req("GET", f"/{TEAM}/ai_bom/scan/{sid}", token)
        last = d.get("scan_status")
        if last in ("success", "failure"):
            return last, d
        time.sleep(3)  # inter-poll backoff; loop EXITS on the terminal condition
    pytest.fail(f"scan {sid} not terminal within {deadline_s}s (last status={last})")


def test_ai_bom_click_to_result_e2e():
    token = _token(USER)

    # 1. create the scan (returns the job id) — the UI's first call.
    st, d = _req("POST", f"/{TEAM}/ai_bom/scan", token, {"title": "E2E AI-BOM"})
    if st != 200:
        pytest.skip(f"cannot create ai_bom scan (status {st}); team {TEAM}/user not seeded")
    sid = d["scan_id"]

    # 2. estimate + 3. start (multipart, exactly as the UI triggers).
    est, _ = _post_multipart(
        f"/{TEAM}/ai_bom/scan/{sid}/estimate_credits", token, "start_scan_payload_string", PAYLOAD
    )
    assert est == 200, f"estimate failed: {est}"
    start, _ = _post_multipart(
        f"/{TEAM}/ai_bom/scan/{sid}/start", token, "start_scan_payload_string", PAYLOAD
    )
    assert start == 200, f"start failed: {start}"

    # 4. AWAIT the terminal job state (condition-based).
    status, d = _await_terminal(token, sid)
    assert status == "success", f"scan did not succeed: {(d.get('info') or {}).get('error')}"

    # 5. assert the results-page payload the UI renders.
    assert len(d.get("findings", [])) >= 1, "no findings persisted"
    dash = d.get("dashboard") or {}
    assert (dash.get("card_data") or {}).get("total_ai_assets", 0) >= 1, "no AI assets"

    # 6. assert the AI-BOM governance data the rich charts consume.
    meta = d.get("scan_metadata") or {}
    comp = meta.get("ai_bom_compliance") or {}
    assert [k for k in comp if k != "disclaimer"], "compliance frameworks missing"
    graph = meta.get("ai_bom_graph") or {}
    assert isinstance(graph.get("nodes"), list), "typed graph missing"
    assert isinstance(meta.get("ai_bom_json"), dict), "CycloneDX BOM missing"
