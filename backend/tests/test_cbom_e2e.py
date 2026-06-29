"""
End-to-end CBOM test — the full click-to-result path through the platform's
NORMAL mechanism: create -> estimate -> start (the same API the UI calls), then
AWAIT the terminal job state via the status endpoint and assert the results-page
payload (crypto findings + dashboard + the CBOM chart/compliance data the C9
CbomCryptoCharts render).

The CBOM peer of test_ai_bom_e2e.py. Both scan types share one async job
lifecycle (start_scan -> scan_worker_queue -> Scan.scan_data -> GET .../scan/{id}).
This test additionally guards the I4 regression that motivated it: a reconciled
CBOM scan's `cbom_distributions`/`cbom_compliance` MUST reach the results-page
`scan_metadata` (the GET-scan `data` field only carries the findings list, so the
metadata branch is the only path that surfaces the C9 chart data — see
backend/utilities/dashboard/scan_metadata.py cbom branch).

Live API, self-skips if the backend is unreachable, JWT minted from backend/.env.
Requires the Celery worker consuming scan_worker_queue. Run from backend:
  uv run pytest tests/test_cbom_e2e.py -q

Waiting is CONDITION-BASED (skill-condition-based-waiting): the poll loop returns
the instant a terminal state (success/failure) is observed and FAILS on a
deadline — it never sleeps a fixed, assumed scan duration.
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
TEAM = int(os.getenv("CBOM_E2E_TEAM", "1"))
USER = os.getenv("CBOM_E2E_USER", "cbom-demo@cyberultron.com")
# A small, reliably-cloned, crypto-bearing repo (HMAC/RSA/ECDSA/Ed25519 algorithm
# references in jwt/algorithms.py) so the scan yields real crypto assets.
REPO = os.getenv("CBOM_E2E_REPO", "https://github.com/jpadilla/pyjwt")
PAYLOAD = json.dumps(
    {
        "cbom": {
            "repo_context": {"mode": "github", "repo_url": REPO, "branch": "master", "PAT": ""},
            "zip_file_used": False,
            "cbom_file_used": False,
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
    boundary = "----cbomE2Eboundary"
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
        st, d = _req("GET", f"/{TEAM}/cbom/scan/{sid}", token)
        last = d.get("scan_status")
        if last in ("success", "failure"):
            return last, d
        time.sleep(3)  # inter-poll backoff; loop EXITS on the terminal condition
    pytest.fail(f"scan {sid} not terminal within {deadline_s}s (last status={last})")


def test_cbom_click_to_result_e2e():
    token = _token(USER)

    # 1. create the scan (returns the job id) — the UI's first call.
    st, d = _req("POST", f"/{TEAM}/cbom/scan", token, {"title": "E2E CBOM"})
    if st != 200:
        pytest.skip(f"cannot create cbom scan (status {st}); team {TEAM}/user not seeded")
    sid = d["scan_id"]

    # 2. estimate + 3. start (multipart, exactly as the UI triggers).
    est, _ = _post_multipart(
        f"/{TEAM}/cbom/scan/{sid}/estimate_credits", token, "start_scan_payload_string", PAYLOAD
    )
    assert est == 200, f"estimate failed: {est}"
    start, _ = _post_multipart(
        f"/{TEAM}/cbom/scan/{sid}/start", token, "start_scan_payload_string", PAYLOAD
    )
    assert start == 200, f"start failed: {start}"

    # 4. AWAIT the terminal job state (condition-based).
    status, d = _await_terminal(token, sid)
    assert status == "success", f"scan did not succeed: {(d.get('info') or {}).get('error')}"

    # 5. assert the results-page payload the UI renders.
    assert len(d.get("findings", [])) >= 1, "no crypto findings persisted"
    dash = d.get("dashboard") or {}
    assert (dash.get("card_data") or {}).get("total_crypto_assets", 0) >= 1, "no crypto assets"

    # 6. assert the CBOM chart/compliance data the C9 CbomCryptoCharts consume —
    # the I4 regression guard. These ride in scan_metadata (the GET-scan `data`
    # field is only the findings list), so a dropped metadata key silently blanks
    # every crypto chart.
    meta = d.get("scan_metadata") or {}
    assert isinstance(meta.get("cbom_json"), dict), "CycloneDX CBOM missing"
    dist = meta.get("cbom_distributions") or {}
    assert isinstance(dist, dict) and dist, "cbom_distributions missing from results payload"
    # The 5 C9 charts bind these keys; algorithms is the always-present spine.
    assert dist.get("algorithms"), "algorithm distribution empty (C9 chart would blank)"
    comp = meta.get("cbom_compliance") or {}
    assert isinstance(comp, dict) and comp, "cbom_compliance (tri-state) missing"
