"""
CERT-In Phase 1 durable E2E — live click-to-result asserts ``cert_in_cbom``.

Peer of ``test_cbom_e2e.py``. Same create → estimate → start → condition-based
poll path. Additionally locks that ``scan_metadata.cbom_compliance.cert_in_cbom``
reaches the results page with a non-empty requirements drilldown, and that at
least one pre-CERT peer framework is still present (regression guard).

Verdict counts stay fixture-locked in aibom hermetic tests — this gate only
asserts transport + presence on a crypto-bearing live scan (default: pyjwt).

Self-skips if the backend is unreachable. Requires Celery on scan_worker_queue.
Run from backend::

  uv run pytest tests/test_certin_cbom_e2e.py -q
"""
from __future__ import annotations

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
REPO = os.getenv("CBOM_E2E_REPO", "https://github.com/jpadilla/pyjwt")
PAYLOAD = json.dumps(
    {
        "cbom": {
            "repo_context": {
                "mode": "github",
                "repo_url": REPO,
                "branch": "master",
                "PAT": "",
            },
            "zip_file_used": False,
            "cbom_file_used": False,
            "scan_binaries": False,
        }
    }
)

_PEER_FRAMEWORKS = (
    "nist_800_57",
    "nist_1800_38b",
    "eu_cra",
    "fips_140_3",
    "rbi_free_ai_protection",
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


def _req(method, path, token=None, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"backend not reachable on {BASE}: {e}")


def _post_multipart(path, token, field, value, timeout=120):
    boundary = "----certinCbomE2Eboundary"
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
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"backend multipart unreachable on {BASE}: {e}")


def _await_terminal(token, sid, deadline_s=300):
    end = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < end:
        st, d = _req("GET", f"/{TEAM}/cbom/scan/{sid}", token)
        last = d.get("scan_status")
        if last in ("success", "failure"):
            return last, d
        time.sleep(3)
    pytest.fail(f"scan {sid} not terminal within {deadline_s}s (last status={last})")


def test_cert_in_cbom_reaches_scan_metadata_e2e():
    token = _token(USER)

    st, d = _req("POST", f"/{TEAM}/cbom/scan", token, {"title": "E2E CERT-In CBOM"})
    if st != 200:
        pytest.skip(f"cannot create cbom scan (status {st}); team {TEAM}/user not seeded")
    sid = d["scan_id"]

    est, _ = _post_multipart(
        f"/{TEAM}/cbom/scan/{sid}/estimate_credits",
        token,
        "start_scan_payload_string",
        PAYLOAD,
    )
    assert est == 200, f"estimate failed: {est}"
    start, _ = _post_multipart(
        f"/{TEAM}/cbom/scan/{sid}/start",
        token,
        "start_scan_payload_string",
        PAYLOAD,
    )
    assert start == 200, f"start failed: {start}"

    status, d = _await_terminal(token, sid)
    assert status == "success", f"scan did not succeed: {(d.get('info') or {}).get('error')}"

    meta = d.get("scan_metadata") or {}
    comp = meta.get("cbom_compliance") or {}
    assert isinstance(comp, dict) and comp, "cbom_compliance missing from scan_metadata"

    assert "cert_in_cbom" in comp, (
        "cert_in_cbom missing from live scan_metadata — restart scan worker after aibom changes"
    )
    ci = comp["cert_in_cbom"]
    assert isinstance(ci, dict)
    for k in ("pass", "fail", "not_bom_evidenceable", "coverage", "requirements"):
        assert k in ci, f"cert_in_cbom missing tri-state key {k}"
    reqs = ci.get("requirements") or []
    assert reqs, "cert_in_cbom requirements drilldown empty"

    peers = [fw for fw in _PEER_FRAMEWORKS if fw in comp]
    assert peers, f"no pre-CERT peer framework present; keys={sorted(comp)}"
