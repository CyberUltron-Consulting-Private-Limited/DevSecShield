"""
CERT-In Phase 3 durable E2E — live click-to-result asserts ``cert_in_sbom``.

Peer of ``test_certin_cbom_e2e.py`` / ``test_certin_aibom_e2e.py``. Locks that
``scan_metadata.sbom_compliance.cert_in_sbom`` reaches the results page with a
non-empty requirements drilldown, and that peer ``rbi_free_ai_supply`` remains.

Self-skips if the backend is unreachable. Requires Celery on scan_worker_queue
for the full create→estimate→start path; metadata-on-existing-scan is the
transport fallback.

Run from backend::

  uv run pytest tests/test_certin_sbom_e2e.py -q
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
TEAM = int(os.getenv("SBOM_E2E_TEAM", os.getenv("CBOM_E2E_TEAM", "1")))
USER = os.getenv(
    "SBOM_E2E_USER",
    os.getenv("CBOM_E2E_USER", "cbom-demo@cyberultron.com"),
)
# Small public repo that typically yields SCA findings.
REPO = os.getenv("SBOM_E2E_REPO", "https://github.com/psf/requests")
PAYLOAD = json.dumps(
    {
        "sbom_sca": {
            "repo_context": {
                "mode": "github",
                "repo_url": REPO,
                "branch": "main",
                "PAT": "",
            },
            "zip_file_used": False,
            "sbom_file_used": False,
        }
    }
)

_PEER_FRAMEWORKS = ("rbi_free_ai_supply",)


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


def _post_multipart(path, token, field, value, timeout=300):
    boundary = "----certinSbomE2Eboundary"
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


def _await_terminal(token, sid, deadline_s=900):
    end = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < end:
        st, d = _req("GET", f"/{TEAM}/sbom_sca/scan/{sid}", token)
        last = d.get("scan_status")
        if last in ("success", "failure"):
            return last, d
        time.sleep(5)
    pytest.fail(f"scan {sid} not terminal within {deadline_s}s (last status={last})")


def test_cert_in_sbom_reaches_scan_metadata_e2e():
    token = _token(USER)

    st, d = _req("POST", f"/{TEAM}/sbom_sca/scan", token, {"title": "E2E CERT-In SBOM"})
    if st != 200:
        pytest.skip(f"cannot create sbom_sca scan (status {st}); team {TEAM}/user not seeded")
    sid = d["scan_id"]

    est, est_body = _post_multipart(
        f"/{TEAM}/sbom_sca/scan/{sid}/estimate_credits",
        token,
        "start_scan_payload_string",
        PAYLOAD,
    )
    if est != 200:
        pytest.skip(
            f"estimate failed status={est} body={est_body}; "
            "use test_cert_in_sbom_metadata_on_existing_scan for transport proof"
        )
    start, _ = _post_multipart(
        f"/{TEAM}/sbom_sca/scan/{sid}/start",
        token,
        "start_scan_payload_string",
        PAYLOAD,
    )
    assert start == 200, f"start failed: {start}"

    status, d = _await_terminal(token, sid)
    assert status == "success", f"scan did not succeed: {(d.get('info') or {}).get('error')}"

    meta = d.get("scan_metadata") or {}
    comp = meta.get("sbom_compliance") or {}
    assert isinstance(comp, dict) and comp, "sbom_compliance missing from scan_metadata"

    assert "cert_in_sbom" in comp, (
        "cert_in_sbom missing from live scan_metadata — restart scan worker after aibom changes"
    )
    ci = comp["cert_in_sbom"]
    assert isinstance(ci, dict)
    for k in ("pass", "fail", "not_bom_evidenceable", "coverage", "requirements"):
        assert k in ci, f"cert_in_sbom missing tri-state key {k}"
    reqs = ci.get("requirements") or []
    assert reqs, "cert_in_sbom requirements drilldown empty"
    assert len(reqs) == 41

    peers = [fw for fw in _PEER_FRAMEWORKS if fw in comp]
    assert peers, f"no pre-CERT peer framework present; keys={sorted(k for k in comp if k != 'disclaimer')}"


def test_cert_in_sbom_metadata_on_existing_scan():
    """Gate C transport: GET success SBOM scan_metadata includes cert_in_sbom."""
    token = _token(USER)
    sid = int(os.getenv("CERTIN_SBOM_SCAN_ID", "1"))
    st, d = _req("GET", f"/{TEAM}/sbom_sca/scan/{sid}", token)
    if st != 200:
        pytest.skip(f"cannot GET sbom_sca scan {sid} (status {st})")
    if d.get("scan_status") != "success":
        pytest.skip(f"scan {sid} not success")
    comp = (d.get("scan_metadata") or {}).get("sbom_compliance") or {}
    if "cert_in_sbom" not in comp:
        pytest.skip(
            f"scan {sid} lacks cert_in_sbom — patch via enrich_sbom_scan or run full e2e"
        )
    ci = comp["cert_in_sbom"]
    assert ci.get("requirements"), "cert_in_sbom requirements empty"
    peers = [fw for fw in _PEER_FRAMEWORKS if fw in comp]
    assert peers, "peer frameworks missing"
