"""
CERT-In Phase 4 durable E2E — attestation + sign + VEX + evidence-pack.

Uses an existing success CBOM scan with ``cert_in_cbom`` (default scan id from
env ``CERTIN_P4_SCAN_ID`` or auto-discovers team 1). Does NOT require a fresh
Celery scan when compliance is already persisted.

Self-skips if backend unreachable. Run from backend::

  uv run pytest tests/test_certin_phase4_e2e.py -q
"""
from __future__ import annotations

import datetime
import io
import json
import os
import re
import urllib.error
import urllib.request
import zipfile

import pytest

BASE = os.getenv("REGRESSION_BASE_URL", "http://127.0.0.1:8081")
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEAM = int(os.getenv("CBOM_E2E_TEAM", "1"))
USER = os.getenv("CBOM_E2E_USER", "cbom-demo@cyberultron.com")
SCAN_HINT = os.getenv("CERTIN_P4_SCAN_ID", "").strip()


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


def _req(method, path, token=None, body=None, timeout=60, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw_bytes = r.read() or b""
            if raw:
                return r.status, raw_bytes, dict(r.headers)
            return r.status, json.loads(raw_bytes or b"{}")
    except urllib.error.HTTPError as e:
        try:
            payload = e.read() or b"{}"
            if raw:
                return e.code, payload, {}
            return e.code, json.loads(payload)
        except Exception:
            return e.code, {} if not raw else (e.code, b"", {})
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"backend not reachable on {BASE}: {e}")


def _post_multipart(path, token, fields: dict, files: dict | None = None, timeout=120):
    boundary = "----certinPhase4E2E"
    parts = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n"
        )
    body = "".join(parts).encode()
    if files:
        for name, (filename, content, ctype) in files.items():
            header = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\n'
                f"Content-Type: {ctype}\r\n\r\n"
            ).encode()
            body += header + content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Authorization": f"Bearer {token}",
    }
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"backend multipart unreachable on {BASE}: {e}")


def _find_success_cbom(token: str) -> int:
    if SCAN_HINT:
        return int(SCAN_HINT)
    st, d = _req("GET", f"/{TEAM}/cbom/scans", token)
    if st != 200:
        pytest.skip(f"cannot list cbom scans: {st}")
    scans = []
    if isinstance(d, list):
        scans = d
    elif isinstance(d, dict):
        scans = (
            d.get("scans_list_data")
            or d.get("scans")
            or d.get("data")
            or d.get("conversations")
            or []
        )
    for row in scans:
        if not isinstance(row, dict):
            continue
        if row.get("scan_status") != "success":
            continue
        sid = row.get("id") or row.get("scan_id")
        if not sid:
            continue
        st2, detail = _req("GET", f"/{TEAM}/cbom/scan/{sid}", token)
        if st2 != 200:
            continue
        meta = detail.get("scan_metadata") or {}
        comp = meta.get("cbom_compliance") or {}
        if "cert_in_cbom" in comp:
            return int(sid)
    # Prefer known Phase-1 success ids if list shape was unexpected
    for sid in (14, 1):
        st2, detail = _req("GET", f"/{TEAM}/cbom/scan/{sid}", token)
        if st2 != 200:
            continue
        meta = detail.get("scan_metadata") or {}
        if "cert_in_cbom" in (meta.get("cbom_compliance") or {}):
            return int(sid)
    pytest.skip("no success CBOM scan with cert_in_cbom found — run Phase 1 e2e first")


def test_phase4_attest_sign_vex_evidence_pack():
    token = _token(USER)
    st_h, health = _req("GET", "/health", token=None)
    if st_h != 200:
        pytest.skip(f"backend health not 200 ({st_h})")
    sid = _find_success_cbom(token)
    st, detail = _req("GET", f"/{TEAM}/cbom/scan/{sid}", token)
    assert st == 200
    meta = detail.get("scan_metadata") or {}
    comp = meta.get("cbom_compliance") or {}
    fw = comp.get("cert_in_cbom") or {}
    reqs = fw.get("requirements") or []
    nbe = next(
        (
            r
            for r in reqs
            if isinstance(r, dict) and r.get("verdict") == "not_bom_evidenceable"
        ),
        None,
    )
    assert nbe, "no NBE requirement to attest on cert_in_cbom"
    rid = nbe["id"]

    # Unknown requirement → 400
    bad, body = _post_multipart(
        f"/{TEAM}/cbom/scan/{sid}/attestations",
        token,
        {"framework": "cert_in_cbom", "requirement_id": "NOT_A_REAL_REQ"},
        files={"file": ("x.txt", b"evidence", "text/plain")},
    )
    assert bad == 400, f"expected 400 for unknown req, got {bad} {body}"

    # Attest real NBE
    ok, body = _post_multipart(
        f"/{TEAM}/cbom/scan/{sid}/attestations",
        token,
        {
            "framework": "cert_in_cbom",
            "requirement_id": rid,
            "note": "phase4-e2e-policy",
        },
        files={"file": ("policy.pdf", b"%PDF-1.4 phase4", "application/pdf")},
    )
    assert ok == 200, f"attest failed: {ok} {body}"
    compliance = body.get("compliance") or {}
    fw2 = compliance.get("cert_in_cbom") or {}
    req2 = next(r for r in (fw2.get("requirements") or []) if r.get("id") == rid)
    assert req2.get("verdict") == "pass_with_evidence", req2

    # Metadata surfaces attestations
    st, detail = _req("GET", f"/{TEAM}/cbom/scan/{sid}", token)
    meta = detail.get("scan_metadata") or {}
    assert meta.get("attestations"), "attestations missing from scan_metadata"
    assert (meta.get("cbom_compliance") or {}).get("cert_in_cbom")

    # Sign
    st, sig_body = _req("POST", f"/{TEAM}/cbom/scan/{sid}/sign", token)
    assert st == 200, f"sign failed: {st} {sig_body}"
    assert (sig_body.get("bom_signature") or {}).get("signature_b64")

    # VEX
    st, vex = _req("GET", f"/{TEAM}/cbom/scan/{sid}/vex", token)
    assert st == 200, f"vex failed: {st}"
    assert isinstance(vex, dict)
    assert "vulnerabilities" in vex or vex.get("bomFormat")

    # Evidence pack ZIP
    st, raw, _headers = _req(
        "GET", f"/{TEAM}/cbom/scan/{sid}/evidence-pack", token, raw=True
    )
    assert st == 200, f"evidence-pack failed: {st}"
    assert raw[:2] == b"PK", "evidence-pack is not a zip"
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        names = set(zf.namelist())
    assert "compliance.json" in names or "vex.json" in names or "bom.cdx.json" in names


def test_backend_health_probe():
    """Cheap reachability probe used by -k filters; keeps skip path clear."""
    st, body = _req("GET", "/health", token=None)
    if st != 200:
        pytest.skip(f"backend health {st}")
    assert body.get("status") == "healthy"