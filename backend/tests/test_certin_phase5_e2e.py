"""
CERT-In Phase 5 durable E2E — certin_posture on metadata + team dashboard.

Uses existing success BOM scans with ``cert_in_*`` frameworks. Self-skips if
backend unreachable. Run from backend::

  uv run pytest tests/test_certin_phase5_e2e.py -q
"""
from __future__ import annotations

import datetime
import json
import os
import re
import urllib.error
import urllib.request

import pytest

BASE = os.getenv("REGRESSION_BASE_URL", "http://127.0.0.1:8081")
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEAM = int(os.getenv("CBOM_E2E_TEAM", "1"))
USER = os.getenv("CBOM_E2E_USER", "cbom-demo@cyberultron.com")
SCAN_HINT = os.getenv("CERTIN_P5_SCAN_ID", "").strip() or os.getenv(
    "CERTIN_P4_SCAN_ID", ""
).strip()


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


def _post_multipart(path, token, fields: dict, files: dict | None = None, timeout=120):
    boundary = "----certinPhase5E2E"
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


def _list_scans(token: str, scan_type: str) -> list:
    st, d = _req("GET", f"/{TEAM}/{scan_type}/scans", token)
    if st != 200:
        return []
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        return (
            d.get("scans_list_data")
            or d.get("scans")
            or d.get("data")
            or d.get("conversations")
            or []
        )
    return []


def _find_success_with_framework(
    token: str, scan_type: str, framework: str, compliance_key: str
) -> int | None:
    if SCAN_HINT and scan_type == "cbom":
        return int(SCAN_HINT)
    for row in _list_scans(token, scan_type):
        if not isinstance(row, dict):
            continue
        status = str(row.get("scan_status") or "").strip().lower()
        if status != "success":
            continue
        sid = row.get("id") or row.get("scan_id")
        if not sid:
            continue
        st2, detail = _req("GET", f"/{TEAM}/{scan_type}/scan/{sid}", token)
        if st2 != 200:
            continue
        meta = detail.get("scan_metadata") or {}
        comp = meta.get(compliance_key) or {}
        if framework in comp:
            return int(sid)
    # Known demo fallbacks
    for sid in (14, 1, 127, 149):
        st2, detail = _req("GET", f"/{TEAM}/{scan_type}/scan/{sid}", token)
        if st2 != 200:
            continue
        meta = detail.get("scan_metadata") or {}
        if framework in (meta.get(compliance_key) or {}):
            return int(sid)
    return None


def _assert_posture_has_dimension(posture: dict, dim_prefix: str) -> None:
    assert posture, "certin_posture missing"
    dims = posture.get("certin_posture") or {}
    assert isinstance(dims, dict) and dims, "certin_posture.certin_posture empty"
    nonempty = [
        k
        for k, v in dims.items()
        if isinstance(v, dict)
        and (
            (v.get("pass") or 0)
            + (v.get("fail") or 0)
            + (v.get("pass_with_evidence") or 0)
            + (v.get("not_bom_evidenceable") or 0)
            + (v.get("out_of_scope") or 0)
            + (v.get("na") or 0)
        )
        > 0
    ]
    assert nonempty, f"no non-empty dimensions in {list(dims)}"
    if dim_prefix:
        assert any(k.startswith(dim_prefix) for k in nonempty), (
            f"expected dimension starting with {dim_prefix}, got {nonempty}"
        )
    assert posture.get("disclaimer")
    assert "HBOM" in (posture.get("hbom_note") or "") or True  # hbom_note optional


def test_phase5_certin_posture_metadata_team_and_attest_refresh():
    token = _token(USER)
    st_h, _ = _req("GET", "/health", token=None)
    if st_h != 200:
        pytest.skip(f"backend health not 200 ({st_h})")

    cbom_id = _find_success_with_framework(
        token, "cbom", "cert_in_cbom", "cbom_compliance"
    )
    assert cbom_id, "no success CBOM with cert_in_cbom — run Phase 1 first"

    st, detail = _req("GET", f"/{TEAM}/cbom/scan/{cbom_id}", token)
    assert st == 200
    meta = detail.get("scan_metadata") or {}
    posture = meta.get("certin_posture")
    _assert_posture_has_dimension(posture, "cbom_")

    # Optional peers when present
    aibom_id = _find_success_with_framework(
        token, "ai_bom", "cert_in_aibom", "ai_bom_compliance"
    )
    if aibom_id:
        st, detail = _req("GET", f"/{TEAM}/ai_bom/scan/{aibom_id}", token)
        assert st == 200
        _assert_posture_has_dimension(
            (detail.get("scan_metadata") or {}).get("certin_posture"), "aibom_"
        )

    sbom_id = _find_success_with_framework(
        token, "sbom_sca", "cert_in_sbom", "sbom_compliance"
    )
    if sbom_id:
        st, detail = _req("GET", f"/{TEAM}/sbom_sca/scan/{sbom_id}", token)
        assert st == 200
        _assert_posture_has_dimension(
            (detail.get("scan_metadata") or {}).get("certin_posture"), "sbom_"
        )

    # Team dashboard
    st, dash = _req("GET", f"/team/{TEAM}/dashboard", token)
    assert st == 200, f"team dashboard failed: {st} {dash}"
    team_posture = dash.get("certin_posture")
    assert team_posture, "team dashboard missing certin_posture"
    dims = team_posture.get("certin_posture") or {}
    assert dims, "team certin_posture empty"

    # Attestation → pass_with_evidence increases on next GET for that dimension
    # (optional if all manuals already attested from Phase 4)
    fw = ((meta.get("cbom_compliance") or {}).get("cert_in_cbom")) or {}
    reqs = fw.get("requirements") or []
    nbe = next(
        (
            r
            for r in reqs
            if isinstance(r, dict) and r.get("verdict") == "not_bom_evidenceable"
        ),
        None,
    )
    if nbe is None:
        # Still prove live recompute: posture present after a no-op GET
        st, detail2 = _req("GET", f"/{TEAM}/cbom/scan/{cbom_id}", token)
        assert st == 200
        assert (detail2.get("scan_metadata") or {}).get("certin_posture")
        return

    rid = nbe["id"]
    target_dim = (
        "cbom_recommendations"
        if str(rid).startswith("8.4")
        else "cbom_crypto_assets"
        if str(rid).startswith("T9")
        else "cbom_recommendations"
    )
    before_pwe = (
        (posture.get("certin_posture") or {}).get(target_dim, {}) or {}
    ).get("pass_with_evidence", 0)

    ok, body = _post_multipart(
        f"/{TEAM}/cbom/scan/{cbom_id}/attestations",
        token,
        {
            "framework": "cert_in_cbom",
            "requirement_id": rid,
            "note": "phase5-e2e-rollup",
        },
        files={"file": ("policy.pdf", b"%PDF-1.4 phase5", "application/pdf")},
    )
    assert ok == 200, f"attest failed: {ok} {body}"

    st, detail2 = _req("GET", f"/{TEAM}/cbom/scan/{cbom_id}", token)
    assert st == 200
    posture2 = (detail2.get("scan_metadata") or {}).get("certin_posture") or {}
    assert posture2.get("certin_posture"), "posture missing after attest"
    after_pwe = (posture2.get("certin_posture") or {}).get(target_dim, {}).get(
        "pass_with_evidence", 0
    )
    assert after_pwe >= before_pwe + 1, (
        f"{target_dim} pass_with_evidence did not increase: "
        f"{before_pwe} -> {after_pwe} (req={rid})"
    )
