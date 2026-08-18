"""
CERT-In Phase 6 durable E2E — 15-repo multi-BOM matrix + deep attest/sign/pack.

Reads ``bench/certin/repos.tsv``. Starts one product scan per row, asserts
``cert_in_*`` + ``certin_posture``, then deep-path on one cell per lane and
team multi-lane posture.

Self-skips only if backend unreachable. Requires Celery ``scan_worker_queue``.

  cd backend && uv run pytest tests/test_certin_phase6_e2e.py -q --tb=short

Env:
  CERTIN_P6_MAX_CELLS — cap matrix size (default 15)
  CERTIN_P6_TIMEOUT_S — per-scan poll budget (default 1200)
  REGRESSION_BASE_URL — default http://127.0.0.1:8081
"""
from __future__ import annotations

import datetime
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

BASE = os.getenv("REGRESSION_BASE_URL", "http://127.0.0.1:8081")
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(BACKEND_DIR)
MANIFEST = Path(REPO_ROOT) / "bench" / "certin" / "repos.tsv"
MATRIX_OUT = Path(os.getenv("CERTIN_P6_MATRIX_OUT", "/tmp/certin_phase6_matrix.json"))
TEAM = int(os.getenv("CBOM_E2E_TEAM", "1"))
USER = os.getenv("CBOM_E2E_USER", "cbom-demo@cyberultron.com")
MAX_CELLS = int(os.getenv("CERTIN_P6_MAX_CELLS", "15"))
TIMEOUT_S = int(os.getenv("CERTIN_P6_TIMEOUT_S", "1200"))

_FW = {
    "cbom": ("cert_in_cbom", "cbom_compliance"),
    "ai_bom": ("cert_in_aibom", "ai_bom_compliance"),
    "sbom_sca": ("cert_in_sbom", "sbom_compliance"),
}

_BRANCH = {
    "jpadilla/pyjwt": "master",
    "karpathy/nanoGPT": "master",
    "langchain-ai/langchain": "master",
    "microsoft/autogen": "main",
    "pyca/pyopenssl": "main",
    "pyca/cryptography": "main",
    "mitmproxy/mitmproxy": "main",
    "paramiko/paramiko": "main",
}


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
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)
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
                return r.status, raw_bytes
            return r.status, json.loads(raw_bytes or b"{}")
    except urllib.error.HTTPError as e:
        try:
            payload = e.read() or b"{}"
            if raw:
                return e.code, payload
            return e.code, json.loads(payload)
        except Exception:
            return e.code, {} if not raw else b""
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        pytest.skip(f"backend not reachable on {BASE}: {e}")


def _post_multipart(path, token, fields: dict, files: dict | None = None, timeout=180):
    boundary = "----certinPhase6E2E"
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


def _load_manifest() -> list[dict]:
    rows = []
    for ln in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not ln.strip() or ln.startswith("#"):
            continue
        parts = ln.split("\t")
        if len(parts) < 6:
            continue
        rows.append(
            {
                "lane": parts[0],
                "id": parts[1],
                "slug": parts[2],
                "url": parts[3],
                "sha": parts[4],
                "subdir": parts[5],
            }
        )
    return rows[:MAX_CELLS]


def _payload(lane: str, url: str, slug: str) -> str:
    branch = _BRANCH.get(slug, "main")
    if lane == "cbom":
        body = {
            "cbom": {
                "repo_context": {
                    "mode": "github",
                    "repo_url": url,
                    "branch": branch,
                    "PAT": "",
                },
                "zip_file_used": False,
                "cbom_file_used": False,
                "scan_binaries": False,
            }
        }
    elif lane == "ai_bom":
        body = {
            "ai_bom": {
                "repo_context": {
                    "mode": "github",
                    "repo_url": url,
                    "branch": branch,
                    "PAT": "",
                },
                "zip_file_used": False,
                "ai_bom_file_used": False,
            }
        }
    else:
        body = {
            "sbom_sca": {
                "repo_context": {
                    "mode": "github",
                    "repo_url": url,
                    "branch": branch,
                    "PAT": "",
                },
                "zip_file_used": False,
                "sbom_file_used": False,
            }
        }
    return json.dumps(body)


def _await(token, lane, sid, deadline_s=TIMEOUT_S):
    end = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < end:
        st, d = _req("GET", f"/{TEAM}/{lane}/scan/{sid}", token)
        last = d.get("scan_status") if isinstance(d, dict) else None
        if last in ("success", "failure"):
            return last, d
        time.sleep(5)
    return last, {"scan_status": last, "info": {"error": "timeout"}}


def _posture_nonempty(posture: dict | None, prefix: str) -> bool:
    if not posture or not isinstance(posture, dict):
        return False
    dims = posture.get("certin_posture") or {}
    for k, v in dims.items():
        if not str(k).startswith(prefix):
            continue
        if not isinstance(v, dict):
            continue
        total = sum(
            int(v.get(x) or 0)
            for x in (
                "pass",
                "fail",
                "pass_with_evidence",
                "not_bom_evidenceable",
                "out_of_scope",
                "na",
            )
        )
        if total > 0:
            return True
    return False


def _deep_path(token, lane: str, sid: int) -> dict:
    fw, comp_key = _FW[lane]
    out: dict = {"lane": lane, "scan_id": sid}
    st, detail = _req("GET", f"/{TEAM}/{lane}/scan/{sid}", token)
    assert st == 200
    meta = detail.get("scan_metadata") or {}
    comp = (meta.get(comp_key) or {}).get(fw) or {}
    reqs = comp.get("requirements") or []
    nbe = next(
        (
            r
            for r in reqs
            if isinstance(r, dict) and r.get("verdict") == "not_bom_evidenceable"
        ),
        None,
    )
    if nbe:
        ok, body = _post_multipart(
            f"/{TEAM}/{lane}/scan/{sid}/attestations",
            token,
            {
                "framework": fw,
                "requirement_id": nbe["id"],
                "note": "phase6-e2e",
            },
            files={"file": ("p6.txt", b"phase6 evidence", "text/plain")},
        )
        out["attest"] = ok
        out["attest_req"] = nbe["id"]
    else:
        out["attest"] = "skipped_no_nbe"

    st, sig = _req("POST", f"/{TEAM}/{lane}/scan/{sid}/sign", token)
    out["sign"] = st
    out["signature"] = bool((sig or {}).get("bom_signature", {}).get("signature_b64"))

    st, vex = _req("GET", f"/{TEAM}/{lane}/scan/{sid}/vex", token)
    out["vex"] = st

    st, raw = _req(
        "GET", f"/{TEAM}/{lane}/scan/{sid}/evidence-pack", token, raw=True
    )
    out["evidence_pack"] = st
    out["evidence_zip"] = isinstance(raw, (bytes, bytearray)) and raw[:2] == b"PK"
    return out


def _run_one_cell(token, row: dict) -> dict:
    lane = row["lane"]
    fw, comp_key = _FW[lane]
    title = f"P6 {row['id']} {row['slug']}"
    t0 = time.monotonic()
    cell = {
        "id": row["id"],
        "lane": lane,
        "slug": row["slug"],
        "url": row["url"],
        "status": "create_failed",
        "scan_id": None,
        "duration_s": 0,
        "cert_in_ok": False,
        "posture_ok": False,
        "req_count": 0,
        "error": None,
    }
    st, d = _req("POST", f"/{TEAM}/{lane}/scan", token, {"title": title})
    if st != 200:
        cell["error"] = f"create {st} {d}"
        return cell
    sid = int(d["scan_id"])
    cell["scan_id"] = sid
    payload = _payload(lane, row["url"], row["slug"])
    est, _ = _post_multipart(
        f"/{TEAM}/{lane}/scan/{sid}/estimate_credits",
        token,
        {"start_scan_payload_string": payload},
    )
    if est != 200:
        cell["status"] = "estimate_failed"
        cell["error"] = str(est)
        return cell
    start, _ = _post_multipart(
        f"/{TEAM}/{lane}/scan/{sid}/start",
        token,
        {"start_scan_payload_string": payload},
    )
    if start != 200:
        cell["status"] = "start_failed"
        cell["error"] = str(start)
        return cell

    status, detail = _await(token, lane, sid)
    cell["duration_s"] = round(time.monotonic() - t0, 1)
    cell["status"] = status or "unknown"
    if status != "success":
        cell["error"] = (detail.get("info") or {}).get("error") or status
        return cell

    meta = detail.get("scan_metadata") or {}
    comp = meta.get(comp_key) or {}
    ci = comp.get(fw) or {}
    reqs = ci.get("requirements") or []
    cell["req_count"] = len(reqs)
    cell["cert_in_ok"] = bool(reqs)
    cell["posture_ok"] = _posture_nonempty(
        meta.get("certin_posture"),
        {"cbom": "cbom_", "ai_bom": "aibom_", "sbom_sca": "sbom_"}[lane],
    )
    return cell


def test_phase6_fifteen_repo_matrix_and_deep_paths():
    assert MANIFEST.is_file(), f"missing manifest {MANIFEST}"
    token = _token(USER)
    st_h, _ = _req("GET", "/health", token=None)
    if st_h != 200:
        pytest.skip(f"backend health not 200 ({st_h})")

    rows = _load_manifest()
    assert len(rows) >= 3, "manifest too small"
    cells = []
    deep_ids: dict[str, int] = {}
    t0_all = time.monotonic()
    retries = int(os.getenv("CERTIN_P6_RETRIES", "2"))

    for row in rows:
        cell = _run_one_cell(token, row)
        attempt = 0
        while (
            cell["status"] != "success" or not cell["cert_in_ok"]
        ) and attempt < retries:
            attempt += 1
            cell = _run_one_cell(token, row)
            cell["retry"] = attempt
        if row["id"] in ("c1", "a1", "s1") or (
            row["lane"] not in deep_ids and cell["status"] == "success"
        ):
            if cell.get("scan_id") and cell["status"] == "success":
                deep_ids[row["lane"]] = int(cell["scan_id"])
        # Prefer canonical deep ids when successful
        if row["id"] == "c1" and cell["status"] == "success":
            deep_ids["cbom"] = int(cell["scan_id"])
        if row["id"] == "a1" and cell["status"] == "success":
            deep_ids["ai_bom"] = int(cell["scan_id"])
        if row["id"] == "s1" and cell["status"] == "success":
            deep_ids["sbom_sca"] = int(cell["scan_id"])
        cells.append(cell)

    deep = {}
    for lane, sid in deep_ids.items():
        deep[lane] = _deep_path(token, lane, sid)

    st, dash = _req("GET", f"/team/{TEAM}/dashboard", token)
    team_posture = (dash or {}).get("certin_posture") if st == 200 else None
    team_ok = bool(team_posture and (team_posture.get("certin_posture") or {}))
    dims = (team_posture or {}).get("certin_posture") or {}
    team_has = {
        "cbom": any(k.startswith("cbom_") for k in dims),
        "aibom": any(k.startswith("aibom_") for k in dims),
        "sbom": any(k.startswith("sbom_") for k in dims),
    }

    report = {
        "ok": False,
        "team_id": TEAM,
        "duration_s": round(time.monotonic() - t0_all, 1),
        "cells": cells,
        "deep": deep,
        "team_posture_ok": team_ok,
        "team_lane_dims": team_has,
    }
    success = [c for c in cells if c["status"] == "success" and c["cert_in_ok"]]
    report["ok"] = (
        len(success) == len(rows)
        and all(c["posture_ok"] for c in success)
        and team_ok
        and all(
            (deep.get(lane) or {}).get("evidence_zip")
            or (deep.get(lane) or {}).get("sign") == 200
            for lane in deep_ids
        )
    )
    MATRIX_OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")

    failed = [c for c in cells if not (c["status"] == "success" and c["cert_in_ok"])]
    assert not failed, (
        f"{len(failed)} matrix cells failed — see {MATRIX_OUT}: "
        + json.dumps(failed[:5], indent=2)
    )
    assert all(c["posture_ok"] for c in success), "certin_posture missing on some cells"
    assert team_ok, "team dashboard missing certin_posture"
    assert team_has["cbom"] and team_has["aibom"] and team_has["sbom"], team_has
    for lane, info in deep.items():
        assert info.get("sign") == 200 or info.get("signature"), info
        assert info.get("vex") == 200, info
        assert info.get("evidence_zip"), info
