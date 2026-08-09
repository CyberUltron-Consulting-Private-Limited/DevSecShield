#!/usr/bin/env python3
"""Live 15-scan matrix (5 CBOM / 5 AIBOM / 5 SBOM) — assert RBI + SEBI + CERT-In.

Uses bench/certin/repos.tsv. Writes /tmp/india_compliance_matrix.json.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"
MANIFEST = REPO / "bench" / "certin" / "repos.tsv"
OUT = Path(os.getenv("MATRIX_OUT", "/tmp/india_compliance_matrix.json"))
BASE = os.getenv("REGRESSION_BASE_URL", "http://127.0.0.1:8081")
TEAM = int(os.getenv("CBOM_E2E_TEAM", "1"))
USER = os.getenv("CBOM_E2E_USER", "cbom-demo@cyberultron.com")
TIMEOUT_S = int(os.getenv("MATRIX_TIMEOUT_S", "1800"))
RETRIES = int(os.getenv("MATRIX_RETRIES", "2"))

# Per-lane required frameworks: CERT-In + SEBI + RBI
REQUIRED = {
    "cbom": {
        "comp_key": "cbom_compliance",
        "keys": ("cert_in_cbom", "sebi_cscrf_cbom", "rbi_free_ai_protection"),
    },
    "ai_bom": {
        "comp_key": "ai_bom_compliance",
        "keys": ("cert_in_aibom", "sebi_cscrf_aibom", "rbi_free_ai"),
    },
    "sbom_sca": {
        "comp_key": "sbom_compliance",
        "keys": ("cert_in_sbom", "sebi_cscrf_sbom", "rbi_free_ai_supply"),
    },
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
    "openai/openai-python": "main",
    "modelcontextprotocol/servers": "main",
    "psf/requests": "main",
    "pallets/flask": "main",
    "urllib3/urllib3": "main",
    "sqlalchemy/sqlalchemy": "main",
    "pallets/click": "main",
}


def _env():
    env, path = {}, BACKEND / ".env"
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
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


def _token():
    import jwt as jwtlib

    secret = _env().get("JWT_SECRET_KEY")
    if not secret:
        raise SystemExit("JWT_SECRET_KEY missing")
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)
    return jwtlib.encode({"exp": exp, "sub": USER}, secret, algorithm="HS256")


def _req(method, path, token=None, body=None, timeout=120):
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
    except Exception as e:
        return 0, {"error": str(e)}


def _post_multipart(path, token, fields: dict, timeout=300):
    boundary = "----indiaMatrixE2E"
    parts = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    body = "".join(parts).encode()
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
    except Exception as e:
        return 0, {"error": str(e)}


def _load_manifest():
    rows = []
    for line in MANIFEST.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rows.append(
            {
                "lane": parts[0],
                "id": parts[1],
                "slug": parts[2],
                "url": parts[3],
            }
        )
    return rows[:15]


def _payload(lane: str, url: str, slug: str) -> str:
    branch = _BRANCH.get(slug, "main")
    ctx = {
        "mode": "github",
        "repo_url": url,
        "branch": branch,
        "PAT": "",
    }
    if lane == "cbom":
        body = {
            "cbom": {
                "repo_context": ctx,
                "zip_file_used": False,
                "cbom_file_used": False,
                "scan_binaries": False,
            }
        }
    elif lane == "ai_bom":
        body = {
            "ai_bom": {
                "repo_context": ctx,
                "zip_file_used": False,
                "ai_bom_file_used": False,
            }
        }
    else:
        body = {
            "sbom_sca": {
                "repo_context": ctx,
                "zip_file_used": False,
                "sbom_file_used": False,
            }
        }
    return json.dumps(body)


def _await(token, lane, sid):
    end = time.monotonic() + TIMEOUT_S
    last = None
    detail = {}
    while time.monotonic() < end:
        st, d = _req("GET", f"/{TEAM}/{lane}/scan/{sid}", token, timeout=60)
        detail = d if isinstance(d, dict) else {}
        last = detail.get("scan_status")
        if last in ("success", "failure"):
            return last, detail
        time.sleep(5)
    return last, {"scan_status": last, "info": {"error": "timeout"}}


def _check_frameworks(meta: dict, lane: str) -> dict:
    spec = REQUIRED[lane]
    comp = meta.get(spec["comp_key"]) or {}
    out = {"present": {}, "missing": [], "ok": True}
    for key in spec["keys"]:
        fw = comp.get(key)
        reqs = (fw or {}).get("requirements") if isinstance(fw, dict) else None
        ok = bool(isinstance(fw, dict) and reqs)
        out["present"][key] = {
            "ok": ok,
            "req_count": len(reqs or []),
            "coverage": (fw or {}).get("coverage") if isinstance(fw, dict) else None,
        }
        if not ok:
            out["missing"].append(key)
            out["ok"] = False
    return out


def _run_one(token, row: dict) -> dict:
    lane = row["lane"]
    title = f"INDIA {row['id']} {row['slug']}"
    t0 = time.monotonic()
    cell = {
        "id": row["id"],
        "lane": lane,
        "slug": row["slug"],
        "url": row["url"],
        "status": "create_failed",
        "scan_id": None,
        "duration_s": 0,
        "frameworks": None,
        "ok": False,
        "error": None,
    }
    print(f"\n=== {row['id']} {lane} {row['slug']} ===", flush=True)
    st, d = _req("POST", f"/{TEAM}/{lane}/scan", token, {"title": title})
    if st != 200:
        cell["error"] = f"create {st} {d}"
        print(" create FAIL", cell["error"], flush=True)
        return cell
    sid = int(d["scan_id"])
    cell["scan_id"] = sid
    print(f" created scan_id={sid}", flush=True)
    payload = _payload(lane, row["url"], row["slug"])
    est, est_body = _post_multipart(
        f"/{TEAM}/{lane}/scan/{sid}/estimate_credits",
        token,
        {"start_scan_payload_string": payload},
        timeout=300,
    )
    if est != 200:
        cell["status"] = "estimate_failed"
        cell["error"] = f"{est} {est_body}"
        print(" estimate FAIL", cell["error"], flush=True)
        return cell
    print(" estimate ok", flush=True)
    start, start_body = _post_multipart(
        f"/{TEAM}/{lane}/scan/{sid}/start",
        token,
        {"start_scan_payload_string": payload},
        timeout=300,
    )
    if start != 200:
        cell["status"] = "start_failed"
        cell["error"] = f"{start} {start_body}"
        print(" start FAIL", cell["error"], flush=True)
        return cell
    print(" started; polling…", flush=True)
    status, detail = _await(token, lane, sid)
    cell["duration_s"] = round(time.monotonic() - t0, 1)
    cell["status"] = status or "unknown"
    if status != "success":
        cell["error"] = (detail.get("info") or {}).get("error") or status
        print(f" terminal={status} error={cell['error']}", flush=True)
        return cell
    meta = detail.get("scan_metadata") or {}
    fw = _check_frameworks(meta, lane)
    cell["frameworks"] = fw
    cell["ok"] = fw["ok"]
    print(
        f" success in {cell['duration_s']}s frameworks={fw['present']} missing={fw['missing']}",
        flush=True,
    )
    return cell


def main() -> int:
    rows = _load_manifest()
    assert len(rows) == 15, f"expected 15 rows, got {len(rows)}"
    by_lane = {}
    for r in rows:
        by_lane.setdefault(r["lane"], 0)
        by_lane[r["lane"]] += 1
    assert by_lane == {"cbom": 5, "ai_bom": 5, "sbom_sca": 5}, by_lane

    token = _token()
    st_h, body_h = _req("GET", "/docs", timeout=30)
    if st_h != 200:
        # fallback: root may 404 but means server is up
        st2, body2 = _req("GET", "/", timeout=30)
        if st2 == 0:
            print("backend not healthy", st_h, body_h, st2, body2)
            return 2
        print(f"docs={st_h} root={st2} — continuing", flush=True)

    t0 = time.monotonic()
    cells = []
    for row in rows:
        cell = _run_one(token, row)
        attempt = 0
        while (not cell["ok"]) and attempt < RETRIES:
            attempt += 1
            print(f" retry {attempt} for {row['id']}", flush=True)
            cell = _run_one(token, row)
            cell["retry"] = attempt
        cells.append(cell)
        OUT.write_text(json.dumps({"partial": True, "cells": cells}, indent=2))

    success = [c for c in cells if c["ok"]]
    failed = [c for c in cells if not c["ok"]]
    summary = {
        "ok": len(success) == 15,
        "duration_s": round(time.monotonic() - t0, 1),
        "success": len(success),
        "failed": len(failed),
        "by_lane": {
            lane: {
                "ok": sum(1 for c in cells if c["lane"] == lane and c["ok"]),
                "total": sum(1 for c in cells if c["lane"] == lane),
            }
            for lane in ("cbom", "ai_bom", "sbom_sca")
        },
        "required": REQUIRED,
        "cells": cells,
    }
    OUT.write_text(json.dumps(summary, indent=2))
    print("\n======== MATRIX SUMMARY ========", flush=True)
    print(json.dumps({k: summary[k] for k in ("ok", "duration_s", "success", "failed", "by_lane")}, indent=2), flush=True)
    if failed:
        print("FAILED CELLS:", flush=True)
        for c in failed:
            print(
                f"  {c['id']} {c['lane']} status={c['status']} "
                f"missing={(c.get('frameworks') or {}).get('missing')} err={c.get('error')}",
                flush=True,
            )
    print(f"wrote {OUT}", flush=True)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.path.insert(0, str(REPO))
    raise SystemExit(main())
