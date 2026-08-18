#!/usr/bin/env python3
"""Poll remaining LOAD30 scans and quality-audit all 30."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://devsecshieldapi.zeroshield.ai"
EMAIL = "shivam@cyberultron.com"
PASSWORD = "Cyber@123"
OTP = "123456"
TEAM = 1
UNKNOWN_RE = re.compile(r"\b(unknown|n/?a)\b", re.I)
OUT = "/tmp/prod_loadtest_30_report.json"


def req(method, path, token=None, body=None, timeout=120):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read() or b"{}"
            return resp.status, json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {"detail": str(e)}


def post_mp(path, token, value, timeout=300):
    b = "----x"
    body = (
        f"--{b}\r\nContent-Disposition: form-data; name=\"start_scan_payload_string\"\r\n\r\n"
        f"{value}\r\n--{b}--\r\n"
    ).encode()
    headers = {
        "Content-Type": f"multipart/form-data; boundary={b}",
        "Authorization": f"Bearer {token}",
    }
    r = urllib.request.Request(API + path, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read() or b"{}"
            return resp.status, json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {"detail": str(e)}
    except Exception as e:
        return 0, {"detail": str(e)}


def walk(obj, path="$", hits=None, limit=50):
    if hits is None:
        hits = []
    if len(hits) >= limit:
        return hits
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            if isinstance(v, str) and UNKNOWN_RE.search(v):
                if k.lower() in (
                    "message",
                    "detail",
                    "error",
                    "info",
                    "description",
                    "suggested_fix",
                    "title",
                ):
                    continue
                hits.append({"path": p, "value": v[:120]})
            else:
                walk(v, p, hits, limit)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:40]):
            walk(v, f"{path}[{i}]", hits, limit)
    return hits


def main():
    req("POST", "/send_code", body={"email": EMAIL})
    st, d = req(
        "POST",
        "/login",
        body={"email": EMAIL, "password": PASSWORD, "verification_code": OTP},
    )
    assert st == 200, d
    token = d["access_token"]
    print("login ok", flush=True)

    sid_type = {}
    titles = {}
    created = {}
    updated = {}
    for stype in ("cbom", "ai_bom", "sbom_sca"):
        st, d = req("GET", f"/{TEAM}/{stype}/scans", token, timeout=60)
        for row in d.get("scans_list_data") or []:
            sid = row.get("id")
            if sid and 151 <= int(sid) <= 180:
                sid_type[int(sid)] = stype
                titles[int(sid)] = row.get("title")
                created[int(sid)] = row.get("created_at")
                updated[int(sid)] = row.get("last_updated")
                # capture list status
                titles[f"status_{sid}"] = row.get("scan_status")
    print("mapped", len(sid_type), sorted(sid_type), flush=True)

    # Fix 167 if still not started
    list_status_167 = titles.get("status_167")
    print("167 list status", list_status_167, flush=True)
    if sid_type.get(167) == "sbom_sca" and str(list_status_167).lower() in (
        "not_started",
        "none",
        "",
    ):
        pl = json.dumps(
            {
                "sbom_sca": {
                    "repo_context": {
                        "mode": "github",
                        "repo_url": "https://github.com/psf/requests",
                        "branch": "main",
                        "PAT": "",
                    },
                    "zip_file_used": False,
                    "sbom_file_used": False,
                }
            }
        )
        for attempt in range(6):
            est, ed = post_mp(f"/{TEAM}/sbom_sca/scan/167/estimate_credits", token, pl)
            print("167 estimate", est, ed if est != 200 else "ok", flush=True)
            if est == 200:
                ss, sd = post_mp(f"/{TEAM}/sbom_sca/scan/167/start", token, pl)
                print("167 start", ss, sd if ss != 200 else "ok", flush=True)
                break
            time.sleep(3)

    deadline = time.monotonic() + 40 * 60
    pending = set(range(151, 181))
    final = {}
    while pending and time.monotonic() < deadline:
        still = set()
        for sid in sorted(pending):
            stype = sid_type.get(sid)
            if not stype:
                still.add(sid)
                continue
            st, d = req("GET", f"/{TEAM}/{stype}/scan/{sid}", token, timeout=60)
            status = (d.get("scan_status") or "").lower()
            if st == 200 and status in ("success", "failure"):
                final[sid] = {
                    "scan_id": sid,
                    "scan_type": stype,
                    "scan_status": status,
                    "title": titles.get(sid),
                    "created_at": created.get(sid),
                    "last_updated": updated.get(sid),
                    "response": d,
                }
                print(f"DONE {stype} {sid} {status}", flush=True)
            else:
                still.add(sid)
                if st != 200:
                    print(f"wait {sid} http={st} detail={str(d)[:120]}", flush=True)
                else:
                    print(f"wait {sid} status={status}", flush=True)
        pending = still
        if pending:
            print(f"remaining {len(pending)}", flush=True)
            time.sleep(8)

    print(f"terminal={len(final)} pending={sorted(pending)}", flush=True)

    audits = []
    rows = []
    for sid in range(151, 181):
        j = final.get(sid)
        if not j:
            audits.append(
                {
                    "scan_id": sid,
                    "issues": ["not_terminal"],
                    "scan_type": sid_type.get(sid),
                    "status": "missing",
                }
            )
            rows.append(
                {
                    "scan_id": sid,
                    "scan_type": sid_type.get(sid),
                    "scan_status": "missing",
                }
            )
            continue
        d = j["response"]
        meta = d.get("scan_metadata") or {}
        data_results = d.get("data") if isinstance(d.get("data"), list) else []
        if not data_results:
            alt = d.get("findings")
            if isinstance(alt, list):
                data_results = alt
        stype = j["scan_type"]
        status = j["scan_status"]
        audit = {
            "scan_id": sid,
            "scan_type": stype,
            "status": status,
            "results_count": len(data_results),
            "issues": [],
            "chart_ready": {},
            "unknown_hits": [],
        }
        if status != "success":
            audit["issues"].append(f"status={status}")
        if stype == "cbom":
            dist = meta.get("cbom_distributions") or {}
            audit["chart_ready"] = {
                "algorithms": bool(dist.get("algorithms")),
                "weakness": bool(dist.get("weakness")),
                "pqc": bool(dist.get("pqc")),
                "certificates": isinstance(dist.get("certificates"), list),
                "protocols": bool(dist.get("protocols")),
                "cbom_json": isinstance(meta.get("cbom_json"), dict),
                "cbom_compliance": bool(meta.get("cbom_compliance")),
                "cbom_scores": bool(meta.get("cbom_scores")),
            }
            if not dist:
                audit["issues"].append("missing cbom_distributions")
            if not dist.get("algorithms"):
                audit["issues"].append("empty algorithms distribution")
            if len(data_results) == 0:
                audit["issues"].append("empty results")
            for r in data_results[:50]:
                for k in ("algorithm_type", "crypto_strength", "asset_type", "impact"):
                    v = str((r or {}).get(k) or "")
                    if UNKNOWN_RE.search(v):
                        audit["unknown_hits"].append(
                            {"field": k, "value": v, "title": (r or {}).get("title")}
                        )
        elif stype == "ai_bom":
            audit["chart_ready"] = {
                "ai_bom_json": isinstance(meta.get("ai_bom_json"), dict),
                "ai_bom_compliance": bool(meta.get("ai_bom_compliance")),
                "ai_bom_graph": bool((meta.get("ai_bom_graph") or {}).get("nodes")),
                "ai_bom_scores": bool(meta.get("ai_bom_scores")),
            }
            if not meta.get("ai_bom_json"):
                audit["issues"].append("missing ai_bom_json")
            if len(data_results) == 0:
                audit["issues"].append("empty results")
            unk = known = 0
            for r in data_results:
                lic = str((r or {}).get("license") or "")
                if UNKNOWN_RE.search(lic) or lic.strip() in ("", "None"):
                    unk += 1
                else:
                    known += 1
            audit["license_known"] = known
            audit["license_unknown_or_empty"] = unk
            for r in data_results:
                lic = str((r or {}).get("license") or "")
                if lic.strip().lower() == "unknown":
                    audit["unknown_hits"].append(
                        {
                            "field": "license",
                            "value": lic,
                            "component": (r or {}).get("component_name"),
                        }
                    )
            ctype_unk = sum(
                1
                for r in data_results
                if UNKNOWN_RE.search(str((r or {}).get("component_type") or ""))
            )
            if ctype_unk:
                audit["issues"].append(f"component_type unknown x{ctype_unk}")
        else:
            dash = d.get("dashboard") or {}
            card = dash.get("card_data") or {}
            audit["chart_ready"] = {
                "dashboard": bool(dash),
                "card_data": bool(card),
                "sbom_compliance": bool(meta.get("sbom_compliance")),
            }
            audit["dashboard_keys"] = sorted(dash.keys())
            audit["card_data"] = card
            if len(data_results) == 0 and not card:
                audit["issues"].append("empty results and no dashboard card_data")
            unk = 0
            for r in data_results:
                lic = str((r or {}).get("license") or "")
                if UNKNOWN_RE.search(lic):
                    unk += 1
                    audit["unknown_hits"].append({"field": "license", "value": lic})
            audit["license_unknown_hits"] = unk

        focus = {
            "meta": {
                k: meta.get(k)
                for k in meta
                if "distribution" in k
                or "compliance" in k
                or k.endswith("_json")
                or "graph" in k
            },
            "results_sample": data_results[:15],
        }
        hits = [
            h
            for h in walk(focus)
            if any(
                x in h["path"].lower()
                for x in (
                    "license",
                    "algorithm",
                    "asset",
                    "weakness",
                    "severity",
                    "component_type",
                    "impact",
                    "primitive",
                    "distribution",
                    "crypto_strength",
                )
            )
        ]
        audit["unknown_hits"] = (audit["unknown_hits"] + hits)[:30]
        if hits:
            audit["issues"].append(f"{len(hits)} unknown-ish metadata/result hits")
        # duration
        dur = None
        if j.get("created_at") and j.get("last_updated"):
            try:
                c = datetime.fromisoformat(j["created_at"])
                u = datetime.fromisoformat(j["last_updated"])
                dur = round((u - c).total_seconds(), 1)
            except Exception:
                pass
        audits.append(audit)
        rows.append(
            {
                "scan_id": sid,
                "scan_type": stype,
                "scan_status": status,
                "title": j.get("title"),
                "results_count": len(data_results),
                "duration_s": dur,
                "repo": (meta.get("repo_url")),
            }
        )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "team_id": TEAM,
        "jobs": rows,
        "audits": audits,
        "summary": {
            "total": 30,
            "success": sum(1 for r in rows if r.get("scan_status") == "success"),
            "failure": sum(1 for r in rows if r.get("scan_status") == "failure"),
            "missing": sum(1 for r in rows if r.get("scan_status") == "missing"),
            "audits_with_issues": sum(1 for a in audits if a.get("issues")),
            "by_type_success": {
                "cbom": sum(
                    1
                    for r in rows
                    if r.get("scan_type") == "cbom" and r.get("scan_status") == "success"
                ),
                "ai_bom": sum(
                    1
                    for r in rows
                    if r.get("scan_type") == "ai_bom"
                    and r.get("scan_status") == "success"
                ),
                "sbom_sca": sum(
                    1
                    for r in rows
                    if r.get("scan_type") == "sbom_sca"
                    and r.get("scan_status") == "success"
                ),
            },
        },
    }
    with open(OUT, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print("SUMMARY", json.dumps(report["summary"], indent=2), flush=True)
    for a in audits:
        if a.get("issues"):
            print(
                "ISSUE",
                a["scan_id"],
                a.get("scan_type"),
                a["issues"],
                "unk",
                (a.get("unknown_hits") or [])[:3],
                flush=True,
            )
    print("wrote", OUT, flush=True)


if __name__ == "__main__":
    main()
