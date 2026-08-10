#!/usr/bin/env python3
"""Retry the 7 credit-failed LOAD30 scans with cheap repos; poll all LOAD30 to success."""
from __future__ import annotations

import concurrent.futures
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://devsecshieldapi.zeroshield.ai"
EMAIL = "shivam@cyberultron.com"
PASSWORD = "Cyber@123"
OTP = "123456"
TEAM = 1
OUT = "/tmp/prod_loadtest_30_report.json"
DEADLINE_S = 45 * 60

# Failed start sids from first wave + cheap replacement payloads
RETRY = [
    # sid, type, repo, branch
    (160, "sbom_sca", "https://github.com/psf/requests", "main"),
    (169, "sbom_sca", "https://github.com/pallets/click", "main"),
    (167, "sbom_sca", "https://github.com/benjaminp/six", "main"),
    (175, "sbom_sca", "https://github.com/pallets/flask", "main"),
    (178, "ai_bom", "https://github.com/openai/openai-python", "main"),
    (159, "ai_bom", "https://github.com/anthropics/anthropic-sdk-python", "main"),
    (180, "ai_bom", "https://github.com/cohere-ai/cohere-python", "main"),
]

# All LOAD30 scan ids from first wave (151-180 except probe 150) — will discover via titles
UNKNOWN_RE = __import__("re").compile(r"\b(unknown|n/?a)\b", __import__("re").I)


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


def post_multipart(path, token, field, value, timeout=300):
    boundary = "----loadTestRetry"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"\r\n\r\n'
        f"{value}\r\n--{boundary}--\r\n"
    ).encode()
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
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


def login():
    req("POST", "/send_code", body={"email": EMAIL})
    st, d = req(
        "POST",
        "/login",
        body={"email": EMAIL, "password": PASSWORD, "verification_code": OTP},
    )
    assert st == 200 and "access_token" in d, d
    return d["access_token"]


def payload(scan_type, repo, branch):
    if scan_type == "cbom":
        return json.dumps(
            {
                "cbom": {
                    "repo_context": {"mode": "github", "repo_url": repo, "branch": branch, "PAT": ""},
                    "zip_file_used": False,
                    "cbom_file_used": False,
                    "scan_binaries": False,
                }
            }
        )
    if scan_type == "ai_bom":
        return json.dumps(
            {
                "ai_bom": {
                    "repo_context": {"mode": "github", "repo_url": repo, "branch": branch, "PAT": ""},
                    "zip_file_used": False,
                    "ai_bom_file_used": False,
                    "scan_binaries": False,
                }
            }
        )
    return json.dumps(
        {
            "sbom_sca": {
                "repo_context": {"mode": "github", "repo_url": repo, "branch": branch, "PAT": ""},
                "zip_file_used": False,
                "sbom_file_used": False,
            }
        }
    )


def start_existing(token, sid, scan_type, repo, branch):
    pl = payload(scan_type, repo, branch)
    est_st, est_d = post_multipart(
        f"/{TEAM}/{scan_type}/scan/{sid}/estimate_credits",
        token,
        "start_scan_payload_string",
        pl,
        timeout=180,
    )
    start_st, start_d = post_multipart(
        f"/{TEAM}/{scan_type}/scan/{sid}/start",
        token,
        "start_scan_payload_string",
        pl,
        timeout=180,
    )
    print(f"retry sid={sid} type={scan_type} est={est_st} start={start_st} detail={start_d if start_st!=200 else 'ok'}", flush=True)
    return {"scan_id": sid, "scan_type": scan_type, "repo": repo, "ok": start_st == 200, "start_status": start_st, "start_detail": start_d if start_st != 200 else None, "t0": time.monotonic()}


def walk_unknowns(obj, path="$", hits=None, limit=40):
    if hits is None:
        hits = []
    if len(hits) >= limit:
        return hits
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            if isinstance(v, str) and UNKNOWN_RE.search(v):
                if k.lower() in ("message", "detail", "error", "info", "description", "suggested_fix"):
                    continue
                hits.append({"path": p, "value": v[:120]})
            else:
                walk_unknowns(v, p, hits, limit)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:40]):
            walk_unknowns(v, f"{path}[{i}]", hits, limit)
    return hits


def quality_audit(stype, sid, d):
    meta = d.get("scan_metadata") or {}
    findings = d.get("findings") or d.get("data") or []
    if isinstance(findings, dict):
        findings = findings.get("results") or []
    audit = {
        "scan_id": sid,
        "scan_type": stype,
        "status": d.get("scan_status"),
        "findings_count": len(findings) if isinstance(findings, list) else 0,
        "issues": [],
        "chart_ready": {},
        "unknown_hits": [],
    }
    if d.get("scan_status") != "success":
        audit["issues"].append(f"status={d.get('scan_status')}")
        return audit
    if stype == "cbom":
        dist = meta.get("cbom_distributions") or {}
        audit["chart_ready"] = {
            "has_distributions": bool(dist),
            "algorithms": bool(dist.get("algorithms")),
            "weakness": bool(dist.get("weakness")),
            "pqc": bool(dist.get("pqc")),
            "certificates": isinstance(dist.get("certificates"), list) and len(dist.get("certificates") or []) > 0,
            "protocols": bool(dist.get("protocols")),
            "cbom_json": isinstance(meta.get("cbom_json"), dict),
            "cbom_compliance": bool(meta.get("cbom_compliance")),
        }
        if not dist:
            audit["issues"].append("missing cbom_distributions")
        if audit["findings_count"] == 0:
            audit["issues"].append("empty findings")
    elif stype == "ai_bom":
        audit["chart_ready"] = {
            "ai_bom_json": isinstance(meta.get("ai_bom_json"), dict),
            "ai_bom_compliance": bool(meta.get("ai_bom_compliance")),
            "ai_bom_graph": bool((meta.get("ai_bom_graph") or {}).get("nodes")),
        }
        if not meta.get("ai_bom_json"):
            audit["issues"].append("missing ai_bom_json")
        if audit["findings_count"] == 0:
            audit["issues"].append("empty findings")
        unk = known = 0
        for f in findings if isinstance(findings, list) else []:
            lic = str(f.get("license") or "")
            if UNKNOWN_RE.search(lic) or lic.strip() in ("", "None"):
                unk += 1
            else:
                known += 1
        audit["license_known"] = known
        audit["license_unknown_or_empty"] = unk
    else:
        dash = d.get("dashboard") or {}
        audit["chart_ready"] = {"dashboard_present": bool(dash), "card_data": bool(dash.get("card_data"))}
        if audit["findings_count"] == 0:
            audit["issues"].append("empty findings")
        unk = 0
        for f in findings if isinstance(findings, list) else []:
            lic = str(f.get("license") or f.get("License") or f.get("resolved_license") or "")
            if UNKNOWN_RE.search(lic):
                unk += 1
        audit["license_unknown_hits"] = unk

    sample = {"scan_metadata": meta, "findings_sample": findings[:20] if isinstance(findings, list) else findings}
    hits = walk_unknowns(sample)
    interesting = [
        h
        for h in hits
        if any(
            x in h["path"].lower()
            for x in ("license", "algorithm", "asset", "weakness", "severity", "component_type", "impact", "primitive", "distribution")
        )
    ]
    audit["unknown_hits"] = interesting[:25]
    if interesting:
        audit["issues"].append(f"{len(interesting)} unknown-ish field hits")
    return audit


def poll_until(token, jobs):
    end = time.monotonic() + DEADLINE_S
    pending = {j["scan_id"]: j for j in jobs}
    results = {}
    while pending and time.monotonic() < end:
        done_ids = []
        for sid, j in list(pending.items()):
            st, d = req("GET", f"/{TEAM}/{j['scan_type']}/scan/{sid}", token, timeout=60)
            status = d.get("scan_status")
            if status in ("success", "failure"):
                j["scan_status"] = status
                j["duration_s"] = round(time.monotonic() - j.get("t0", time.monotonic()), 1)
                j["response"] = d
                results[sid] = j
                done_ids.append(sid)
                print(f"DONE sid={sid} type={j['scan_type']} status={status}", flush=True)
        for sid in done_ids:
            pending.pop(sid, None)
        if pending:
            print(f"waiting {len(pending)}: {sorted(pending)}", flush=True)
            time.sleep(8)
    for sid, j in pending.items():
        st, d = req("GET", f"/{TEAM}/{j['scan_type']}/scan/{sid}", token, timeout=60)
        j["scan_status"] = d.get("scan_status") or "timeout"
        j["response"] = d
        results[sid] = j
        print(f"TIMEOUT sid={sid} status={j['scan_status']}", flush=True)
    return results


def main():
    token = login()
    print("credits check via teams...", flush=True)
    st, teams = req("GET", "/teams", token)
    for t in teams:
        if t.get("team_id") == 1:
            print("team1 credits", t.get("team_credit_balance"), flush=True)

    # Retry failed starts
    retried = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as ex:
        futs = [ex.submit(start_existing, token, sid, stype, repo, br) for sid, stype, repo, br in RETRY]
        for f in concurrent.futures.as_completed(futs):
            retried.append(f.result())

    # Discover all LOAD30 scans 151-180
    all_jobs = []
    for sid in range(151, 181):
        # probe type by trying list is hard; use DB types from earlier knowledge via GET attempts
        for stype in ("cbom", "ai_bom", "sbom_sca"):
            st, d = req("GET", f"/{TEAM}/{stype}/scan/{sid}", token, timeout=30)
            if st == 200 and d.get("scan_id") == sid or (st == 200 and d.get("scan_status")):
                # confirm title
                title = d.get("title") or (d.get("scan_metadata") or {}).get("title") or ""
                # GET response may nest differently — also accept any 200 with scan_status
                if d.get("scan_status") is not None:
                    all_jobs.append(
                        {
                            "scan_id": sid,
                            "scan_type": stype,
                            "scan_status": d.get("scan_status"),
                            "t0": time.monotonic(),
                            "response": d if d.get("scan_status") in ("success", "failure") else None,
                            "title": title,
                        }
                    )
                    break

    print(f"discovered {len(all_jobs)} jobs", flush=True)
    # For ones already terminal, keep; else poll
    terminal = []
    pending = []
    for j in all_jobs:
        if j.get("scan_status") in ("success", "failure"):
            if j.get("response") is None:
                st, d = req("GET", f"/{TEAM}/{j['scan_type']}/scan/{j['scan_id']}", token)
                j["response"] = d
                j["scan_status"] = d.get("scan_status")
            terminal.append(j)
        else:
            pending.append(j)

    print(f"already terminal={len(terminal)} pending={len(pending)}", flush=True)
    polled = poll_until(token, pending) if pending else {}
    finished = terminal + list(polled.values())

    audits = []
    slim = []
    for j in finished:
        d = j.get("response") or {}
        if not d:
            st, d = req("GET", f"/{TEAM}/{j['scan_type']}/scan/{j['scan_id']}", token)
            j["response"] = d
            j["scan_status"] = d.get("scan_status")
        audits.append(quality_audit(j["scan_type"], j["scan_id"], j["response"]))
        slim.append({k: v for k, v in j.items() if k != "response"})

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "team_id": TEAM,
        "retry": retried,
        "jobs": slim,
        "audits": audits,
        "summary": {
            "total": len(finished),
            "success": sum(1 for j in finished if j.get("scan_status") == "success"),
            "failure": sum(1 for j in finished if j.get("scan_status") == "failure"),
            "other": sum(1 for j in finished if j.get("scan_status") not in ("success", "failure")),
            "audits_with_issues": sum(1 for a in audits if a.get("issues")),
        },
    }
    with open(OUT, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print("SUMMARY", json.dumps(report["summary"], indent=2), flush=True)
    print("wrote", OUT, flush=True)


if __name__ == "__main__":
    main()
