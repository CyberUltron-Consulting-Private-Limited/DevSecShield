#!/usr/bin/env python3
"""Prod parallel 30-scan load test: 10 CBOM + 10 AIBOM + 10 SBOM."""
from __future__ import annotations

import concurrent.futures
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://devsecshieldapi.zeroshield.ai"
EMAIL = "shivam@cyberultron.com"
PASSWORD = "Cyber@123"
OTP = "123456"
TEAM = 1  # Ansh Singhal's Team
OUT = "/tmp/prod_loadtest_30_report.json"
DEADLINE_S = 45 * 60  # 45 min for all 30

# Rich targets (rotate) — known to yield licenses/algos/components
CBOM_REPOS = [
    ("https://github.com/jpadilla/pyjwt", "master"),
    ("https://github.com/pyca/pyopenssl", "main"),
    ("https://github.com/encode/httpx", "master"),
    ("https://github.com/psf/requests", "main"),
    ("https://github.com/urllib3/urllib3", "main"),
]
AIBOM_REPOS = [
    ("https://github.com/openai/openai-python", "main"),
    ("https://github.com/anthropics/anthropic-sdk-python", "main"),
    ("https://github.com/cohere-ai/cohere-python", "main"),
    ("https://github.com/google-gemini/deprecated-generative-ai-python", "main"),
    ("https://github.com/run-llama/llama_index", "main"),
]
SBOM_REPOS = [
    ("https://github.com/psf/requests", "main"),
    ("https://github.com/pallets/flask", "main"),
    ("https://github.com/encode/django-rest-framework", "main"),  # HEAD is main (master 404)
    ("https://github.com/pallets/click", "main"),
    ("https://github.com/benjaminp/six", "main"),  # HEAD is main (master 404)
]

UNKNOWN_RE = re.compile(r"\b(unknown|n/?a)\b", re.I)


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
    boundary = "----loadTestBoundary"
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
    st, d = req("POST", "/send_code", body={"email": EMAIL})
    st, d = req(
        "POST",
        "/login",
        body={"email": EMAIL, "password": PASSWORD, "verification_code": OTP},
    )
    if st != 200 or "access_token" not in d:
        raise SystemExit(f"login failed: {st} {d}")
    return d["access_token"]


def payload_for(scan_type: str, repo: str, branch: str) -> str:
    if scan_type == "cbom":
        return json.dumps(
            {
                "cbom": {
                    "repo_context": {
                        "mode": "github",
                        "repo_url": repo,
                        "branch": branch,
                        "PAT": "",
                    },
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
                    "repo_context": {
                        "mode": "github",
                        "repo_url": repo,
                        "branch": branch,
                        "PAT": "",
                    },
                    "zip_file_used": False,
                    "ai_bom_file_used": False,
                    "scan_binaries": False,
                }
            }
        )
    return json.dumps(
        {
            "sbom_sca": {
                "repo_context": {
                    "mode": "github",
                    "repo_url": repo,
                    "branch": branch,
                    "PAT": "",
                },
                "zip_file_used": False,
                "sbom_file_used": False,
            }
        }
    )


def start_one(token: str, scan_type: str, idx: int, repo: str, branch: str) -> dict:
    title = f"LOAD30-{scan_type}-{idx}-{datetime.now(timezone.utc).strftime('%H%M%S')}"
    t0 = time.monotonic()
    st, d = req("POST", f"/{TEAM}/{scan_type}/scan", token, {"title": title})
    if st != 200:
        return {
            "scan_type": scan_type,
            "idx": idx,
            "repo": repo,
            "ok": False,
            "error": f"create {st} {d}",
            "t0": t0,
        }
    sid = d["scan_id"]
    pl = payload_for(scan_type, repo, branch)
    # Estimate (best-effort; proceed even if slow/fail — start may still work)
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
    return {
        "scan_type": scan_type,
        "idx": idx,
        "repo": repo,
        "branch": branch,
        "scan_id": sid,
        "title": title,
        "estimate_status": est_st,
        "start_status": start_st,
        "start_detail": start_d if start_st != 200 else None,
        "ok": start_st == 200,
        "t0": t0,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


def poll_one(token: str, job: dict) -> dict:
    if not job.get("ok"):
        job["scan_status"] = "start_failed"
        job["duration_s"] = round(time.monotonic() - job["t0"], 1)
        return job
    sid = job["scan_id"]
    stype = job["scan_type"]
    end = time.monotonic() + DEADLINE_S
    last = None
    while time.monotonic() < end:
        st, d = req("GET", f"/{TEAM}/{stype}/scan/{sid}", token, timeout=60)
        last = d.get("scan_status")
        if last in ("success", "failure"):
            job["scan_status"] = last
            job["duration_s"] = round(time.monotonic() - job["t0"], 1)
            job["response"] = d
            return job
        time.sleep(5)
    job["scan_status"] = f"timeout_last={last}"
    job["duration_s"] = round(time.monotonic() - job["t0"], 1)
    st, d = req("GET", f"/{TEAM}/{stype}/scan/{sid}", token, timeout=60)
    job["response"] = d
    return job


def walk_unknowns(obj, path="$", hits=None, limit=40):
    if hits is None:
        hits = []
    if len(hits) >= limit:
        return hits
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            if isinstance(v, str) and UNKNOWN_RE.search(v):
                # ignore benign paths
                if k.lower() in ("message", "detail", "error", "info"):
                    continue
                hits.append({"path": p, "value": v[:120]})
            else:
                walk_unknowns(v, p, hits, limit)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            walk_unknowns(v, f"{path}[{i}]", hits, limit)
    elif isinstance(obj, str) and UNKNOWN_RE.search(obj):
        hits.append({"path": path, "value": obj[:120]})
    return hits


def quality_audit(job: dict) -> dict:
    d = job.get("response") or {}
    meta = d.get("scan_metadata") or {}
    findings = d.get("findings") or d.get("data") or []
    if isinstance(findings, dict):
        findings = findings.get("results") or []
    stype = job["scan_type"]
    audit = {
        "scan_id": job.get("scan_id"),
        "scan_type": stype,
        "status": job.get("scan_status"),
        "findings_count": len(findings) if isinstance(findings, list) else 0,
        "issues": [],
        "chart_ready": {},
        "unknown_hits": [],
    }
    if job.get("scan_status") != "success":
        audit["issues"].append(f"status={job.get('scan_status')}")
        err = ((d.get("info") or {}) if isinstance(d.get("info"), dict) else {})
        if err:
            audit["issues"].append(f"info={json.dumps(err)[:200]}")
        return audit

    # Chart / distribution checks
    if stype == "cbom":
        dist = meta.get("cbom_distributions") or d.get("cbom_distributions") or {}
        audit["chart_ready"] = {
            "has_distributions": bool(dist),
            "algorithms": bool(dist.get("algorithms")),
            "weakness": bool(dist.get("weakness")),
            "pqc": bool(dist.get("pqc")),
            "certificates": bool(dist.get("certificates")),
            "protocols": bool(dist.get("protocols")),
            "cbom_json": isinstance(meta.get("cbom_json"), dict),
            "cbom_compliance": bool(meta.get("cbom_compliance")),
            "cbom_scores": bool(meta.get("cbom_scores")),
        }
        if not dist:
            audit["issues"].append("missing cbom_distributions")
        elif not any(dist.get(k) for k in ("algorithms", "weakness", "protocols", "certificates")):
            audit["issues"].append("cbom_distributions empty of chart series")
        if audit["findings_count"] == 0:
            audit["issues"].append("empty findings for crypto-bearing target")
    elif stype == "ai_bom":
        audit["chart_ready"] = {
            "ai_bom_json": isinstance(meta.get("ai_bom_json"), dict),
            "ai_bom_compliance": bool(meta.get("ai_bom_compliance")),
            "ai_bom_graph": bool((meta.get("ai_bom_graph") or {}).get("nodes")),
            "ai_bom_scores": bool(meta.get("ai_bom_scores")),
        }
        if not meta.get("ai_bom_json"):
            audit["issues"].append("missing ai_bom_json")
        if audit["findings_count"] == 0:
            audit["issues"].append("empty findings for AI-bearing target")
        # license unknown pollution in findings
        unk_lic = 0
        known_lic = 0
        for f in findings if isinstance(findings, list) else []:
            lic = str(f.get("license") or f.get("licenses") or f.get("component_license") or "")
            if UNKNOWN_RE.search(lic) or lic.strip() in ("", "None"):
                unk_lic += 1
            else:
                known_lic += 1
        audit["license_known"] = known_lic
        audit["license_unknown_or_empty"] = unk_lic
    else:  # sbom_sca
        dash = d.get("dashboard") or {}
        audit["chart_ready"] = {
            "dashboard_present": bool(dash),
            "card_data": bool(dash.get("card_data")),
        }
        if audit["findings_count"] == 0:
            audit["issues"].append("empty findings for package-bearing target")
        unk_lic = 0
        for f in findings if isinstance(findings, list) else []:
            lic = str(
                f.get("license")
                or f.get("License")
                or f.get("resolved_license")
                or f.get("license_id")
                or ""
            )
            if UNKNOWN_RE.search(lic):
                unk_lic += 1
        audit["license_unknown_hits"] = unk_lic

    # Broad unknown walk on metadata + first 20 findings
    sample = {"scan_metadata": meta, "findings_sample": (findings[:20] if isinstance(findings, list) else findings)}
    hits = walk_unknowns(sample)
    # Filter noise: CycloneDX often has empty fields; focus on display-ish keys
    interesting = [
        h
        for h in hits
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
            )
        )
    ]
    audit["unknown_hits"] = interesting[:25]
    if interesting:
        audit["issues"].append(f"{len(interesting)} unknown-ish chart/field hits")
    return audit


def build_jobs():
    jobs = []
    for i in range(10):
        repo, branch = CBOM_REPOS[i % len(CBOM_REPOS)]
        jobs.append(("cbom", i + 1, repo, branch))
    for i in range(10):
        repo, branch = AIBOM_REPOS[i % len(AIBOM_REPOS)]
        jobs.append(("ai_bom", i + 1, repo, branch))
    for i in range(10):
        repo, branch = SBOM_REPOS[i % len(SBOM_REPOS)]
        jobs.append(("sbom_sca", i + 1, repo, branch))
    return jobs


def main():
    print("=== LOGIN ===", flush=True)
    token = login()
    print("login ok", flush=True)

    specs = build_jobs()
    print(f"firing {len(specs)} scans in parallel...", flush=True)
    started = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futs = [
            ex.submit(start_one, token, stype, idx, repo, branch)
            for stype, idx, repo, branch in specs
        ]
        for f in concurrent.futures.as_completed(futs):
            job = f.result()
            started.append(job)
            print(
                f"STARTED type={job['scan_type']} idx={job['idx']} sid={job.get('scan_id')} ok={job['ok']} start={job.get('start_status')}",
                flush=True,
            )

    print(f"=== POLLING {len(started)} ===", flush=True)
    finished = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futs = [ex.submit(poll_one, token, job) for job in started]
        for f in concurrent.futures.as_completed(futs):
            job = f.result()
            finished.append(job)
            print(
                f"DONE type={job['scan_type']} sid={job.get('scan_id')} status={job.get('scan_status')} dur={job.get('duration_s')}s",
                flush=True,
            )

    audits = [quality_audit(j) for j in finished]
    # strip bulky response from saved jobs (keep audits)
    slim = []
    for j in finished:
        s = {k: v for k, v in j.items() if k != "response"}
        slim.append(s)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "team_id": TEAM,
        "jobs": slim,
        "audits": audits,
        "summary": {
            "total": len(finished),
            "success": sum(1 for j in finished if j.get("scan_status") == "success"),
            "failure": sum(1 for j in finished if j.get("scan_status") == "failure"),
            "start_failed": sum(1 for j in finished if j.get("scan_status") == "start_failed"),
            "timeout": sum(1 for j in finished if str(j.get("scan_status", "")).startswith("timeout")),
            "audits_with_issues": sum(1 for a in audits if a.get("issues")),
        },
    }
    with open(OUT, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print("=== SUMMARY ===", json.dumps(report["summary"], indent=2), flush=True)
    print("wrote", OUT, flush=True)
    # non-zero exit if not all success + clean audits
    if report["summary"]["success"] != 30 or report["summary"]["audits_with_issues"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
