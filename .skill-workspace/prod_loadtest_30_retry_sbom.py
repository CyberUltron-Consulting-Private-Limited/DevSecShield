#!/usr/bin/env python3
"""Retry the 4 SBOM scans that failed start due to estimate race; re-audit all 30."""
from __future__ import annotations

import concurrent.futures
import importlib.util
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

FAILED = [
    (198, 3, "https://github.com/encode/django-rest-framework", "main"),
    (186, 5, "https://github.com/psf/requests", "main"),
    (202, 8, "https://github.com/encode/django-rest-framework", "main"),
    (189, 10, "https://github.com/benjaminp/six", "main"),
]


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
    boundary = "----retrySBOM"
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


def payload(repo, branch):
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


def estimate_then_start(token, sid, repo, branch):
    pl = payload(repo, branch)
    est_st, est_d = 0, {}
    for attempt in range(10):
        est_st, est_d = post_multipart(
            f"/{TEAM}/sbom_sca/scan/{sid}/estimate_credits",
            token,
            "start_scan_payload_string",
            pl,
            timeout=240,
        )
        print(
            f"estimate sid={sid} attempt={attempt} st={est_st} detail={str(est_d)[:180]}",
            flush=True,
        )
        if est_st == 200:
            break
        time.sleep(3)
    else:
        return {"scan_id": sid, "ok": False, "error": f"estimate_failed {est_st} {est_d}"}

    time.sleep(2)
    st_st, st_d = 0, {}
    for attempt in range(8):
        st_st, st_d = post_multipart(
            f"/{TEAM}/sbom_sca/scan/{sid}/start",
            token,
            "start_scan_payload_string",
            pl,
            timeout=240,
        )
        print(
            f"start sid={sid} attempt={attempt} st={st_st} detail={str(st_d)[:180]}",
            flush=True,
        )
        if st_st == 200:
            return {
                "scan_id": sid,
                "ok": True,
                "repo": repo,
                "branch": branch,
                "scan_type": "sbom_sca",
            }
        if "estimated" in str(st_d).lower():
            post_multipart(
                f"/{TEAM}/sbom_sca/scan/{sid}/estimate_credits",
                token,
                "start_scan_payload_string",
                pl,
                timeout=240,
            )
            time.sleep(3)
            continue
        time.sleep(2)
    return {"scan_id": sid, "ok": False, "error": f"start_failed {st_st} {st_d}"}


def poll(token, sid, t0):
    end = time.monotonic() + 40 * 60
    while time.monotonic() < end:
        st, d = req("GET", f"/{TEAM}/sbom_sca/scan/{sid}", token, timeout=60)
        status = d.get("scan_status")
        if status in ("success", "failure"):
            return {
                "scan_id": sid,
                "scan_type": "sbom_sca",
                "scan_status": status,
                "duration_s": round(time.monotonic() - t0, 1),
                "response": d,
            }
        time.sleep(5)
    st, d = req("GET", f"/{TEAM}/sbom_sca/scan/{sid}", token, timeout=60)
    return {
        "scan_id": sid,
        "scan_type": "sbom_sca",
        "scan_status": f"timeout_last={d.get('scan_status')}",
        "duration_s": round(time.monotonic() - t0, 1),
        "response": d,
    }


def load_quality_audit():
    spec = importlib.util.spec_from_file_location(
        "lt",
        "/home/contact_cyberultron_com/DevSecShield/.skill-workspace/prod_loadtest_30.py",
    )
    lt = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(lt)
    return lt.quality_audit


def main():
    quality_audit = load_quality_audit()
    token = login()
    print("login ok; retrying 4 SBOMs", flush=True)
    t0 = time.monotonic()
    started = []
    for sid, idx, repo, branch in FAILED:
        r = estimate_then_start(token, sid, repo, branch)
        r["idx"] = idx
        r["t0"] = t0
        r["title"] = f"LOAD30-sbom_sca-{idx}-retry"
        started.append(r)
        print("STARTED_RETRY", r, flush=True)

    finished = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = []
        for j in started:
            if j.get("ok"):
                futs.append(ex.submit(poll, token, j["scan_id"], t0))
            else:
                finished.append({**j, "scan_status": "start_failed", "scan_type": "sbom_sca"})
        for f in concurrent.futures.as_completed(futs):
            job = f.result()
            finished.append(job)
            print(
                f"DONE sid={job['scan_id']} status={job['scan_status']} dur={job.get('duration_s')}",
                flush=True,
            )

    report = json.load(open(OUT))
    by_sid = {j.get("scan_id"): j for j in report["jobs"]}
    for job in finished:
        sid = job["scan_id"]
        slim = {k: v for k, v in job.items() if k != "response"}
        for fsid, idx, repo, branch in FAILED:
            if fsid == sid:
                slim["repo"] = repo
                slim["branch"] = branch
                slim["idx"] = idx
                slim["ok"] = job.get("scan_status") == "success"
                slim["scan_type"] = "sbom_sca"
                slim["title"] = f"LOAD30-sbom_sca-{idx}-retry"
        by_sid[sid] = slim

    print("Re-auditing all jobs...", flush=True)
    new_jobs = []
    new_audits = []
    for j in by_sid.values():
        sid = j.get("scan_id")
        stype = j.get("scan_type")
        if not sid or not stype:
            continue
        st, d = req("GET", f"/{TEAM}/{stype}/scan/{sid}", token, timeout=90)
        j2 = {**j, "scan_status": d.get("scan_status"), "response": d}
        new_jobs.append({k: v for k, v in j2.items() if k != "response"})
        audit = quality_audit(j2)
        new_audits.append(audit)
        print(
            f"AUDITED sid={sid} type={stype} status={d.get('scan_status')} "
            f"findings={audit.get('findings_count')} issues={audit.get('issues')}",
            flush=True,
        )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "team_id": TEAM,
        "jobs": new_jobs,
        "audits": new_audits,
        "summary": {
            "total": len(new_jobs),
            "success": sum(1 for j in new_jobs if j.get("scan_status") == "success"),
            "failure": sum(1 for j in new_jobs if j.get("scan_status") == "failure"),
            "start_failed": sum(
                1
                for j in new_jobs
                if j.get("scan_status") in ("start_failed", "not_started")
            ),
            "timeout": sum(
                1 for j in new_jobs if str(j.get("scan_status", "")).startswith("timeout")
            ),
            "audits_with_issues": sum(1 for a in new_audits if a.get("issues")),
        },
    }
    with open(OUT, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print("=== FINAL SUMMARY ===", json.dumps(report["summary"], indent=2), flush=True)


if __name__ == "__main__":
    main()
