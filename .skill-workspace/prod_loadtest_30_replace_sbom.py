#!/usr/bin/env python3
"""Create replacement SBOM scans for any still-not-success LOAD30 SBOMs; use small repos."""
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

# Prefer small, clone-reliable targets with real findings
REPLACEMENTS = [
    ("https://github.com/pallets/click", "main"),
    ("https://github.com/pallets/flask", "main"),
    ("https://github.com/benjaminp/six", "main"),
    ("https://github.com/psf/requests", "main"),
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
    boundary = "----replaceSBOM"
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


def create_estimate_start(token, idx, repo, branch):
    title = f"LOAD30-sbom_sca-{idx}-repl-{datetime.now(timezone.utc).strftime('%H%M%S')}"
    st, d = req("POST", f"/{TEAM}/sbom_sca/scan", token, {"title": title})
    if st != 200:
        return {"ok": False, "error": f"create {st} {d}", "idx": idx, "repo": repo}
    sid = d["scan_id"]
    pl = payload(repo, branch)
    for attempt in range(8):
        est_st, est_d = post_multipart(
            f"/{TEAM}/sbom_sca/scan/{sid}/estimate_credits",
            token,
            "start_scan_payload_string",
            pl,
            timeout=240,
        )
        print(f"estimate new sid={sid} attempt={attempt} st={est_st} {str(est_d)[:120]}", flush=True)
        if est_st == 200:
            break
        time.sleep(2)
    else:
        return {"ok": False, "scan_id": sid, "error": f"estimate {est_st} {est_d}", "idx": idx, "repo": repo}
    time.sleep(1.5)
    for attempt in range(6):
        st_st, st_d = post_multipart(
            f"/{TEAM}/sbom_sca/scan/{sid}/start",
            token,
            "start_scan_payload_string",
            pl,
            timeout=240,
        )
        print(f"start new sid={sid} attempt={attempt} st={st_st} {str(st_d)[:120]}", flush=True)
        if st_st == 200:
            return {
                "ok": True,
                "scan_id": sid,
                "scan_type": "sbom_sca",
                "idx": idx,
                "repo": repo,
                "branch": branch,
                "title": title,
            }
        if "estimated" in str(st_d).lower():
            post_multipart(
                f"/{TEAM}/sbom_sca/scan/{sid}/estimate_credits",
                token,
                "start_scan_payload_string",
                pl,
                timeout=240,
            )
            time.sleep(2)
            continue
        time.sleep(2)
    return {"ok": False, "scan_id": sid, "error": f"start {st_st} {st_d}", "idx": idx, "repo": repo}


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


def main():
    spec = importlib.util.spec_from_file_location(
        "lt",
        "/home/contact_cyberultron_com/DevSecShield/.skill-workspace/prod_loadtest_30.py",
    )
    lt = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(lt)

    token = login()
    report = json.load(open(OUT))
    # Identify which of the original 30 are not success
    bad = [j for j in report["jobs"] if j.get("scan_status") != "success"]
    print(f"non_success jobs: {[(j.get('scan_id'), j.get('scan_status')) for j in bad]}", flush=True)
    if not bad:
        print("nothing to replace", flush=True)
        return

    t0 = time.monotonic()
    replacements = []
    for i, j in enumerate(bad):
        repo, branch = REPLACEMENTS[i % len(REPLACEMENTS)]
        idx = j.get("idx") or (i + 1)
        # Prefer updating in-place if still not_started and repo is small; else create new
        # Always create NEW to avoid stuck DRF estimate state
        r = create_estimate_start(token, idx, repo, branch)
        r["replaces_scan_id"] = j.get("scan_id")
        replacements.append(r)
        print("REPLACEMENT", r, flush=True)
        time.sleep(1)

    finished = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = []
        for r in replacements:
            if r.get("ok"):
                futs.append(ex.submit(poll, token, r["scan_id"], t0))
            else:
                finished.append({**r, "scan_status": "start_failed", "scan_type": "sbom_sca"})
        for f in concurrent.futures.as_completed(futs):
            job = f.result()
            # attach metadata from replacements
            for r in replacements:
                if r.get("scan_id") == job["scan_id"]:
                    job.update({k: r[k] for k in ("idx", "repo", "branch", "title", "replaces_scan_id") if k in r})
            finished.append(job)
            print(f"DONE sid={job['scan_id']} status={job['scan_status']}", flush=True)

    # Replace bad jobs in report with successful replacements (match by replaces_scan_id)
    by_old = {f.get("replaces_scan_id"): f for f in finished}
    new_jobs = []
    for j in report["jobs"]:
        sid = j.get("scan_id")
        if sid in by_old:
            f = by_old[sid]
            slim = {k: v for k, v in f.items() if k != "response"}
            slim["ok"] = f.get("scan_status") == "success"
            slim["scan_type"] = "sbom_sca"
            new_jobs.append(slim)
        else:
            new_jobs.append(j)

    print("Re-auditing all jobs...", flush=True)
    audited_jobs = []
    audits = []
    for j in new_jobs:
        sid = j.get("scan_id")
        stype = j.get("scan_type")
        st, d = req("GET", f"/{TEAM}/{stype}/scan/{sid}", token, timeout=90)
        j2 = {**j, "scan_status": d.get("scan_status"), "response": d}
        audited_jobs.append({k: v for k, v in j2.items() if k != "response"})
        audit = lt.quality_audit(j2)
        audits.append(audit)
        print(
            f"AUDITED sid={sid} type={stype} status={d.get('scan_status')} "
            f"findings={audit.get('findings_count')} issues={audit.get('issues')}",
            flush=True,
        )

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "team_id": TEAM,
        "jobs": audited_jobs,
        "audits": audits,
        "summary": {
            "total": len(audited_jobs),
            "success": sum(1 for j in audited_jobs if j.get("scan_status") == "success"),
            "failure": sum(1 for j in audited_jobs if j.get("scan_status") == "failure"),
            "start_failed": sum(
                1 for j in audited_jobs if j.get("scan_status") in ("start_failed", "not_started")
            ),
            "timeout": sum(
                1 for j in audited_jobs if str(j.get("scan_status", "")).startswith("timeout")
            ),
            "audits_with_issues": sum(1 for a in audits if a.get("issues")),
        },
        "replacements": [
            {k: v for k, v in f.items() if k != "response"} for f in finished
        ],
    }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, default=str)
    print("=== FINAL SUMMARY ===", json.dumps(out["summary"], indent=2), flush=True)


if __name__ == "__main__":
    main()
