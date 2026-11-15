"""AWX REST emulator for the F1.3 lab: the AWX endpoints the scan node's AWX transport calls, backed by REAL
ansible-runner / ansible-core running the generated zs-collect playbook against real hosts over SSH.

What is real: the playbook ZeroShield generates, ansible-core's SSH connection, privilege escalation and ``script``
module, the launcher and zs-collect on every host, and the job events (AWX stores exactly the events ansible-runner
emits; ``host_name`` is ``event_data.host``).  What is emulated: AWX's REST layer (token check, the launch prompts,
``ignored_fields``, job status, cancel, the events list with ``event__in`` / ``order_by=counter`` / paging) and its
``MAX_EVENT_RES_DATA`` limit (700,000 bytes by default): an event whose ``res`` is larger is stored with ``res``
emptied, so output that does not respect the limit is lost here as it would be in AWX.

Environment: ZS_AWX_TOKEN (bearer token), ZS_AWX_PORT (8443), ZS_AWX_ASK_LIMIT / ZS_AWX_ASK_VARIABLES (1/0),
ZS_AWX_FORKS (50).  Files (written by bench/f1_transports/live.py): /opt/awx-emu/project/{zs-collect.yml,files/...},
/opt/awx-emu/inventory.ini, /opt/awx-emu/id_ed25519.  Job template id 42.
"""
from __future__ import annotations

import json
import os
import shutil
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import ansible_runner

ROOT = "/opt/awx-emu"
TEMPLATE_ID = 42
MAX_EVENT_RES_DATA = int(os.environ.get("ZS_AWX_MAX_EVENT_RES_DATA", "700000"))
TOKEN = os.environ.get("ZS_AWX_TOKEN", "")
ASK_LIMIT = os.environ.get("ZS_AWX_ASK_LIMIT", "1") == "1"
ASK_VARS = os.environ.get("ZS_AWX_ASK_VARIABLES", "1") == "1"
FORKS = int(os.environ.get("ZS_AWX_FORKS", "50"))

_lock = threading.Lock()
JOBS: dict[int, dict] = {}
STATS = {"events": 0, "events_truncated": 0, "largest_res": 0}


def _run(job: dict) -> None:
    pdd = tempfile.mkdtemp(prefix=f"awx-job-{job['id']}.")
    shutil.copytree(f"{ROOT}/project", f"{pdd}/project")

    def on_event(ev: dict) -> bool:
        data = ev.get("event_data") or {}
        res = data.get("res")
        size = len(json.dumps(res, default=str)) if res is not None else 0
        with _lock:
            STATS["events"] += 1
            STATS["largest_res"] = max(STATS["largest_res"], size)
            if size > MAX_EVENT_RES_DATA:
                STATS["events_truncated"] += 1
                data = {**data, "res": {}}
            job["events"].append({"id": len(job["events"]) + 1, "counter": ev.get("counter"), "event": ev.get("event"),
                                  "host_name": data.get("host") or "", "event_data": data})
        return True

    def cancelled() -> bool:
        return job["cancel"]

    try:
        r = ansible_runner.run(private_data_dir=pdd, playbook="zs-collect.yml", inventory=f"{ROOT}/inventory.ini",
                               extravars=job["extra_vars"], limit=job["limit"], forks=FORKS, quiet=True,
                               event_handler=on_event, cancel_callback=cancelled,
                               envvars={"ANSIBLE_HOST_KEY_CHECKING": "False", "ANSIBLE_SSH_RETRIES": "1",
                                        "ANSIBLE_TIMEOUT": "20", "ANSIBLE_PIPELINING": "False"})
        status = {"successful": "successful", "failed": "failed", "canceled": "canceled",
                  "timeout": "error"}.get(r.status, "error")
    except Exception as exc:  # the emulator reports it the way AWX would: an errored job
        job["explanation"] = f"{exc.__class__.__name__}: {exc}"[:500]
        status = "error"
    job["status"], job["finished"] = status, time.time()
    shutil.rmtree(pdd, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "AWX-emulator/1"

    def log_message(self, fmt, *args):  # quiet
        pass

    def _send(self, code: int, body: dict | None = None) -> None:
        data = json.dumps(body if body is not None else {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth(self) -> bool:
        if self.headers.get("Authorization") != f"Bearer {TOKEN}" or not TOKEN:
            self._send(401, {"detail": "Authentication credentials were not provided."})
            return False
        return True

    def do_GET(self):  # noqa: N802
        if not self._auth():
            return
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        parts = [p for p in url.path.split("/") if p]
        if url.path == "/api/v2/me/":
            return self._send(200, {"count": 1, "results": [{"id": 1, "username": "zeroshield"}]})
        if url.path == "/api/v2/emulator/stats/":
            return self._send(200, STATS)
        if parts[:3] == ["api", "v2", "job_templates"] and len(parts) == 5 and parts[4] == "launch":
            if parts[3] != str(TEMPLATE_ID):
                return self._send(404, {"detail": "Not found."})
            return self._send(200, {"ask_limit_on_launch": ASK_LIMIT, "ask_variables_on_launch": ASK_VARS,
                                    "can_start_without_user_input": True})
        if parts[:3] == ["api", "v2", "jobs"] and len(parts) == 4:
            job = JOBS.get(int(parts[3]))
            if not job:
                return self._send(404, {"detail": "Not found."})
            return self._send(200, {"id": job["id"], "status": job["status"], "limit": job["limit"],
                                    "job_explanation": job.get("explanation", "")})
        if parts[:3] == ["api", "v2", "jobs"] and len(parts) == 5 and parts[4] == "job_events":
            job = JOBS.get(int(parts[3]))
            if not job:
                return self._send(404, {"detail": "Not found."})
            kinds = set((q.get("event__in") or [""])[0].split(",")) - {""}
            with _lock:
                events = [e for e in job["events"] if not kinds or e["event"] in kinds]
            events.sort(key=lambda e: e["counter"] or 0)
            size = min(int((q.get("page_size") or ["25"])[0]), 200)
            page = int((q.get("page") or ["1"])[0])
            chunk = events[(page - 1) * size: page * size]
            extra = "&event__in=" + ",".join(sorted(kinds)) if kinds else ""
            nxt = f"/api/v2/jobs/{job['id']}/job_events/?page={page + 1}&page_size={size}&order_by=counter{extra}" \
                if page * size < len(events) else None
            return self._send(200, {"count": len(events), "next": nxt, "previous": None, "results": chunk})
        return self._send(404, {"detail": "Not found."})

    def do_POST(self):  # noqa: N802
        if not self._auth():
            return
        url = urlsplit(self.path)
        parts = [p for p in url.path.split("/") if p]
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if parts[:3] == ["api", "v2", "job_templates"] and len(parts) == 5 and parts[4] == "launch":
            if parts[3] != str(TEMPLATE_ID):
                return self._send(404, {"detail": "Not found."})
            ignored = {}
            limit, extra = body.get("limit", ""), body.get("extra_vars") or {}
            if isinstance(extra, str):
                extra = json.loads(extra or "{}")
            if not ASK_LIMIT and limit:
                ignored["limit"], limit = limit, ""
            if not ASK_VARS and extra:
                ignored["extra_vars"], extra = extra, {}
            with _lock:
                job_id = 1000 + len(JOBS)
                job = {"id": job_id, "status": "running", "limit": limit or "all", "extra_vars": extra,
                       "events": [], "cancel": False, "started": time.time()}
                JOBS[job_id] = job
            threading.Thread(target=_run, args=(job,), daemon=True).start()
            return self._send(201, {"job": job_id, "id": job_id, "ignored_fields": ignored, "status": "pending"})
        if parts[:3] == ["api", "v2", "jobs"] and len(parts) == 5 and parts[4] == "cancel":
            job = JOBS.get(int(parts[3]))
            if not job:
                return self._send(404, {"detail": "Not found."})
            job["cancel"] = True
            return self._send(202, {})
        return self._send(404, {"detail": "Not found."})


def main() -> None:
    port = int(os.environ.get("ZS_AWX_PORT", "8443"))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/etc/zs-tls/api.crt", "/etc/zs-tls/api.key")
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
