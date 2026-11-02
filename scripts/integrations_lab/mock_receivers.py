"""Mock receivers for the WP11 integration proof: standard library only, air-gap safe (python:3.12-slim, no network).

Run on a private Docker network (see ``run_lab.sh``); every receiver records what it got to ``$LAB_OUT/received.jsonl``
(never a credential: only whether authentication / the signature was valid).

* syslog: TLS on 6514 and TCP on 1514 (octet counting, RFC 5425 / RFC 6587), UDP on 1514 (one message per datagram);
* Splunk HEC on 8088 (HTTPS): ``POST /services/collector/event`` with ``Authorization: Splunk <token>``, stacked JSON
  events; the first ``LAB_HEC_FAIL_FIRST`` requests get ``503 {"text":"Server is busy","code":9}``;
* webhook on 8443 (HTTPS): verifies X-ZS-Signature (HMAC-SHA256 of "timestamp.body", 5 minute window); ``/oscal``
  also stores each pushed document as ``oscal-<event id>.json`` for validation on the host;
* ServiceNow Table API on 9443 (HTTPS, basic auth): ``GET/POST /api/now/table/incident``,
  ``PATCH /api/now/table/incident/<sys_id>`` (``correlation_id=..^active=true`` queries), and a paged
  ``GET /api/now/table/cmdb_ci_server`` answering ``sysparm_display_value=all``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import os
import socketserver
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit

OUT = os.environ.get("LAB_OUT", "/out")
CERT, KEY = os.environ["LAB_CERT"], os.environ["LAB_KEY"]
HOOK_SECRET = os.environ["LAB_HOOK_SECRET"].encode()
HEC_TOKEN = os.environ["LAB_HEC_TOKEN"]
SN_AUTH = "Basic " + base64.b64encode(f"{os.environ['LAB_SN_USER']}:{os.environ['LAB_SN_PASS']}".encode()).decode()
HEC_FAIL = {"left": int(os.environ.get("LAB_HEC_FAIL_FIRST", "0"))}
_lock = threading.Lock()
INCIDENTS: dict[str, dict] = {}
CIS = [
    {"sys_id": "1" * 32, "name": "app-01", "fqdn": "app-01.bank.lab", "ip_address": "10.20.0.1",
     "sys_class_name": ("cmdb_ci_linux_server", "Linux Server"), "owned_by": ("6816f79c", "Payments Team"),
     "u_application": "Payments", "used_for": "Production"},
    {"sys_id": "2" * 32, "name": "app-07", "fqdn": "app-07.bank.lab", "ip_address": "10.20.0.7",
     "sys_class_name": ("cmdb_ci_linux_server", "Linux Server"), "owned_by": ("6816f79d", "Cards Team"),
     "u_application": "Cards", "used_for": "Staging"},
    {"sys_id": "3" * 32, "name": "win-01", "fqdn": "win-01.bank.lab", "ip_address": "10.20.0.9",
     "sys_class_name": ("cmdb_ci_win_server", "Windows Server"), "owned_by": ("6816f79e", "Cards Team"),
     "u_application": "Cards", "used_for": "Staging"},
]


def record(receiver: str, **fields) -> None:
    line = json.dumps({"t": round(time.time(), 3), "receiver": receiver, **fields}, sort_keys=True)
    with _lock, open(os.path.join(OUT, "received.jsonl"), "a") as fh:
        fh.write(line + "\n")


def tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    return ctx


# ----------------------------------------------------------------------------- syslog
def syslog_fields(message: bytes) -> dict:
    text = message.decode("utf-8", "replace")
    head, _, rest = text.partition(" ")
    parts = text.split(" ", 7)
    out = {"bytes": len(message), "pri": head.split(">")[0].lstrip("<") if head.startswith("<") else None,
           "version": head.split(">")[1] if ">" in head else None, "msgid": parts[5] if len(parts) > 5 else None,
           "head": text[:160]}
    body = parts[7] if len(parts) > 7 else ""
    if body.startswith("CEF:0|"):
        out["format"] = "cef"
        out["cef_class"] = body.split("|")[4] if body.count("|") >= 7 else None
        marker = "externalId="
        out["event_id"] = body.split(marker, 1)[1].split(" ", 1)[0] if marker in body else None
    elif body.startswith("{"):
        out["format"] = "json"
        try:
            out["event_id"] = json.loads(body).get("id")
        except ValueError:
            out["event_id"] = None
    return out


class StreamSyslog(socketserver.BaseRequestHandler):
    tls = False

    def handle(self) -> None:
        sock = self.request
        if self.tls:
            sock = tls_context().wrap_socket(sock, server_side=True)
        sock.settimeout(15)
        reader = sock.makefile("rb")
        count = 0
        while True:
            digits = b""
            while True:
                ch = reader.read(1)
                if not ch:
                    record("syslog-tls" if self.tls else "syslog-tcp", connection_closed=True, frames=count)
                    return
                if ch == b" ":
                    break
                digits += ch
            if not digits.isdigit():
                record("syslog-tls" if self.tls else "syslog-tcp", error="not octet-counted", got=digits[:20].decode("latin1"))
                return
            message = reader.read(int(digits))
            count += 1
            record("syslog-tls" if self.tls else "syslog-tcp", framing="octet-counting", msg_len=int(digits),
                   **syslog_fields(message))


class TlsSyslog(StreamSyslog):
    tls = True


class UdpSyslog(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        record("syslog-udp", **syslog_fields(data))


# ----------------------------------------------------------------------------- HTTPS
class Base(http.server.BaseHTTPRequestHandler):
    receiver = "http"

    def log_message(self, *_a) -> None:
        pass

    def reply(self, status: int, payload: dict | list | None = None, headers: dict | None = None) -> None:
        body = json.dumps(payload if payload is not None else {}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""


class Hec(Base):
    def do_POST(self) -> None:
        raw = self.body()
        if not self.path.startswith("/services/collector"):
            return self.reply(404, {"text": "Not found", "code": 404})
        if self.headers.get("Authorization") != f"Splunk {HEC_TOKEN}":
            record("splunk-hec", status=403, auth_ok=False)
            return self.reply(403, {"text": "Invalid token", "code": 4})
        with _lock:
            fail = HEC_FAIL["left"] > 0
            if fail:
                HEC_FAIL["left"] -= 1
        if fail:
            record("splunk-hec", status=503, auth_ok=True, note="injected busy")
            return self.reply(503, {"text": "Server is busy", "code": 9}, {"Retry-After": "1"})
        decoder, text, pos, events = json.JSONDecoder(), raw.decode(), 0, []
        while pos < len(text):
            while pos < len(text) and text[pos].isspace():
                pos += 1
            if pos >= len(text):
                break
            obj, pos = decoder.raw_decode(text, pos)
            events.append(obj)
        for e in events:
            record("splunk-hec", status=200, auth_ok=True, sourcetype=e.get("sourcetype"), index=e.get("index"),
                   time=e.get("time"), event_id=(e.get("event") or {}).get("id"), type=(e.get("event") or {}).get("type"))
        return self.reply(200, {"text": "Success", "code": 0})


class Webhook(Base):
    def do_POST(self) -> None:
        raw = self.body()
        stamp, sig = self.headers.get("X-ZS-Timestamp", ""), self.headers.get("X-ZS-Signature", "")
        fresh = stamp.isdigit() and abs(time.time() - int(stamp)) <= 300
        expected = hmac.new(HOOK_SECRET, stamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
        verified = fresh and any(hmac.compare_digest(expected, p.strip()[3:]) for p in sig.split(",")
                                 if p.strip().startswith("v1="))
        event_id = self.headers.get("X-ZS-Event-Id")
        fields = {"path": self.path, "verified": verified, "fresh": fresh, "event_id": event_id,
                  "event_type": self.headers.get("X-ZS-Event-Type"), "bytes": len(raw)}
        if self.path == "/oscal" and verified:
            name = f"oscal-{event_id}.json"
            with open(os.path.join(OUT, name), "wb") as fh:
                fh.write(raw)
            fields["stored"] = name
        else:
            try:
                fields["body_id"] = json.loads(raw).get("id")
            except ValueError:
                pass
        record("webhook", **fields)
        return self.reply(200 if verified else 401, {"ok": verified})


def _dv(value) -> dict:
    if isinstance(value, tuple):
        return {"value": value[0], "display_value": value[1]}
    return {"value": value, "display_value": value}


class ServiceNow(Base):
    def _auth(self) -> bool:
        ok = self.headers.get("Authorization") == SN_AUTH
        if not ok:
            record("servicenow", method=self.command, path=urlsplit(self.path).path, status=401, auth_ok=False)
            self.reply(401, {"error": {"message": "User Not Authenticated"}})
        return ok

    def do_GET(self) -> None:
        if not self._auth():
            return
        parts = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        if parts.path == "/api/now/table/cmdb_ci_server":
            offset, limit = int(q.get("sysparm_offset", 0)), int(q.get("sysparm_limit", 10))
            fields = (q.get("sysparm_fields") or "").split(",")
            page = [{f: _dv(ci.get(f, "")) for f in fields} for ci in CIS[offset:offset + limit]]
            record("servicenow", method="GET", path=parts.path, status=200, display_value=q.get("sysparm_display_value"),
                   offset=offset, rows=len(page))
            return self.reply(200, {"result": page})
        if parts.path == "/api/now/table/incident":
            query = q.get("sysparm_query", "")
            if query:
                cid = query.split("^")[0].split("=", 1)[1]
                hits = [r for r in INCIDENTS.values() if r["correlation_id"] == cid and r["active"]]
                record("servicenow", method="GET", path=parts.path, status=200, lookup=cid, hits=len(hits))
                return self.reply(200, {"result": [{"sys_id": r["sys_id"], "number": r["number"]} for r in hits[:1]]})
            record("servicenow", method="GET", path=parts.path, status=200, note="read one (test)")
            return self.reply(200, {"result": [{"sys_id": "0" * 32}]})
        return self.reply(404, {"error": {"message": "No such table"}})

    def do_POST(self) -> None:
        if not self._auth():
            return
        body = json.loads(self.body() or b"{}")
        with _lock:
            sys_id = f"{len(INCIDENTS) + 1:032x}"
            rec = {**body, "sys_id": sys_id, "number": f"INC{len(INCIDENTS) + 1:07d}", "active": True, "state": "1"}
            INCIDENTS[sys_id] = rec
            self._dump()
        record("servicenow", method="POST", path=urlsplit(self.path).path, status=201, number=rec["number"],
               correlation_id=rec.get("correlation_id"), short_description=rec.get("short_description"),
               impact=rec.get("impact"), urgency=rec.get("urgency"))
        return self.reply(201, {"result": rec})

    def do_PATCH(self) -> None:
        if not self._auth():
            return
        sys_id = urlsplit(self.path).path.rsplit("/", 1)[1]
        body = json.loads(self.body() or b"{}")
        with _lock:
            rec = INCIDENTS.get(sys_id)
            if rec is None:
                return self.reply(404, {"error": {"message": "No Record found"}})
            rec.update(body)
            if str(body.get("state")) in ("6", "7"):
                rec["active"] = False
            self._dump()
        record("servicenow", method="PATCH", path=urlsplit(self.path).path, status=200, number=rec["number"],
               state=rec.get("state"), close_code=rec.get("close_code"), active=rec["active"])
        return self.reply(200, {"result": rec})

    @staticmethod
    def _dump() -> None:
        with open(os.path.join(OUT, "servicenow_incidents.json"), "w") as fh:
            json.dump(list(INCIDENTS.values()), fh, indent=1, sort_keys=True)


def https(port: int, handler) -> None:
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
    srv.socket = tls_context().wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    for port, handler in ((6514, TlsSyslog), (1514, StreamSyslog)):
        srv = socketserver.ThreadingTCPServer(("0.0.0.0", port), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    udp = socketserver.ThreadingUDPServer(("0.0.0.0", 1514), UdpSyslog)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    https(8088, Hec)
    https(8443, Webhook)
    https(9443, ServiceNow)
    record("lab", started=True, ports=[6514, 1514, 8088, 8443, 9443])
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
