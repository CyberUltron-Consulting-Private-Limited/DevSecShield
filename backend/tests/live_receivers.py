"""Local receivers for the integration connectors, run in-process by the tests: no Docker, nothing leaves this machine.

``ReceiverLab`` starts, on threads, the destinations the product delivers to:

* signed webhook and OSCAL push (HTTPS): the signature is checked with the product's documented receiver snippet
  (``webhook.VERIFY_SNIPPET``, the code a customer copies from Settings > Integrations), not with product code;
* Splunk HTTP Event Collector (HTTPS): ``POST /services/collector/event``, ``Authorization: Splunk <token>``, stacked
  JSON events, Splunk's status bodies (``{"text": ..., "code": ...}``);
* syslog over UDP, TCP and TLS: TCP and TLS read octet-counted frames (RFC 6587 3.4.1 / RFC 5425 4.3), UDP one message
  per datagram (RFC 5426); every message is parsed with ``RFC5424`` (the section 6 ABNF as a regular expression);
* ServiceNow Table API (HTTPS, basic auth or OAuth client credentials): ``GET/POST /api/now/table/<table>``,
  ``PATCH /api/now/table/<table>/<sys_id>``, ``POST /oauth_token.do``;
* Jira Cloud REST v3 (HTTPS, basic auth with an API token): ``POST /rest/api/3/issue``,
  ``GET/POST /rest/api/3/issue/<key>/transitions``.

All servers listen on one NON-loopback address of this host (``local_address``): the product's SSRF guard refuses
loopback whatever the operator allows, so the tests go through the real guard with the address listed in
``INTEGRATION_ALLOWED_PRIVATE``, exactly as an operator opens an on-premises SIEM. Traffic to a local address stays
on this machine (the kernel delivers it locally). TLS uses a throwaway CA (``integrations_helpers.make_pki``): the
product is told to trust it the documented way (``ca_pem`` on the integration, or ``CBOM_EXTRA_CA_FILE``).

Faults are scripted per receiver: ``lab.fail(name, 503, 503)`` answers the next two requests with 503,
``lab.fail(name, ("hang", 3.0))`` holds the next request for three seconds before answering, ``("lost", 201)`` does
the work and then drops the connection without an answer (a lost response). Everything received is recorded in
``lab.records`` (method, path, headers, raw body, parsed fields); secrets are generated per lab and never logged.
"""
from __future__ import annotations

import base64
import fcntl
import http.server
import ipaddress
import json
import re
import secrets
import socket
import socketserver
import ssl
import struct
import threading
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from integrations_helpers import make_pki, server_context

# RFC 5424 section 6: SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]
#   HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
#   PRI = "<" PRIVAL ">" (0-191, no leading zeros), VERSION = NONZERO-DIGIT 0*2DIGIT
#   TIMESTAMP = NILVALUE / FULL-DATE "T" FULL-TIME (TIME-SECFRAC at most 6 digits; "Z" or an offset)
#   HOSTNAME 1*255 PRINTUSASCII, APP-NAME 1*48, PROCID 1*128, MSGID 1*32 (or "-"); PRINTUSASCII = %d33-126
RFC5424 = re.compile(
    rb"^<(?P<pri>0|[1-9][0-9]{0,2})>(?P<version>[1-9][0-9]{0,2}) "
    rb"(?P<timestamp>-|\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60)"
    rb"(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)) "
    rb"(?P<hostname>[\x21-\x7e]{1,255}) (?P<app>[\x21-\x7e]{1,48}) (?P<procid>[\x21-\x7e]{1,128}) "
    rb"(?P<msgid>[\x21-\x7e]{1,32}) "
    rb"(?P<sd>-|(?:\[[^\]]*\])+)"
    rb"(?: (?P<msg>.*))?$", re.S)


def parse_syslog(message: bytes) -> dict[str, Any]:
    """The RFC 5424 fields of one message, or ``{"valid": False}``."""
    m = RFC5424.match(message)
    if not m or int(m.group("pri")) > 191:
        return {"valid": False, "head": message[:120].decode("latin1")}
    msg = m.group("msg") or b""
    out: dict[str, Any] = {"valid": True, **{k: m.group(k).decode("ascii") for k in
                                             ("pri", "version", "timestamp", "hostname", "app", "procid", "msgid",
                                              "sd")},
                           "msg": msg.decode("utf-8", "replace"), "bytes": len(message)}
    text = out["msg"]
    if text.startswith("CEF:0|"):
        out["format"] = "cef"
        hit = re.search(r"(?:^| )externalId=([^ ]+)", text)
        out["event_id"] = hit.group(1) if hit else None
    elif text.startswith("{"):
        out["format"] = "json"
        try:
            out["event"] = json.loads(text)
            out["event_id"] = out["event"].get("id")
        except ValueError:
            out["event"] = None
    return out


def _interface_addresses() -> list[str]:
    """IPv4 addresses of this host's interfaces (SIOCGIFADDR), without any lookup or packet."""
    found: list[str] = []
    for _index, name in socket.if_nameindex():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                packed = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))
            except OSError:
                continue
        found.append(socket.inet_ntoa(packed[20:24]))
    return found


def local_address() -> str | None:
    """A non-loopback address of this host that the SSRF guard does not refuse outright: RFC 1918 first (it needs
    INTEGRATION_ALLOWED_PRIVATE, like an on-premises receiver), then any other usable one. None when there is none."""
    from backend.utilities.integrations.outbound import _never

    usable = []
    for text in _interface_addresses():
        if _never(text):
            continue
        try:
            with socket.socket() as probe:  # bindable here (not just configured on a down interface)
                probe.bind((text, 0))
        except OSError:
            continue
        usable.append(text)
    rfc1918 = [a for a in usable if any(ipaddress.ip_address(a) in ipaddress.ip_network(n)
                                        for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))]
    return (rfc1918 or usable or [None])[0]


class _Tcp(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Udp(socketserver.UDPServer):
    """One thread reads every datagram (a thread per datagram drops a burst), with the largest receive buffer the
    host allows: like rsyslog's imudp, the receiver must keep up with a dispatcher batch of 200 messages."""
    allow_reuse_address = True

    def server_bind(self) -> None:
        for option in (getattr(socket, "SO_RCVBUFFORCE", None), socket.SO_RCVBUF):
            if option is None:
                continue
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, option, 8 * 1024 * 1024)
                break
            except OSError:
                continue
        super().server_bind()


class _Https(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, lab: "ReceiverLab", name: str, address: tuple[str, int]):
        super().__init__(address, _Handler)
        self.lab, self.name = lab, name
        self.socket = server_context(lab.pki).wrap_socket(self.socket, server_side=True)

    def handle_error(self, request, client_address) -> None:  # a client that hung up (timeouts): quiet
        pass


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Https

    def log_message(self, *_a) -> None:
        pass

    def _go(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        lab, name = self.server.lab, self.server.name
        rec: dict[str, Any] = {"receiver": name, "t": time.time(), "method": self.command, "path": self.path,
                               "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body,
                               "event_id": self.headers.get("X-ZS-Event-Id")}
        fault = lab._next_fault(name)
        if isinstance(fault, tuple) and fault[0] == "hang":
            rec["fault"] = f"hang {fault[1]} s"
            lab._record(rec)
            lab._release.wait(fault[1])
            self.close_connection = True
            return
        if isinstance(fault, int):
            rec.update(status=fault, fault="injected")
            lab._record(rec)
            payload = {"text": "Server is busy", "code": 9} if name == "hec" and fault == 503 else {"error": "injected"}
            if name == "hec" and fault == 400:
                payload = {"text": "Incorrect index", "code": 7, "invalid-event-number": 0}
            return self._reply(fault, payload, {"Retry-After": "120"} if fault in (429, 503) else None)
        status, payload, headers = getattr(lab, f"_on_{name}")(self.command, self.path, rec["headers"], body, rec)
        rec["status"] = status
        lab._record(rec)
        if isinstance(fault, tuple) and fault[0] == "lost":  # the work is done, the answer never arrives
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        self._reply(status, payload, headers)

    def _reply(self, status: int, payload: Any, headers: dict[str, str] | None = None) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = _go


class ReceiverLab:
    """The receivers, started on ``local_address()``. Use as a context manager (``stop`` closes every socket)."""

    def __init__(self, workdir: Path, address: str):
        self.ip = address
        self.pki = make_pki(workdir / "pki", [address])
        self.ca_pem = self.pki["ca_pem"]
        # per-lab secrets (never printed, never written to a file)
        self.hook_secret = secrets.token_urlsafe(24)
        self.hec_token = str(uuid.uuid4())
        self.sn_user, self.sn_pass = "zs-integration", secrets.token_urlsafe(18)
        self.sn_client_id, self.sn_client_secret = "zs-cbom-client", secrets.token_urlsafe(18)
        self.jira_email, self.jira_token = "secops@bank.example", secrets.token_urlsafe(18)
        self.records: list[dict[str, Any]] = []
        self.incidents: dict[str, dict[str, Any]] = {}
        self.issues: dict[str, dict[str, Any]] = {}
        self.oauth_tokens: set[str] = set()
        self._faults: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        self._release = threading.Event()
        self._servers: list[socketserver.BaseServer] = []
        self.ports: dict[str, int] = {}
        verify_ns: dict[str, Any] = {}
        from backend.utilities.integrations.webhook import VERIFY_SNIPPET

        exec(compile(VERIFY_SNIPPET, "webhook.VERIFY_SNIPPET", "exec"), verify_ns)  # the documented receiver check
        self.verify = verify_ns["verify"]

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> "ReceiverLab":
        for name in ("webhook", "hec", "servicenow", "jira"):
            self._serve(name, _Https(self, name, (self.ip, 0)))
        lab = self

        class Stream(socketserver.BaseRequestHandler):
            tls = False

            def handle(self) -> None:
                lab._stream(self.request, "syslog-tls" if self.tls else "syslog-tcp", self.tls)

        class TlsStream(Stream):
            tls = True

        class Datagram(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                data = self.request[0]
                lab._record({"receiver": "syslog-udp", "t": time.time(), "connection": None, "raw": data,
                             **parse_syslog(data)})

        self._serve("syslog-tcp", _Tcp((self.ip, 0), Stream))
        self._serve("syslog-tls", _Tcp((self.ip, 0), TlsStream))
        self._serve("syslog-udp", _Udp((self.ip, 0), Datagram))
        return self

    def _serve(self, name: str, server: socketserver.BaseServer) -> None:
        self._servers.append(server)
        self.ports[name] = server.server_address[1]
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()

    def stop_receiver(self, name: str) -> None:
        """Close one receiver's listening socket (the port then refuses connections)."""
        port = self.ports[name]
        for server in list(self._servers):
            if server.server_address[1] == port:
                server.shutdown()
                server.server_close()
                self._servers.remove(server)

    def stop(self) -> None:
        self._release.set()
        for server in self._servers:
            server.shutdown()
            server.server_close()
        self._servers.clear()

    def __enter__(self) -> "ReceiverLab":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    # ------------------------------------------------------------------ helpers for tests
    def url(self, name: str, path: str = "") -> str:
        return f"https://{self.ip}:{self.ports[name]}{path}"

    def fail(self, name: str, *actions: Any) -> None:
        with self._lock:
            self._faults[name].extend(actions)

    def got(self, receiver: str, **match: Any) -> list[dict[str, Any]]:
        with self._lock:
            rows = [r for r in self.records if r["receiver"] == receiver]
        return [r for r in rows if all(r.get(k) == v for k, v in match.items())]

    def wait_for(self, receiver: str, count: int, timeout: float = 5.0, **match: Any) -> list[dict[str, Any]]:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            rows = self.got(receiver, **match)
            if len(rows) >= count:
                return rows
            time.sleep(0.05)
        return self.got(receiver, **match)

    def secret_values(self) -> list[str]:
        return [self.hook_secret, self.hec_token, self.sn_pass, self.sn_client_secret, self.jira_token]

    def _next_fault(self, name: str) -> Any:
        with self._lock:
            return self._faults[name].popleft() if self._faults[name] else None

    def _record(self, rec: dict[str, Any]) -> None:
        with self._lock:
            self.records.append(rec)

    # ------------------------------------------------------------------ syslog over TCP / TLS
    def _stream(self, sock: socket.socket, name: str, tls: bool) -> None:
        conn_id = uuid.uuid4().hex[:8]
        try:
            if tls:
                sock = server_context(self.pki).wrap_socket(sock, server_side=True)
            sock.settimeout(10)
            reader = sock.makefile("rb")
            frames = 0
            while True:
                digits = b""
                while True:
                    ch = reader.read(1)
                    if not ch:
                        self._record({"receiver": name, "t": time.time(), "connection": conn_id, "closed": True,
                                      "frames": frames})
                        return
                    if ch == b" ":
                        break
                    digits += ch
                    if len(digits) > 7:
                        break
                if not digits.isdigit() or digits.startswith(b"0"):
                    self._record({"receiver": name, "t": time.time(), "connection": conn_id,
                                  "framing_error": digits[:20].decode("latin1")})
                    return
                message = reader.read(int(digits))
                frames += 1
                self._record({"receiver": name, "t": time.time(), "connection": conn_id, "msg_len": int(digits),
                              "raw": message, **parse_syslog(message)})
        except (OSError, ssl.SSLError) as exc:
            self._record({"receiver": name, "t": time.time(), "connection": conn_id, "error": type(exc).__name__})
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------ webhook / OSCAL push
    def _on_webhook(self, method: str, path: str, headers: dict[str, str], body: bytes, rec: dict) -> tuple:
        stamp, sig = headers.get("x-zs-timestamp", ""), headers.get("x-zs-signature", "")
        rec["verified"] = bool(self.verify(self.hook_secret.encode(), body, stamp, sig))
        rec["event_id"], rec["event_type"] = headers.get("x-zs-event-id"), headers.get("x-zs-event-type")
        try:
            rec["json"] = json.loads(body)
        except ValueError:
            rec["json"] = None
        if not rec["verified"]:
            return 401, {"ok": False}, None
        return 200, {"ok": True}, None

    # ------------------------------------------------------------------ Splunk HEC
    def _on_hec(self, method: str, path: str, headers: dict[str, str], body: bytes, rec: dict) -> tuple:
        if method != "POST" or not urlsplit(path).path.startswith("/services/collector"):
            return 404, {"text": "The requested URL was not found on this server.", "code": 404}, None
        auth = headers.get("authorization", "")
        rec["auth_ok"] = secrets.compare_digest(auth, f"Splunk {self.hec_token}")
        if not auth:
            return 401, {"text": "Token is required", "code": 2}, None
        if not rec["auth_ok"]:
            return 403, {"text": "Invalid token", "code": 4}, None
        events, text, pos, decoder = [], body.decode("utf-8"), 0, json.JSONDecoder()
        try:
            while pos < len(text):
                while pos < len(text) and text[pos].isspace():
                    pos += 1
                if pos >= len(text):
                    break
                obj, pos = decoder.raw_decode(text, pos)
                if not isinstance(obj, dict) or "event" not in obj:
                    return 400, {"text": "Event field is required", "code": 12, "invalid-event-number": len(events)}, None
                events.append(obj)
        except ValueError:
            return 400, {"text": "Invalid data format", "code": 6, "invalid-event-number": len(events)}, None
        if not events:
            return 400, {"text": "No data", "code": 5}, None
        rec["events"] = events
        return 200, {"text": "Success", "code": 0}, None

    # ------------------------------------------------------------------ ServiceNow Table API
    def _sn_auth(self, headers: dict[str, str]) -> bool:
        auth = headers.get("authorization", "")
        basic = "Basic " + base64.b64encode(f"{self.sn_user}:{self.sn_pass}".encode()).decode()
        if secrets.compare_digest(auth, basic):
            return True
        return auth.startswith("Bearer ") and auth[7:] in self.oauth_tokens

    def _on_servicenow(self, method: str, path: str, headers: dict[str, str], body: bytes, rec: dict) -> tuple:
        parts = urlsplit(path)
        if parts.path == "/oauth_token.do" and method == "POST":
            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            ok = (form.get("grant_type") == "client_credentials" and form.get("client_id") == self.sn_client_id
                  and secrets.compare_digest(form.get("client_secret", ""), self.sn_client_secret))
            if not ok:
                return 401, {"error": "access_denied", "error_description": "access_denied"}, None
            token = secrets.token_urlsafe(16)
            self.oauth_tokens.add(token)
            return 200, {"access_token": token, "token_type": "Bearer", "expires_in": 1799}, None
        if not self._sn_auth(headers):
            return 401, {"error": {"message": "User Not Authenticated", "detail": "Required to provide Auth information"},
                         "status": "failure"}, None
        m = re.fullmatch(r"/api/now/table/([a-z0-9_]+)(?:/([0-9a-f]{32}))?", parts.path)
        if not m:
            return 400, {"error": {"message": "Invalid table"}}, None
        table, sys_id = m.group(1), m.group(2)
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        rec["table"], rec["query"] = table, q
        with self._lock:
            if method == "GET" and sys_id is None:
                rows = [r for r in self.incidents.values() if r["_table"] == table]
                for clause in filter(None, (q.get("sysparm_query") or "").split("^")):
                    field, _, value = clause.partition("=")
                    rows = [r for r in rows if str(r.get(field, "")).lower() == value.lower()]
                limit = int(q.get("sysparm_limit") or 10000)
                fields = [f for f in (q.get("sysparm_fields") or "").split(",") if f]
                result = [{f: r.get(f, "") for f in fields} if fields else self._public(r) for r in rows[:limit]]
                return 200, {"result": result}, None
            if method == "POST" and sys_id is None:
                data = json.loads(body or b"{}")
                n = len(self.incidents) + 1
                row = {**{k: str(v) for k, v in data.items()}, "_table": table, "sys_id": uuid.uuid4().hex,
                       "number": f"INC{n:07d}", "active": "true", "state": "1"}
                self.incidents[row["sys_id"]] = row
                rec["created"] = row["number"]
                return 201, {"result": self._public(row)}, None
            if method == "PATCH" and sys_id is not None:
                row = self.incidents.get(sys_id)
                if row is None or row["_table"] != table:
                    return 404, {"error": {"message": "No Record found"}, "status": "failure"}, None
                data = json.loads(body or b"{}")
                row.update({k: str(v) for k, v in data.items()})
                if row.get("state") in ("6", "7"):  # Resolved / Closed: no longer active
                    row["active"] = "false"
                rec["updated"] = row["number"]
                return 200, {"result": self._public(row)}, None
        return 405, {"error": {"message": "Method not supported"}}, None

    @staticmethod
    def _public(row: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in row.items() if not k.startswith("_")}

    # ------------------------------------------------------------------ Jira REST v3
    def _on_jira(self, method: str, path: str, headers: dict[str, str], body: bytes, rec: dict) -> tuple:
        basic = "Basic " + base64.b64encode(f"{self.jira_email}:{self.jira_token}".encode()).decode()
        if not secrets.compare_digest(headers.get("authorization", ""), basic):
            return 401, {"errorMessages": ["You are not authenticated."]}, None
        parts = urlsplit(path)
        with self._lock:
            if method == "POST" and parts.path == "/rest/api/3/issue":
                data = json.loads(body or b"{}")
                fields = data.get("fields") or {}
                if not (fields.get("project") or {}).get("id") or not fields.get("summary"):
                    return 400, {"errors": {"summary": "You must specify a summary of the issue."}}, None
                n = len(self.issues) + 1
                key = f"SEC-{n}"
                self.issues[key] = {"id": str(10000 + n), "key": key, "fields": fields, "status": "To Do"}
                rec["created"] = key
                return 201, {"id": str(10000 + n), "key": key, "self": f"{self.url('jira')}/rest/api/3/issue/{n}"}, None
            m = re.fullmatch(r"/rest/api/3/issue/([A-Z][A-Z0-9]*-\d+)/transitions", parts.path)
            if m:
                issue = self.issues.get(m.group(1))
                if issue is None:
                    return 404, {"errorMessages": ["Issue does not exist or you do not have permission to see it."]}, None
                if method == "GET":
                    return 200, {"transitions": [
                        {"id": "21", "name": "In Progress", "to": {"statusCategory": {"key": "indeterminate"}}},
                        {"id": "31", "name": "Done", "to": {"statusCategory": {"key": "done"}}}]}, None
                if method == "POST":
                    tid = ((json.loads(body or b"{}").get("transition") or {}).get("id"))
                    issue["status"] = {"21": "In Progress", "31": "Done"}.get(str(tid), issue["status"])
                    rec["transitioned"] = (m.group(1), issue["status"])
                    return 204, None, None
            if method == "GET" and parts.path == "/rest/api/3/project/search":
                return 200, {"values": [{"id": "10001", "key": "SEC", "name": "Security"}]}, None
        return 404, {"errorMessages": ["Not found"]}, None
