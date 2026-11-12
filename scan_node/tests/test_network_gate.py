"""The central network gate (netutil): every collector connection goes through it, and it does what it says.

The AST check fails when a collector module
  * opens a socket, resolves a name for connecting, or builds an HTTP client directly (RAW), or
  * calls / hands over a connecting function (CONNECTORS: drivers, tlsprobe handshakes) in a function that does not
    itself pass the gate (calls netutil.connect / checked_ip / resolve_checked / http_client, or a local function
    that does).
New collectors (WP6-8) are checked the moment their module lands in zs_scan_node/collectors/.
"""
from __future__ import annotations

import ast
import socket
import ssl
import threading
from pathlib import Path

import pytest

from zs_scan_node import netutil
from zs_scan_node.netutil import Blocked, NeverScan

COLLECTORS = Path(__file__).resolve().parents[1] / "zs_scan_node" / "collectors"

RAW = {"socket.socket", "socket.create_connection", "socket.getaddrinfo", "socket.gethostbyname",
       "socket.gethostbyname_ex", "T.connect", "tlsprobe.connect", "httpx.Client", "httpx.AsyncClient", "httpx.get",
       "httpx.post", "httpx.put", "httpx.delete", "httpx.request", "httpx.stream", "urllib.request.urlopen",
       "http.client.HTTPConnection", "http.client.HTTPSConnection", "resolve", "netutil.resolve"}
RAW_PREFIXES = ("requests.", "urllib3.", "aiohttp.")
CONNECTORS = {"psycopg.connect", "redis.Redis", "pymongo.MongoClient", "winrm.Session", "paramiko.Transport",
              "paramiko.SSHClient", "_strict_mysql", "T.probe", "T.s_client", "T.python_handshake", "T.open_tls_socket",
              "T.ssh_kexinit", "T.ssh_host_key", "S.read_server", "sshprobe.read_server"}
GATES = {"netutil.connect", "netutil.checked_ip", "netutil.resolve_checked", "netutil.http_client", "checked_ip",
         "resolve_checked", "http_client", "netutil.udp_connect"}
# Reviewed exceptions: (module, function, call) with the reason.
ALLOWED = {
    ("network.py", "_sni_for", "netutil.resolve"): "matches SNI names against the address being scanned; no connection",
}


def _dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _calls(fn: ast.AST) -> set[str]:
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name:
                out.add(name)
    return out


def _refs(fn: ast.AST) -> set[str]:
    """Every dotted name used in the function (calls and function values handed to another function)."""
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, (ast.Attribute, ast.Name)):
            name = _dotted(node)
            if name:
                out.add(name)
    return out


def check_sources(sources: dict[str, str]) -> list[str]:
    trees = {name: ast.parse(text) for name, text in sources.items()}
    functions = [(name, node) for name, tree in trees.items() for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    gates = set(GATES)
    changed = True
    while changed:  # local wrappers that pass the gate are gates too (self._gate, api.check_scope, _tcp ...)
        changed = False
        for _module, fn in functions:
            if fn.name not in gates and any(c in gates or c.rsplit(".", 1)[-1] in gates for c in _calls(fn)):
                gates.add(fn.name)
                changed = True
    problems = []
    for module, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func) or ""
            if name in RAW or name.startswith(RAW_PREFIXES):
                owner = next((fn.name for m, fn in functions if m == module and node in list(ast.walk(fn))), "<module>")
                if (module, owner, name) not in ALLOWED:
                    problems.append(f"{module}:{node.lineno} {owner}() calls {name} directly; use the netutil gate")
    for module, fn in functions:
        used = sorted(r for r in _refs(fn) if r in CONNECTORS)
        if used and not any(c in gates or c.rsplit(".", 1)[-1] in gates for c in _calls(fn)):
            problems.append(f"{module}:{fn.lineno} {fn.name}() uses {', '.join(used)} without passing the network gate")
    return problems


def test_every_collector_connection_passes_the_gate():
    sources = {p.name: p.read_text(encoding="utf-8") for p in sorted(COLLECTORS.glob("*.py"))}
    assert len(sources) >= 6
    assert check_sources(sources) == []


@pytest.mark.parametrize("src, needle", [
    ("import socket\ndef grab(ip):\n    return socket.create_connection((ip, 22))\n", "socket.create_connection"),
    ("import httpx\ndef api(url):\n    return httpx.Client(base_url=url)\n", "httpx.Client"),
    ("import requests\ndef api(url):\n    return requests.get(url)\n", "requests.get"),
    ("import psycopg\ndef pg(ip):\n    return psycopg.connect(hostaddr=ip)\n", "psycopg.connect"),
    ("from zs_scan_node import tlsprobe as T\ndef run(ip):\n    return T.s_client(ip, 443, 'tls', None)\n", "T.s_client"),
    ("from zs_scan_node import tlsprobe as T\ndef run(self, ip):\n    return self.go(T.probe, ip)\n", "T.probe"),
])
def test_the_check_catches_an_ungated_connection(src, needle):
    problems = check_sources({"new_collector.py": src})
    assert problems and needle in problems[0]


def test_the_check_accepts_gated_connections():
    src = ("import psycopg\nfrom zs_scan_node.netutil import checked_ip\n"
           "def pg(ctx, ip):\n    ip = checked_ip(ip, ctx.never_scan)\n    return psycopg.connect(hostaddr=ip)\n"
           "def _gate(self, ip):\n    return checked_ip(ip, self.never)\n"
           "def run(self, ip):\n    self._gate(ip)\n    return psycopg.connect(hostaddr=ip)\n")
    assert check_sources({"ok.py": src}) == []


# ----------------------------------------------------------------------------- the gate itself
def test_resolve_checked_applies_never_scan_to_names_and_addresses(monkeypatch):
    monkeypatch.setattr(netutil, "resolve", lambda name, timeout=5.0: ["10.0.0.5", "10.0.0.6"])
    never = NeverScan(["10.0.0.6/32", "blocked.corp"])
    assert netutil.resolve_checked("db.corp", never) == ["10.0.0.5"]  # connect only to the allowed address
    with pytest.raises(Blocked):
        netutil.resolve_checked("db.corp", never, every=True)  # a client that resolves again must not be used
    with pytest.raises(Blocked):
        netutil.resolve_checked("Blocked.Corp.", never)
    with pytest.raises(Blocked):
        netutil.resolve_checked("10.0.0.6", never)
    assert netutil.resolve_checked("[::1]", NeverScan()) == ["::1"]
    never.update(["10.0.0.0/24"])  # the list changed while the job ran
    with pytest.raises(Blocked):
        netutil.resolve_checked("db.corp", never)


def test_connect_rechecks_at_connect_time():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    never = NeverScan()
    netutil.connect("127.0.0.1", port, never, 2).close()
    never.update(["127.0.0.0/8"])
    with pytest.raises(Blocked):
        netutil.connect("127.0.0.1", port, never, 2)
    srv.close()


def _tls_server(tmp_path):
    """HTTPS server on 127.0.0.1 with a certificate for k8s.test only (no IP SAN)."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "k8s.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("k8s.test")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    (tmp_path / "c.pem").write_bytes(cert_pem)
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    seen = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Host"))
            body = b'{"gitVersion": "v1.31.0"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, cert_pem.decode(), seen


def test_http_client_is_pinned_to_the_checked_address_and_keeps_the_name(tmp_path, monkeypatch):
    httpd, ca_pem, seen = _tls_server(tmp_path)
    port = httpd.server_port
    lookups = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: lookups.append(a[0]) or
                        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", a[1] or 0))])
    try:
        client = netutil.http_client(f"https://k8s.test:{port}", "127.0.0.1", NeverScan(),
                                     verify=ssl.create_default_context(cadata=ca_pem), timeout=5.0)
        r = client.get("/version")
        assert r.status_code == 200 and r.json()["gitVersion"] == "v1.31.0"
        assert seen == [f"k8s.test:{port}"]  # Host header keeps the name; the certificate matched k8s.test via SNI
        assert "k8s.test" not in lookups  # the HTTP client never resolved the name itself
        client.close()
        # a wrong expected name fails certificate verification even though the address is the same
        bad = netutil.http_client(f"https://other.test:{port}", "127.0.0.1", NeverScan(),
                                  verify=ssl.create_default_context(cadata=ca_pem), timeout=5.0)
        import httpx

        with pytest.raises(httpx.ConnectError):
            bad.get("/version")
        bad.close()
        with pytest.raises(Blocked):
            netutil.http_client(f"https://k8s.test:{port}", "127.0.0.1", NeverScan(["127.0.0.1"]))
    finally:
        httpd.shutdown()


def test_kubernetes_api_connects_to_the_checked_address(tmp_path, monkeypatch):
    """check_scope() resolves once, applies never-scan and pins the client: DNS changing afterwards changes nothing."""
    import base64

    import yaml

    from zs_scan_node.collectors import kubernetes as K
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.scrub import Scrubber
    import time

    httpd, ca_pem, seen = _tls_server(tmp_path)
    port = httpd.server_port
    answers = {"k8s.test": ["127.0.0.1"]}
    monkeypatch.setattr(netutil, "resolve", lambda name, timeout=5.0: answers[name])
    kubeconfig = yaml.safe_dump({"clusters": [{"name": "c", "cluster": {
        "server": f"https://k8s.test:{port}", "certificate-authority-data": base64.b64encode(ca_pem.encode()).decode()}}],
        "users": [{"name": "u", "user": {"token": "tok-123456"}}],
        "contexts": [{"name": "x", "context": {"cluster": "c", "user": "u"}}], "current-context": "x"})
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="kubernetes", scrubber=Scrubber(),
                     never_scan=NeverScan(), deadline=time.monotonic() + 60)
    api = K.Api(ctx, {"api_url": f"https://k8s.test:{port}"}, {"kubeconfig": kubeconfig})
    try:
        assert api.check_scope() == "127.0.0.1"
        answers["k8s.test"] = ["10.255.255.1"]  # DNS rebinding after the check
        status, body = api.get("/version")
        assert status == 200 and body["gitVersion"] == "v1.31.0"
        ctx.never_scan.update(["127.0.0.1/32"])
        answers["k8s.test"] = ["127.0.0.1"]
        with pytest.raises(K._Skip):
            api.check_scope()
    finally:
        api.close()
        httpd.shutdown()
