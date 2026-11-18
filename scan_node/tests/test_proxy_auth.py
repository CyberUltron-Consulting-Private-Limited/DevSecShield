"""#199: the node reaches ZeroShield through a proxy that needs a login. The login is in a file
(``ZS_PROXY_AUTH_FILE``, ``user:password``), mounted read-only: never in the proxy URL, the environment, ``docker
inspect``, the shell history or a log line. #196/#198: through a TLS-inspecting proxy the node trusts the proxy's CA
with ``ZS_CA_FILE``.

A real HTTP CONNECT proxy on 127.0.0.1 that requires ``Proxy-Authorization: Basic``, in front of a real TLS server.
"""
from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import select
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from zs_scan_node import api as A

USER, PASSWORD = "svc-zs", "p@ss:word w/ spaces"


def _cert(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.zs.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    (tmp_path / "api.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "api.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
    return tmp_path / "api.pem", tmp_path / "api.key"


class _Api:
    """A TLS server answering every request 200 {"ok": true}."""

    def __init__(self, tmp_path):
        cert, key = _cert(tmp_path)
        self.ca = str(cert)
        self.sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.sctx.load_cert_chain(cert, key)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        try:
            tls = self.sctx.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:  # the whole request (head, then its Content-Length body): a close with
                chunk = tls.recv(65536)        # unread data is an RST, which can drop the response
                if not chunk:
                    break
                data += chunk
            head, _sep, rest = data.partition(b"\r\n\r\n")
            length = next((int(ln.split(b":", 1)[1]) for ln in head.split(b"\r\n")
                           if ln.lower().startswith(b"content-length:")), 0)
            while len(rest) < length:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                rest += chunk
            body = b'{"ok": true}'
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close"
                        b"\r\n\r\n%s" % (len(body), body))
            tls.close()
        except (ssl.SSLError, OSError):
            conn.close()

    def close(self):
        self.srv.close()


class _Proxy:
    """HTTP CONNECT proxy that wants Basic USER:PASSWORD (407 otherwise) and tunnels to the target."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.seen: list[str] = []  # the Proxy-Authorization values it received
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(4096)
            if not chunk:
                conn.close()
                return
            head += chunk
        lines = head.decode("latin-1").split("\r\n")
        target = lines[0].split(" ")[1]
        auth = next((ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith("proxy-authorization:")), "")
        self.seen.append(auth)
        want = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        if auth != want:
            conn.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="corp"\r\n'
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            conn.close()
            return
        host, port = target.rsplit(":", 1)
        up = socket.create_connection((host, int(port)))
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        try:  # tunnel until either side closes or resets; both ends are always closed after
            socks = [conn, up]
            while True:
                ready, _w, _x = select.select(socks, [], [], 5)
                if not ready:
                    return
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        if s is up:  # half-close toward the client and drain it: a close with unread data is an
                            conn.shutdown(socket.SHUT_WR)  # RST, which can drop the response it has not read
                            conn.settimeout(2)
                            while conn.recv(65536):
                                pass
                        return
                    (up if s is conn else conn).sendall(data)
        except OSError:
            return
        finally:
            up.close()
            conn.close()

    def close(self):
        self.srv.close()


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    api, proxy = _Api(tmp_path), _Proxy()
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "ZS_PROXY_AUTH_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{proxy.port}")
    monkeypatch.setenv("ZS_CA_FILE", api.ca)  # what a TLS-inspecting proxy's CA does for the API (#196)
    lines: list[tuple[str, dict]] = []
    monkeypatch.setattr(A, "log", lambda msg, **kw: lines.append((msg, kw)))
    yield api, proxy, tmp_path, lines
    api.close()
    proxy.close()


def _auth_file(tmp_path, text: str):
    path = tmp_path / "proxy-auth"
    path.write_text(text)
    path.chmod(0o400)
    return str(path)


def _call(api_port: int):
    client = A.Api(f"https://127.0.0.1:{api_port}")
    client._sign = lambda *a: {}
    client._wait = lambda s: None
    return client.call("POST", "/cbom/node/heartbeat", {}, retries=0)


def test_199_the_node_logs_in_to_the_proxy_from_the_auth_file(lab, monkeypatch):
    api, proxy, tmp_path, lines = lab
    monkeypatch.setenv("ZS_PROXY_AUTH_FILE", _auth_file(tmp_path, f"{USER}:{PASSWORD}\n"))
    status, body = _call(api.port)
    assert status == 200 and body == {"ok": True}  # dev: 407 from the proxy (ZS_PROXY_AUTH_FILE not read)
    assert proxy.seen[-1].startswith("Basic ")
    logged = repr(lines)
    assert PASSWORD not in logged and "p@ss" not in logged


def test_199_without_the_login_the_error_says_the_proxy_wants_one(lab):
    api, _proxy, _tmp, lines = lab
    with pytest.raises(A.ApiError) as err:
        _call(api.port)
    assert "the proxy asked for a login (HTTP 407)" in str(err.value) and "ZS_PROXY_AUTH_FILE" in str(err.value)


@pytest.mark.parametrize("text", ["no-colon-here", ":only-password", ""])
def test_199_a_malformed_auth_file_stops_the_node_without_printing_it(lab, monkeypatch, text):
    _api, _proxy, tmp_path, _lines = lab
    monkeypatch.setenv("ZS_PROXY_AUTH_FILE", _auth_file(tmp_path, text))
    with pytest.raises(SystemExit) as stop:
        A.Api("https://127.0.0.1:1")
    msg = str(stop.value)
    assert "ZS_PROXY_AUTH_FILE" in msg and "user:password" in msg
    assert (not text) or text not in msg


def test_199_an_auth_file_without_a_proxy_is_refused(lab, monkeypatch):
    _api, _proxy, tmp_path, _lines = lab
    monkeypatch.delenv("HTTPS_PROXY")
    monkeypatch.setenv("ZS_PROXY_AUTH_FILE", _auth_file(tmp_path, f"{USER}:{PASSWORD}"))
    with pytest.raises(SystemExit) as stop:
        A.Api("https://127.0.0.1:1")
    assert "HTTPS_PROXY" in str(stop.value) and PASSWORD not in str(stop.value)


def test_199_a_login_inside_the_proxy_url_still_works_and_is_never_logged(lab, monkeypatch):
    """A customer who set HTTPS_PROXY=http://user:pass@host by hand keeps working (httpx reads it)."""
    api, proxy, _tmp, lines = lab
    quoted = PASSWORD.replace("@", "%40").replace(":", "%3A").replace(" ", "%20").replace("/", "%2F")
    monkeypatch.setenv("HTTPS_PROXY", f"http://{USER}:{quoted}@127.0.0.1:{proxy.port}")
    status, _body = _call(api.port)
    assert status == 200 and quoted not in repr(lines) and PASSWORD not in repr(lines)


def test_199_the_chart_mounts_the_proxy_login_secret_where_the_env_points():
    from pathlib import Path

    chart = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "cbom-scan-node"
    helpers = (chart / "templates" / "_helpers.tpl").read_text()
    values = (chart / "values.yaml").read_text()
    assert 'proxyAuthSecret: ""' in values
    assert "name: ZS_PROXY_AUTH_FILE\n  value: /etc/zs-node/trust/proxy/auth" in helpers
    assert "mountPath: /etc/zs-node/trust/proxy\n  readOnly: true" in helpers
    block = helpers.split("- name: proxy-auth\n  secret:", 1)[1].split("{{- end }}", 1)[0]
    assert "defaultMode: 0440" in block and "key: auth" in block and "path: auth" in block  # never world-readable
    daemonset = (chart / "templates" / "daemonset.yaml").read_text()
    assert "{{- if or .Values.trust.clientSecret .Values.proxyAuthSecret }}" in daemonset  # fsGroup for the 0440 file
