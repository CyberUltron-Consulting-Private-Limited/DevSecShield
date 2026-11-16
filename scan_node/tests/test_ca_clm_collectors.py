"""Recorded HTTP for the Venafi, Keyfactor, DigiCert and Sectigo collectors. No vendor network.

One success and one refused credential per product. A timeout stays a timeout, and a 2xx body that is not JSON
is reported as not JSON (never the other way round).
"""
from __future__ import annotations

import datetime as dt
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx
import pytest

from zs_scan_node import netutil
from zs_scan_node.collectors import ca, ca_http


def _ctx(secrets=()):
    import time

    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="ca_connector",
                      scrubber=Scrubber(list(secrets)), never_scan=NeverScan(), deadline=time.monotonic() + 30)


def _leaf():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issued.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(0xA1B2).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return pem, cert.subject.rfc4514_string()


def _serve(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _routes(table):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _go(self, method):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            path = urlsplit(self.path).path
            found = table.get((method, path))
            if found is None:
                self._send(404, b"missing")
                return
            found(self, raw)

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

        def log_message(self, *_args):
            return

    return H


@pytest.fixture
def local_dns(monkeypatch):
    monkeypatch.setattr(netutil, "resolve", lambda _name, timeout=5.0: ["127.0.0.1"])


def _ran(cfg, secrets):
    ctx = _ctx(secrets=list(secrets.values()))
    text = ca.collect(ctx, cfg, secrets, {})
    ctx.flush()
    return ctx, text


def test_venafi_lists_certificates_after_authorize(local_dns):
    pem, subject = _leaf()
    del pem
    seen = []

    def authorize(handler, raw):
        body = json.loads(raw)
        seen.append(body["scope"])
        assert body["client_id"] == "MyApp" and body["username"] == "local:admin" and body["password"] == "venafi-secret"
        handler._send(200, json.dumps({"access_token": "issued-token", "token_type": "Bearer"}))

    def listing(handler, _raw):
        seen.append(handler.headers.get("Authorization"))
        handler._send(200, json.dumps({"Certificates": [{
            "DN": r"\VED\Policy\issued.example", "Guid": "{abc}", "Name": "issued.example",
            "X509": {"CN": "issued.example", "Subject": subject, "Issuer": subject, "KeyAlgorithm": "RSA",
                     "KeySize": 2048, "Serial": "A1B2", "ValidFrom": "2026-01-01T00:00:00.0000000Z",
                     "ValidTo": "2027-01-01T00:00:00.0000000Z"}}], "TotalCount": 1}))

    httpd = _serve(_routes({("POST", "/vedauth/authorize/oauth"): authorize,
                            ("GET", "/vedsdk/certificates/"): listing}))
    try:
        ctx, _text = _ran({"provider": "venafi", "api_url": f"http://venafi.test:{httpd.server_port}/vedsdk",
                           "login": "local:admin", "client_id": "MyApp"}, {"password": "venafi-secret"})
        assert [o.status for o in ctx.outcomes] == ["ok"]
        assert seen == ["certificate", "Bearer issued-token"]
        row = next(a for a in ctx.collected if a["type"] == "certificate")
        assert row["facts"]["subject"] == subject and row["key_size"] == 2048 and row["facts"]["provider"] == "venafi"
        assert row["facts"]["self_signed"] is True and row["facts"]["not_after"] == "2027-01-01T00:00:00Z"
        assert "venafi-secret" not in json.dumps(ctx.collected) and "issued-token" not in json.dumps(ctx.collected)
    finally:
        httpd.shutdown()


def test_venafi_auth_failure_is_the_target(local_dns):
    def authorize(handler, _raw):
        handler._send(401, b"<html>no</html>", "text/html")

    httpd = _serve(_routes({("POST", "/vedauth/authorize/oauth"): authorize}))
    try:
        ctx, text = _ran({"provider": "venafi", "api_url": f"http://venafi.test:{httpd.server_port}/vedsdk",
                          "login": "local:admin", "client_id": "MyApp"}, {"password": "venafi-secret"})
        assert ctx.outcomes[0].status == "auth_failed"
        assert "not JSON" not in (ctx.outcomes[0].error or "") and "venafi-secret" not in (text or "")
        assert ctx.collected == []
    finally:
        httpd.shutdown()


def test_keyfactor_reads_certificate_bytes(local_dns):
    pem, subject = _leaf()
    import base64
    blob = base64.b64encode(pem).decode()
    seen = []

    def listing(handler, _raw):
        seen.append(handler.headers.get("x-keyfactor-requested-with"))
        seen.append(handler.headers.get("Authorization"))
        handler._send(200, json.dumps([{"Id": 7, "ContentBytes": blob, "IssuedDN": subject}]))

    httpd = _serve(_routes({("GET", "/KeyfactorAPI/Certificates"): listing}))
    try:
        ctx, _text = _ran({"provider": "keyfactor", "api_url": f"http://kf.test:{httpd.server_port}/KeyfactorAPI"},
                          {"token": "kf-token"})
        assert [o.status for o in ctx.outcomes] == ["ok"]
        assert seen == ["APIClient", "Bearer kf-token"]
        row = ctx.collected[0]
        assert row["type"] == "certificate" and row["facts"]["subject"] == subject and row["facts"]["key_size"] == 2048
        assert "kf-token" not in json.dumps(ctx.collected)
    finally:
        httpd.shutdown()


def test_keyfactor_auth_failure_is_the_target(local_dns):
    def listing(handler, _raw):
        handler._send(401, b"not-json", "text/plain")

    httpd = _serve(_routes({("GET", "/KeyfactorAPI/Certificates"): listing}))
    try:
        ctx, _text = _ran({"provider": "keyfactor", "api_url": f"http://kf.test:{httpd.server_port}/KeyfactorAPI"},
                          {"token": "kf-token"})
        assert ctx.outcomes[0].status == "auth_failed" and "not JSON" not in (ctx.outcomes[0].error or "")
        assert ctx.collected == []
    finally:
        httpd.shutdown()


def test_digicert_lists_orders_and_downloads_the_certificate(local_dns):
    pem, subject = _leaf()
    seen = []

    def listing(handler, _raw):
        seen.append(handler.headers.get("X-DC-DEVKEY"))
        handler._send(200, json.dumps({"orders": [{"id": 9, "status": "issued", "certificate": {"id": 44, "common_name": "issued.example"}}],
                                       "page": {"total": 1, "limit": 100, "offset": 0}}))

    def download(handler, _raw):
        seen.append(urlsplit(handler.path).path)
        handler._send(200, pem, "application/x-pem-file")

    httpd = _serve(_routes({("GET", "/services/v2/order/certificate"): listing,
                            ("GET", "/services/v2/certificate/44/download/format/pem_nointermediate"): download}))
    try:
        ctx, _text = _ran({"provider": "digicert", "api_url": f"http://dc.test:{httpd.server_port}/services/v2"},
                          {"api_key": "dc-key"})
        assert [o.status for o in ctx.outcomes] == ["ok"]
        assert seen[0] == "dc-key" and seen[1].endswith("/pem_nointermediate")
        assert ctx.collected[0]["facts"]["subject"] == subject and "dc-key" not in json.dumps(ctx.collected)
    finally:
        httpd.shutdown()


def test_digicert_auth_failure_is_the_target(local_dns):
    def listing(handler, _raw):
        handler._send(403, b"<html>denied</html>", "text/html")

    httpd = _serve(_routes({("GET", "/services/v2/order/certificate"): listing}))
    try:
        ctx, _text = _ran({"provider": "digicert", "api_url": f"http://dc.test:{httpd.server_port}/services/v2"},
                          {"api_key": "dc-key"})
        assert ctx.outcomes[0].status == "auth_failed" and "not JSON" not in (ctx.outcomes[0].error or "")
    finally:
        httpd.shutdown()


def test_sectigo_searches_and_downloads_pem(local_dns):
    pem, subject = _leaf()
    seen = []

    def listing(handler, _raw):
        seen.append((handler.headers.get("login"), handler.headers.get("password"), handler.headers.get("customerUri"),
                     urlsplit(handler.path).query))
        if "status=Issued" in handler.path:
            handler._send(200, json.dumps([{"sslId": 67, "commonName": "issued.example"}]))
        else:
            handler._send(200, b"[]")

    def download(handler, _raw):
        seen.append(urlsplit(handler.path).query)
        handler._send(200, pem, "application/x-pem-file")

    httpd = _serve(_routes({("GET", "/api/ssl/v1"): listing, ("GET", "/api/ssl/v1/collect/67"): download}))
    try:
        ctx, _text = _ran({"provider": "sectigo", "api_url": f"http://cm.test:{httpd.server_port}/api",
                           "login": "reader", "customer_uri": "cst1152"}, {"password": "sectigo-secret"})
        assert [o.status for o in ctx.outcomes] == ["ok"]
        queries = [item[3] for item in seen if isinstance(item, tuple)]
        assert seen[0][:3] == ("reader", "sectigo-secret", "cst1152") and any("status=Issued" in q for q in queries)
        assert "format=pemco" in seen
        assert "keystore" not in json.dumps(seen)
        assert ctx.collected[0]["facts"]["subject"] == subject and "sectigo-secret" not in json.dumps(ctx.collected)
    finally:
        httpd.shutdown()


def test_sectigo_auth_failure_is_the_target(local_dns):
    def listing(handler, _raw):
        handler._send(401, b"nope", "text/plain")

    httpd = _serve(_routes({("GET", "/api/ssl/v1"): listing}))
    try:
        ctx, _text = _ran({"provider": "sectigo", "api_url": f"http://cm.test:{httpd.server_port}/api",
                           "login": "reader", "customer_uri": "cst1152"}, {"password": "sectigo-secret"})
        assert ctx.outcomes[0].status == "auth_failed" and "not JSON" not in (ctx.outcomes[0].error or "")
        assert "sectigo-secret" not in (ctx.outcomes[0].error or "")
    finally:
        httpd.shutdown()


def test_a_success_that_is_not_json_says_so(local_dns):
    def listing(handler, _raw):
        handler._send(200, b"<html>nope</html>", "text/html")

    httpd = _serve(_routes({("GET", "/services/v2/order/certificate"): listing}))
    try:
        ctx, _text = _ran({"provider": "digicert", "api_url": f"http://dc.test:{httpd.server_port}/services/v2"},
                          {"api_key": "dc-key"})
        assert ctx.outcomes[0].status == "error"
        assert "not JSON" in (ctx.outcomes[0].error or "") and "timed out" not in (ctx.outcomes[0].error or "").lower()
    finally:
        httpd.shutdown()


def test_a_timeout_is_not_reported_as_not_json(local_dns, monkeypatch):
    class _Boom:
        def request(self, *_args, **_kwargs):
            raise httpx.ReadTimeout("read timed out")

        def close(self):
            return None

    monkeypatch.setattr(ca_http, "http_client", lambda *_a, **_k: _Boom())
    ctx, _text = _ran({"provider": "digicert", "api_url": "http://dc.test/services/v2"}, {"api_key": "dc-key"})
    assert ctx.outcomes[0].status == "timeout"
    assert "not JSON" not in (ctx.outcomes[0].error or "")
