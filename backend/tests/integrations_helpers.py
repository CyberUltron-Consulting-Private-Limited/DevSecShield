"""Test helpers for the integration connectors: a throwaway CA and server certificate, and small local servers."""
from __future__ import annotations

import datetime as dt
import http.server
import ipaddress
import socket
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_pki(directory: Path, names: list[str]) -> dict[str, str]:
    """A CA and a server certificate for ``names`` (DNS names and IP addresses). Returns PEM paths and the CA PEM."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WP11 test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = []
    for name in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    directory.mkdir(parents=True, exist_ok=True)
    ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    (directory / "ca.pem").write_text(ca_pem)
    (directory / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "server.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                             serialization.PrivateFormat.PKCS8,
                                                             serialization.NoEncryption()))
    return {"ca_pem": ca_pem, "ca": str(directory / "ca.pem"), "cert": str(directory / "server.pem"),
            "key": str(directory / "server.key")}


def server_context(pki: dict[str, str]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki["cert"], pki["key"])
    return ctx


class Recorder(http.server.BaseHTTPRequestHandler):
    """Records requests on the server object; answers with ``server.reply(handler, body) -> (status, headers, body)``."""

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers),  # type: ignore[attr-defined]
                                     "body": body})
        status, headers, payload = self.server.reply(self, body)  # type: ignore[attr-defined]
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PATCH = do_PUT = _handle

    def log_message(self, *_a) -> None:  # quiet
        pass


def https_server(pki: dict[str, str], reply) -> tuple[http.server.ThreadingHTTPServer, int]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    srv.socket = server_context(pki).wrap_socket(srv.socket, server_side=True)
    srv.requests = []  # type: ignore[attr-defined]
    srv.reply = reply  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def silent_server() -> tuple[socket.socket, int]:
    """Accepts connections and never answers (timeouts)."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    held: list[socket.socket] = []

    def loop() -> None:
        while True:
            try:
                conn, _ = sock.accept()
                held.append(conn)
            except OSError:
                return

    threading.Thread(target=loop, daemon=True).start()
    return sock, sock.getsockname()[1]
