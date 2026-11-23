"""A small in-process LDAP server for the Active Directory collector tests (FIX-B3).

It speaks LDAPS (TLS from the first byte) or plain LDAP with StartTLS, with a throw-away CA and a DC certificate for
``localhost`` / 127.0.0.1, and answers from an in-memory directory keyed by (base, scope, filter text).  It records
what the client did (operations by tag, attributes requested, binds and whether TLS was active at the bind), so the
tests can prove the collector is read-only, never asks for secret attributes and never binds before TLS.
"""
from __future__ import annotations

import datetime as dt
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from zs_scan_node import ldapmini as L

BIND_NAME = "svc-zscbom@lab.test"
PASSWORD = "Corr3ct-Horse-Battery-9x!"
BASE = "DC=lab,DC=test"
CONFIG_NC = f"CN=Configuration,{BASE}"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_pki(names=("localhost",), ips=("127.0.0.1",)) -> dict[str, str]:
    """A CA and a server certificate it signed (PEM strings)."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("Lab Test Root CA")).issuer_name(_name("Lab Test Root CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    import ipaddress

    san = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder().subject_name(_name(names[0] if names else "dc")).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
    return {"ca": pem(ca), "cert": pem(cert), "ca_der": ca.public_bytes(serialization.Encoding.DER),
            "key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()).decode()}


def _attrs(**values) -> list[tuple[str, list[bytes]]]:
    out = []
    for name, vals in values.items():
        name = name.replace("__", "-")
        vals = vals if isinstance(vals, list) else [vals]
        out.append((name, [v if isinstance(v, bytes) else str(v).encode() for v in vals]))
    return out


FT_2024 = str(int((dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
                   - dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)).total_seconds() * 10_000_000))


def default_directory(ca_der: bytes) -> dict[tuple[str, int, str], list[tuple[str, list[tuple[str, list[bytes]]]]]]:
    return {
        ("", 0, "(objectClass=*)"): [("", _attrs(defaultNamingContext=BASE, configurationNamingContext=CONFIG_NC,
                                                 rootDomainNamingContext=BASE, dnsHostName="dc1.lab.test",
                                                 domainFunctionality="6", forestFunctionality="6",
                                                 domainControllerFunctionality="7", supportedLDAPVersion=["3", "2"]))],
        (BASE, 2, "(|(primaryGroupID=516)(primaryGroupID=521))"): [
            (f"CN=DC1,OU=Domain Controllers,{BASE}", _attrs(sAMAccountName="DC1$", dNSHostName="dc1.lab.test",
                                                            msDS__SupportedEncryptionTypes="28",
                                                            operatingSystem="Windows Server 2016 Datacenter"))],
        (BASE, 2, "(sAMAccountName=krbtgt)"): [
            (f"CN=krbtgt,CN=Users,{BASE}", _attrs(sAMAccountName="krbtgt", pwdLastSet=FT_2024))],
        (BASE, 2, "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"): [
            (f"CN=svc-sql,CN=Users,{BASE}", _attrs(sAMAccountName="svc-sql", userAccountControl="512",
                                                   # a hostile or misconfigured server sending a secret: dropped
                                                   unicodePwd=b"\x00secret-hash\x00", pwdLastSet=FT_2024)),
            (f"CN=svc-legacy,CN=Users,{BASE}", _attrs(sAMAccountName="svc-legacy", userAccountControl=str(0x200000 | 512),
                                                      msDS__SupportedEncryptionTypes="3")),
            (f"CN=svc-web,CN=Users,{BASE}", _attrs(sAMAccountName="svc-web", msDS__SupportedEncryptionTypes="24"))],
        (BASE, 2, "(objectClass=msDS-GroupManagedServiceAccount)"): [
            (f"CN=gmsa-app,CN=Managed Service Accounts,{BASE}", _attrs(sAMAccountName="gmsa-app$",
                                                                      msDS__SupportedEncryptionTypes="28"))],
        (BASE, 2, "(&(objectCategory=computer)(!(primaryGroupID=516))(!(primaryGroupID=521)))"): [
            (f"CN=WS{i:03d},CN=Computers,{BASE}", _attrs(sAMAccountName=f"WS{i:03d}$",
                                                         **({"msDS__SupportedEncryptionTypes": "24"} if i % 2 else {})))
            for i in range(7)],
        (f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{CONFIG_NC}", 1,
         "(objectClass=pKIEnrollmentService)"): [
            (f"CN=Lab-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,{CONFIG_NC}",
             _attrs(cn="Lab-CA", dNSHostName="ca1.lab.test", cACertificate=ca_der,
                    certificateTemplates=["WebServer", "DomainController", "User"]))],
    }


@dataclass
class Record:
    connections: int = 0
    ops: list[int] = field(default_factory=list)
    attributes: list[str] = field(default_factory=list)
    filters: list[str] = field(default_factory=list)
    binds: list[tuple[str, bool]] = field(default_factory=list)  # (bind name, TLS active)
    passwords_seen: int = 0


class LdapStub:
    def __init__(self, mode: str = "ldaps", directory=None, pki=None, page_size_cap: int = 3,
                 stall_after_bind: bool = False) -> None:
        self.mode, self.pki = mode, pki or make_pki()
        self.directory = directory if directory is not None else default_directory(self.pki["ca_der"])
        self.page_size_cap, self.stall_after_bind = page_size_cap, stall_after_bind
        self.record = Record()
        folder = Path(tempfile.mkdtemp(prefix="ldapstub-"))
        (folder / "c.pem").write_text(self.pki["cert"])
        (folder / "k.pem").write_text(self.pki["key"])
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(folder / "c.pem"), str(folder / "k.pem"))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------------ server
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.record.connections += 1
            threading.Thread(target=self._conn, args=(conn,), daemon=True).start()

    def _conn(self, conn: socket.socket) -> None:
        conn.settimeout(10)
        tls = False
        try:
            if self.mode == "ldaps":
                conn = self.ctx.wrap_socket(conn, server_side=True)
                tls = True
            client = L.LdapClient(conn, time.monotonic() + 30)
            while True:
                msg = client.read()
                self.record.ops.append(msg.op_tag)
                if msg.op_tag == 0x77:  # extended: only StartTLS is answered
                    parts = L.children(msg.op)
                    oid = parts[0][1].decode() if parts else ""
                    ok = oid == L.STARTTLS_OID and not tls and self.mode == "starttls"
                    conn.sendall(L.seq(L.ber_int(msg.message_id), L.seq(
                        L.ber_int(0 if ok else 2, 0x0A), L.octets(""), L.octets(""), tag=0x78)))
                    if ok:
                        conn = self.ctx.wrap_socket(conn, server_side=True)
                        client = L.LdapClient(conn, time.monotonic() + 30)
                        tls = True
                elif msg.op_tag == 0x60:
                    fields = L.children(msg.op)
                    name = fields[1][1].decode()
                    password = fields[2][1].decode()
                    self.record.binds.append((name, tls))
                    if password:
                        self.record.passwords_seen += 1
                    ok = tls and name == BIND_NAME and password == PASSWORD
                    code = 0 if ok else (13 if not tls else 49)
                    conn.sendall(L.seq(L.ber_int(msg.message_id), L.seq(
                        L.ber_int(code, 0x0A), L.octets(""), L.octets("" if ok else "80090308: LdapErr"), tag=0x61)))
                    if ok and self.stall_after_bind:
                        time.sleep(30)
                        return
                elif msg.op_tag == 0x63:
                    self._search(conn, msg)
                elif msg.op_tag == 0x42:
                    return
                else:
                    return  # anything else (a write) ends the session: the tests assert it never comes
        except (OSError, L.LdapError, ssl.SSLError, ConnectionError, TimeoutError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _search(self, conn: socket.socket, msg: L.Message) -> None:
        f = L.children(msg.op)
        base, scope = f[0][1].decode(), L.as_int(f[1][1])
        filt = L.decode_filter(L.tlv(f[6][0], f[6][1]))
        attrs = [v.decode() for _t, v in L.children(f[7][1])]
        self.record.filters.append(filt)
        self.record.attributes.extend(attrs)
        entries = self.directory.get((base, scope, filt))
        start, size = 0, None
        for oid, value in msg.controls:
            if oid == L.PAGED_OID:
                _t, body, _ = L.read_tlv(value)
                parts = L.children(body)
                size = min(L.as_int(parts[0][1]), self.page_size_cap)
                start = int(parts[1][1].decode() or 0) if parts[1][1] else 0
        if entries is None:
            done = L.seq(L.ber_int(32, 0x0A), L.octets(""), L.octets("0000208D: NameErr"), tag=0x65)
            conn.sendall(L.seq(L.ber_int(msg.message_id), done))
            return
        end = len(entries) if size is None else min(len(entries), start + size)
        for dn, values in entries[start:end]:
            body = L.seq(*(L.seq(L.octets(n), L.seq(*(L.octets(v) for v in vs), tag=0x31)) for n, vs in values))
            conn.sendall(L.seq(L.ber_int(msg.message_id), L.seq(L.octets(dn), body, tag=0x64)))
        controls = b""
        if size is not None:
            cookie = str(end).encode() if end < len(entries) else b""
            controls = L.seq(L.seq(L.octets(L.PAGED_OID), L.octets(L.seq(L.ber_int(0), L.octets(cookie)))), tag=0xA0)
        done = L.seq(L.ber_int(0, 0x0A), L.octets(""), L.octets(""), tag=0x65)
        conn.sendall(L.seq(L.ber_int(msg.message_id), done, controls))
