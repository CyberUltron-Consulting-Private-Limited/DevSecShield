"""OpenSSH user certificates with ``cryptography`` (``SSHCertificateBuilder``; no new dependency).

Everything here is pure: no database, no network, no logging.  Private keys are only ever passed in as objects and
are never turned into text here.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    SSHCertificate,
    SSHCertificateBuilder,
    SSHCertificateType,
    load_ssh_private_key,
    load_ssh_public_identity,
)

MAX_PRINCIPALS = 16
MAX_SOURCE_ADDRESSES = 32
# zs-<team id>-<group>: a certificate can never carry root, a real login name or another team's principal
_PRINCIPAL = re.compile(r"^zs-(\d{1,10})-[a-z0-9][a-z0-9._-]{0,47}$")
_PUBLIC_LINE = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa) "
                          r"([A-Za-z0-9+/]+={0,2})(?: [^\r\n]{0,256})?$")


class CertError(ValueError):
    """``str(err)`` is safe to show (never contains key material)."""


@dataclass(frozen=True)
class CertFacts:
    """What a certificate says, read back from its text."""
    key_type: str
    cert_type: str  # user | host
    serial: int
    key_id: str
    principals: tuple[str, ...]
    valid_after: int
    valid_before: int
    critical_options: dict[str, str]
    extensions: tuple[str, ...]
    public_key_blob: bytes  # the certified key
    signature_key_blob: bytes  # the CA key


def principal_shape_ok(principal: str) -> bool:
    """zs-<digits>-<group> (the team is checked when a certificate is issued)."""
    return bool(_PRINCIPAL.match(principal or ""))


def principal_problem(principal: str, team_id: int) -> str | None:
    match = _PRINCIPAL.match(principal or "")
    if not match:
        return f"principal {principal[:64]!r} must look like zs-{team_id}-<group> (lowercase letters, digits, . _ -)"
    if int(match.group(1)) != team_id:
        return f"principal {principal[:64]!r} belongs to another team; use zs-{team_id}-<group>"
    return None


def check_principals(principals: Sequence[str], team_id: int) -> tuple[str, ...]:
    out = tuple(dict.fromkeys(str(p).strip() for p in principals if str(p).strip()))
    if not out:
        raise CertError("at least one principal is required")
    if len(out) > MAX_PRINCIPALS:
        raise CertError(f"at most {MAX_PRINCIPALS} principals")
    for principal in out:
        problem = principal_problem(principal, team_id)
        if problem:
            raise CertError(problem)
    return out


def source_address_list(values: Sequence[str]) -> tuple[str, ...]:
    """Normalised addresses / CIDRs for the ``source-address`` critical option (OpenSSH: comma-separated)."""
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise CertError(f"{text[:64]!r} is not an IP address or CIDR") from None
        if net.prefixlen == net.max_prefixlen:
            text = str(net.network_address)
        else:
            text = str(net)
        if text not in out:
            out.append(text)
    if len(out) > MAX_SOURCE_ADDRESSES:
        raise CertError(f"at most {MAX_SOURCE_ADDRESSES} source addresses")
    return tuple(out)


def public_blob(line: str) -> bytes:
    parts = (line or "").strip().split()
    if len(parts) < 2:
        raise CertError("not an OpenSSH public key")
    try:
        return base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise CertError("not an OpenSSH public key") from None


def public_line_of(line: str) -> str:
    """``<type> <base64>`` of a public key line (the comment dropped)."""
    parts = (line or "").strip().split()
    if len(parts) < 2:
        raise CertError("not an OpenSSH public key")
    return f"{parts[0]} {parts[1]}"


def fingerprint(line_or_blob: str | bytes) -> str:
    blob = line_or_blob if isinstance(line_or_blob, bytes) else public_blob(line_or_blob)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def blob_sha256_hex(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def load_subject_key(line: str):
    """The key to certify: a plain Ed25519, ECDSA or RSA (>= 3072) public key line, never a certificate."""
    text = (line or "").strip()
    if not _PUBLIC_LINE.match(text):
        raise CertError("the scan node has not reported a usable SSH public key")
    try:
        key = load_ssh_public_identity(text.encode())
    except (ValueError, TypeError):
        raise CertError("the scan node's SSH public key could not be read") from None
    if isinstance(key, SSHCertificate):
        raise CertError("the scan node's SSH public key could not be read")
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < 3072:
        raise CertError("the scan node's RSA key is shorter than 3072 bits")
    return key


def generate_ca_key(alg: str):
    if alg == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if alg == "ecdsa-p256":
        return ec.generate_private_key(ec.SECP256R1())
    raise CertError("key_alg must be ed25519 or ecdsa-p256")


def private_to_openssh(key) -> bytes:
    """The private key in OpenSSH format, unencrypted: only ever handed to ``keywrap`` (never stored or logged as is)."""
    return key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())


def private_from_openssh(data: bytes):
    return load_ssh_private_key(data, password=None)


def public_line(private_key) -> str:
    """The OpenSSH public key line (no comment) of a private key."""
    return private_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()


def _epoch(moment: _dt.datetime) -> int:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.timezone.utc)
    return int(moment.timestamp())


def sign_user_cert(ca_key, subject_line: str, *, serial: int, key_id: str, principals: Sequence[str],
                   valid_after: _dt.datetime, valid_before: _dt.datetime, source_addresses: Sequence[str]) -> str:
    """One OpenSSH user certificate.  No extensions (no pty, forwarding, agent or user-rc; exec works without
    them); the only critical option is ``source-address`` when addresses are given."""
    subject = load_subject_key(subject_line)
    if serial < 1 or serial >= 2 ** 64:
        raise CertError("serial out of range")
    builder = (SSHCertificateBuilder()
               .public_key(subject)
               .serial(serial)
               .type(SSHCertificateType.USER)
               .key_id(key_id.encode())
               .valid_principals([p.encode() for p in principals])
               .valid_after(_epoch(valid_after))
               .valid_before(_epoch(valid_before)))
    if source_addresses:
        builder = builder.add_critical_option(b"source-address", ",".join(source_addresses).encode())
    cert = builder.sign(ca_key)
    return cert.public_bytes().decode()


def read_cert(text: str) -> CertFacts:
    """Parse and check the CA signature of an OpenSSH certificate (raises ``CertError``)."""
    try:
        cert = load_ssh_public_identity((text or "").strip().encode())
    except (ValueError, TypeError, UnicodeError):
        raise CertError("not an OpenSSH certificate") from None
    if not isinstance(cert, SSHCertificate):
        raise CertError("not an OpenSSH certificate")
    try:
        cert.verify_cert_signature()
    except Exception:
        raise CertError("the certificate's CA signature does not verify") from None
    sig_key = cert.signature_key()
    pub = cert.public_key()
    return CertFacts(
        key_type=(text or "").strip().split()[0],
        cert_type="user" if cert.type == SSHCertificateType.USER else "host",
        serial=int(cert.serial),
        key_id=cert.key_id.decode(errors="replace"),
        principals=tuple(p.decode(errors="replace") for p in cert.valid_principals),
        valid_after=int(cert.valid_after),
        valid_before=int(cert.valid_before),
        critical_options={k.decode(errors="replace"): v.decode(errors="replace")
                          for k, v in cert.critical_options.items()},
        extensions=tuple(sorted(k.decode(errors="replace") for k in cert.extensions)),
        public_key_blob=public_blob(pub.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()),
        signature_key_blob=public_blob(sig_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()),
    )
