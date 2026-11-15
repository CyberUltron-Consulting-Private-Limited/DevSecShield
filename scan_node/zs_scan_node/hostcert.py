"""OpenSSH host certificates for ``host_key_policy: host_ca`` (#59).

paramiko 3.5.1 negotiates a ``*-cert-v01@openssh.com`` host key and checks the key-exchange signature with the key
inside the certificate, but never checks the certificate itself ("very little effort is made to validate the
certificate contents", paramiko/pkey.py).  This module does, with ``cryptography`` (44):

* the certificate's CA signature verifies, and the CA is one of the source's listed host-CA public keys;
* it is a HOST certificate (a user certificate presented as a host key is refused);
* one of its principals is the target's name or address (a certificate valid for every host is refused);
* ``valid_after <= now < valid_before`` (OpenSSH's own rule);
* it has no critical options (none are defined for host certificates; an unknown one must not be ignored);
* the key it certifies is the key that signed the key exchange (paramiko's verifying key, compared byte for byte).

Anything else raises HostCertRefused with a sentence safe to show the customer; the caller reports
``host_key_mismatch`` before any credential is sent.
"""
from __future__ import annotations

import base64
import hashlib
import time
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import SSHCertificate, SSHCertificateType, load_ssh_public_identity

# Offered, in this order, and nothing else under host_ca: a plain host key never satisfies the policy, so it is not
# negotiated at all (no downgrade).  ssh-rsa-cert-v01 (SHA-1 signatures) and DSA are left out.
CERT_HOST_KEY_TYPES = ("ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                       "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
                       "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com")
MAX_HOST_CAS = 20


class HostCertRefused(Exception):
    """``str(exc)`` is safe to show the customer."""


def offered_key_types(known: Any) -> tuple[str, ...]:
    """The certificate host-key types to offer, of those this paramiko knows (``Transport._key_info``)."""
    return tuple(t for t in CERT_HOST_KEY_TYPES if t in known)


def fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _key_blob(public_key: Any) -> bytes:
    line = public_key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return base64.b64decode(line.split()[1])


def ca_blobs(lines: list[str]) -> set[bytes]:
    """The key blobs of the listed host CAs (``type base64 [comment]`` lines; anything else is skipped: the backend
    refused it at save)."""
    out = set()
    for line in lines or []:
        fields = str(line).split()
        if len(fields) >= 2 and "-cert-v01@openssh.com" not in fields[0]:
            try:
                out.add(base64.b64decode(fields[1], validate=True))
            except ValueError:
                continue
    return out


def check_host_certificate(cert_type: str, cert_blob: bytes, kex_key_blob: bytes, ca_lines: list[str],
                           names: list[str], now: float | None = None) -> dict[str, Any]:
    """The certificate's facts when it may be trusted for one of ``names``; raises HostCertRefused otherwise.
    ``kex_key_blob``: the public key blob paramiko verified the key-exchange signature with."""
    if not cert_type.endswith("-cert-v01@openssh.com"):
        raise HostCertRefused("the server presented a plain host key, not a host certificate")
    try:
        cert = load_ssh_public_identity(cert_type.encode() + b" " + base64.b64encode(cert_blob))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise HostCertRefused(f"the host certificate could not be read ({exc.__class__.__name__})") from None
    if not isinstance(cert, SSHCertificate):
        raise HostCertRefused("the server presented a plain host key, not a host certificate")
    try:
        cert.verify_cert_signature()
    except (InvalidSignature, ValueError, UnsupportedAlgorithm):
        raise HostCertRefused("the host certificate's signature does not verify") from None
    ca_blob = _key_blob(cert.signature_key())
    ca_fp = fingerprint(ca_blob)
    if ca_blob not in ca_blobs(ca_lines):
        raise HostCertRefused(f"the host certificate is not signed by a host CA listed for this source (signed by "
                              f"{ca_fp})")
    if cert.type != SSHCertificateType.HOST:
        raise HostCertRefused("the server presented a user certificate, not a host certificate")
    principals = [p.decode("utf-8", "replace") for p in cert.valid_principals]
    wanted = [n for n in dict.fromkeys(str(n).strip().lower() for n in names) if n]
    if not principals:
        raise HostCertRefused("the host certificate names no host (it would be valid for every host)")
    if not {p.lower() for p in principals} & set(wanted):
        raise HostCertRefused(f"the host certificate is not for {' or '.join(wanted)} (it names "
                              f"{', '.join(principals[:5])})")
    moment = int(time.time() if now is None else now)
    if moment < cert.valid_after:
        raise HostCertRefused(f"the host certificate is not valid before {_utc(cert.valid_after)}")
    if moment >= cert.valid_before:
        raise HostCertRefused(f"the host certificate expired at {_utc(cert.valid_before)}")
    if cert.critical_options:
        raise HostCertRefused("the host certificate has critical options, which host certificates do not use")
    if _key_blob(cert.public_key()) != kex_key_blob:
        raise HostCertRefused("the host certificate certifies another key than the one that signed the key exchange")
    return {"key_id": cert.key_id.decode("utf-8", "replace"), "serial": cert.serial, "principals": principals,
            "ca_fingerprint": ca_fp, "valid_after": _utc(cert.valid_after), "valid_before": _utc(cert.valid_before)}


def _utc(ts: int) -> str:
    if ts >= 2**63 - 1 or ts >= 253402300800:  # OpenSSH "forever"
        return "forever"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
