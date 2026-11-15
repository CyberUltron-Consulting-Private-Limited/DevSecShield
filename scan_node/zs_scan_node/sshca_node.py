"""A customer-held SSH CA key on the scan node (``provider: node``, #61).

ZeroShield stores only the CA's public key.  For each job (claim) and each renewal (``POST .../ssh-cert``) it records
the certificate it allows in ``cbomsshcertissued`` (so the audit list and the KRL know its serial) and sends the node a
grant: the CA's public key, the serial, key id, principals, source addresses and validity.  The node signs ITS OWN key
with the CA key file, for exactly that grant, and reports the certificate (``POST .../ssh-cert/report``); ZeroShield
compares it with the grant and revokes the serial if it differs.  The CA private key never leaves the node.

The key file: ``ZS_SSH_CA_KEY``, default ``<state dir>/ssh-ca/ca_key``, an unencrypted OpenSSH Ed25519 or ECDSA
private key (``ssh-keygen -t ed25519 -N '' -f ca_key``), owned by the node's user, mode 0400.

The signer refuses, whatever the grant says:
* principals or a TTL it was not sent for the job (``sign(..., principals=, ttl_s=)`` asks for a subset only);
* principals other than ``zs-<team>-<group>`` (never ``root`` or a person's login), none at all, or no source
  address (never an unbound certificate);
* a validity window that is not exactly the grant's TTL, or longer than ``ZS_SSH_CA_MAX_TTL_S`` (default 3600);
* a grant for another CA key than the one installed here.
The certificate has no extensions and only the ``source-address`` critical option.
"""
from __future__ import annotations

import os
import re
import stat
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    SSHCertificateBuilder,
    SSHCertificateType,
    load_ssh_private_key,
    load_ssh_public_identity,
)

from zs_scan_node.collectors import ConfigError

KEY_ENV = "ZS_SSH_CA_KEY"
MAX_TTL_ENV = "ZS_SSH_CA_MAX_TTL_S"
DEFAULT_RELATIVE_PATH = os.path.join("ssh-ca", "ca_key")
MAX_TTL_S = 3600
_PRINCIPAL = re.compile(r"^zs-\d+-[a-z0-9][a-z0-9._-]{0,63}$")


class SignRefused(Exception):
    """The node will not sign this (``str(exc)`` is safe to show and to report)."""


def _line(public_key) -> str:
    return public_key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def _identity(line: str) -> str:
    return " ".join(str(line or "").split()[:2])


class NodeSigner:
    def __init__(self, ca_key, path: str, max_ttl_s: int = MAX_TTL_S) -> None:
        self._ca_key = ca_key  # never serialised, logged or sent
        self.path = path
        self.max_ttl_s = max_ttl_s
        self.public_line = _line(ca_key.public_key())

    @classmethod
    def from_state(cls, state_dir: str, env: Mapping[str, str] | None = None) -> "NodeSigner":
        env = os.environ if env is None else env
        path = env.get(KEY_ENV) or os.path.join(state_dir, DEFAULT_RELATIVE_PATH)
        try:
            info = os.stat(path)
        except FileNotFoundError:
            raise ConfigError(f"no SSH CA key at {path}: install the customer's CA private key there (mode 0400), or "
                              f"set {KEY_ENV} to its path") from None
        except OSError as exc:
            raise ConfigError(f"the SSH CA key at {path} cannot be read ({exc.__class__.__name__})") from None
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"the SSH CA key at {path} is not a regular file")
        if stat.S_IMODE(info.st_mode) != 0o400:
            raise ConfigError(f"the SSH CA key at {path} must be mode 0400 (it is {stat.S_IMODE(info.st_mode):04o}): "
                              f"chmod 0400 {path}")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise ConfigError(f"the SSH CA key at {path} must be owned by the scan node's user")
        try:
            with open(path, "rb") as fh:
                key = load_ssh_private_key(fh.read(), password=None)
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"the SSH CA key at {path} is not an unencrypted OpenSSH private key "
                              f"({exc.__class__.__name__})") from None
        if not isinstance(key, (ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
            raise ConfigError(f"the SSH CA key at {path} must be Ed25519 or ECDSA")
        try:
            max_ttl = max(60, min(MAX_TTL_S, int(env.get(MAX_TTL_ENV) or MAX_TTL_S)))
        except ValueError:
            max_ttl = MAX_TTL_S
        return cls(key, path, max_ttl)

    def sign(self, grant: Mapping[str, Any], node_public_line: str, *, principals: list[str] | None = None,
             ttl_s: int | None = None) -> str:
        """The node's user certificate for ``grant``.  ``principals`` / ``ttl_s``: what is asked for, which must be
        within what the grant sent (default: the grant itself)."""
        granted = [str(p) for p in grant.get("principals") or []]
        try:
            granted_ttl = int(grant.get("ttl_s") or 0)
            valid_after, valid_before = int(grant["valid_after"]), int(grant["valid_before"])
            serial = int(grant.get("serial") or 0)
        except (KeyError, TypeError, ValueError):
            raise SignRefused("the grant from ZeroShield cannot be read") from None
        wanted = granted if principals is None else [str(p) for p in principals]
        if set(wanted) - set(granted):
            raise SignRefused("the scan node does not sign for principals it was not sent for this job")
        if ttl_s is not None and int(ttl_s) > granted_ttl:
            raise SignRefused(f"the scan node does not sign a certificate longer than the {granted_ttl} s it was sent "
                              "for this job")
        if not wanted:
            raise SignRefused("the grant has no principals")
        if any(not _PRINCIPAL.match(p) for p in wanted):
            raise SignRefused("the scan node signs only zs-<team>-<group> principals")
        addresses = [str(a) for a in grant.get("source_addresses") or [] if str(a).strip()]
        if not addresses:
            raise SignRefused("the grant has no source address (a certificate is never unbound)")
        if granted_ttl > self.max_ttl_s:
            raise SignRefused(f"the scan node signs certificates of at most {self.max_ttl_s} s")
        if valid_before - valid_after != granted_ttl or granted_ttl < 1:
            raise SignRefused("the grant's validity does not match its TTL")
        if not 1 <= serial < 2 ** 64:
            raise SignRefused("the grant's serial is out of range")
        if _identity(str(grant.get("ca_public_key") or "")) != _identity(self.public_line):
            raise SignRefused("the grant is for another CA key: the key installed on this scan node is not this "
                              "node's CA key in ZeroShield")
        try:
            subject = load_ssh_public_identity(node_public_line.strip().encode())
        except (ValueError, TypeError):
            raise SignRefused("the scan node's own public key cannot be read") from None
        if not isinstance(subject, ed25519.Ed25519PublicKey):
            raise SignRefused("the scan node's own key must be Ed25519")
        cert = (SSHCertificateBuilder().public_key(subject).serial(serial).type(SSHCertificateType.USER)
                .key_id(str(grant.get("key_id") or "").encode()[:255])
                .valid_principals([p.encode() for p in wanted])
                .valid_after(valid_after).valid_before(valid_before)
                .add_critical_option(b"source-address", ",".join(addresses).encode())
                .sign(self._ca_key))
        return cert.public_bytes().decode()


def node_public_line(private_key_path: str) -> str:
    try:
        with open(private_key_path, "rb") as fh:
            key = load_ssh_private_key(fh.read(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ConfigError(f"the scan node's own SSH key is not available ({exc.__class__.__name__})") from None
    return _line(key.public_key())


def sign_and_report(signer: NodeSigner, grant: Mapping[str, Any], node_line: str,
                    reporter: Callable[[str], Any] | None) -> str:
    """Sign the grant and report the certificate; a certificate ZeroShield did not take is never used."""
    try:
        line = signer.sign(grant, node_line)
    except SignRefused as exc:
        raise ConfigError(f"SSH CA (on this node): {exc}") from None
    if reporter is None:
        raise ConfigError("SSH CA (on this node): the certificate could not be reported to ZeroShield (this node "
                          "cannot report it)")
    try:
        reporter(line)
    except Exception as exc:  # LeaseLost / Unauthorized included: the job stops without using it
        detail = str(getattr(exc, "detail", "") or exc)[:200] or exc.__class__.__name__
        raise ConfigError(f"SSH CA (on this node): the certificate could not be reported to ZeroShield ({detail}); "
                          "it was not used") from None
    return line


def adapt_refresher(state_dir: str, key_path: str, fetch: Callable[[], dict] | None,
                    reporter: Callable[[str], Any] | None) -> Callable[[], dict] | None:
    """``CertSource``'s renewal: ZeroShield answers with a certificate (builtin and Vault CAs) or, for a node CA,
    with a grant this node signs here and reports.  The CA key file is read on the first grant only, so a node without
    one never needs it for the other providers."""
    if fetch is None:
        return None
    cache: dict[str, Any] = {}

    def renew() -> dict:
        fresh = fetch() or {}
        grant = fresh.get("node_sign")
        if not isinstance(grant, dict):
            return fresh
        if "signer" not in cache:
            cache["signer"] = NodeSigner.from_state(state_dir)
            cache["line"] = node_public_line(key_path)
        line = sign_and_report(cache["signer"], grant, cache["line"], reporter)
        return {"certificate": line, "expires_in_s": fresh.get("expires_in_s"), "serial": grant.get("serial"),
                "backdated_s": fresh.get("backdated_s")}

    return renew
