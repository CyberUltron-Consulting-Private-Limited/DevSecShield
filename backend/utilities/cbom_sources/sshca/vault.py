"""HashiCorp Vault SSH secrets engine (the optional CA provider), called from ZeroShield's servers.

The Vault address is customer input, so every call is SSRF-checked like ``safe_fetch``: https only, every address the
name resolves to must be public (private addresses only when the operator lists them in
``CBOM_SSHCA_VAULT_ALLOWED_PRIVATE``, CIDRs or host names; loopback, link-local/metadata, CGNAT and the like never),
the connection goes to the checked addresses, the certificate is verified for the name (the CA's ``ca_pem`` when set),
no proxy, no redirects (point it at the active node), 1 MB body cap, 30 s per call.

Endpoints: ``GET /v1/<mount>/public_key`` (the CA key, unauthenticated), ``POST /v1/<mount>/sign/<role>`` (sign),
``POST /v1/auth/approle/login`` (AppRole).  Tokens are sent only in ``X-Vault-Token`` and never logged.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from backend.utilities.cbom_sources import safe_fetch as SF
from backend.utilities.cbom_sources.kinds import check_pem_certificates

ALLOW_ENV = "CBOM_SSHCA_VAULT_ALLOWED_PRIVATE"
_MOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}){0,3}$")
_ROLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_NAMESPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}){0,7}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._-]{8,512}$")
_UUIDISH = re.compile(r"^[A-Za-z0-9._-]{8,256}$")


class VaultError(Exception):
    """``str(err)`` is safe to show (no token, no key)."""


def check_config(cfg: dict[str, Any] | None) -> dict[str, Any]:
    cfg = dict(cfg or {})
    addr = str(cfg.get("addr") or "").strip().rstrip("/")
    parts = urlsplit(addr)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query \
            or parts.fragment or parts.path not in ("", "/"):
        raise VaultError("vault_config.addr: the Vault address must be https://host[:port] with no path")
    try:
        port = parts.port or 443
    except ValueError:
        raise VaultError("vault_config.addr: invalid port") from None
    if port != 443 and port < 1024:
        raise VaultError("vault_config.addr: the port must be 443 or above 1023")
    mount = str(cfg.get("mount") or "ssh-client-signer").strip().strip("/")
    if ".." in mount or not _MOUNT.match(mount):
        raise VaultError("vault_config.mount: letters, digits and . _ - (the SSH engine's mount path)")
    role = str(cfg.get("role") or "").strip()
    if not _ROLE.match(role):
        raise VaultError("vault_config.role: the SSH engine role that signs (letters, digits and . _ -)")
    namespace = str(cfg.get("namespace") or "").strip().strip("/") or None
    if namespace and (".." in namespace or not _NAMESPACE.match(namespace)):
        raise VaultError("vault_config.namespace: letters, digits and . _ - separated by /")
    try:
        ca_pem = check_pem_certificates(cfg.get("ca_pem") or None)
    except ValueError as exc:
        raise VaultError(f"vault_config.ca_pem: {exc}") from None
    extra = set(cfg) - {"addr", "mount", "role", "namespace", "ca_pem"}
    if extra:
        raise VaultError(f"vault_config.{sorted(extra)[0]}: not a Vault setting")
    return {"addr": addr, "mount": mount, "role": role, "namespace": namespace, "ca_pem": ca_pem}


def check_secrets(secrets: dict[str, str] | None) -> dict[str, str]:
    secrets = {k: v for k, v in (secrets or {}).items() if isinstance(v, str) and v}
    if set(secrets) - {"token", "role_id", "secret_id"}:
        raise VaultError("secrets: use token, or role_id and secret_id (AppRole)")
    if "token" in secrets:
        if not _TOKEN.match(secrets["token"]) or "role_id" in secrets or "secret_id" in secrets:
            raise VaultError("secrets.token: a Vault token (or AppRole role_id and secret_id, not both)")
        return {"token": secrets["token"]}
    if not (_UUIDISH.match(secrets.get("role_id", "")) and _UUIDISH.match(secrets.get("secret_id", ""))):
        raise VaultError("secrets: a Vault token, or AppRole role_id and secret_id, is required")
    return {"role_id": secrets["role_id"], "secret_id": secrets["secret_id"]}


def _allowlist() -> SF.PrivateAllowlist:
    return SF.parse_private_allowlist(os.environ.get(ALLOW_ENV), ALLOW_ENV)


def _context(ca_pem: str | None) -> ssl.SSLContext:
    if not ca_pem:
        return SF._context()
    ctx = ssl.create_default_context(cadata=ca_pem)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def call(cfg: dict[str, Any], method: str, path: str, *, token: str | None = None,
         body: dict[str, Any] | None = None) -> tuple[int, Any]:
    """(status, parsed JSON or text).  ``cfg`` is a checked config.  Raises ``VaultError``."""
    parts = urlsplit(cfg["addr"])
    host, port = parts.hostname or "", parts.port or 443
    try:
        addresses = SF._resolve(host, port, SF._lab_private_allowed(), _allowlist())
    except SF.FetchError as exc:
        text = str(exc).replace("only public metadata URLs can be read",
                                "only public Vault addresses can be used")
        text = text.replace("private IdP addresses can be allowed in", "private Vault addresses can be allowed in")
        raise VaultError(text) from None
    conn = SF._PinnedHTTPS(host, addresses, port, _context(cfg.get("ca_pem")))
    deadline = time.monotonic() + SF.TOTAL_TIMEOUT
    timer = threading.Timer(SF.TOTAL_TIMEOUT, SF._abort, (conn,))
    timer.daemon = True
    timer.start()
    headers = {"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": "ZeroShield-CBOM/1.0",
               "Host": parts.netloc}
    if token:
        headers["X-Vault-Token"] = token
    if cfg.get("namespace"):
        headers["X-Vault-Namespace"] = cfg["namespace"]
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        if resp.status in (301, 302, 303, 307, 308):
            raise VaultError("Vault answered with a redirect; use the address of the active Vault node")
        raw = SF._read_capped(resp, conn, deadline)
        status = resp.status
    except ssl.SSLCertVerificationError as exc:
        raise VaultError(f"the TLS certificate of {host} is not trusted ({exc.verify_message}); add its CA "
                         "certificate") from None
    except SF.FetchError as exc:
        raise VaultError(str(exc).replace("document", "answer")) from None
    except VaultError:
        raise
    except Exception as exc:
        raise VaultError(f"could not reach Vault at {host} ({type(exc).__name__})") from None
    finally:
        timer.cancel()
        conn.close()
    try:
        data: Any = json.loads(raw) if raw else {}
    except ValueError:
        data = raw.decode("utf-8", "replace")
    return status, data


def _errors(data: Any) -> str:
    if isinstance(data, dict) and isinstance(data.get("errors"), list):
        return "; ".join(str(e)[:200] for e in data["errors"][:3])
    return ""


def login(cfg: dict[str, Any], secrets: dict[str, str]) -> str:
    if secrets.get("token"):
        return secrets["token"]
    status, data = call(cfg, "POST", "/v1/auth/approle/login",
                        body={"role_id": secrets.get("role_id"), "secret_id": secrets.get("secret_id")})
    token = (data.get("auth") or {}).get("client_token") if isinstance(data, dict) else None
    if status != 200 or not isinstance(token, str):
        raise VaultError(f"Vault AppRole login was refused ({status})")
    return token


def public_key(cfg: dict[str, Any]) -> str:
    status, data = call(cfg, "GET", f"/v1/{cfg['mount']}/public_key")
    text = data if isinstance(data, str) else ""
    if status != 200 or not text.strip():
        raise VaultError(f"Vault did not return the SSH CA public key of mount {cfg['mount']} ({status})")
    return text.strip().splitlines()[0].strip()


def sign(cfg: dict[str, Any], secrets: dict[str, str], *, public_key_line: str, principals: list[str], ttl_s: int,
         key_id: str, source_addresses: list[str]) -> str:
    """The signed certificate text (checked by the caller)."""
    token = login(cfg, secrets)
    body: dict[str, Any] = {"public_key": public_key_line, "valid_principals": ",".join(principals),
                            "ttl": f"{int(ttl_s)}s", "cert_type": "user", "key_id": key_id, "extensions": {}}
    if source_addresses:
        body["critical_options"] = {"source-address": ",".join(source_addresses)}
    status, data = call(cfg, "POST", f"/v1/{cfg['mount']}/sign/{cfg['role']}", token=token, body=body)
    signed = ((data.get("data") or {}).get("signed_key") if isinstance(data, dict) else None)
    if status != 200 or not isinstance(signed, str):
        detail = _errors(data)
        raise VaultError(f"Vault refused to sign ({status}{': ' + detail if detail else ''})")
    return signed.strip()
