"""Scan-node request authentication beyond the node token: deployment id, Ed25519 request signatures, mTLS headers.

Deployment id
    One row in ``cbomdeployment`` (created by migration ``wp5a0node001``; created here on first use when a database was
    built without it), so every worker and replica stamps the same ``X-ZS-Deployment`` on every ``/cbom/node/*``
    response, 401s included (``NodeDeploymentHeader``).  A node clears its token only on a 401 that carries the id of
    the deployment it enrolled with AND says so explicitly (``X-ZS-Refused: node_token_revoked``, set by
    ``routers/cbom_node.py`` only when a well-formed node token arrived and no node has it); a 401 from anything else
    (a wrong ``ZS_API_URL``, a proxy, a token header a proxy dropped) leaves the token alone.
    Over plain HTTP (``ZS_ALLOW_INSECURE_HTTP``, labs only) a man in the middle can forge this header like anything else.

Signed requests
    At enrollment the node sends the public half of an Ed25519 key it generated for this enrollment.  From then on
    every request carries ``X-ZS-Timestamp`` (Unix seconds), ``X-ZS-Nonce`` and ``X-ZS-Signature`` (base64) over::

        METHOD \\n PATH \\n TIMESTAMP \\n NONCE \\n hex(sha256(raw body))

    The server checks the signature on the raw bytes before it parses them, refuses timestamps more than
    ``SKEW_S`` away from its clock, and stores each nonce until the timestamp is out of that window (``cbomnodenonce``,
    shared by every worker), so a captured request cannot be replayed.  A node with a key on file must sign every
    request (no downgrade); a node enrolled before signing existed is "legacy" until it enrolls again, and a team can
    refuse legacy nodes altogether (``require_signed_nodes``).  Refusals are 403 with ``X-ZS-Refused: <code>``: never
    401, which would make the node drop its token.

mTLS
    The TLS proxy (``deploy/staging/nginx``) verifies node client certificates and always overwrites
    ``X-ZS-Client-Verify`` and ``X-ZS-Client-Cert``.  The backend reads them only when ``CBOM_MTLS_HEADER_TRUSTED=1``
    (set it only when the backend port is reachable through that proxy alone).  ``CBOM_MTLS_REQUIRED=1`` refuses node
    requests without a verified certificate; ``CBOM_MTLS_PIN=1`` holds each node to the certificate it enrolled with.
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import hashlib
import os
import re
import threading
import time
import uuid
import weakref
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from fastapi import HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from backend.get_db import get_db
from backend.new_models import CbomDeployment, CbomNodeNonce, CbomScanNode
from backend.utilities.cbom_sources.common import iso_z, log

SKEW_S = 300  # accepted distance between the node's timestamp and the server clock, either way
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
DEPLOYMENT_HEADER = "X-ZS-Deployment"
REFUSED_HEADER = "X-ZS-Refused"
NODE_PREFIX = "/cbom/node/"

# ----------------------------------------------------------------------------- deployment id
_DEPLOYMENT: "weakref.WeakKeyDictionary[Any, str]" = weakref.WeakKeyDictionary()
_DEPLOYMENT_LOCK = threading.Lock()


def deployment_id(engine) -> str:
    """This deployment's stable id (cached per engine: it never changes once created)."""
    cached = _DEPLOYMENT.get(engine)
    if cached:
        return cached
    with _DEPLOYMENT_LOCK:
        cached = _DEPLOYMENT.get(engine)
        if cached:
            return cached
        with Session(engine) as session:
            row = session.get(CbomDeployment, 1)
            if row is None:
                try:
                    session.add(CbomDeployment(id=1, deployment_id=str(uuid.uuid4())))
                    session.commit()
                    log("deployment id created")
                except IntegrityError:  # another worker created it first: use theirs
                    session.rollback()
                row = session.get(CbomDeployment, 1)
            value = str(row.deployment_id)  # type: ignore[union-attr]
        _DEPLOYMENT[engine] = value
        return value


class NodeDeploymentHeader:
    """ASGI middleware: stamp ``X-ZS-Deployment`` on every ``/cbom/node/*`` response.  A middleware rather than the
    route, because 401s are raised inside the token check, 429s inside the limiter and 404/405 by the router."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or not str(scope.get("path") or "").startswith(NODE_PREFIX):
            await self.app(scope, receive, send)
            return
        value: str | None = None
        try:
            engine = get_db()
            value = _DEPLOYMENT.get(engine) or await run_in_threadpool(deployment_id, engine)
        except Exception as exc:  # the request itself will report the database problem
            log("deployment id unavailable", error=type(exc).__name__)
        if not value:
            await self.app(scope, receive, send)
            return
        stamp = (DEPLOYMENT_HEADER.lower().encode(), value.encode())

        async def send_with_id(message) -> None:
            if message.get("type") == "http.response.start":
                headers = [h for h in message.get("headers") or [] if h[0].lower() != stamp[0]]
                message = {**message, "headers": headers + [stamp]}
            await send(message)

        await self.app(scope, receive, send_with_id)


# ----------------------------------------------------------------------------- request facts
@dataclass(frozen=True)
class NodeRequest:
    method: str
    path: str
    timestamp: str | None = None
    nonce: str | None = None
    signature: str | None = None
    client_verify: str | None = None
    client_cert: str | None = None

    @classmethod
    def of(cls, request: Request) -> "NodeRequest":
        path = str(request.scope.get("path") or "")
        root = str(request.scope.get("root_path") or "")
        if root and path.startswith(root):
            path = path[len(root):]
        h = request.headers
        return cls(method=request.method.upper(), path=path, timestamp=h.get("x-zs-timestamp"),
                   nonce=h.get("x-zs-nonce"), signature=h.get("x-zs-signature"),
                   client_verify=h.get("x-zs-client-verify"), client_cert=h.get("x-zs-client-cert"))


def signing_message(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """The exact bytes a node signs (the node builds the same string in ``zs_scan_node/api.py``)."""
    return "\n".join((method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest())).encode()


def refuse(code: str, detail: str) -> HTTPException:
    return HTTPException(status_code=403, detail=detail, headers={REFUSED_HEADER: code})


def load_public_key(text: str):
    """Ed25519 public key from base64 of its 32 raw bytes; ValueError otherwise."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("signing_public_key is not base64") from None
    if len(raw) != 32:
        raise ValueError("signing_public_key must be a 32-byte Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_signature(session: Session, node_id: int, key_b64: str, req: NodeRequest, body: bytes,
                     now: _dt.datetime) -> None:
    """Check timestamp, signature and nonce; record the nonce (committed at once, so a replay of a request that later
    fails is refused too).  Raises 403 with a refusal code."""
    from cryptography.exceptions import InvalidSignature

    if not (req.timestamp and req.nonce and req.signature):
        raise refuse("signature_required", "This scan node signs its requests: the signature headers are missing")
    try:
        ts = int(req.timestamp)
    except ValueError:
        raise refuse("signature_invalid", "X-ZS-Timestamp must be Unix seconds") from None
    server_ts = int(now.replace(tzinfo=_dt.timezone.utc).timestamp())
    if abs(server_ts - ts) > SKEW_S:
        raise refuse("clock_skew", f"The request timestamp is {ts - server_ts:+d} s from server time {iso_z(now)}; "
                                   f"more than {SKEW_S} s is refused. Fix the node's clock (NTP).")
    if not NONCE_RE.match(req.nonce):
        raise refuse("signature_invalid", "X-ZS-Nonce must be 16-64 characters [A-Za-z0-9_-]")
    try:
        signature = base64.b64decode(req.signature, validate=True)
        load_public_key(key_b64).verify(signature, signing_message(req.method, req.path, req.timestamp, req.nonce, body))
    except (binascii.Error, ValueError, InvalidSignature):
        log("node request refused", node=node_id, reason="signature_invalid", path=req.path)
        raise refuse("signature_invalid", "The request signature does not verify with this node's key") from None
    expires = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).replace(tzinfo=None) + _dt.timedelta(seconds=SKEW_S + 60)
    try:
        session.add(CbomNodeNonce(node_id=node_id, nonce=req.nonce, expires_at=expires))
        session.commit()
    except IntegrityError:
        session.rollback()
        log("node request refused", node=node_id, reason="replay", path=req.path)
        raise refuse("replay", "This request was already received (nonce reused)") from None


_SWEPT = [0.0]


def sweep_nonces(session: Session, now: _dt.datetime, every_s: float = 60.0) -> int:
    """Delete expired nonces (at most once a minute per worker; any worker's sweep serves all)."""
    mono = time.monotonic()
    if mono - _SWEPT[0] < every_s:
        return 0
    _SWEPT[0] = mono
    result = session.exec(delete(CbomNodeNonce).where(CbomNodeNonce.expires_at < now))  # type: ignore[call-overload]
    return int(result.rowcount or 0)


# ----------------------------------------------------------------------------- mTLS
def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip() == "1"


def client_cert_sha256(req: NodeRequest) -> str | None:
    """SHA-256 of the DER client certificate the proxy verified, or None (headers not trusted, not verified, absent)."""
    if not _flag("CBOM_MTLS_HEADER_TRUSTED") or (req.client_verify or "").strip() != "SUCCESS" or not req.client_cert:
        return None
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    try:
        cert = x509.load_pem_x509_certificate(unquote(req.client_cert).encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return None
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def check_mtls(node: CbomScanNode | None, req: NodeRequest) -> str | None:
    """Apply CBOM_MTLS_REQUIRED / CBOM_MTLS_PIN; returns the verified certificate's SHA-256 (or None)."""
    required, pin = _flag("CBOM_MTLS_REQUIRED"), _flag("CBOM_MTLS_PIN")
    if not _flag("CBOM_MTLS_HEADER_TRUSTED"):
        if required:  # fail closed: the backend cannot know whether the proxy checked a certificate
            log("node request refused", reason="mtls_headers_not_trusted")
            raise refuse("client_cert_required", "This server requires scan-node client certificates but does not "
                                                 "trust its proxy's verification headers (CBOM_MTLS_HEADER_TRUSTED)")
        return None
    fingerprint = client_cert_sha256(req)
    if required and not fingerprint:
        log("node request refused", node=node.id if node else None, reason="client_cert_required", path=req.path)
        raise refuse("client_cert_required", "This server requires a client certificate from scan nodes")
    if pin and node is not None and node.client_cert_sha256 and fingerprint != node.client_cert_sha256:
        log("node request refused", node=node.id, reason="client_cert_mismatch", path=req.path)
        raise refuse("client_cert_mismatch", "This node enrolled with a different client certificate; reset the "
                                             "node to enroll it with the new one")
    return fingerprint


def signing_mode(node: CbomScanNode) -> str:
    return "required" if node.signing_public_key else "legacy"
