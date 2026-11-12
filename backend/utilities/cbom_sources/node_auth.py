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

    The server checks the signature on the raw bytes before it parses them and refuses timestamps more than
    ``SKEW_S`` away from its clock.  A captured request cannot be replayed:

    * protocol 2 (scan node 1.2+): the nonce is a per-node sequence number, ``s2_<19 digits>`` (dense within a node
      process, larger after every restart).  The node row keeps an anti-replay window (RFC 4303 section 3.4.3 / RFC
      6479): the highest sequence accepted (``replay_hwm``) and a bitmap of the ``REPLAY_WINDOW`` below it
      (``replay_bits``).  ONE conditional UPDATE of the node row checks and advances it (and stamps last-seen in the
      same statement), so requests that arrive slightly out of order are accepted, a repeat is refused, and two
      workers or replicas can never both accept the same sequence (the row lock serialises them and the WHERE is
      re-checked).  A sequence below the window is refused with ``replay_window`` and ``X-ZS-Seq-Next``: a node whose
      clock went back across a restart re-bases its counter there and signs again.  No row is inserted.
      The window belongs to one credential: the UPDATE also requires the node's current signing key and token hash,
      and enrolling, re-binding a pool pod or a Reset clears it, so a request signed before a Reset can never advance
      the next enrollment's window (security review S1).  A sequence more than ``SEQ_AHEAD_US`` (30 days) of
      microseconds ahead of the server clock is refused with ``seq_out_of_range`` and ``X-ZS-Seq-Next`` set to
      ``max(hwm + 1, now_us << 11)``, so no injected sequence can push the window out of reach of an honest node.
      Only an accepted request commits its window step; a refused one rolls back and changes nothing (S2).
    * enrollments (``enrollment=True``) record their nonce, whatever its form, in ``cbomnodenonce`` inside the
      enrollment's own transaction: an enrollment binds a new key, so it cannot be checked against a window that
      belongs to the previous one, and a replayed pool re-bind is refused without changing anything.
    * protocol 1 (scan node 1.0/1.1, random nonces): each nonce is stored until its timestamp is outside the window
      (``cbomnodenonce``, shared by every worker), exactly as before.  A ``s2_`` nonce sent to an older server is just
      a nonce there, so new nodes work against older servers too.

    A node with a key on file must sign every request (no downgrade); a node enrolled before signing existed is
    "legacy" until it enrolls again, and a team can refuse legacy nodes altogether (``require_signed_nodes``).
    Refusals are 403 with ``X-ZS-Refused: <code>``: never 401, which would make the node drop its token.

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
from sqlalchemy import BigInteger, Integer, and_, case, cast, delete, literal, or_, update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import CbomDeployment, CbomNodeNonce, CbomScanNode
from backend.utilities.cbom_sources.common import iso_z, log

SKEW_S = 300  # accepted distance between the node's timestamp and the server clock, either way
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
SEQ_NONCE_RE = re.compile(r"^s2_([0-9]{19})$")  # protocol 2: a per-node sequence number
SEQ_SHIFT = 11  # counter bits below the process-start microsecond (scan_node/zs_scan_node/api.py)
SEQ_AHEAD_US = 30 * 86_400 * 1_000_000  # a sequence may run at most 30 days of microseconds ahead of server time
REPLAY_WINDOW = 63  # sequences below the highest accepted one that are still remembered (bits 0..62 of a BIGINT)
_WINDOW_MASK = (1 << REPLAY_WINDOW) - 1
SEQ_NEXT_HEADER = "X-ZS-Seq-Next"
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
    """ASGI middleware for every ``/cbom/node/*`` request (a middleware rather than the route, because 401s are raised
    inside the token check, 429s inside the limiter and 404/405 by the router):

    * stamps ``X-ZS-Deployment``;
    * admission (DA D5): when this worker already has ``CBOM_NODE_MAX_INFLIGHT`` node requests in flight, a claim or
      an enrollment is answered 429 with a jittered ``Retry-After`` of 5-15 s before its body is read or anything
      touches the database; heartbeats, results and assets are never shed (a shed heartbeat would cost a lease);
    * instrumentation (DA section 4, ``node_obs``): ``X-ZS-Request-Id`` (echoed when the node sent one),
      ``Server-Timing: app;dur=<ASGI entry to response start>, tp;dur=<node threadpool wait>, pool;dur=<connection
      checkout>``, per-kind counters and latency buckets, the slow-request line, and the per-worker stats line;
    * a 401 ``node_token_revoked`` evicts the token from the rate limiter's node-id cache (DA E1)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or not str(scope.get("path") or "").startswith(NODE_PREFIX):
            await self.app(scope, receive, send)
            return
        from backend.utilities.cbom_sources import node_obs as OBS

        value: str | None = None
        try:
            engine = get_db()
            value = _DEPLOYMENT.get(engine) or await OBS.to_node_thread(deployment_id, engine)
        except Exception as exc:  # the request itself will report the database problem
            log("deployment id unavailable", error=type(exc).__name__)
        await OBS.serve(self.app, scope, receive, send, value)


# ----------------------------------------------------------------------------- one connection per request (DA E3)
import contextlib  # noqa: E402

ONE_CONNECTION = [os.environ.get("CBOM_NODE_ONE_CONNECTION", "1") != "0"]


@contextlib.contextmanager
def node_session(engine):
    """The Session a node route works in.  With one connection per request (DA E3) the Session is bound to ONE pooled
    connection for the whole request, so the replay-window step's own commit and the work after it share a single
    checkout and pre-ping.  ``join_transaction_mode="control_fully"``: the Session's commit really commits on the
    connection (the default mode would turn it into a savepoint release when the connection already had a
    transaction: the window step would look committed and be lost, cx3 S-1).  The connection must be fresh."""
    if not ONE_CONNECTION[0]:
        with Session(engine, expire_on_commit=False) as session:
            yield session
        return
    with engine.connect() as conn:
        with bind_fresh(conn) as session:
            yield session


def bind_fresh(conn):
    """A Session in full control of ``conn``; refuses a connection that already ran a statement."""
    if conn.in_transaction():
        raise RuntimeError("node_session: the connection already has a transaction; bind only a fresh connection")
    return Session(bind=conn, join_transaction_mode="control_fully", expire_on_commit=False)


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


def seq_of(nonce: str | None) -> int | None:
    """The sequence number of a protocol-2 nonce, or None (a protocol-1 random nonce).  An ``s2_`` nonce outside
    1..2^63-1 is refused (``signature_invalid``), never treated as a random protocol-1 nonce (E8)."""
    m = SEQ_NONCE_RE.match(nonce or "")
    if not m:
        return None
    value = int(m.group(1))
    if not 0 < value < (1 << 63):
        raise refuse("signature_invalid", "X-ZS-Nonce: a sequence nonce must be below 2^63")
    return value


def seq_floor(now: _dt.datetime) -> int:
    """The lowest sequence an honest node signing now would use: server time in microseconds, shifted."""
    return int(now.replace(tzinfo=_dt.timezone.utc).timestamp() * 1_000_000) << SEQ_SHIFT


def seq_in_range(seq: int, now: _dt.datetime) -> bool:
    """A sequence's time part may be at most ``SEQ_AHEAD_US`` ahead of server time."""
    now_us = int(now.replace(tzinfo=_dt.timezone.utc).timestamp() * 1_000_000)
    return (seq >> SEQ_SHIFT) <= now_us + SEQ_AHEAD_US


def window_accepts(hwm: int, bits: int, seq: int) -> tuple[bool, int, int]:
    """Reference anti-replay window (what ``_record_seq`` does in one UPDATE): (accepted, new hwm, new bits).
    Bit k of ``bits`` set = sequence ``hwm - k`` was accepted."""
    if seq > hwm:
        shift = seq - hwm
        return True, seq, (1 if shift >= REPLAY_WINDOW else ((bits << shift) | 1) & _WINDOW_MASK)
    k = hwm - seq
    if k >= REPLAY_WINDOW or bits & (1 << k):
        return False, hwm, bits
    return True, hwm, bits | (1 << k)


def _record_seq(session: Session, node_id: int, seq: int, touch: dict[str, Any] | None,
                key_b64: str | None = None, token_hash: str | None = None) -> bool:
    """Check and advance the node's anti-replay window in ONE conditional UPDATE (plus ``touch``, e.g. last-seen
    columns, in the same statement).  True = accepted and COMMITTED (the sequence stays consumed even if the work
    after it fails); False = refused and ROLLED BACK, so a refused request changes nothing (S2).  The window is bound
    to the credential: ``key_b64`` / ``token_hash`` must still be the node's (a Reset or a new enrollment in between
    refuses the request).  The shift amounts are clamped to 0..62 inside the expressions so no branch PostgreSQL
    evaluates early can overflow."""
    hwm, bits = CbomScanNode.replay_hwm, CbomScanNode.replay_bits
    s = literal(seq, BigInteger)
    ahead = s - hwm   # > 0: a new highest sequence
    behind = hwm - s  # >= 0: inside or below the window

    def clamp(expr):
        return cast(case((and_(expr >= 0, expr < REPLAY_WINDOW), expr), else_=0), Integer)

    one = cast(literal(1), BigInteger)  # a typed 1: an untyped one is int4 on PostgreSQL, and 1 << 40 wraps there
    new_bits = case(
        (ahead >= REPLAY_WINDOW, one),
        (ahead > 0, (bits.op("<<")(clamp(ahead)).op("|")(one)).op("&")(literal(_WINDOW_MASK, BigInteger))),
        else_=bits.op("|")(one.op("<<")(clamp(behind))),
    )
    fresh = or_(ahead > 0, and_(behind < REPLAY_WINDOW, bits.op("&")(one.op("<<")(clamp(behind))) == 0))
    bound = [CbomScanNode.id == node_id, fresh]
    if key_b64 is not None:
        bound.append(CbomScanNode.signing_public_key == key_b64)
    if token_hash is not None:
        bound.append(CbomScanNode.node_token_hash == token_hash)
    changed = session.exec(  # type: ignore[call-overload]
        update(CbomScanNode).where(*bound)
        .values(replay_hwm=case((ahead > 0, s), else_=hwm), replay_bits=new_bits, **(touch or {}))
        .execution_options(synchronize_session=False)
    ).rowcount
    if changed != 1:
        session.rollback()
        return False
    session.commit()
    return True


def verify_signature(session: Session, node_id: int, key_b64: str, req: NodeRequest, body: bytes,
                     now: _dt.datetime, touch: dict[str, Any] | None = None, *, token_hash: str | None = None,
                     enrollment: bool = False) -> bool:
    """Check timestamp, signature and nonce; record the nonce (committed at once, so a replay of a request that later
    fails is refused too).  Raises 403 with a refusal code; a refused request changes nothing.

    ``touch``: node columns to set in the same statement when the request uses protocol-2 sequence nonces (the
    heartbeat's and claim's last-seen stamp).  Returns True when they were written, False when the caller must write
    them itself (protocol 1, enrollments).  ``token_hash``: the request's node-token hash; the window step requires
    it (and ``key_b64``) to still be the node's.  ``enrollment``: the nonce goes to ``cbomnodenonce`` in the caller's
    transaction, which commits it together with the enrollment (or rolls both back)."""
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
    seq = seq_of(req.nonce)
    if seq is not None and not seq_in_range(seq, now):
        hwm = session.exec(select(CbomScanNode.replay_hwm).where(CbomScanNode.id == node_id)).first() or 0
        session.rollback()
        log("node request refused", node=node_id, reason="seq_out_of_range", path=req.path)
        raise HTTPException(status_code=403, detail="This request's sequence number is too far ahead of server time; "
                                                    "sign it again from X-ZS-Seq-Next",
                            headers={REFUSED_HEADER: "seq_out_of_range",
                                     SEQ_NEXT_HEADER: str(max(hwm + 1, seq_floor(now)))})
    if enrollment:
        _store_nonce(session, node_id, req, ts, commit=False)
        return False
    if seq is not None:
        if _record_seq(session, node_id, seq, touch, key_b64, token_hash):
            return bool(touch)
        row = session.exec(select(CbomScanNode.replay_hwm, CbomScanNode.signing_public_key,
                                  CbomScanNode.node_token_hash).where(CbomScanNode.id == node_id)).first()
        session.rollback()
        hwm = int(row[0] or 0) if row else 0
        if row is None or row[1] != key_b64 or (token_hash is not None and row[2] != token_hash):
            log("node request refused", node=node_id, reason="credential_changed", path=req.path)
            raise refuse("credential_changed", "This node was reset or enrolled again while the request was in "
                                               "flight; it was not applied")
        if seq <= hwm - REPLAY_WINDOW:
            log("node request refused", node=node_id, reason="replay_window", path=req.path, behind=hwm - seq)
            raise HTTPException(status_code=403, detail="This request's sequence number is older than the replay "
                                                        "window; sign it again with a newer one",
                                headers={REFUSED_HEADER: "replay_window", SEQ_NEXT_HEADER: str(hwm + 1)})
        log("node request refused", node=node_id, reason="replay", path=req.path)
        raise refuse("replay", "This request was already received (sequence reused)")
    _store_nonce(session, node_id, req, ts, commit=True)
    return False


def _store_nonce(session: Session, node_id: int, req: NodeRequest, ts: int, *, commit: bool) -> None:
    """Record a nonce in ``cbomnodenonce`` until its timestamp leaves the window (protocol 1, and every enrollment).
    ``commit`` False: inside the caller's transaction (flushed now, committed with the caller's work).  A repeat is
    refused (403 ``replay``) and the transaction rolled back."""
    expires = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).replace(tzinfo=None) + _dt.timedelta(seconds=SKEW_S + 60)
    try:
        session.add(CbomNodeNonce(node_id=node_id, nonce=req.nonce, expires_at=expires))
        if commit:
            session.commit()
        else:
            session.flush()
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
