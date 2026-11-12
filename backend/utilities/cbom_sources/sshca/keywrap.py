"""CA private keys at rest (contract section 9: AWS KMS when one is configured, otherwise the deployment key).

``fernet``  the deployment's ``ENCRYPTION_KEY`` (``backend/utilities/db/encryption.py``).  The plaintext carries the
            team and the CA fingerprint, checked on unwrap, so a wrapped key copied onto another CA row or team is
            refused.  Refused for new keys while the deployment configures KMS (no opt-out, sec M2).
``aws_kms`` envelope encryption: ``GenerateDataKey`` (AES-256) under a KMS key from the deployment's allow-list
            ``CBOM_SSHCA_KMS_KEY_ARNS`` (comma-separated; the first one is the default for new CAs), with the
            EncryptionContext ``{zs:purpose, zs:team, zs:ca_fp}``; the CA key is sealed with AES-GCM using that context
            as associated data.  Only the KMS-encrypted data key, the nonce and the ciphertext are stored.  A team admin
            can only pick a key the deployment listed (no confused deputy over the backend's KMS permissions), and sees
            it only as an opaque label (``kms-<8 hex>``), never the ARN (account id, region, key id).

KMS client: one per region, ``connect_timeout`` 2 s, ``read_timeout`` 5 s, standard retries, 3 attempts in all.  Errors
reach the customer as plain text (``WrapError``): a missing grant, a disabled key and the like are configuration
faults; throttling, KMS internal errors, timeouts and connection failures are ``transient`` (the node route answers
503 with ``Retry-After``, the claim leaves the certificate to the route).

Unwrapped keys (per worker): one thread unwraps a key while the others wait for it (single flight), and the flight's
outcome is shared: when the unwrap fails, the threads that waited for it get the same error at once, and every caller
for the next ``NEGATIVE_CACHE_S`` (10 s) gets it without calling KMS again; after that one caller asks KMS again while
the others keep getting the last error at once instead of queueing behind that call (a failing call can take 16 s
with ``client_config()``'s timeouts and retries).  So an outage costs one KMS call per CA and worker at a time, and
only that one thread waits for it (architecture re-review 5874161772).  An entry lives at
most ``CACHE_SECONDS`` (contract: 10 minutes): expired entries are removed on every call and by a background sweeper
every ``SWEEP_EVERY_S`` while anything is cached, so no key stays in memory more than ``CACHE_SECONDS +
SWEEP_EVERY_S`` after it was unwrapped.  A CA that is no longer active drops its entry when this worker sees it
(``ca._Base``), and revoke / promote drop it on the worker that served them.  Nothing here logs key material: errors
carry no key, no ARN and no exception text from AWS.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.utilities.cbom_sources.sshca import certs as C

PURPOSE = "devsecshield-sshca"
CACHE_SECONDS = 600
SWEEP_EVERY_S = 30
NEGATIVE_CACHE_S = 10.0  # a failed unwrap is answered from memory this long (no KMS call per request in an outage)
FAILURE_KEEP_S = 300.0  # ... and while KMS is asked again within this time, the others get it instead of waiting
KMS_ENV = "CBOM_SSHCA_KMS_KEY_ARNS"
_ARN = re.compile(r"^arn:aws(-cn|-us-gov)?:kms:([a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d):(\d{12}):(key|alias)/[A-Za-z0-9/_+=,.@:-]{1,256}$")


class WrapError(Exception):
    """``str(err)`` is safe to show.  ``transient``: AWS KMS did not answer (throttled, internal error, timeout);
    asking again later may work.  ``code``: a short reason code for the audit and the log."""

    def __init__(self, message: str, *, transient: bool = False, code: str = "ca_key_unavailable") -> None:
        super().__init__(message)
        self.transient = transient
        self.code = code


def allowed_kms_keys() -> list[str]:
    raw = os.environ.get(KMS_ENV, "")
    return [part.strip() for part in raw.split(",") if _ARN.match(part.strip())]


def kms_label(arn: str | None) -> str | None:
    """The opaque name a browser sees for a KMS key ARN (stable for one ARN; reveals nothing about it)."""
    if not arn:
        return None
    return "kms-" + hashlib.sha256(arn.encode()).hexdigest()[:8]


def kms_choices() -> list[dict[str, object]]:
    """``[{"label", "default"}]`` of the deployment's allow-list, for the CA form (never the ARNs)."""
    return [{"label": kms_label(arn), "default": i == 0} for i, arn in enumerate(allowed_kms_keys())]


def resolve_kms_key(ref: str | None) -> str | None:
    """A label (or, for operators, the ARN itself) -> an allowed ARN, or None."""
    if not ref:
        return None
    for arn in allowed_kms_keys():
        if ref in (arn, kms_label(arn)):
            return arn
    return None


def default_wrap() -> tuple[str, str | None]:
    """("aws_kms", arn) when the deployment configured KMS keys, else ("fernet", None)."""
    keys = allowed_kms_keys()
    return ("aws_kms", keys[0]) if keys else ("fernet", None)


def kms_configured() -> bool:
    return bool(allowed_kms_keys())


def kms_region(arn: str) -> str:
    match = _ARN.match(arn)
    if not match:
        raise WrapError("kms_key_ref is not a KMS key ARN")
    return match.group(2)


def _context(team_id: int, ca_fingerprint: str) -> dict[str, str]:
    return {"zs:purpose": PURPOSE, "zs:team": str(team_id), "zs:ca_fp": ca_fingerprint}


def _aad(context: dict[str, str]) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode()


# A factory so tests (moto, Stubber) and the live proof can hand in their own client; production uses boto3's default
# credential chain, one client per region (a client is thread-safe; creating one is not, and costs 15-20 ms).
_kms_factory: Callable[[str], Any] | None = None
_clients: dict[str, Any] = {}
_clients_lock = threading.Lock()


def set_kms_client_factory(factory: Callable[[str], Any] | None) -> None:
    global _kms_factory
    _kms_factory = factory


def client_config():
    from botocore.config import Config

    # 3 attempts in all (botocore: max_attempts counts retries, total_max_attempts every attempt)
    return Config(connect_timeout=2, read_timeout=5, retries={"mode": "standard", "total_max_attempts": 3})


def _kms(region: str):
    if _kms_factory is not None:
        return _kms_factory(region)
    with _clients_lock:
        client = _clients.get(region)
        if client is None:
            import boto3

            client = boto3.client("kms", region_name=region, config=client_config())
            _clients[region] = client
        return client


_TRANSIENT_CODES = frozenset({
    "ThrottlingException", "Throttling", "RequestLimitExceeded", "TooManyRequestsException", "LimitExceededException",
    "KMSInternalException", "InternalFailure", "InternalError", "ServiceUnavailable", "ServiceUnavailableException",
    "DependencyTimeoutException", "RequestTimeout", "RequestTimeoutException"})


def _kms_failure(exc: BaseException, action: str, key_ref: str | None) -> WrapError:
    """Plain text for a failed KMS call (no ARN, no AWS message, no exception class)."""
    label = kms_label(key_ref) or "the KMS key"
    code = None
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = str((response.get("Error") or {}).get("Code") or "") or None
    if code in ("AccessDeniedException", "AccessDenied", "UnauthorizedOperation"):
        return WrapError(f"the backend's AWS role may not use the SSH CA's KMS key {label} (operator: allow "
                         f"kms:{action} on it)", code="kms_access_denied")
    if code in ("DisabledException", "KMSInvalidStateException"):
        return WrapError(f"the SSH CA's KMS key {label} is disabled or pending deletion (operator: enable it, or "
                         "rotate the CA onto another key)", code="kms_key_disabled")
    if code in ("NotFoundException",):
        return WrapError(f"the SSH CA's KMS key {label} does not exist in this AWS account and region",
                         code="kms_key_not_found")
    if code in ("IncorrectKeyException", "InvalidCiphertextException"):
        return WrapError("the wrapped CA key does not belong to this KMS key or this CA", code="kms_wrong_key")
    if code in _TRANSIENT_CODES:
        return WrapError("AWS KMS is not answering right now (throttled or busy); try again in a moment",
                         transient=True, code="kms_unavailable")
    if code:
        return WrapError(f"AWS KMS refused to {action.lower()} the CA key (error code {code[:64]})", code="kms_refused")
    name = type(exc).__name__
    if name in ("NoCredentialsError", "PartialCredentialsError", "NoRegionError"):
        return WrapError("the backend has no usable AWS credentials for KMS (operator)", code="kms_no_credentials")
    # connection errors, connect/read timeouts and anything else that never got an AWS answer
    return WrapError("AWS KMS could not be reached; try again in a moment", transient=True, code="kms_unavailable")


def wrap(private_pem: bytes, *, team_id: int, ca_fingerprint: str, key_wrap: str, kms_key_ref: str | None) -> str:
    if key_wrap == "fernet":
        from backend.utilities.db.encryption import encrypt_value

        doc = {"v": 1, "team": team_id, "fp": ca_fingerprint, "key": private_pem.decode()}
        return "fernet:" + encrypt_value(json.dumps(doc, separators=(",", ":")))
    if key_wrap == "aws_kms":
        if not kms_key_ref or kms_key_ref not in allowed_kms_keys():
            raise WrapError(f"kms_key_ref must be one of the KMS keys this deployment allows ({KMS_ENV})")
        context = _context(team_id, ca_fingerprint)
        try:
            out = _kms(kms_region(kms_key_ref)).generate_data_key(KeyId=kms_key_ref, KeySpec="AES_256",
                                                                   EncryptionContext=context)
        except Exception as exc:
            raise _kms_failure(exc, "GenerateDataKey", kms_key_ref) from None
        nonce = secrets.token_bytes(12)
        sealed = AESGCM(out["Plaintext"]).encrypt(nonce, private_pem, _aad(context))
        doc = {"v": 1, "key_ref": kms_key_ref, "edk": base64.b64encode(out["CiphertextBlob"]).decode(),
               "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(sealed).decode()}
        return "aws_kms:" + json.dumps(doc, separators=(",", ":"))
    raise WrapError("key_wrap must be fernet or aws_kms")


def unwrap(blob: str, *, team_id: int, ca_fingerprint: str) -> bytes:
    """The OpenSSH private key, or ``WrapError``.  Bound to (team, CA fingerprint)."""
    if not blob:
        raise WrapError("this CA has no private key")
    scheme, _, body = blob.partition(":")
    if scheme == "fernet":
        from backend.utilities.db.encryption import decrypt_value

        try:
            doc = json.loads(decrypt_value(body))
        except Exception:
            raise WrapError("the CA key could not be decrypted with this deployment's ENCRYPTION_KEY") from None
        if doc.get("team") != team_id or doc.get("fp") != ca_fingerprint:
            raise WrapError("the wrapped CA key belongs to another CA")
        return str(doc["key"]).encode()
    if scheme == "aws_kms":
        try:
            doc = json.loads(body)
            edk, nonce, sealed = (base64.b64decode(doc[k]) for k in ("edk", "nonce", "ct"))
            key_ref = str(doc["key_ref"])
        except Exception:
            raise WrapError("the wrapped CA key is damaged") from None
        context = _context(team_id, ca_fingerprint)
        try:
            out = _kms(kms_region(key_ref)).decrypt(CiphertextBlob=edk, KeyId=key_ref, EncryptionContext=context)
        except WrapError:
            raise
        except Exception as exc:
            raise _kms_failure(exc, "Decrypt", key_ref) from None
        try:
            return AESGCM(out["Plaintext"]).decrypt(nonce, sealed, _aad(context))
        except Exception:
            raise WrapError("the wrapped CA key does not belong to this CA") from None
    raise WrapError("unknown key wrap")


# ----------------------------------------------------------------------------- per-worker cache
_cache: dict[tuple[int, str], tuple[float, Any]] = {}
_cache_lock = threading.Lock()
_inflight: dict[tuple[int, str], threading.Lock] = {}
_failed: dict[tuple[int, str], tuple[float, float, str, bool, str]] = {}  # fresh until, kept until, message, ...
_sweeper: threading.Thread | None = None


def _sweep_locked(now: float) -> int:
    expired = [k for k, (until, _key) in _cache.items() if until <= now]
    for k in expired:
        del _cache[k]
    for k in [k for k, (_fresh, kept, *_rest) in _failed.items() if kept <= now]:
        del _failed[k]
    for k in [k for k, lock in _inflight.items() if k not in _cache and k not in _failed and not lock.locked()]:
        del _inflight[k]
    return len(expired)


def _failure_locked(key: tuple[int, str], now: float, *, retrying: bool = False) -> WrapError | None:
    """The remembered failure of the last unwrap of ``key`` while it is fresh, or while another thread is asking KMS
    again (``retrying``).  A new exception object per caller: one instance raised in several threads would share its
    traceback."""
    hit = _failed.get(key)
    if hit is None or (hit[0] <= now and not retrying):
        return None
    return WrapError(hit[2], transient=hit[3], code=hit[4])


def sweep() -> int:
    """Drop every expired entry; the number dropped."""
    with _cache_lock:
        return _sweep_locked(time.monotonic())


def _sweep_loop() -> None:
    global _sweeper
    while True:
        time.sleep(SWEEP_EVERY_S)
        with _cache_lock:
            _sweep_locked(time.monotonic())
            if not _cache:
                _sweeper = None
                return


def _ensure_sweeper_locked() -> None:
    global _sweeper
    if _sweeper is None or not _sweeper.is_alive():
        _sweeper = threading.Thread(target=_sweep_loop, name="sshca-key-sweeper", daemon=True)
        _sweeper.start()


def is_cached(ca_id: int, ca_fingerprint: str) -> bool:
    """This worker holds the unwrapped key now (signing needs no KMS call)."""
    with _cache_lock:
        _sweep_locked(time.monotonic())
        return (ca_id, ca_fingerprint) in _cache


def cached_private_key(ca_id: int, team_id: int, ca_fingerprint: str, blob: str):
    """The CA's private key object, unwrapped at most once per ``CACHE_SECONDS`` in this worker (one thread unwraps,
    the others wait for it)."""
    key = (ca_id, ca_fingerprint)
    with _cache_lock:
        now = time.monotonic()
        _sweep_locked(now)
        hit = _cache.get(key)
        if hit:
            return hit[1]
        flight = _inflight.setdefault(key, threading.Lock())
        failed = _failure_locked(key, now, retrying=flight.locked())
        if failed is not None:
            raise failed  # an unwrap failed a moment ago, or KMS is being asked again right now: no wait, no call
    with flight:
        with _cache_lock:
            now = time.monotonic()
            hit = _cache.get(key)  # another thread unwrapped it while this one waited
            if hit and hit[0] > now:
                return hit[1]
            failed = _failure_locked(key, now)  # ... or failed to: share its outcome
            if failed is not None:
                raise failed
        try:
            pem = unwrap(blob, team_id=team_id, ca_fingerprint=ca_fingerprint)
        except WrapError as exc:
            with _cache_lock:
                now = time.monotonic()
                _failed[key] = (now + NEGATIVE_CACHE_S, now + FAILURE_KEEP_S, str(exc), exc.transient, exc.code)
            raise
        try:
            private = C.private_from_openssh(pem)
        except Exception:
            raise WrapError("the unwrapped CA key could not be read") from None
        finally:
            pem = b""
        if C.fingerprint(C.public_line(private)) != ca_fingerprint:
            raise WrapError("the unwrapped CA key does not match the CA's public key")
        with _cache_lock:
            _cache[key] = (time.monotonic() + CACHE_SECONDS, private)
            _failed.pop(key, None)
            _ensure_sweeper_locked()
        return private


def forget(ca_id: int | None = None) -> None:
    """Drop cached keys (one CA when it is no longer active on this worker, or all of them in tests)."""
    with _cache_lock:
        for key in [k for k in _cache if ca_id is None or k[0] == ca_id]:
            del _cache[key]
        for key in [k for k in _failed if ca_id is None or k[0] == ca_id]:
            del _failed[key]
