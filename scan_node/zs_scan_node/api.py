"""HTTPS client for the ZeroShield node API (enroll, heartbeat, claim, assets, result).

* Every request is signed with the node's Ed25519 signing key when it has one (enrolled with this version or later):
  ``X-ZS-Timestamp``, ``X-ZS-Nonce`` and ``X-ZS-Signature`` over ``METHOD\\nPATH\\nTIMESTAMP\\nNONCE\\nsha256(body)``;
  the body is sent as exactly the bytes that were signed.  A ``clock_skew`` refusal (403) re-signs once with the offset
  learned from the server's ``Date`` header.
* mTLS: ``ZS_CLIENT_CERT`` + ``ZS_CLIENT_KEY`` (PEM files) present a client certificate to the TLS proxy;
  ``ZS_CA_FILE`` replaces the trusted CAs for the ZeroShield API (for a private CA or a TLS-inspecting proxy).
* 401 is ``Unauthorized`` (the node token was revoked) only when it carries the ``X-ZS-Deployment`` of the ZeroShield
  this node enrolled with (or, for state from before deployment ids, any ZeroShield deployment id).  A 401 without it
  or with another id came from a wrong server or a proxy: it is retried like a 5xx and finally raised as
  ``WrongServer``, and the token is kept.  The id is adopted from successful answers (``on_deployment``).
* 409/404 on a job call means the job is no longer leased to this node: ``LeaseLost``.
* 429, 5xx and network errors are retried with exponential backoff capped at 60 s (well under half the 15-minute
  lease); a 5xx body's ``ref`` is logged so the node log can be matched with the server log.
"""
from __future__ import annotations

import base64
import email.utils
import hashlib
import json
import os
import random
import secrets
import ssl
import threading
import time
from typing import Any, Callable

import httpx

from zs_scan_node import VERSION
from zs_scan_node.jobctx import LeaseLost
from zs_scan_node.log import log

MAX_BACKOFF = 60.0
DEPLOYMENT_HEADER = "X-ZS-Deployment"
REFUSED_HEADER = "X-ZS-Refused"


class Unauthorized(Exception):
    """This node's ZeroShield no longer accepts its token (or the registration token)."""

    def __init__(self, path: str, deployment: str | None = None) -> None:
        super().__init__(path)
        self.deployment = deployment


class ApiError(Exception):
    def __init__(self, status: int, detail: str, refused: str | None = None) -> None:
        super().__init__(f"HTTP {status}: {detail}")
        self.status, self.detail, self.refused = status, detail, refused


class WrongServer(ApiError):
    """A 401 that did not come from this node's ZeroShield deployment (wrong ZS_API_URL, a proxy): token kept."""

    def __init__(self, path: str, deployment: str | None) -> None:
        who = f"deployment {deployment}" if deployment else "a server that is not ZeroShield (no deployment id)"
        super().__init__(401, f"{path} was refused by {who}, not by the ZeroShield this node enrolled with; check "
                              "ZS_API_URL and any proxy in between")
        self.deployment = deployment


def signing_message(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """Must equal backend/utilities/cbom_sources/node_auth.py signing_message (a test checks both)."""
    return "\n".join((method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest())).encode()


def tls_context() -> ssl.SSLContext | None:
    """The TLS context for the ZeroShield API when ZS_CA_FILE or a client certificate is configured, else None
    (httpx's default: certifi, or SSL_CERT_FILE / SSL_CERT_DIR from the environment)."""
    ca, cert, key = (os.environ.get(n, "").strip() for n in ("ZS_CA_FILE", "ZS_CLIENT_CERT", "ZS_CLIENT_KEY"))
    if not (ca or cert or key):
        return None
    if bool(cert) != bool(key):
        raise SystemExit("set both ZS_CLIENT_CERT and ZS_CLIENT_KEY (PEM files) for a client certificate, or neither")
    ctx = ssl.create_default_context(cafile=ca) if ca else httpx.create_ssl_context()
    if cert:
        ctx.load_cert_chain(cert, key)
    return ctx


class Api:
    def __init__(self, base_url: str, token: str | None = None, timeout: float = 30.0, signing_key=None,
                 deployment_id: str | None = None, on_deployment: Callable[[str], None] | None = None,
                 stop: threading.Event | None = None) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.signing_key = signing_key  # ed25519.Ed25519PrivateKey or None (legacy, unsigned)
        self.deployment_id = deployment_id
        self.on_deployment = on_deployment
        self.stop = stop or threading.Event()
        self.skew = 0.0  # server clock minus ours, learned from a clock_skew refusal
        self._lock = threading.Lock()
        tls = tls_context()
        # trust_env=True: HTTPS_PROXY / NO_PROXY and SSL_CERT_FILE from the customer's environment apply
        kwargs: dict[str, Any] = {"verify": tls} if tls is not None else {}
        self.client = httpx.Client(base_url=self.base, timeout=timeout, headers={"User-Agent": f"zs-scan-node/{VERSION}"},
                                   follow_redirects=False, **kwargs)

    def _headers(self, job: str | None = None) -> dict[str, str]:
        h: dict[str, str] = {}
        if self.token:
            h["X-ZS-Node-Token"] = self.token
        if job:
            h["X-ZS-Job"] = job
        return h

    def _sign(self, method: str, path: str, data: bytes) -> dict[str, str]:
        if self.signing_key is None:
            return {}
        ts = str(int(time.time() + self.skew))
        nonce = secrets.token_urlsafe(18)
        sig = self.signing_key.sign(signing_message(method, path, ts, nonce, data))
        return {"X-ZS-Timestamp": ts, "X-ZS-Nonce": nonce, "X-ZS-Signature": base64.b64encode(sig).decode()}

    def _authoritative(self, deployment: str | None) -> bool:
        """Did this 401 come from the ZeroShield this node belongs to?"""
        return bool(deployment) and (self.deployment_id is None or deployment == self.deployment_id)

    def _seen(self, deployment: str | None) -> None:
        """A successful answer: the server knows our token, so it is our deployment (adopt or follow a change)."""
        if not deployment or deployment == self.deployment_id:
            return
        with self._lock:
            if deployment == self.deployment_id:
                return
            previous, self.deployment_id = self.deployment_id, deployment
        log("ZeroShield deployment id " + ("adopted" if previous is None else "changed"), deployment=deployment,
            previous=previous, level="info" if previous is None else "warn")
        if self.on_deployment:
            self.on_deployment(deployment)

    def _wait(self, seconds: float) -> None:
        if self.stop.wait(seconds):
            raise ApiError(0, "node shutting down")

    def call(self, method: str, path: str, body: Any = None, job: str | None = None, retries: int = 6,
             lease_sensitive: bool = False) -> tuple[int, Any]:
        # serialised once; the exact bytes are signed and sent (same encoding as httpx's json=)
        data = b"" if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":"),
                                                   allow_nan=False).encode("utf-8")
        delay = 2.0
        skew_retried = False
        for attempt in range(retries + 1):
            headers = self._headers(job)
            headers.update(self._sign(method, path, data))
            if body is not None:
                headers["Content-Type"] = "application/json"
            try:
                r = self.client.request(method, path, content=data, headers=headers)
            except httpx.HTTPError as exc:
                if attempt >= retries:
                    raise ApiError(0, exc.__class__.__name__) from None
                log("api unreachable, retrying", path=path, error=exc.__class__.__name__, wait_s=int(delay), job=job)
                self._wait(delay + random.random())
                delay = min(delay * 2, MAX_BACKOFF)
                continue
            deployment = r.headers.get(DEPLOYMENT_HEADER) or None
            if r.status_code == 401:
                if self._authoritative(deployment):
                    raise Unauthorized(path, deployment)
                if attempt >= retries:
                    raise WrongServer(path, deployment)
                log("wrong server or proxy: a 401 without this node's ZeroShield deployment id; keeping the token and "
                    "retrying", path=path, deployment=deployment, expected=self.deployment_id, wait_s=int(delay),
                    level="warn")
                self._wait(delay + random.random())
                delay = min(delay * 2, MAX_BACKOFF)
                continue
            if r.status_code == 403 and r.headers.get(REFUSED_HEADER) == "clock_skew" and not skew_retried:
                skew_retried = True
                self._learn_skew(r)
                continue
            if lease_sensitive and r.status_code in (404, 409):
                raise LeaseLost(_detail(r))
            if r.status_code == 429 or r.status_code >= 500:
                ref = _ref(r)
                if attempt >= retries:
                    raise ApiError(r.status_code, _detail(r))
                wait = delay
                if r.status_code == 429:
                    try:
                        wait = max(wait, float(r.headers.get("Retry-After") or 0))
                    except ValueError:
                        pass
                log("api busy, retrying", path=path, status=r.status_code, ref=ref, wait_s=int(wait), job=job)
                self._wait(min(wait, MAX_BACKOFF) + random.random())
                delay = min(delay * 2, MAX_BACKOFF)
                continue
            if r.status_code < 400:
                self._seen(deployment)
            if r.status_code == 204:
                return 204, None
            try:
                data_out = r.json()
            except ValueError:
                data_out = None
            if r.status_code >= 400:
                refused = r.headers.get(REFUSED_HEADER)
                if refused:
                    log("ZeroShield refused the request", path=path, reason=refused, detail=_detail(r), level="error")
                raise ApiError(r.status_code, _detail(r), refused)
            return r.status_code, data_out
        raise ApiError(0, "retries exhausted")

    def _learn_skew(self, r: httpx.Response) -> None:
        try:
            server = email.utils.parsedate_to_datetime(r.headers["Date"]).timestamp()
        except (KeyError, TypeError, ValueError):
            return
        self.skew = server - time.time()
        log("node clock differs from ZeroShield; signing with the server's time (fix NTP on this host)",
            skew_s=int(self.skew), level="warn")

    # ------------------------------------------------------------------ endpoints
    def enroll(self, body: dict) -> dict:
        return self.call("POST", "/cbom/node/enroll", body, retries=3)[1]

    def heartbeat(self, body: dict) -> dict:
        return self.call("POST", "/cbom/node/heartbeat", body, retries=1)[1] or {}

    def claim(self, body: dict | None = None) -> dict | None:
        status, data = self.call("POST", "/cbom/node/jobs/claim", body, retries=1)
        return None if status == 204 else data

    def assets(self, job_id: int, attempt: int, lease_id: str, batch_id: str, assets: list[dict]) -> dict:
        body = {"lease_id": lease_id, "batch_id": batch_id, "assets": assets}
        return self.call("POST", f"/cbom/node/jobs/{job_id}/assets", body, job=f"{job_id}/{attempt}",
                         lease_sensitive=True)[1] or {}

    def result(self, job_id: int, attempt: int, body: dict) -> dict:
        return self.call("POST", f"/cbom/node/jobs/{job_id}/result", body, job=f"{job_id}/{attempt}",
                         lease_sensitive=True)[1] or {}


def _detail(r: httpx.Response) -> str:
    try:
        d = r.json().get("detail")
        return str(d)[:300] if d is not None else r.text[:300]
    except (ValueError, AttributeError):
        return r.text[:300]


def _ref(r: httpx.Response) -> str | None:
    import re

    m = re.search(r"ref[ :=]+([A-Za-z0-9\-]{6,40})", r.text or "")
    return m.group(1) if m else None
