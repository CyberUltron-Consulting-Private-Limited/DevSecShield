"""HTTPS client for the ZeroShield node API (enroll, heartbeat, claim, assets, result).

* 401 means the node token is no longer valid (node reset/revoked): ``Unauthorized``.
* 409/404 on a job call means the job is no longer leased to this node: ``LeaseLost``.
* 429, 5xx and network errors are retried with exponential backoff capped at 60 s (well under half the 15-minute
  lease); a 5xx body's ``ref`` is logged so the node log can be matched with the server log.
"""
from __future__ import annotations

import random
import time
from typing import Any

import httpx

from zs_scan_node import VERSION
from zs_scan_node.jobctx import LeaseLost
from zs_scan_node.log import log

MAX_BACKOFF = 60.0


class Unauthorized(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"HTTP {status}: {detail}")
        self.status, self.detail = status, detail


class Api:
    def __init__(self, base_url: str, token: str | None = None, timeout: float = 30.0) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        # trust_env=True: HTTPS_PROXY / NO_PROXY and SSL_CERT_FILE from the customer's environment apply
        self.client = httpx.Client(base_url=self.base, timeout=timeout, headers={"User-Agent": f"zs-scan-node/{VERSION}"},
                                   follow_redirects=False)

    def _headers(self, job: str | None = None) -> dict[str, str]:
        h: dict[str, str] = {}
        if self.token:
            h["X-ZS-Node-Token"] = self.token
        if job:
            h["X-ZS-Job"] = job
        return h

    def call(self, method: str, path: str, body: Any = None, job: str | None = None, retries: int = 6,
             lease_sensitive: bool = False) -> tuple[int, Any]:
        delay = 2.0
        for attempt in range(retries + 1):
            try:
                r = self.client.request(method, path, json=body, headers=self._headers(job))
            except httpx.HTTPError as exc:
                if attempt >= retries:
                    raise ApiError(0, exc.__class__.__name__) from None
                log("api unreachable, retrying", path=path, error=exc.__class__.__name__, wait_s=int(delay), job=job)
                time.sleep(delay + random.random())
                delay = min(delay * 2, MAX_BACKOFF)
                continue
            if r.status_code == 401:
                raise Unauthorized(path)
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
                time.sleep(min(wait, MAX_BACKOFF) + random.random())
                delay = min(delay * 2, MAX_BACKOFF)
                continue
            if r.status_code == 204:
                return 204, None
            try:
                data = r.json()
            except ValueError:
                data = None
            if r.status_code >= 400:
                raise ApiError(r.status_code, _detail(r))
            return r.status_code, data
        raise ApiError(0, "retries exhausted")

    # ------------------------------------------------------------------ endpoints
    def enroll(self, body: dict) -> dict:
        return self.call("POST", "/cbom/node/enroll", body, retries=3)[1]

    def heartbeat(self, body: dict) -> dict:
        return self.call("POST", "/cbom/node/heartbeat", body, retries=1)[1] or {}

    def claim(self) -> dict | None:
        status, data = self.call("POST", "/cbom/node/jobs/claim", None, retries=1)
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
    except ValueError:
        return r.text[:300]


def _ref(r: httpx.Response) -> str | None:
    import re

    m = re.search(r"ref[ :=]+([A-Za-z0-9\-]{6,40})", r.text or "")
    return m.group(1) if m else None
