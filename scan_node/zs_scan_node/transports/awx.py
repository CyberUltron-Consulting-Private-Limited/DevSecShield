"""AWX / Ansible Automation Platform transport: the customer's job template runs zs-collect on its own hosts.

Config (``transport`` in the claim payload): ``base_url`` (https), ``job_template_id``, ``verify_tls``, ``ca_pem``,
``timeout_s``, ``max_hosts_per_launch`` (at most 200).  Secret: ``token`` (an AWX OAuth2 / personal access token of an
account that may execute the template).

One launch per batch of hosts:
1. ``GET  /api/v2/job_templates/<id>/launch/``: the template must prompt on launch for Limit and for Variables; a
   template that does not would run on its whole inventory, so it is refused before anything is launched.
2. ``POST /api/v2/job_templates/<id>/launch/`` with ``limit`` = the batch's AWX host names and ``extra_vars``
   ``zs_nonce``, ``zs_tier`` and ``zs_timeout_s`` (the source's per-host timeout, passed to zs-collect).  If AWX still reports ``limit`` or ``extra_vars`` as ignored, the job is cancelled.
3. ``GET  /api/v2/jobs/<id>/`` until it finishes (cancelled at the job deadline or when the run is stopped).
4. ``GET  /api/v2/jobs/<id>/job_events/`` (paged): per host, the ``debug`` events of the generated playbook
   (``ZSRC <rc> <stderr tail>`` and one ``ZSC1`` chunk per event), unreachable and failed events.  The chunks are
   reassembled (count, order, sha256), the document is validated (format, nonce, version, schema) and handed on.
"""
from __future__ import annotations

import re
import time
from typing import Any, ClassVar, Iterator, Sequence

from zs_scan_node.netutil import NeverScan
from zs_scan_node.transports import control
from zs_scan_node.transports import zsdoc
from zs_scan_node.transports.base import (CollectOptions, CollectTarget, TargetResult, TransportCredential,
                                          TransportError)
from zs_scan_node.transports.wrappers import host_timeout

WHAT = "AWX"
MAX_HOSTS_PER_LAUNCH = 200
POLL_S = 3.0
DONE = {"successful", "failed", "error", "canceled"}
EVENTS = "runner_on_ok,runner_item_on_ok,runner_on_unreachable,runner_on_failed,runner_item_on_failed"
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")  # an Ansible limit pattern lists names; nothing that changes it


class AwxTransport:
    name: ClassVar[str] = "awx"

    def __init__(self, never: NeverScan, log=None, poll_s: float = POLL_S, check_options: CollectOptions | None = None):
        self.never = never
        self.log = log or (lambda *a, **k: None)
        self.poll_s = poll_s
        self.check_options = check_options

    # ------------------------------------------------------------------ helpers
    def _http(self, credential: TransportCredential):
        token = (credential.secrets or {}).get("token")
        if not token:
            raise TransportError("auth_failed", "no AWX token is stored for this transport")
        timeout = float(credential.config.get("timeout_s") or 30)
        return control.client(credential.config, self.never, headers={"Authorization": f"Bearer {token}",
                                                                      "Accept": "application/json"},
                              timeout=min(timeout, 60.0), what=WHAT)

    @staticmethod
    def _json(resp, what: str) -> Any:
        control.raise_for_auth(resp, WHAT)
        if resp.status_code == 404:
            raise TransportError("error", f"{what} was not found in AWX (404)")
        if resp.status_code >= 400:
            detail = ""
            try:
                body = resp.json()
                detail = "; ".join(f"{k}: {v}" for k, v in body.items())[:300] if isinstance(body, dict) else ""
            except ValueError:
                pass
            raise TransportError("refused", f"AWX refused {what} ({resp.status_code}){': ' + detail if detail else ''}")
        try:
            return resp.json()
        except ValueError:
            raise TransportError("error", f"AWX answered {what} with something that is not JSON") from None

    def _template(self, http, config) -> str:
        tid = int(config.get("job_template_id") or 0)
        if tid <= 0:
            raise TransportError("error", "the transport has no job template id")
        path = f"/api/v2/job_templates/{tid}/launch/"
        info = self._json(control.request(http, "GET", path, WHAT), f"job template {tid}")
        missing = [label for key, label in (("ask_limit_on_launch", "Limit"), ("ask_variables_on_launch", "Variables"))
                   if not info.get(key)]
        if missing:
            raise TransportError("refused", f"job template {tid} must prompt on launch for {' and '.join(missing)} "
                                            "(otherwise it would run on its whole inventory)")
        return path

    # ------------------------------------------------------------------ protocol
    def check(self, credential: TransportCredential, sample: Sequence[CollectTarget]) -> list[TargetResult]:
        """Login and template checks, then a real collection of up to 5 sample hosts."""
        with self._http(credential) as http:
            self._json(control.request(http, "GET", "/api/v2/me/", WHAT), "the login")
            self._template(http, credential.config)
        if self.check_options is None:
            return []
        return list(self.run_collect(list(sample)[:5], credential, self.check_options))

    def run_collect(self, targets: Sequence[CollectTarget], credential: TransportCredential,
                    options: CollectOptions) -> Iterator[TargetResult]:
        bad = [t for t in targets if not HOST_RE.match(t.handle or "")]
        for t in bad:
            yield TargetResult(t, "error", "not a usable AWX host name (letters, digits, . _ - only)", None)
        targets = [t for t in targets if t not in bad]
        if not targets:
            return
        size = max(1, min(int(credential.config.get("max_hosts_per_launch") or MAX_HOSTS_PER_LAUNCH),
                          MAX_HOSTS_PER_LAUNCH))
        with self._http(credential) as http:
            launch = self._template(http, credential.config)
            for start in range(0, len(targets), size):
                batch = targets[start:start + size]
                stop = options.should_stop()
                if stop:
                    for t in batch:
                        yield TargetResult(t, stop, None, None)
                    continue
                yield from self._one_launch(http, launch, batch, options)

    # ------------------------------------------------------------------ one job
    def _one_launch(self, http, launch: str, batch: Sequence[CollectTarget],
                    options: CollectOptions) -> Iterator[TargetResult]:
        body = {"limit": ",".join(t.handle for t in batch),
                "extra_vars": {"zs_nonce": options.run_nonce, "zs_tier": int(options.tier),
                               "zs_timeout_s": host_timeout(options)}}
        started = self._json(control.request(http, "POST", launch, WHAT, json=body), "the launch")
        job_id = int(started.get("job") or started.get("id") or 0)
        if job_id <= 0:
            raise TransportError("error", "AWX did not return a job id for the launch")
        ignored = started.get("ignored_fields") or {}
        if "limit" in ignored or "extra_vars" in ignored:
            self._cancel(http, job_id)
            raise TransportError("refused", f"AWX ignored the {' and '.join(k for k in ('limit', 'extra_vars') if k in ignored)}"
                                            f" of job {job_id} (cancelled): enable Prompt on launch on the template")
        self.log("awx job launched", awx_job=job_id, hosts=len(batch))
        status = self._wait(http, job_id, options)
        by_host = self._events(http, job_id)
        for t in batch:
            try:
                res = self._result(t, by_host.get(t.handle), options, job_id, status)
            except Exception as exc:  # one host's output is that host's error, never the batch's
                res = TargetResult(t, "error", f"zs-collect output from AWX job {job_id} could not be read "
                                               f"({exc.__class__.__name__})", None)
            yield res

    def _cancel(self, http, job_id: int) -> None:
        try:
            control.request(http, "POST", f"/api/v2/jobs/{job_id}/cancel/", WHAT)
        except TransportError:
            pass

    def _wait(self, http, job_id: int, options: CollectOptions) -> str:
        while True:
            job = self._json(control.request(http, "GET", f"/api/v2/jobs/{job_id}/", WHAT), f"job {job_id}")
            status = str(job.get("status") or "")
            if status in DONE:
                return status
            stop = options.should_stop()
            if stop or time.monotonic() >= options.deadline:
                self._cancel(http, job_id)
                self.log("awx job cancelled", awx_job=job_id, reason=stop or "deadline")
                return "canceled"
            time.sleep(self.poll_s)

    def _events(self, http, job_id: int) -> dict[str, dict[str, Any]]:
        by_host: dict[str, dict[str, Any]] = {}
        path = f"/api/v2/jobs/{job_id}/job_events/"
        params: dict[str, Any] | None = {"event__in": EVENTS, "page_size": 200, "order_by": "counter"}
        pages = 0
        while path and pages < 10_000:
            pages += 1
            page = self._json(control.request(http, "GET", path, WHAT, params=params), f"the events of job {job_id}")
            for ev in page.get("results") or []:
                host = str(ev.get("host_name") or "")
                if not host:
                    continue
                h = by_host.setdefault(host, {"chunks": [], "rc": None, "stderr": "", "unreachable": None,
                                              "failed": None})
                kind = ev.get("event")
                res = ((ev.get("event_data") or {}).get("res")) or {}
                if kind == "runner_on_unreachable":
                    h["unreachable"] = str(res.get("msg") or "host unreachable")[:256]
                elif kind in ("runner_on_failed", "runner_item_on_failed"):
                    h["failed"] = str(res.get("msg") or "task failed")[:256]
                else:
                    msg = res.get("msg")
                    if zsdoc.is_chunk(msg):
                        h["chunks"].append(msg)
                    elif isinstance(msg, str) and msg.startswith("ZSRC "):
                        parts = msg.split(" ", 2)
                        try:
                            h["rc"] = int(parts[1])
                        except (IndexError, ValueError):
                            h["rc"] = -1
                        h["stderr"] = parts[2] if len(parts) > 2 else ""
            nxt = page.get("next")
            path, params = (str(nxt), None) if nxt else ("", None)
        return by_host

    @staticmethod
    def _result(t: CollectTarget, h: dict[str, Any] | None, options: CollectOptions, job_id: int,
                status: str) -> TargetResult:
        if h is None:
            if status == "canceled":
                return TargetResult(t, options.should_stop() or "skipped_deadline", f"AWX job {job_id} was cancelled",
                                    None)
            return TargetResult(t, "error", f"AWX job {job_id} ({status}) has no event for this host "
                                            "(not in the template's inventory?)", None)
        if h["unreachable"]:
            return TargetResult(t, "unreachable", h["unreachable"], None)
        if h["chunks"]:
            try:
                doc = zsdoc.reassemble(h["chunks"], options.run_nonce)
            except (zsdoc.ChunkError, ValueError) as exc:
                return TargetResult(t, "error", f"zs-collect output from AWX job {job_id}: {exc}", None)
            problem = zsdoc.validate_document(doc, options.run_nonce, options.collector_version)
            if problem:
                return TargetResult(t, "error", f"zs-collect document refused: {problem}", None)
            return TargetResult(t, "ok", None, doc)
        rc, err = h["rc"], (h["stderr"] or "").strip()
        if rc == 4:
            return TargetResult(t, "refused", f"zs-collect integrity check failed: {err[-200:]}", None)
        if rc == 3:
            return TargetResult(t, "error", f"zs-collect is not installed on the host: {err[-200:]}", None)
        if h["failed"]:
            return TargetResult(t, "error", f"AWX task failed: {h['failed']}", None)
        return TargetResult(t, "error", f"AWX job {job_id} returned no zs-collect output (exit {rc}): {err[-160:]}", None)

