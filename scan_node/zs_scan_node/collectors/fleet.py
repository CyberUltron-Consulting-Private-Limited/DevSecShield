"""Agentless fleet sources (``awx_hosts``, ``salt_hosts``): zs-collect run through the customer's own AWX/AAP or Salt.

The claim payload (F1 contract, section 3) carries, for a source of one of these kinds:
* ``source.config``: the fleet-hosts config (``targets``, ``handles`` {inventory address -> AWX host / minion id},
  ``addresses`` {inventory address -> every address the inventory knows for it}, ``tier``, ``timeout_s``), plus
  ``transport`` (the transport's non-secret config) and ``zs_collect`` (``version`` and ``sha256`` per architecture of
  the deployment's verified release);
* ``source.secrets``: the transport's secrets (AWX token, salt-api login);
* ``scope.targets``: the inventory addresses of this batch.

Before anything is dispatched, every target is checked against the never-scan list: the inventory address and every
other address the inventory has for it (a hostname is checked by name; the scan node does not resolve customer names
here, because it never connects to the hosts itself).  A listed target is ``skipped_never_scan`` and the tool never
sees it.  Each validated document's assets are posted exactly as zs-collect built them, with ``target`` set to the
inventory address (the SSH path does the same), and the host's outcome is the one zs-collect recorded.
"""
from __future__ import annotations

import ipaddress
import secrets as _secrets
import time
from typing import Any

from zs_scan_node.collectors import ConfigError
from zs_scan_node.jobctx import ASSET_TYPES, JobContext, LeaseLost
from zs_scan_node.netutil import NeverScan
from zs_scan_node.transports import zsdoc
from zs_scan_node.transports.base import CollectOptions, CollectTarget, TargetResult, TransportCredential, TransportError

KINDS = {"awx_hosts": ("awx", "awx_token"), "salt_hosts": ("salt", "salt_eauth")}
TEST_SAMPLE = 5
_FIELDS = ("name", "algorithm", "key_size", "protocol", "facts")


def _transport(name: str, ctx: JobContext, check_options: CollectOptions | None = None):
    if name == "awx":
        from zs_scan_node.transports.awx import AwxTransport

        return AwxTransport(ctx.never_scan, log=ctx.log, check_options=check_options)
    from zs_scan_node.transports.salt import SaltTransport

    return SaltTransport(ctx.never_scan, log=ctx.log, check_options=check_options)


def never_scan_reason(target: CollectTarget, never: NeverScan) -> str | None:
    """Why ``target`` must not be collected (any of its addresses, or its name, is on the list), else None."""
    for raw in (target.label, *target.addresses):
        text = str(raw or "").strip().strip("[]")
        if not text:
            continue
        try:
            ipaddress.ip_address(text)
        except ValueError:
            if never.blocks_host(text.lower().rstrip(".")):
                return f"{text} is on the never-scan list"
            continue
        if never.blocks_ip(text):
            return f"{text} is on the never-scan list"
    return None


def _nonce(ctx: JobContext) -> str:
    return f"zs-{int(ctx.job_id)}-{int(ctx.attempt)}-{_secrets.token_hex(8)}"


def _setup(ctx: JobContext, config: dict, secrets: dict, scope: dict, limit: int | None = None):
    kind = ctx.source_kind or ""
    if kind not in KINDS:
        raise ConfigError(f"{kind} is not a fleet source kind")
    transport_name, cred_kind = KINDS[kind]
    zs = config.get("zs_collect") or {}
    version, sha = zs.get("version"), zs.get("sha256") or {}
    if not version or not sha:
        raise ConfigError("No verified zs-collect release is active in ZeroShield: import and verify one first")
    transport_cfg = config.get("transport")
    if not isinstance(transport_cfg, dict) or not transport_cfg:
        # the backend's claim plugin says why (deleted, disabled, another kind, flag off); older servers say nothing
        raise ConfigError(str(config.get("transport_problem") or "The transport of this source is missing, disabled "
                                                                  "or deleted")[:300])
    handles = config.get("handles") or {}
    addresses = config.get("addresses") or {}
    labels = [str(x).strip() for x in (scope.get("targets") or config.get("targets") or []) if str(x).strip()]
    if limit is not None:
        labels = labels[:limit]
    targets = [CollectTarget(label=label, handle=str(handles.get(label) or label),
                             addresses=tuple(str(a) for a in (addresses.get(label) or []) if a))
               for label in labels]
    tier = 2 if int(config.get("tier") or 1) == 2 else 1
    timeout = int(config.get("timeout_s") or 300)
    options = CollectOptions(tier=tier, run_nonce=_nonce(ctx), deadline=ctx.deadline, timeout_per_target_s=timeout,
                             max_concurrency=str(transport_cfg.get("max_concurrency") or ""),
                             zs_collect_sha256=dict(sha), should_stop=ctx.should_stop, collector_version=str(version))
    credential = TransportCredential(kind=cred_kind, config={**transport_cfg, "timeout_s": transport_cfg.get(
        "timeout_s") or timeout}, secrets=dict(secrets or {}))
    return transport_name, targets, options, credential


def _admit(ctx: JobContext, targets: list[CollectTarget]) -> list[CollectTarget]:
    out = []
    for t in targets:
        reason = never_scan_reason(t, ctx.never_scan)
        if reason:
            ctx.outcome(t.label, "skipped_never_scan", reason)
        else:
            out.append(t)
    return out


def _assets(ctx: JobContext, res: TargetResult) -> tuple[list[dict], tuple[str, str | None, int | None]]:
    """One host's assets as the node posts them, and its outcome (status, error, zs-collect's count).  Pure: posts
    nothing, so whatever it raises is about this host's document, never about ZeroShield or the job."""
    t = res.target
    assets = []
    for a in zsdoc.relabel(res.document, t.label):
        if a.get("type") not in ASSET_TYPES:
            ctx.log("zs-collect asset type unknown to this node; dropped", target=t.label, type=str(a.get("type"))[:32],
                    level="warn")
            continue
        assets.append(a)
    return assets, zsdoc.target_outcome(res.document)


def _post(ctx: JobContext, label: str, assets: list[dict], outcome: tuple[str, str | None, int | None],
          started: float) -> int:
    """Emit one host's assets and record its outcome; returns the number of assets."""
    for a in assets:
        ctx.emit(a["type"], a["target"], a["location"], **{k: a.get(k) for k in _FIELDS})
    status, error, counted = outcome
    # the outcome row carries zs-collect's own count (what the SSH path records for the same host)
    ctx.outcome(label, status, error, started=started, assets=len(assets) if counted is None else counted)
    return len(assets)


def _take(ctx: JobContext, res: TargetResult, transport_name: str, started: float) -> None:
    """One reported host: its row, and its assets posted.  Only reading its document is guarded (one host's document
    is that host's error row, never the job's); posting is not, so a lost lease (LeaseLost from ``ctx.emit``) or any
    other failure to post ends the job, as everywhere else on the node, instead of becoming host rows while the
    transport goes on to launch its next batch on the customer's hosts."""
    t = res.target
    if res.document is None:
        ctx.outcome(t.label, res.status, res.error, started=started)
        return
    try:
        assets, outcome = _assets(ctx, res)
    except LeaseLost:
        raise
    except Exception as exc:
        ctx.log("fleet host result not usable", target=t.label, error=exc.__class__.__name__, level="warn")
        ctx.outcome(t.label, "error", f"the zs-collect document from {transport_name} could not be read "
                                      f"({exc.__class__.__name__})", started=started)
        return
    _post(ctx, t.label, assets, outcome, started)


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str | None:
    transport_name, targets, options, credential = _setup(ctx, config, secrets, scope)
    todo = _admit(ctx, targets)
    if not todo:
        return None
    transport = _transport(transport_name, ctx)
    done: set[str] = set()
    started = time.monotonic()
    ctx.log("fleet collection start", transport=transport_name, targets=len(todo), tier=options.tier)

    def reported():  # the transport's call itself, not only its iteration, is inside the guard below
        yield from transport.run_collect(todo, credential, options)

    def fail_the_rest(status: str, error: str) -> None:
        for t in todo:
            if t.label not in done:
                done.add(t.label)
                ctx.outcome(t.label, status, error, started=started)

    results = reported()
    try:
        while True:
            try:  # guarded: the transport's own step only (posting happens in _take, outside this)
                res = next(results)
            except StopIteration:
                break
            except LeaseLost:
                raise
            except TransportError as exc:
                ctx.log("fleet transport refused the run", transport=transport_name, status=exc.status, level="warn")
                fail_the_rest(exc.status, exc.detail)
                break
            except Exception as exc:  # the transport itself broke: the hosts it reported keep their rows
                ctx.log("fleet transport failed", transport=transport_name, error=exc.__class__.__name__,
                        level="warn")
                fail_the_rest("error", f"the {transport_name} transport failed before this host was reported "
                                       f"({exc.__class__.__name__})")
                break
            if res.target.label in done:
                continue
            done.add(res.target.label)
            _take(ctx, res, transport_name, started)
            started = time.monotonic()
    finally:
        results.close()  # whatever ended the loop (a lost lease too) ends the transport's run: no next batch
    for t in todo:  # anything the transport did not report (stopped, or a tool that skipped it)
        if t.label not in done:
            ctx.outcome(t.label, ctx.should_stop() or "error", None if ctx.should_stop() else
                        f"{transport_name} reported nothing for this host", started=started)
    ctx.flush()
    return None


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str | None:
    """Control-plane login and template/state checks, then a real collection of up to five sample hosts (their
    assets are not posted; each sample says what happened)."""
    try:
        transport_name, targets, options, credential = _setup(ctx, config, secrets, scope, limit=TEST_SAMPLE)
    except ConfigError as exc:
        for line in (scope.get("targets") or [])[:TEST_SAMPLE]:
            ctx.samples.append({"target": line, "status": "error", "reachable": None, "login": False,
                                "privilege": None, "note": str(exc)})
        return str(exc)
    todo = _admit(ctx, targets)
    for t in targets:
        if t not in todo:
            ctx.samples.append({"target": t.label, "status": "skipped_never_scan", "reachable": None, "login": False,
                                "privilege": None, "note": "on the never-scan list"})
    transport = _transport(transport_name, ctx, check_options=options)
    try:
        results = transport.check(credential, todo)
    except TransportError as exc:
        for t in todo:
            ctx.samples.append({"target": t.label, "status": exc.status, "reachable": None, "login": False,
                                "privilege": None, "note": exc.detail})
        return f"{transport_name}: {exc.detail}"
    for res in results:
        sample: dict[str, Any] = {"target": res.target.label, "status": res.status, "reachable": res.status == "ok",
                                  "login": True, "privilege": None, "note": res.error or ""}
        if res.document is not None:
            status, error, _n = zsdoc.target_outcome(res.document)
            assets = res.document.get("assets") or []
            sample.update(status="ready" if status == "ok" else status, reachable=True,
                          note=error or f"zs-collect {res.document.get('collector_version')} collected "
                                        f"{len(assets)} assets through {transport_name}")
        ctx.samples.append(sample)
    return None
