"""AWS Systems Manager transport, run by the cloud worker (contract sections 3 and 8.1).

Config (``transport``): ``role_arn`` (the customer's **run-command role**, separate from the read-only reader role,
which must stay read-only), ``regions[]``, ``document_name`` (``devsecshield-*``, the Command document from the
``ssm-document`` artifact), ``output_s3_bucket`` / ``output_s3_prefix`` (optional), ``max_concurrency``,
``max_errors``.  No stored secret: the role is assumed with the team's external id, from ZeroShield's own principal
(``CBOM_AWS_*``; ambient credentials are never used).

Per region, per batch of at most 50 instance ids (the SendCommand limit):
1. ``DescribeInstanceInformation`` for those ids: an instance that SSM does not manage, or whose agent is not Online, is
   ``unreachable`` and is never sent a command (one such id would make SendCommand refuse the whole batch).
2. ``SendCommand`` with explicit ``InstanceIds`` (never tags or a fleet-wide target), the document, the parameters
   ``nonce`` / ``tier`` / ``output`` (SSM checks them against the document's allowed patterns), the S3 output location
   when one is configured, and a comment naming the ZeroShield job.
3. ``ListCommandInvocations`` until every invocation is final.  SSM runs the batch in waves of ``MaxConcurrency``, so
   the wait is one per-target timeout per wave plus slack (``wait_budget``), never past the job's deadline, and
   ``TimeoutSeconds`` (after which SSM never starts a waiting instance) is at least that wait; at its end the command
   is cancelled (``CancelCommand``).
4. The output: from S3 when a bucket is configured (``GetCommandInvocation`` truncates stdout at 24,000 characters),
   otherwise inline from ``GetCommandInvocation`` with ``output=chunks`` (one gzip+base64 line); inline output that hits
   the 24,000-character cap is refused with "configure an output bucket", never half-read.
Every document is validated (format, nonce, version, schema) before it is handed on.
"""
from __future__ import annotations

import math
import time
from typing import Any, Callable, ClassVar, Iterator, Sequence

from backend.utilities.cbom_sources.transports import zsdoc
from backend.utilities.cbom_sources.transports.base import (CollectOptions, CollectTarget, TargetResult,
                                                            TransportCredential, TransportError)
from backend.utilities.cbom_sources.transports.wrappers import host_timeout

BATCH = 50  # SendCommand InstanceIds limit
POLL_S = 3.0
INLINE_CAP = 24_000
FINAL = {"Success", "Failed", "TimedOut", "Cancelled", "Undeliverable", "Terminated", "InvalidPlatform",
         "AccessDenied", "DeliveryTimedOut", "ExecutionTimedOut", "Incomplete", "RateExceeded", "Cancelling"}
STEP = "zsCollect"
DEFAULT_MAX_CONCURRENCY = "10%"  # contract section 3: the customer's blast radius, honoured rather than overridden
SLACK_S = 120  # SSM delivery, the launcher's checks and the output upload, once per batch
MAX_TIMEOUT_SECONDS = 2_592_000  # SendCommand's TimeoutSeconds range is 30..2592000
DELIVERY_MARGIN_S = 60  # TimeoutSeconds runs this much past the wait: the command is cancelled first
NOT_STARTED = ("Pending", "Delayed")


def concurrency(max_concurrency: str, n: int) -> int:
    """How many of ``n`` instances SSM runs at once under ``MaxConcurrency`` (a count or a percentage of the
    command's targets).  A percentage is rounded down here (at least 1): the smaller reading gives the longer, safe
    wait budget."""
    text = str(max_concurrency or DEFAULT_MAX_CONCURRENCY).strip()
    try:
        value = n * int(text[:-1]) // 100 if text.endswith("%") else int(text)
    except ValueError:
        value = 1
    return max(1, min(max(n, 1), value))


def wait_budget(n: int, max_concurrency: str, per_target_s: int) -> int:
    """Seconds one command over ``n`` instances may need: one per-target timeout per wave, plus slack."""
    waves = math.ceil(max(n, 1) / concurrency(max_concurrency, n))
    return waves * int(per_target_s) + SLACK_S


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None) or {}
    return str((response.get("Error") or {}).get("Code") or type(exc).__name__)


class SsmTransport:
    name: ClassVar[str] = "ssm"

    def __init__(self, client_factory: Callable[[str, str], Any], log=None, poll_s: float = POLL_S):
        """``client_factory(service, region)`` returns a boto3 client acting as the customer's run-command role."""
        self.client = client_factory
        self.log = log or (lambda *a, **k: None)
        self.poll_s = poll_s

    # ------------------------------------------------------------------ protocol
    def check(self, credential: TransportCredential, sample: Sequence[CollectTarget]) -> list[TargetResult]:
        """The role, the document and which sample instances SSM manages (no command is sent)."""
        cfg = credential.config
        region = (cfg.get("regions") or ["us-east-1"])[0]
        self._document(region, cfg)
        online = self._online(region, [t.handle for t in sample[:50]])
        return [TargetResult(t, "ok" if t.handle in online else "unreachable",
                             None if t.handle in online else "not managed by SSM, or its agent is not online", None)
                for t in sample[:50]]

    def run_collect(self, targets: Sequence[CollectTarget], credential: TransportCredential,
                    options: CollectOptions) -> Iterator[TargetResult]:
        cfg = credential.config
        regions = list(cfg.get("regions") or [])
        if not regions:
            raise TransportError("error", "the SSM transport names no region")
        by_region: dict[str, list[CollectTarget]] = {}
        region_of = cfg.get("instance_regions") or {}
        for t in targets:
            by_region.setdefault(str(region_of.get(t.handle) or regions[0]), []).append(t)
        for region, group in by_region.items():
            document = self._document(region, cfg)
            for start in range(0, len(group), BATCH):
                batch = group[start:start + BATCH]
                stop = options.should_stop()
                if stop:
                    for t in batch:
                        yield TargetResult(t, stop, None, None)
                    continue
                yield from self._batch(region, document, batch, cfg, options)

    # ------------------------------------------------------------------ steps
    def _document(self, region: str, cfg: dict) -> str:
        name = str(cfg.get("document_name") or "")
        if not name.startswith("devsecshield-"):
            raise TransportError("refused", "the SSM document must be named devsecshield-* (the run-command role may "
                                            "send only those)")
        ssm = self.client("ssm", region)
        try:
            ssm.describe_document(Name=name)
        except Exception as exc:
            code = _code(exc)
            if code in ("AccessDeniedException", "AccessDenied", "UnrecognizedClientException"):
                raise TransportError("auth_failed", f"the run-command role may not read document {name} ({code})") from None
            if code == "InvalidDocument":
                raise TransportError("error", f"SSM document {name} does not exist in {region}") from None
            raise TransportError("error", f"SSM document {name}: {code}") from None
        return name

    def _online(self, region: str, ids: list[str]) -> set[str]:
        ssm = self.client("ssm", region)
        online: set[str] = set()
        for start in range(0, len(ids), BATCH):
            chunk = ids[start:start + BATCH]
            token = None
            while True:
                kw: dict[str, Any] = {"Filters": [{"Key": "InstanceIds", "Values": chunk}], "MaxResults": 50}
                if token:
                    kw["NextToken"] = token
                try:
                    page = ssm.describe_instance_information(**kw)
                except Exception as exc:
                    code = _code(exc)
                    if code in ("AccessDeniedException", "AccessDenied"):
                        raise TransportError("auth_failed", "the run-command role may not describe managed instances"
                                             ) from None
                    raise TransportError("error", f"SSM DescribeInstanceInformation: {code}") from None
                for info in page.get("InstanceInformationList") or []:
                    if info.get("PingStatus") == "Online":
                        online.add(str(info.get("InstanceId")))
                token = page.get("NextToken")
                if not token:
                    break
        return online

    def _batch(self, region: str, document: str, batch: list[CollectTarget], cfg: dict,
               options: CollectOptions) -> Iterator[TargetResult]:
        online = self._online(region, [t.handle for t in batch])
        ready = [t for t in batch if t.handle in online]
        for t in batch:
            if t not in ready:
                yield TargetResult(t, "unreachable", "not managed by SSM in " + region + ", or its agent is not online",
                                   None)
        if not ready:
            return
        bucket = str(cfg.get("output_s3_bucket") or "")
        prefix = str(cfg.get("output_s3_prefix") or "").strip("/")
        timeout = max(60, min(int(options.timeout_per_target_s or 300), 3600))
        max_concurrency = str(cfg.get("max_concurrency") or DEFAULT_MAX_CONCURRENCY)
        # the whole command's wait: SSM runs the batch in waves, each host within its own timeout; never past the
        # job's deadline (what is still running then is cancelled and reported, the next batches are not sent)
        wait_s = min(wait_budget(len(ready), max_concurrency, timeout), options.deadline - time.monotonic())
        if wait_s <= 0:
            for t in ready:
                yield TargetResult(t, options.should_stop() or "skipped_deadline",
                                   "the job's deadline passed before this batch was sent", None)
            return
        kw: dict[str, Any] = {
            "InstanceIds": [t.handle for t in ready], "DocumentName": document,
            "Parameters": {"nonce": [options.run_nonce], "tier": [str(int(options.tier))],
                           "timeout": [str(host_timeout(options))], "output": ["json" if bucket else "chunks"]},
            # SSM never starts an instance still waiting for its wave when this runs out, and calls it
            # DeliveryTimedOut: past the wait (plus a margin), so a healthy instance is never reported unreachable
            "TimeoutSeconds": max(30, min(MAX_TIMEOUT_SECONDS, math.ceil(wait_s) + DELIVERY_MARGIN_S)),
            "Comment": f"ZeroShield CBOM collection {options.run_nonce}"[:100],
            "MaxConcurrency": max_concurrency,
            "MaxErrors": str(cfg.get("max_errors") or "100%"),
        }
        if bucket:
            kw["OutputS3BucketName"] = bucket
            if prefix:
                kw["OutputS3KeyPrefix"] = prefix
        ssm = self.client("ssm", region)
        try:
            command_id = ssm.send_command(**kw)["Command"]["CommandId"]
        except Exception as exc:
            code = _code(exc)
            if code in ("AccessDeniedException", "AccessDenied"):
                raise TransportError("auth_failed", f"the run-command role may not send {document} ({code})") from None
            raise TransportError("error", f"SSM SendCommand: {code}") from None
        self.log("ssm command sent", region=region, command=command_id, instances=len(ready))
        status = self._wait(ssm, command_id, {t.handle for t in ready}, options, wait_s)
        for t in ready:
            try:
                res = self._result(ssm, region, command_id, t, status.get(t.handle), bucket, prefix, options)
            except Exception as exc:  # one instance's output is that instance's error, never the batch's
                res = TargetResult(t, "error", f"the SSM output of this instance could not be read "
                                               f"({exc.__class__.__name__})", None)
            yield res

    def _wait(self, ssm, command_id: str, ids: set[str], options: CollectOptions, wait_s: float) -> dict[str, dict]:
        until = min(options.deadline, time.monotonic() + wait_s)
        seen: dict[str, dict] = {}
        while True:
            token = None
            while True:
                kw: dict[str, Any] = {"CommandId": command_id, "Details": False, "MaxResults": 50}
                if token:
                    kw["NextToken"] = token
                page = ssm.list_command_invocations(**kw)
                for inv in page.get("CommandInvocations") or []:
                    seen[str(inv.get("InstanceId"))] = inv
                token = page.get("NextToken")
                if not token:
                    break
            if all(seen.get(i, {}).get("Status") in FINAL for i in ids):
                return seen
            if options.should_stop() or time.monotonic() >= until:
                try:
                    ssm.cancel_command(CommandId=command_id)
                except Exception:  # best effort: the command times out on its own
                    pass
                return seen
            time.sleep(self.poll_s)

    def _result(self, ssm, region: str, command_id: str, t: CollectTarget, inv: dict | None, bucket: str, prefix: str,
                options: CollectOptions) -> TargetResult:
        status = (inv or {}).get("Status")
        if status in NOT_STARTED:  # still waiting for its wave when the wait ran out: it never ran
            return TargetResult(t, options.should_stop() or "skipped_deadline",
                                f"SSM had not started command {command_id} on this instance when the job's time ran "
                                "out", None)
        if status is None or status not in FINAL or status in ("Cancelled", "Cancelling"):
            return TargetResult(t, options.should_stop() or "timeout", f"SSM command {command_id} did not finish", None)
        if status in ("Undeliverable", "Terminated", "DeliveryTimedOut", "InvalidPlatform"):
            return TargetResult(t, "unreachable", f"SSM: {status}", None)
        if status in ("TimedOut", "ExecutionTimedOut"):
            return TargetResult(t, "timeout", f"SSM: {status}", None)
        if status == "AccessDenied":
            return TargetResult(t, "refused", "SSM: AccessDenied on the instance", None)
        try:
            inv_out = ssm.get_command_invocation(CommandId=command_id, InstanceId=t.handle, PluginName=STEP)
        except Exception as exc:
            return TargetResult(t, "error", f"SSM GetCommandInvocation: {_code(exc)}", None)
        stderr = str(inv_out.get("StandardErrorContent") or "")
        rc = None
        for line in stderr.splitlines():
            if line.startswith("ZSRC "):
                try:
                    rc = int(line.split()[1])
                except (IndexError, ValueError):
                    rc = None
        if rc == 4:
            return TargetResult(t, "refused", f"zs-collect integrity check failed: {stderr.strip()[-200:]}", None)
        if rc == 3:
            return TargetResult(t, "error", f"zs-collect is not installed on the instance: {stderr.strip()[-200:]}", None)
        if bucket:
            key = "/".join(p for p in (prefix, command_id, t.handle, "awsrunShellScript", STEP, "stdout") if p)
            try:
                body = self.client("s3", region).get_object(Bucket=bucket, Key=key)["Body"].read(
                    zsdoc.MAX_DOCUMENT_BYTES + 1)
            except Exception as exc:
                return TargetResult(t, "error", f"SSM output s3://{bucket}/{key}: {_code(exc)}", None)
            text = body.decode("utf-8", "replace")
        else:
            text = str(inv_out.get("StandardOutputContent") or "")
            if len(text) >= INLINE_CAP:
                return TargetResult(t, "error", "the zs-collect output is larger than SSM's 24,000-character inline "
                                                "limit: configure an output bucket for this transport", None)
        try:
            doc = zsdoc.parse_output(text, options.run_nonce)
        except (zsdoc.ChunkError, ValueError) as exc:
            return TargetResult(t, "error", f"no zs-collect document from SSM ({status}): {str(exc)[:160]}", None)
        problem = zsdoc.validate_document(doc, options.run_nonce, options.collector_version)
        if problem:
            return TargetResult(t, "error", f"zs-collect document refused: {problem}", None)
        return TargetResult(t, "ok", None, doc)


def role_client_factory(team_id: int, role_arn: str, external_id: str):
    """``client(service, region)`` acting as the customer's run-command role, assumed from ZeroShield's own principal
    with the team's external id (``aws_collect._Account``, re-assumed before the credentials expire)."""
    from backend.utilities.cbom_sources.aws_collect import _Account
    from backend.utilities.cbom_sources.aws_validate import _boto

    base, cfg = _boto(retries=5, mode="adaptive")
    account = _Account(base, cfg, role_arn, external_id, team_id)
    return account.client
