"""The transport interface (F1 contract, section 3).  Standard library only.

Canonical copy: ``scan_node/zs_scan_node/transports/base.py``.  A byte-identical copy lives at
``backend/utilities/cbom_sources/transports/base.py`` (the cloud worker's SSM adapter implements the same protocol);
a backend test compares the two files, so change both or neither.

A transport runs zs-collect on hosts through a tool the customer already operates (AWX/AAP, salt-api, AWS SSM) and
streams one ``TargetResult`` per host.  ``status`` is one of the scan node's target statuses
(``jobctx.TARGET_STATUSES``): the host or minion not answering is ``unreachable``, the tool refusing our login is
``auth_failed``, the tool (or the launcher's integrity check) refusing to run is ``refused``, and a document whose
nonce or schema does not match is ``error``.  ``document`` is set only for a validated zs-collect/1 document.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, ClassVar, Iterator, Mapping, Protocol, Sequence


@dataclass(frozen=True)
class CollectTarget:
    label: str                      # the inventory address; becomes asset.target, same as the SSH path
    handle: str                     # awx host | salt minion id | ec2 instance id | address (ssh)
    addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class TransportCredential:
    kind: str                       # "ssh" | "awx_token" | "salt_eauth" | "aws_role"
    config: Mapping[str, Any]
    secrets: Mapping[str, str]


@dataclass(frozen=True)
class CollectOptions:
    tier: int
    run_nonce: str
    deadline: float                 # time.monotonic() value
    timeout_per_target_s: int
    max_concurrency: str
    zs_collect_sha256: Mapping[str, str]
    should_stop: Callable[[], str | None]
    collector_version: str | None = None   # the release the launcher runs; a document of another version is refused


@dataclass
class TargetResult:
    target: CollectTarget
    status: str
    error: str | None
    document: dict | None           # validated zs-collect/1


class Transport(Protocol):
    name: ClassVar[str]             # "ssh" | "awx" | "salt" | "ssm"

    def check(self, credential: TransportCredential, sample: Sequence[CollectTarget]) -> list[TargetResult]: ...

    def run_collect(self, targets: Sequence[CollectTarget], credential: TransportCredential,
                    options: CollectOptions) -> Iterator[TargetResult]: ...   # streams as targets finish


class TransportError(Exception):
    """The control plane refused the whole run (login, template, document).  ``status`` is a target status."""

    def __init__(self, status: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
