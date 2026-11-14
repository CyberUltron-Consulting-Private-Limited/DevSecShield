"""Where each collected asset came from: the per-asset provenance the CycloneDX export carries (CB-06).

One table per source kind (collector, method, transport) and one function per stored asset row. The run export
(``inventory.cyclonedx``) is the first reader; the estate store, the correlation keys and VEX read the same values from
here, so "who read this, how, with which build, and can it be trusted" has one answer.

Every value is a string, and a value that cannot be known is ``unknown``: a field is never left out (the export is
judged field by field, and a missing field must read as a defect, not as "not applicable").

* ``collector``: the code that read the asset: a scan-node collector module (``linux_ssh``, ``windows_winrm``,
  ``kubernetes``, ``database``, ``network``, ``key_manager``, ``ca``, ``appliance``, ``container_images``,
  ``host_agent``) or a cloud-worker collector (``aws``, ``azure``, ``gcp``, ``idp``); ``zs_collect`` for hosts read
  through the customer's own automation (F1.3).
* ``method``: ``agentless`` (logged in to or probed from outside; nothing installed), ``agent`` (an agent-mode node read
  its own host), ``api`` (a read-only management or metadata API). ``evidence`` (customer evidence) and ``code`` (code
  scans) are reserved for the estate-wide export; no collection-run row has them.
* ``transport``: ``direct`` (the node or the cloud worker connected to the target itself), ``local`` (an agent-mode node
  read its own host), ``awx`` / ``salt`` / ``ssm`` (through the customer's automation, F1.3).
* ``node_id``: the scan node's id; ``cloud-worker`` for rows the cloud worker read; ``unknown`` once the node was
  deleted (its name stays in the job's ``params.node_name``).
* ``node_build``: the version the node (or the cloud worker) reported with the job's result for the row's attempt
  (``<version>+<12-character commit>`` since CB-03); ``unknown`` while the job runs.
* ``job_id`` / ``attempt``: the collection job and its attempt (earlier attempts' rows are deleted when a job is
  re-claimed, so every stored row belongs to the job's current attempt).
* ``collected_at``: when ZeroShield stored the row (UTC, ``YYYY-MM-DDTHH:MM:SSZ``): within seconds of the read.
* ``signed``: ``true`` when the row came from a node that has held an Ed25519 request-signing key since before the row
  was stored (such a node must sign every request: ``node_auth``); ``false`` for the cloud worker (server-side, there
  is no node to sign; by design) and for a node enrolled without a key (legacy); ``unknown`` when the node was deleted,
  reset and not enrolled again (a reset clears ``enrolled_at``), or enrolled again after the row (what signed it then
  is no longer known).
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any, Iterable

from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources.common import iso_z
from backend.utilities.cbom_sources.jobs import TERMINAL
from backend.utilities.cbom_sources.kinds import KINDS

UNKNOWN = "unknown"
CLOUD_WORKER = "cloud-worker"
METHODS = ("agentless", "agent", "api", "evidence", "code")
TRANSPORTS = ("direct", "local", "awx", "salt", "ssm")
# the export's property names, in the order they are written
NAMES = ("zs:collector", "zs:method", "zs:transport", "zs:node_id", "zs:node_build", "zs:job_id", "zs:attempt",
         "zs:collected_at", "zs:signed")


@dataclass(frozen=True)
class KindProvenance:
    collector: str
    method: str
    transport: str


_KINDS: dict[str, KindProvenance] = {
    "linux_servers": KindProvenance("linux_ssh", "agentless", "direct"),
    "windows_servers": KindProvenance("windows_winrm", "agentless", "direct"),
    # not collectable today (kinds.py: _never); listed so the table covers every kind
    "active_directory": KindProvenance("active_directory", "agentless", "direct"),
    "kubernetes": KindProvenance("kubernetes", "agentless", "direct"),
    "database": KindProvenance("database", "agentless", "direct"),
    "network_range": KindProvenance("network", "agentless", "direct"),
    "appliance": KindProvenance("appliance", "agentless", "direct"),
    "container_images": KindProvenance("container_images", "agentless", "direct"),
    "key_manager": KindProvenance("key_manager", "api", "direct"),
    "ca_connector": KindProvenance("ca", "api", "direct"),
    "aws_account": KindProvenance("aws", "api", "direct"),
    "azure_subscription": KindProvenance("azure", "api", "direct"),
    "gcp_project": KindProvenance("gcp", "api", "direct"),
    "idp": KindProvenance("idp", "api", "direct"),
    "host_agent": KindProvenance("host_agent", "agent", "local"),
    # F1.3 (CONTRACT §2): hosts read by zs-collect through the customer's AWX / Salt / AWS Systems Manager
    "awx_hosts": KindProvenance("zs_collect", "agentless", "awx"),
    "salt_hosts": KindProvenance("zs_collect", "agentless", "salt"),
    "ssm_hosts": KindProvenance("zs_collect", "agentless", "ssm"),
}
_UNKNOWN_KIND = KindProvenance(UNKNOWN, UNKNOWN, UNKNOWN)


def kind_provenance(kind: str | None) -> KindProvenance:
    """Collector, method and transport of a source kind (``unknown`` for a kind this table does not know)."""
    return _KINDS.get(str(kind or ""), _UNKNOWN_KIND)


@dataclass(frozen=True)
class JobProvenance:
    """What one collection job says about every row it stored."""
    job_id: int | None
    attempts: int
    source_kind: str | None
    kind: KindProvenance
    runner: str  # "node" | "cloud" | "unknown"
    node_id: str
    node_build: str  # the job's reported build, valid for rows of ``attempts`` only
    node_enrolled_at: _dt.datetime | None
    node_has_key: bool | None  # None: the node row is gone

    def signed(self, stored_at: _dt.datetime | None) -> str:
        if self.runner == "cloud":
            return "false"
        if self.runner != "node" or self.node_has_key is None or self.node_enrolled_at is None or stored_at is None:
            return UNKNOWN  # node deleted, or reset (enrolled_at cleared) and not enrolled again
        if self.node_enrolled_at > stored_at:
            return UNKNOWN  # enrolled again since: the key (or its absence) now on file says nothing about the row
        return "true" if self.node_has_key else "false"


def _text(value: Any, limit: int = 64) -> str | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = "".join(ch for ch in str(value) if ch.isprintable()).strip()[:limit]
    return text or None


def source_kind_of(job: CbomCollectionJob, source: CbomCollectionSource | None) -> str | None:
    """The job's source kind: the live source's, else the kind snapshotted when the source was deleted."""
    if job.kind == "discovery":
        return "network_range"
    if source is not None:
        return source.kind
    return _text((job.params or {}).get("source_kind"), 32)


def job_provenance(job: CbomCollectionJob, source: CbomCollectionSource | None,
                   node: CbomScanNode | None) -> JobProvenance:
    if source is not None and source.team_id != job.team_id:
        source = None
    if node is not None and node.team_id != job.team_id:
        node = None
    kind = source_kind_of(job, source)
    params = job.params if isinstance(job.params, dict) else {}
    result = job.result if isinstance(job.result, dict) else {}
    reported = _text(result.get("node_version")) if job.status in TERMINAL else None  # a finished attempt's own report
    spec = KINDS.get(kind or "")
    if spec is not None:
        runner = "cloud" if spec.node_less else "node"
    elif job.node_id is not None or params.get("node_name"):
        runner = "node"
    elif (reported or "").startswith(CLOUD_WORKER):
        runner = "cloud"
    else:
        runner = UNKNOWN
    if runner == "cloud":
        node_id = CLOUD_WORKER
    elif runner == "node" and job.node_id is not None:
        node_id = str(job.node_id)
    else:
        node_id = UNKNOWN  # the node was deleted (or nothing says which runner read it)
    return JobProvenance(
        job_id=job.id, attempts=int(job.attempts or 0), source_kind=kind, kind=kind_provenance(kind), runner=runner,
        node_id=node_id, node_build=reported or UNKNOWN,
        node_enrolled_at=node.enrolled_at if node is not None else None,
        node_has_key=bool(node.signing_public_key) if node is not None else None)


def load(session: Session, team_id: int, jobs: Iterable[CbomCollectionJob]) -> dict[int, JobProvenance]:
    """Provenance of every job in ``jobs`` (two queries: their sources and their nodes, team-scoped)."""
    jobs = [j for j in jobs if j.id is not None]
    source_ids = sorted({j.source_id for j in jobs if j.source_id})
    node_ids = sorted({j.node_id for j in jobs if j.node_id})
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id, CbomCollectionSource.id.in_(source_ids))).all()} if source_ids else {}  # type: ignore[union-attr]
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(
        CbomScanNode.team_id == team_id, CbomScanNode.id.in_(node_ids))).all()} if node_ids else {}  # type: ignore[union-attr]
    return {int(j.id): job_provenance(j, sources.get(j.source_id or 0), nodes.get(j.node_id or 0))  # type: ignore[arg-type]
            for j in jobs}


_NO_JOB = JobProvenance(job_id=None, attempts=0, source_kind=None, kind=_UNKNOWN_KIND, runner=UNKNOWN,
                        node_id=UNKNOWN, node_build=UNKNOWN, node_enrolled_at=None, node_has_key=None)


def values(row: CbomCollectedAsset, job: JobProvenance | None) -> dict[str, str]:
    """The provenance of one stored asset row, keyed by the export's property names (``NAMES``, in that order)."""
    job = job or _NO_JOB
    build = job.node_build if row.attempt == job.attempts else UNKNOWN
    return {
        "zs:collector": job.kind.collector, "zs:method": job.kind.method, "zs:transport": job.kind.transport,
        "zs:node_id": job.node_id, "zs:node_build": build,
        "zs:job_id": str(row.job_id) if row.job_id is not None else UNKNOWN,
        "zs:attempt": str(row.attempt) if row.attempt is not None else UNKNOWN,
        "zs:collected_at": iso_z(row.created_at) or UNKNOWN,
        "zs:signed": job.signed(row.created_at),
    }


__all__ = ["CLOUD_WORKER", "METHODS", "NAMES", "TRANSPORTS", "UNKNOWN", "JobProvenance", "KindProvenance",
           "job_provenance", "kind_provenance", "load", "source_kind_of", "values"]
