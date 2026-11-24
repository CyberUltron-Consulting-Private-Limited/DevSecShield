"""What "the same resource" means across CBOM Sources sources and across the jobs of one run (staging QA Q3-01).

Two sources that read one cloud account (two IAM roles, two regions sets that overlap, a test role next to the
production one) collect the same KMS key, bucket, listener and secret.  Before this module every Sources asset was
identified within its own source (``identity.node_identity`` behind ``node|<source uid>|``), so D6 / D9 printed each
resource once per source (KMS 70 rows for 48 keys) and a run with both sources counted every asset twice.

``resource_identity`` gives an asset an identity that is the same whichever source read it:

* a cloud resource id (an ARN, a GCP resource name or URL, an Azure resource id or Key Vault URL, an OCI OCID or
  ``oci://`` URI): the id already names the provider, the account / project / subscription / tenancy, the region
  and the resource, so it is the identity (``res|<asset type>|<id>``);
* a network endpoint a scan node connected to (TLS, SSH, IKE, OT): ``host:port`` without the ``#fragment``, plus the
  SNI the probe sent (the key ``network_estate.endpoint_key`` de-duplicates D7 with);
* any other asset with a target (a host, a database server): asset type, target and location as stored (the
  read-elsewhere rule's ``posture.sibling_key``: one key file read by two collectors of one host is one key);
* ``None`` otherwise: certificates (``asset_keys`` correlates them, CB-21), libraries (D10 pools them by package URL
  or name and version, keeping every source), coverage rows, the Kerberos / AD posture (D6 prints it per directory
  read, #493), and an asset with neither a resource id nor a target
  (a Vault path or a PKCS#11 URI without a host is not unique across two servers).

Rows that share an identity are ONE asset: the newest observation is kept (a source that still exists before a
deleted one, then an observation with a quantum verdict before one that could not judge the asset (CB-18 EC-3: one
key file a collector could not read and another read as root is the readable one), then the newer collection, then
the higher job id) and the other sources are recorded in ``also_seen``.
If two rows of the SAME collection share an identity the identity is ambiguous for them (two SNI names behind one
address, a collector that emits one location twice) and they keep their own identities: a fold never merges two rows
one source reported as different.

Pure functions plus ``run_fold`` (one light query per run; imports ``sqlmodel`` lazily).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

PREFIX = "res|"
# certificates have their own correlation (asset_keys, CB-21); libraries are pooled by D10 with every source
_CERTS = frozenset({"certificate", "k8s_certificate"})
# the Kerberos / AD register is per source by design (#493: one row set per directory read, each site's DC its own)
_NOT_FOLDED = _CERTS | frozenset({"crypto_library", "process_library", "coverage", "kerberos_account", "ad_domain"})
_ENDPOINTS = frozenset({"tls_endpoint", "ssh_endpoint", "ike_endpoint", "ot_endpoint", "database_tls"})


def cloud_resource_id(location: Any) -> bool:
    """A location that is a provider's own resource id (unique across accounts and sources)."""
    where = str(location or "").strip()
    if not where:
        return False
    return (where.startswith(("arn:aws", "arn:aws-cn:", "arn:aws-us-gov:", "projects/", "//", "oci://",
                              "https://www.googleapis.com/", "https://compute.googleapis.com/"))
            or "/subscriptions/" in where or ".vault.azure.net" in where or where.startswith("ocid1."))


def resource_identity(asset_type: Any, target: Any, location: Any, facts: Mapping[str, Any] | None = None, *,
                      certificates: bool = False) -> str | None:
    """The cross-source identity of one collected asset, or None when it can only be identified within its source.

    ``certificates``: also a certificate whose location is a cloud resource id (an ACM certificate ARN).  The team
    view leaves certificates to ``asset_keys`` (CB-21, serial / fingerprint); one run has no such correlation, so its
    fold keys a cloud certificate by its ARN."""
    kind = str(asset_type or "")
    where = str(location or "").strip()
    if certificates and kind in _CERTS and cloud_resource_id(where):
        return f"{PREFIX}{kind}|{where}"
    if not kind or kind in _NOT_FOLDED or not where:
        return None
    if cloud_resource_id(where):
        return f"{PREFIX}{kind}|{where}"
    if kind in _ENDPOINTS:
        base = where.split("#", 1)[0]
        data = facts if isinstance(facts, Mapping) else {}
        sni = str(data.get("sni") or data.get("server_name") or "").strip()
        return f"{PREFIX}{kind}|{base}" + (f"/{sni}" if sni and sni not in base else "")
    host = str(target or "").strip()
    return f"{PREFIX}{kind}|{host}|{where}" if host else None


@dataclass(frozen=True)
class Observation:
    """One row as the fold ranks it."""

    ident: Any  # the caller's handle (a row id, a SourcesRow)
    group: str  # the collection the row belongs to (job id or source key): rows of one group never fold together
    key: str | None
    live: bool  # its source still exists
    judged: bool  # the collector gave it a quantum verdict (it read the asset)
    observed_at: Any  # comparable (a datetime)
    job_id: int
    label: str  # the source name printed in "also seen"


@dataclass
class Fold:
    """``kept``: the handle that stands for each folded identity; ``dropped``: handle -> the handle kept instead;
    ``also_seen``: kept handle -> the other (live) sources that read it, by name."""

    kept: dict[str, Any] = field(default_factory=dict)
    dropped: dict[Any, Any] = field(default_factory=dict)
    also_seen: dict[Any, tuple[str, ...]] = field(default_factory=dict)


def rank(item: Observation) -> tuple:
    """Kept first: a source that still exists, then an observation with a quantum verdict, then the newer
    collection, then the higher job id."""
    return (item.live, item.judged, item.observed_at, item.job_id)


def fold(observations: Iterable[Observation]) -> Fold:
    """Group by ``key``; a key two rows of one group share is ambiguous and not folded."""
    groups: dict[str, list[Observation]] = {}
    for item in observations:
        if item.key:
            groups.setdefault(item.key, []).append(item)
    out = Fold()
    for key, members in groups.items():
        if len(members) < 2:
            continue
        if len({m.group for m in members}) < len(members):
            continue  # one collection reported this key twice: keep its rows apart
        ordered = sorted(members, key=rank, reverse=True)
        head = ordered[0]
        out.kept[key] = head.ident
        others = tuple(dict.fromkeys(m.label for m in ordered[1:] if m.live and m.label and m.label != head.label))
        if others:
            out.also_seen[head.ident] = others
        for member in ordered[1:]:
            out.dropped[member.ident] = head.ident
    return out


def also_seen_text(label: str, also: Sequence[str] | None) -> str:
    """``"AWS production (also: AWS audit role)"``: the Source cell of a register row read by more than one source."""
    names = [str(a) for a in also or () if a and a != label]
    return f"{label} (also: {', '.join(names)})" if names and label else (label or ", ".join(names))


# ----------------------------------------------------------------------------- one run
@dataclass
class RunFold:
    """The rows of one run that another job of the run also read (``dropped``: row id -> the row id kept), and the
    other sources that read each kept row (``also_seen``).  Empty for a run with one job."""

    dropped: dict[int, int] = field(default_factory=dict)
    also_seen: dict[int, tuple[str, ...]] = field(default_factory=dict)

    @property
    def dropped_ids(self) -> list[int]:
        return sorted(self.dropped)

    def keeps(self, row_id: Any) -> bool:
        return int(row_id or 0) not in self.dropped



def run_fold(session: Any, team_id: int, run_id: int) -> RunFold:
    """The fold of one run's rows (``resource_identity``, newest job kept), from one query of light columns (facts
    only for TLS endpoints, for their SNI).  A run with fewer than two jobs has nothing to fold (no row query)."""
    from sqlalchemy import func
    from sqlmodel import select

    from backend.new_models import CbomCollectedAsset

    memo = getattr(session, "info", None)
    count, newest = session.exec(select(func.count(), func.max(CbomCollectedAsset.id)).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id)).one()
    # one request computes it once (list, totals, facets); a row written since is a new key
    key = ("cbom.run_fold", int(team_id), int(run_id), int(count or 0), int(newest or 0))
    if isinstance(memo, dict) and key in memo:
        return memo[key]
    found = _run_fold(session, team_id, run_id)
    if isinstance(memo, dict):
        memo[key] = found
    return found


def _run_fold(session: Any, team_id: int, run_id: int) -> RunFold:
    from sqlmodel import select

    from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource
    from backend.utilities.cbom_sources import identity as ID

    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id,
                                                        CbomCollectionJob.run_id == run_id)).all()
    if len(jobs) < 2:
        return RunFold()
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    info: dict[int, tuple[bool, Any, str]] = {}
    for job in jobs:
        source = sources.get(job.source_id or 0)
        info[int(job.id)] = (source is not None, job.finished_at or job.created_at,
                             str(ID.job_source_name(job, source) or ""))
    cols = (CbomCollectedAsset.id, CbomCollectedAsset.job_id, CbomCollectedAsset.asset_type, CbomCollectedAsset.target,
            CbomCollectedAsset.location, CbomCollectedAsset.quantum_vulnerable)
    scope = (CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id,
             CbomCollectedAsset.asset_type.notin_(sorted(_NOT_FOLDED - _CERTS)))  # type: ignore[union-attr]
    observed: list[Observation] = []
    for with_facts in (False, True):
        kind_clause = (CbomCollectedAsset.asset_type == "tls_endpoint") if with_facts else (
            CbomCollectedAsset.asset_type != "tls_endpoint")
        query = select(*cols, CbomCollectedAsset.facts) if with_facts else select(*cols)
        for rec in session.exec(query.where(*scope, kind_clause)).all():
            aid, job_id, kind, target, location, qv = rec[:6]
            key = resource_identity(kind, target, location, rec[6] if with_facts else None, certificates=True)
            if key is None or job_id is None:
                continue
            live, at, label = info.get(int(job_id), (False, None, ""))
            observed.append(Observation(int(aid), str(job_id), key, live, qv is not None, _sortable(at), int(job_id),
                                        label))
    found = fold(observed)
    return RunFold(dropped={int(k): int(v) for k, v in found.dropped.items()},
                   also_seen={int(k): v for k, v in found.also_seen.items()})


def _sortable(moment: Any) -> Any:
    import datetime as _dt

    if isinstance(moment, _dt.datetime):
        return moment.replace(tzinfo=None) if moment.tzinfo is not None else moment
    return _dt.datetime(1970, 1, 1)


def kept_clause(fold_: RunFold):
    """A SQL predicate: the row is not a duplicate another job of its run read (``true()`` when nothing folds)."""
    from sqlalchemy import true

    from backend.new_models import CbomCollectedAsset

    if not fold_.dropped:
        return true()
    return CbomCollectedAsset.id.notin_(fold_.dropped_ids)  # type: ignore[union-attr]


__all__ = ["Fold", "Observation", "PREFIX", "RunFold", "also_seen_text", "cloud_resource_id", "fold", "kept_clause",
           "rank", "resource_identity", "run_fold"]
