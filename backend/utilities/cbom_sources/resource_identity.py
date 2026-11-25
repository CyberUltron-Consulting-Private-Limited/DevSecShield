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

import re
import threading
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

PREFIX = "res|"
# certificates have their own correlation (asset_keys, CB-21); libraries are pooled by D10 with every source
_CERTS = frozenset({"certificate", "k8s_certificate"})
# the Kerberos / AD register is per source by design (#493: one row set per directory read, each site's DC its own)
_NOT_FOLDED = _CERTS | frozenset({"crypto_library", "process_library", "coverage", "kerberos_account", "ad_domain"})
_ENDPOINTS = frozenset({"tls_endpoint", "ssh_endpoint", "ike_endpoint", "ot_endpoint", "database_tls"})
_K8S = "k8s_"  # Kubernetes asset types: one resource per cluster read (``resource_identity``'s ``cluster``)


# a GCP resource name is ``projects/<project>/<collection>/...`` (cloud.google.com/apis/design/resource_names); a
# relative file path such as ``projects/billing/key.pem`` is not one (review 6039899144 M2)
_GCP_NAME = re.compile(r"^projects/[^/\s#]+/(?:locations|secrets|global|regions|zones|serviceAccounts|keyRings)/")
_GCP_FULL = re.compile(r"^//[a-z0-9.-]+\.googleapis\.com/")  # a full resource name (//storage.googleapis.com/...)
# Azure resource ids start at the root (``/subscriptions/<id>/...``); Key Vault / Managed HSM object ids are URLs on
# the vault's own host, per cloud (learn.microsoft.com/azure/key-vault/general/about-keys-secrets-certificates)
_AZURE_VAULT_HOSTS = (".vault.azure.net", ".vault.azure.cn", ".vault.usgovcloudapi.net", ".vault.microsoftazure.de",
                      ".managedhsm.azure.net", ".managedhsm.azure.cn", ".managedhsm.usgovcloudapi.net")


def cloud_resource_id(location: Any) -> bool:
    """A location that is a provider's own resource id (unique across accounts and sources).  Every pattern is
    anchored at the start: a file path that merely contains ``/subscriptions/`` or ``.vault.azure.net`` is a path on
    its host, never a cloud id (review 6039899144 M2: two hosts holding ``/srv/billing/subscriptions/key.pem``)."""
    where = str(location or "").strip()
    if not where:
        return False
    if where.startswith(("arn:aws:", "arn:aws-cn:", "arn:aws-us-gov:", "arn:aws-iso:", "arn:aws-iso-b:",
                         "oci://", "ocid1.", "https://www.googleapis.com/", "https://compute.googleapis.com/",
                         "/subscriptions/")):
        return True
    if _GCP_NAME.match(where) or _GCP_FULL.match(where):
        return True
    if where.startswith("https://"):
        host = where[len("https://"):].split("/", 1)[0].split(":", 1)[0].casefold()
        return host.endswith(_AZURE_VAULT_HOSTS)
    return False


# ----------------------------------------------------------------------------- network scope (review 6039899144 M2)
# A name or address that is only unique inside one network: two scan nodes in two sites can both reach a different
# "10.0.0.5:22", and two hosts can both report "localhost".  Such a key carries the scope of the job that read it
# (``job_scope``: the scan node's segment, else the node, else the source; never shared by two unsegmented nodes).
#   * one machine: loopback (127.0.0.0/8, ::1, "localhost", "*.localhost": RFC 6761 s6.3) and link-local addresses
#     (169.254.0.0/16 RFC 3927, fe80::/10 RFC 4291: unique per link only; 169.254.169.254 is each VM's own metadata
#     service), review 6058574998 F5;
#   * one network: private / shared / unique-local addresses (RFC 1918, RFC 6598, RFC 4193: every other address
#     ``ipaddress`` says is not global) and names resolved inside one network only: a single label, "*.local" (mDNS,
#     RFC 6762), "*.home.arpa" (RFC 8375), "*.internal" (ICANN 2024), "*.localdomain", "*.lan", and the Kubernetes
#     service names "*.svc", "*.svc.cluster.local", "*.cluster.local", "kubernetes.default" (review 6058574998 F1).
# An IPv4-mapped IPv6 address (::ffff:a.b.c.d, RFC 4291 s2.5.5.2) is its IPv4 address.  A target written as a URL or
# as host:port is judged by its host (F1: the Kubernetes collector's target is the API server URL).
# Identity is textual: an endpoint seen once by DNS name and once by IP address is two resources, and a split-horizon
# internal FQDN that resolves to different private addresses per site is one (D7 states both in its rubric).
_LOCAL_SUFFIXES = (".local", ".home.arpa", ".internal", ".localdomain", ".lan", ".svc", ".cluster.local", ".default")
_HOSTNAME = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")


def canonical_host(host: Any) -> str:
    """The host as identities compare it: case-folded, without brackets, zone index or trailing dot, an IPv4-mapped
    IPv6 address as its IPv4 address."""
    import ipaddress

    name = str(host or "").strip().strip("[]").rstrip(".").casefold()
    try:
        ip = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        return name
    mapped = getattr(ip, "ipv4_mapped", None)
    return str(mapped) if mapped is not None else str(ip)


def target_host(target: Any) -> str:
    """The host of a target: a URL's host (``https://10.0.0.1:6443`` -> ``10.0.0.1``), a ``host:port`` / ``[v6]:port``
    target's host, else the target itself (an "aws:<account>" label is not host:port: its "port" is no port)."""
    from urllib.parse import urlsplit

    text = str(target or "").strip()
    if "://" in text:
        try:
            return urlsplit(text).hostname or text
        except ValueError:
            return text
    host, port = split_endpoint(text)
    if port and port[1:].isdigit() and int(port[1:]) <= 65535 and _HOSTNAME.fullmatch(canonical_host(host) or "-") \
            or text.startswith("["):
        return host
    return text


def host_scope(host: Any) -> str:
    """"machine", "network" or "" (globally unique: a public address or a fully qualified DNS name).  ``host`` may be
    a URL or host:port (``target_host``)."""
    import ipaddress

    name = canonical_host(target_host(host))
    if not name:
        return ""
    try:
        ip = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            return "machine"
        return "" if ip.is_global else "network"
    if not _HOSTNAME.fullmatch(name):
        return ""  # not a host name (a cloud account label "aws:4444...", a source's display name): as before
    if name == "localhost" or name.endswith(".localhost"):
        return "machine"
    if "." not in name or name.endswith(_LOCAL_SUFFIXES) or name == "kubernetes.default":
        return "network"
    return ""


def split_endpoint(base: str) -> tuple[str, str]:
    """``("host", ":port")`` of a ``host:port`` / ``[v6]:port`` location (the port part "" when there is none)."""
    text = str(base or "").strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, rest
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, f":{port}"
    return text, ""  # a bare host, or an IPv6 address without brackets (no port to split off)


def scope_suffix(host: Any, *, network: str = "", machine: str = "") -> str:
    """``"@<scope>"`` for a host that is not globally unique (``host_scope``), "" otherwise or when the caller gave no
    scope (a unit test of the bare key)."""
    kind = host_scope(host)
    if kind == "machine":
        chosen = machine or network
    elif kind == "network":
        chosen = network or machine
    else:
        return ""
    return f"@{chosen}" if chosen else ""


def endpoint_identity(location: Any, facts: Mapping[str, Any] | None = None, target: Any = None, *,
                      network: str = "", machine: str = "") -> str:
    """``host:port`` (the host case-folded: DNS names are case-insensitive, RFC 4343) plus ``/sni`` when the probe
    sent a server name other than the host itself, plus the job's scope for a host that is not globally unique.
    The SNI is compared with the HOST exactly (review 6039899144 M1: a substring test made ``api.example.com:443``
    with SNI ``example.com`` the same endpoint as with no SNI)."""
    base = str(location or "").split("#", 1)[0].strip() or str(target or "").strip()
    host, port = split_endpoint(base)
    host_cf = canonical_host(host)
    shown = f"[{host_cf}]{port}" if ":" in host_cf else f"{host_cf}{port}"
    data = facts if isinstance(facts, Mapping) else {}
    sni = str(data.get("sni") or data.get("server_name") or "").strip().casefold().rstrip(".")
    suffix = f"/{sni}" if sni and sni != host_cf else ""
    return shown + suffix + scope_suffix(host_cf, network=network, machine=machine)


def resource_identity(asset_type: Any, target: Any, location: Any, facts: Mapping[str, Any] | None = None, *,
                      certificates: bool = False, network: str = "", machine: str = "",
                      cluster: str = "") -> str | None:
    """The cross-source identity of one collected asset, or None when it can only be identified within its source.

    ``certificates``: also a certificate whose location is a cloud resource id (an ACM certificate ARN).  The team
    view leaves certificates to ``asset_keys`` (CB-21, serial / fingerprint); one run has no such correlation, so its
    fold keys a cloud certificate by its ARN.

    ``network`` / ``machine``: the scope of the job that read the asset (``job_scope``), added to a key whose host is
    only unique inside one network or one machine (``host_scope``), so two sites' "10.0.0.5:22" or two hosts'
    "localhost" stay two resources.

    ``cluster``: the source that read a Kubernetes asset (``k8s_*``).  Its target is the API server URL, which two
    clusters can share (``https://127.0.0.1:6443`` for two kind / k3s labs, ``https://kubernetes.default.svc`` for two
    in-cluster readers) and its location ("default/secret/tls") is unique only inside one cluster, so a Kubernetes
    asset is one resource per cluster read, never folded across sources (review 6058574998 F1)."""
    kind = str(asset_type or "")
    where = str(location or "").strip()
    if certificates and kind in _CERTS and cloud_resource_id(where):
        return f"{PREFIX}{kind}|{where}"
    if not kind or kind in _NOT_FOLDED or not where:
        return None
    if cloud_resource_id(where):
        return f"{PREFIX}{kind}|{where}"  # ARNs and resource ids keep their case (an S3 bucket key is case-sensitive)
    own = f"@cluster:{cluster}" if cluster and kind.startswith(_K8S) else ""
    if kind in _ENDPOINTS:
        return f"{PREFIX}{kind}|" + endpoint_identity(where, facts, target, network=network, machine=machine) + own
    raw = str(target or "").strip()
    if not raw:
        return None
    host = canonical_host(target_host(raw))
    shown = canonical_host(raw) if target_host(raw) == raw else raw.casefold()  # a bare host as compared
    return f"{PREFIX}{kind}|{shown}{scope_suffix(host, network=network, machine=machine)}{own}|{where}"


def job_scope(job: Any, node: Any = None, source_ref: str = "") -> tuple[str, str]:
    """``(network, machine)`` scope of one collect job (review 6058574998 F5: the safe rule, never a shared default).

    * network: the scan node's segment, the product's declared network boundary (the snapshot the run took, else the
      job's segment, else the node's current one); else the node (two unsegmented nodes are never one network, even
      in one lab: nothing says they are); else the source (a job no node ran);
    * machine: the scan node that ran the job, else the source."""
    params = getattr(job, "params", None)
    snap = params.get("metadata") if isinstance(params, Mapping) else None
    segment = (snap.get("node_segment") if isinstance(snap, Mapping) else None) or getattr(job, "node_segment", None) \
        or (getattr(node, "segment", None) if node is not None else None)
    segment = str(segment or "").strip().casefold()
    node_id = getattr(job, "node_id", None)
    machine = f"node:{node_id}" if node_id else f"source:{source_ref}"
    return (f"segment:{segment}" if segment else machine), machine


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
    # a stable preference between sources (review 6058574998 F2): higher wins, before recency.  The fold uses minus
    # the source id, so the oldest live source keeps a resource run after run whichever job finished last
    preference: int = 0


@dataclass
class Fold:
    """``kept``: the handle that stands for each folded identity; ``dropped``: handle -> the handle kept instead;
    ``also_seen``: kept handle -> the other (live) sources that read it, by name."""

    kept: dict[str, Any] = field(default_factory=dict)
    dropped: dict[Any, Any] = field(default_factory=dict)
    also_seen: dict[Any, tuple[str, ...]] = field(default_factory=dict)


def rank(item: Observation) -> tuple:
    """Kept first: a source that still exists, then an observation with a quantum verdict, then the stable source
    preference (the oldest source: review 6058574998 F2, the kept row, its remediation key, its tickets and the D6
    "Source" cell no longer flip with the order two jobs finished in), then the newer collection, then the higher job
    id (recency only orders the reads of one source)."""
    return (item.live, item.judged, item.preference, item.observed_at, item.job_id)


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



# finished folds, in process (review 6039899144 m5: the fold was recomputed on every request; at 50k rows with 25k
# folded page 1 of the run list took 5.9 s against 4.1 s unfolded).  The key is everything the fold reads: the run's
# row count and newest row id (a row written since is a new key) and, per job, whether its source still exists, its
# name and when it finished (a deleted or renamed source re-ranks or relabels).  Bounded, least recently used out.
_CACHE_SIZE = 16
_cache: OrderedDict[tuple, RunFold] = OrderedDict()
_cache_lock = threading.Lock()


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def run_fold(session: Any, team_id: int, run_id: int) -> RunFold:
    """The fold of one run's rows (``resource_identity``, newest job kept), from one query of light columns (facts
    only for TLS endpoints, for their SNI).  A run with fewer than two jobs has nothing to fold (no row query).
    Computed once per process for the same rows and jobs (``_cache``), and once per request (``session.info``)."""
    from sqlalchemy import func
    from sqlmodel import select

    from backend.new_models import CbomCollectedAsset

    memo = getattr(session, "info", None)
    count, newest = session.exec(select(func.count(), func.max(CbomCollectedAsset.id)).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id)).one()
    key = ("cbom.run_fold", int(team_id), int(run_id), int(count or 0), int(newest or 0))
    if isinstance(memo, dict) and key in memo:
        return memo[key]
    context = _jobs_context(session, team_id, run_id)
    if len(context) < 2:
        found = RunFold()
    else:
        full = (_database(session), *key, tuple(sorted((job_id, *rest) for job_id, rest in context.items())))
        with _cache_lock:
            found = _cache.get(full)
            if found is not None:
                _cache.move_to_end(full)
        if found is None:
            found = _run_fold(session, team_id, run_id, context)
            with _cache_lock:
                _cache[full] = found
                while len(_cache) > _CACHE_SIZE:
                    _cache.popitem(last=False)
    if isinstance(memo, dict):
        memo[key] = found
    return found


def _database(session: Any) -> str:
    """Which database the rows come from (one per process in production; a test's own SQLite file otherwise)."""
    try:
        return str(session.get_bind().url)
    except Exception:  # a session without a bind (a stub): its own object
        return f"session:{id(session)}"


def _jobs_context(session: Any, team_id: int, run_id: int) -> dict[int, tuple]:
    """Per job of the run: (source exists, finished (naive UTC), source name, network scope, machine scope, source
    ref, source preference); an
    empty tuple per job for a run with fewer than two jobs (nothing to fold, nothing else read)."""
    from sqlmodel import select

    from backend.new_models import (
        CbomCollectionJob,
        CbomCollectionSource,
        CbomScanNode,
    )
    from backend.utilities.cbom_sources import identity as ID

    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id,
                                                        CbomCollectionJob.run_id == run_id)).all()
    if len(jobs) < 2:
        return {int(j.id): () for j in jobs if j.id is not None}
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    out: dict[int, tuple] = {}
    for job in jobs:
        source = sources.get(job.source_id or 0)
        ref = ID.job_source_ref(job, source)
        network, machine = job_scope(job, nodes.get(job.node_id or 0), ref)
        out[int(job.id)] = (source is not None, _sortable(job.finished_at or job.created_at),
                            str(ID.job_source_name(job, source) or ""), network, machine, ref,
                            -int(job.source_id or 0) if source is not None else 0)
    return out


def _run_fold(session: Any, team_id: int, run_id: int, context: Mapping[int, tuple]) -> RunFold:
    from sqlmodel import select

    from backend.new_models import CbomCollectedAsset

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
            if job_id is None:
                continue
            live, at, label, network, machine, ref, preference = context.get(int(job_id)) or (
                False, _sortable(None), "", "", "", "", 0)
            key = resource_identity(kind, target, location, rec[6] if with_facts else None, certificates=True,
                                    network=network, machine=machine, cluster=ref)
            if key is None:
                continue
            observed.append(Observation(int(aid), str(job_id), key, live, qv is not None, at, int(job_id), label,
                                        preference))
    found = fold(observed)
    return RunFold(dropped={int(k): int(v) for k, v in found.dropped.items()},
                   also_seen={int(k): v for k, v in found.also_seen.items()})


def _sortable(moment: Any) -> Any:
    import datetime as _dt

    if isinstance(moment, _dt.datetime):
        return moment.replace(tzinfo=None) if moment.tzinfo is not None else moment
    return _dt.datetime(1970, 1, 1)  # noqa: DTZ001 - compared with the jobs' naive UTC times


def kept_clause(fold_: RunFold):
    """A SQL predicate: the row is not a duplicate another job of its run read (``true()`` when nothing folds)."""
    from sqlalchemy import true

    from backend.new_models import CbomCollectedAsset

    if not fold_.dropped:
        return true()
    return CbomCollectedAsset.id.notin_(fold_.dropped_ids)  # type: ignore[union-attr]


__all__ = [
    "PREFIX",
    "Fold",
    "Observation",
    "RunFold",
    "also_seen_text",
    "clear_cache",
    "cloud_resource_id",
    "fold",
    "kept_clause",
    "rank",
    "endpoint_identity",
    "host_scope",
    "job_scope",
    "resource_identity",
    "run_fold",
    "scope_suffix",
    "split_endpoint",
]
