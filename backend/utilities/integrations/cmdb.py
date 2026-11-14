"""CMDB import: a CSV upload or a ServiceNow CMDB pull becomes server and network-range sources with their metadata.

Preview, then confirm. The preview is computed from the rows and the team's current sources; confirming recomputes it
and refuses (409) when the result differs from what was previewed (``digest``), so nothing changes behind the user.

* A row names a host by FQDN, host name or IP (several identity columns are tried in order) or a network by CIDR.
* A row whose host is already a target of a Linux / Windows server source (exact match of the normalised target) or
  whose CIDR is a network-range source updates THAT source's metadata: owner, application, business criticality,
  exposure, data classification, environment. Metadata never changes how a source connects, so running and queued
  jobs and the connection test are kept (the WP9 connection-version split). A blank cell leaves the stored value.
* Several rows that land on the same source with different values for a field are a conflict: that field is left
  alone and listed.
* Hosts not found anywhere become NEW Linux server sources (scan-node key login, trust on first use) grouped by scan
  node and identical metadata (one source per group, at most 1000 targets each); CIDRs become network ranges.
* Windows hosts become NEW Windows (WinRM over HTTPS) sources whose login is read from a vault: the import's
  ``windows_vault`` choice, or a row's ``vault_path`` column. Without either they are skipped with the reason (#225).
* Rows of kind database, Kubernetes cluster or HSM (a ``kind`` column, or ``engine`` / ``api_url`` / ``module``
  columns, or a ServiceNow class such as cmdb_ci_db_*) become one source each of the existing kinds (``database``,
  ``kubernetes``, ``key_manager``), with credentials read from a vault (``vault_path``); a password, kubeconfig or
  client certificate is never imported from a file, so rows that would need one are skipped with the reason. A
  row matching an existing source of these kinds (engine + host + port, API URL, PKCS#11 module + token) updates its
  metadata instead (#225).
* Scan node per row (#225): a ``scan_node`` column (node name) wins; else a ``segment`` column picks the import's
  ``segment_nodes`` choice for that segment, or the team's only agentless node in it; else the import's ``node_id``.
  A segment with no node, or with several and no choice, skips the row with the reason.
* The team's source cap (``source_cap``: ``CBOM_MAX_SOURCES``, per-team overrides) is checked in the preview: new
  sources past it are listed as ``over_limit`` with the reason, are not counted as created, and are not created by
  Apply (#224). Apply re-checks the cap in its own transaction.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources import agents as AG
from backend.utilities.cbom_sources import source_cap as SOURCE_CAP
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.common import NAME_RE, audit, log, utcnow
from backend.utilities.cbom_sources.kinds import DB_DEFAULT_PORTS, KINDS, _metadata_text, credential_target_problem

MAX_ROWS = 5000
MAX_CSV_BYTES = 2 * 1024 * 1024
# the team's source cap is source_cap.max_sources(team) (CBOM_MAX_SOURCES), the same one the Sources API applies
SERVER_KINDS = ("linux_servers", "windows_servers")
FIELDS = ("owner", "application", "criticality", "exposure", "data_classification", "environment")
CONFIG_FIELD = {"owner": "owner", "application": "application", "criticality": "business_criticality",
                "exposure": "exposure", "data_classification": "data_classification", "environment": "environment"}
HOST_COLUMNS = ("fqdn", "hostname", "host_name", "host", "name", "ip", "ip_address", "address", "target", "cidr",
                "network")
ALIASES = {
    "owner": ("owner", "owned_by", "owner_group", "support_group"),
    "application": ("application", "app", "u_application", "business_service", "service"),
    "criticality": ("criticality", "business_criticality", "busines_criticality"),
    "exposure": ("exposure", "internet_facing", "zone"),
    "data_classification": ("data_classification", "classification", "data_class"),
    "environment": ("environment", "env", "used_for"),
    "os": ("os", "os_type", "operating_system", "sys_class_name", "class"),
}
# #225: optional columns, put on a row only when the cell has a value (so a plain host file reads exactly as before)
EXTRA_ALIASES = {
    "segment": ("segment", "network_segment", "site", "data_center", "datacenter", "data_centre", "datacentre"),
    "scan_node": ("scan_node", "scan_node_name", "node"),
    "kind": ("kind", "source_kind", "asset_type", "ci_type", "type"),
    "engine": ("engine", "db_engine", "database_engine", "db_type", "database_type"),
    "port": ("port",),
    "login": ("login", "login_user", "db_user", "username", "user_name"),
    "database_name": ("database_name", "db_name", "service_name", "database"),
    "vault_path": ("vault_path", "secret_path", "vault"),
    "vault_provider": ("vault_provider",),
    "api_url": ("api_url", "api_server", "apiserver", "server_url", "kube_api", "cluster_url"),
    "context": ("context", "kube_context"),
    "module": ("module", "pkcs11_module"),
    "token_label": ("token_label", "token", "slot_label"),
}
VAULT_PROVIDERS = ("hashicorp", "cyberark", "aws_secrets_manager", "azure_key_vault")
SPECIAL_KINDS = ("database", "kubernetes", "key_manager")
_ENGINES = {"postgres": "postgres", "postgresql": "postgres", "pg": "postgres", "mysql": "mysql", "mariadb": "mysql",
            "mssql": "mssql", "sql_server": "mssql", "sqlserver": "mssql", "microsoft_sql_server": "mssql",
            "oracle": "oracle", "mongodb": "mongodb", "mongo": "mongodb", "redis": "redis"}
_KIND_WORDS = {
    "linux_servers": {"linux", "linux_server", "linux_servers", "unix"},
    "windows_servers": {"windows", "windows_server", "windows_servers", "win", "winrm"},
    "database": {"database", "databases", "db", "db_instance", *_ENGINES},
    "kubernetes": {"kubernetes", "k8s", "cluster", "kubernetes_cluster", "eks", "aks", "gke", "openshift"},
    "key_manager": {"hsm", "pkcs11", "key_manager", "kmip"},
    "network_range": {"network", "network_range", "cidr", "subnet"},
}


class ImportError_(ValueError):
    """A problem with the whole input (safe to show)."""


# ----------------------------------------------------------------------------- values
def norm_criticality(value: str) -> str | None:
    """Words, or ServiceNow's ``1 - most critical`` ... ``4 - not critical`` choices (qualified phrases first)."""
    v = value.strip().lower()
    for phrase, out in (("not critical", "low"), ("less critical", "medium"), ("somewhat critical", "high"),
                        ("most critical", "critical"), ("very high", "critical")):
        if phrase in v:
            return out
    number = re.match(r"^\s*([1-5])\s*(-|$)", v)
    if number:
        return {"1": "critical", "2": "high", "3": "medium", "4": "low", "5": "low"}[number.group(1)]
    for word, out in (("critical", "critical"), ("high", "high"), ("medium", "medium"), ("moderate", "medium"),
                      ("low", "low")):
        if word in v:
            return out
    return None


def norm_exposure(value: str) -> str | None:
    v = value.strip().lower()
    if v in ("internet", "internet-facing", "internet facing", "external", "public", "dmz", "yes", "true", "1"):
        return "internet"
    if v in ("internal", "private", "intranet", "no", "false", "0"):
        return "internal"
    if v in ("unknown", "-"):
        return "unknown"
    return None


def norm_classification(value: str) -> str | None:
    v = value.strip().lower()
    if v in ("public", "open"):
        return "public"
    if v in ("internal", "internal use", "internal only"):
        return "internal"
    if v in ("confidential", "sensitive"):
        return "confidential"
    if v in ("restricted", "secret", "highly confidential", "strictly confidential", "top secret"):
        return "restricted"
    return None


def norm_field(name: str, value: Any) -> tuple[str | None, str | None]:
    """(normalised value or None, problem or None)."""
    text = _metadata_text(str(value)) if value not in (None, "") else None
    if text is None:
        return None, None
    if name == "criticality":
        out = norm_criticality(text)
    elif name == "exposure":
        out = norm_exposure(text)
    elif name == "data_classification":
        out = norm_classification(text)
    elif name == "environment":
        out = text.lower()[:32]
    else:
        out = text[:128]
    return out, (None if out is not None else f"{name}: {text[:40]!r} is not a known value; ignored")


# ----------------------------------------------------------------------------- rows
def parse_csv(text: str) -> list[dict[str, Any]]:
    """CSV with a header row -> import rows ``{line, hosts, os, owner, ...}``. Raises ImportError_."""
    if len(text.encode("utf-8")) > MAX_CSV_BYTES:
        raise ImportError_("the CSV is larger than 2 MB")
    text = text.lstrip("﻿")
    try:
        sample = text[:4096]
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t") if sample.strip() else csv.excel
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    try:
        return _read_rows(reader)
    except csv.Error as exc:
        # a cell over the csv module's field limit (128 KB), a quote never closed ...: the file, not the server
        raise ImportError_(f"the CSV could not be read near line {reader.line_num}: {str(exc)[:120]}") from None


def _read_rows(reader: Any) -> list[dict[str, Any]]:
    try:
        header = next(reader)
    except StopIteration:
        raise ImportError_("the CSV is empty") from None
    names = [re.sub(r"[^a-z0-9]+", "_", h.strip().lower()).strip("_") for h in header]
    host_cols = [names.index(c) for c in HOST_COLUMNS if c in names]
    cols = {k: next((names.index(a) for a in aliases if a in names), None) for k, aliases in ALIASES.items()}
    extra = {k: i for k, aliases in EXTRA_ALIASES.items()
             if (i := next((names.index(a) for a in aliases if a in names and names.index(a) not in host_cols), None))
             is not None}
    if not host_cols and "api_url" not in extra:
        raise ImportError_("no host column: name one column host, hostname, fqdn, ip or cidr (or api_url for clusters)")
    rows: list[dict[str, Any]] = []
    for line, record in enumerate(reader, start=2):
        if not any(cell.strip() for cell in record):
            continue
        if len(rows) >= MAX_ROWS:
            raise ImportError_(f"more than {MAX_ROWS} rows; split the file")

        def cell(i: int | None) -> str | None:
            return record[i].strip() if i is not None and i < len(record) and record[i].strip() else None

        rows.append({"line": line, "hosts": [h for h in (cell(i) for i in host_cols) if h],
                     **{k: cell(i) for k, i in cols.items()},
                     **{k: v for k, i in extra.items() if (v := cell(i)) is not None}})
    return rows


_WINDOWS = re.compile(r"\bwin|windows|cmdb_ci_win")  # Windows, Win2019, cmdb_ci_win_server; never Darwin


def _os_kind(os_value: str | None) -> str:
    return "windows_servers" if os_value and _WINDOWS.search(os_value.lower()) else "linux_servers"


@dataclass
class Plan:
    creates: list[dict[str, Any]] = field(default_factory=list)
    updates: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    # new sources past the team's source cap: never created; each says why (#224)
    over_limit: list[dict[str, Any]] = field(default_factory=list)
    limit: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    unchanged: int = 0
    rows: int = 0

    def digest(self) -> str:
        # over_limit is part of what the user confirms: if the cap or the team's count moves, Apply answers 409
        creates = [{k: v for k, v in c.items() if k != "node_name"} for c in self.creates]
        blob = json.dumps({"c": creates, "u": self.updates, "o": [o["name"] for o in self.over_limit]},
                          sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:32]

    def public(self, limit: int = 500) -> dict[str, Any]:
        return {"rows": self.rows, "digest": self.digest(), "unchanged": self.unchanged,
                "counts": {"create": len(self.creates), "update": len(self.updates), "conflict": len(self.conflicts),
                           "skipped": len(self.skipped), "over_limit": len(self.over_limit),
                           "new_targets": sum(len(c.get("targets") or [c.get("cidr")]) for c in self.creates)},
                "limit": self.limit, "warnings": self.warnings,
                "creates": self.creates[:limit], "updates": self.updates[:limit], "conflicts": self.conflicts[:limit],
                "skipped": self.skipped[:limit], "over_limit": self.over_limit[:limit],
                "truncated": max(len(self.creates), len(self.updates), len(self.conflicts), len(self.skipped),
                                 len(self.over_limit)) > limit}


def _identities(row: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    """(family 'server' | 'network', canonical identities, problems)."""
    family, out, problems = None, [], []
    for raw in row.get("hosts") or []:
        try:
            kind, _value, canonical = T.parse_line(str(raw).strip())
        except T.TargetError as exc:
            problems.append(str(exc)[:120])
            continue
        is_net = kind == "net" and ("/" in canonical or "-" in canonical)
        this = "network" if is_net else "server"
        if family is None:
            family = this
        if this == family and canonical not in out:
            out.append(canonical)
    return family or "server", out, problems


def _special_identity(kind: str, cfg: dict[str, Any]) -> str:
    """How a database, cluster or HSM row is matched to an existing source of its kind."""
    if kind == "database":
        return f"{cfg.get('engine')}|{str(cfg.get('host') or '').lower()}|{cfg.get('port')}"
    if kind == "kubernetes":
        return str(cfg.get("api_url") or "").lower().rstrip("/")
    if cfg.get("provider") == "kmip":
        return f"kmip|{str(cfg.get('host') or '').lower()}|{cfg.get('port')}"
    return f"pkcs11|{str(cfg.get('module') or '').lower()}|{str(cfg.get('token_label') or '').lower()}"


def _index(sources: list[CbomCollectionSource]) -> dict[tuple[str, str], set[int]]:
    index: dict[tuple[str, str], set[int]] = {}
    for s in sources:
        cfg = s.config or {}
        if s.kind in SERVER_KINDS:
            for target in cfg.get("targets") or []:
                index.setdefault(("server", str(target).lower()), set()).add(s.id)  # type: ignore[arg-type]
        elif s.kind == "network_range" and cfg.get("cidr"):
            index.setdefault(("network", str(cfg["cidr"]).lower()), set()).add(s.id)  # type: ignore[arg-type]
        elif s.kind in SPECIAL_KINDS:
            index.setdefault((s.kind, _special_identity(s.kind, cfg)), set()).add(s.id)  # type: ignore[arg-type]
    return index


def _name(base: str, taken: set[str]) -> str:
    clean = re.sub(r"[^A-Za-z0-9 ._-]+", "-", base).strip(" -._") or "CMDB"
    if not clean[0].isalnum():
        clean = "CMDB " + clean
    clean = clean[:56].rstrip(" -._")
    name, n = clean, 2
    while name.lower() in taken:
        name, n = f"{clean} {n}", n + 1
    taken.add(name.lower())
    assert NAME_RE.match(name)
    return name


def _word(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _row_kind(row: dict[str, Any], family: str | None) -> str:
    """The source kind a row asks for: its kind column, else hints (class, engine, api_url, module), else its OS."""
    word = _word(row.get("kind"))
    for kind, words in _KIND_WORDS.items():
        if word in words:
            return kind if kind != "network_range" or family == "network" else "linux_servers"
    cls = str(row.get("os") or "").lower()
    if cls.startswith("cmdb_ci_db") or cls.startswith("cmdb_ci_database"):
        return "database"
    if "kubernetes" in cls:
        return "kubernetes"
    if row.get("engine"):
        return "database"
    if row.get("api_url") and family is None:
        return "kubernetes"
    if row.get("module") and family is None:
        return "key_manager"
    if family == "network":
        return "network_range"
    return _os_kind(row.get("os"))


def _first_error(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            first = errors()[0]
            where = ".".join(str(x) for x in first.get("loc") or () if x != "__root__")
            msg = str(first.get("msg") or "").removeprefix("Value error, ")
            return f"{where}: {msg}" if where and not msg.startswith(f"{where}:") else msg
        except Exception:  # noqa: BLE001 - fall back to the plain text
            pass
    return str(exc).splitlines()[0]


@dataclass
class _Context:
    """What the planner needs besides the rows: the team's nodes, and the import's node and vault choices."""
    default_node: CbomScanNode | None = None
    by_name: dict[str, CbomScanNode] = field(default_factory=dict)
    by_segment: dict[str, list[CbomScanNode]] = field(default_factory=dict)
    segment_nodes: dict[str, CbomScanNode] = field(default_factory=dict)
    vault_provider: str | None = None
    windows_vault: dict[str, str] | None = None


def _context(session: Session, team_id: int, node_id: int | None, segment_nodes: dict[str, int] | None,
             vault_provider: str | None, windows_vault: dict[str, str] | None) -> _Context:
    nodes = list(session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)
                              .order_by(CbomScanNode.id)).all())
    by_id = {n.id: n for n in nodes}
    ctx = _Context(vault_provider=vault_provider, windows_vault=windows_vault)
    ctx.default_node = by_id.get(node_id) if node_id else None
    for n in nodes:
        ctx.by_name[n.name.lower()] = n
        if not AG.is_agent(n) and (n.segment or "").strip():
            ctx.by_segment.setdefault(n.segment.strip().lower(), []).append(n)
    for segment, nid in (segment_nodes or {}).items():
        chosen = by_id.get(nid)
        if chosen is None:
            raise ValueError(f"segment_nodes: scan node {nid} (for segment {segment!r}) is not a node of this team")
        problem = AG.kind_problem(chosen, "linux_servers")
        if problem:
            raise ValueError(f"segment_nodes: {problem}")
        ctx.segment_nodes[segment.strip().lower()] = chosen
    return ctx


def _row_node(ctx: _Context, row: dict[str, Any], kind: str) -> tuple[CbomScanNode | None, str | None]:
    """(the row's own scan node, or None for the import's node; the reason it has none)."""
    name = str(row.get("scan_node") or "").strip()
    if name:
        node = ctx.by_name.get(name.lower())
        if node is None:
            return None, f"no scan node named {name!r} in this team"
        problem = AG.kind_problem(node, kind)
        return (None, problem) if problem else (node, None)
    segment = str(row.get("segment") or "").strip()
    if not segment:
        return None, None
    key = segment.lower()
    if key in ctx.segment_nodes:
        return ctx.segment_nodes[key], None
    found = ctx.by_segment.get(key) or []
    if not found:
        return None, (f"no scan node in segment {segment!r}: add a scan node with that segment, or choose a node for "
                      "it in the import")
    if len(found) > 1:
        names = ", ".join(n.name for n in found[:5])
        return None, f"segment {segment!r} has {len(found)} scan nodes ({names}): choose one for it in the import"
    return found[0], None


def _vault(ctx: _Context, row: dict[str, Any], fallback: dict[str, str] | None = None) -> tuple[dict | None, str | None]:
    path = str(row.get("vault_path") or "").strip()
    if not path:
        return (dict(fallback), None) if fallback else (None, None)
    provider = _word(row.get("vault_provider")) or (fallback or {}).get("provider") or ctx.vault_provider
    if provider not in VAULT_PROVIDERS:
        return None, ("vault_provider: choose the vault in the import (or a vault_provider column: "
                      + ", ".join(VAULT_PROVIDERS) + ")")
    return {"provider": provider, "path": path}, None


def _port(row: dict[str, Any]) -> tuple[int | None, str | None]:
    raw = str(row.get("port") or "").strip()
    if not raw:
        return None, None
    return (int(raw), None) if raw.isdigit() and 1 <= int(raw) <= 65535 else (None, f"port: {raw[:12]!r} is not a port")


_BY_HAND = "add it in the Kubernetes & Databases tab"


def _special_config(ctx: _Context, kind: str, row: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """The connection config of a database, cluster or HSM row (validated by its kind's model), or why not."""
    vault, problem = _vault(ctx, row)
    if problem:
        return None, problem
    hosts = [str(h).strip() for h in row.get("hosts") or [] if str(h).strip()]
    port, problem = _port(row)
    if problem:
        return None, problem
    cfg: dict[str, Any]
    if kind == "database":
        engine = _ENGINES.get(_word(row.get("engine"))) or _ENGINES.get(_word(row.get("kind")))
        if engine is None:
            return None, "engine: name the database engine (postgres, mysql, mssql, oracle, mongodb or redis)"
        if not hosts:
            return None, "no host: name the database server's host name or IP address"
        login = str(row.get("login") or "").strip() or None
        if vault is None and login and engine != "redis":
            return None, ("vault_path: name the vault secret that holds this login's password (passwords are never "
                          f"imported from a file), or {_BY_HAND}")
        cfg = {"engine": engine, "host": hosts[0], "port": port, "login": login,
               "database_name": str(row.get("database_name") or "").strip() or None,
               "credential_type": "vault" if vault else "password", "vault": vault}
    elif kind == "kubernetes":
        api_url = str(row.get("api_url") or "").strip()
        if not api_url:
            return None, "api_url: name the cluster's API server URL (https://...)"
        if vault is None:
            return None, ("vault_path: name the vault secret that holds the cluster's kubeconfig (a kubeconfig is "
                          f"never imported from a file), or {_BY_HAND}")
        cfg = {"api_url": api_url, "credential_type": "vault", "vault": vault,
               "context": str(row.get("context") or "").strip() or None}
    else:
        if _word(row.get("kind")) == "kmip" or (not row.get("module") and hosts):
            return None, ("KMIP servers authenticate the scan node with a client certificate and key, which are never "
                          f"imported from a file: {_BY_HAND}")
        cfg = {"provider": "pkcs11", "module": str(row.get("module") or "").strip() or None,
               "token_label": str(row.get("token_label") or "").strip() or None,
               "credential_type": "vault" if vault else "password", "vault": vault}
    cfg = {k: v for k, v in cfg.items() if v is not None}
    try:
        model = KINDS[kind].model.model_validate(cfg)
    except Exception as exc:  # noqa: BLE001 - pydantic ValidationError: shown as the row's reason
        return None, _first_error(exc)
    missing = KINDS[kind].secret_fields(model) - KINDS[kind].optional_secrets
    if missing:
        return None, f"needs a stored {', '.join(sorted(missing))}, which is never imported from a file: {_BY_HAND}"
    problem = credential_target_problem(kind, model, {})
    if problem:
        return None, f"{problem} ({_BY_HAND})"
    return {k: v for k, v in model.model_dump(mode="json").items() if k not in CONFIG_FIELD.values()
            and v not in (None, [], {})}, None


def _row_identity(kind: str, row: dict[str, Any]) -> str | None:
    """``_special_identity`` of a row before its credentials are checked (a metadata-only re-import still matches)."""
    hosts = [str(h).strip() for h in row.get("hosts") or [] if str(h).strip()]
    port, _problem = _port(row)
    if kind == "database":
        engine = _ENGINES.get(_word(row.get("engine"))) or _ENGINES.get(_word(row.get("kind")))
        if not engine or not hosts:
            return None
        return _special_identity(kind, {"engine": engine, "host": hosts[0], "port": port or DB_DEFAULT_PORTS[engine]})
    if kind == "kubernetes":
        return _special_identity(kind, {"api_url": str(row.get("api_url") or "").strip()}) if row.get("api_url") else None
    if _word(row.get("kind")) == "kmip" or (not row.get("module") and hosts):
        return _special_identity(kind, {"provider": "kmip", "host": hosts[0], "port": port or 5696}) if hosts else None
    if not row.get("module"):
        return None
    return _special_identity(kind, {"module": str(row["module"]).strip(),
                                    "token_label": str(row.get("token_label") or "").strip()})


def _special_name(kind: str, cfg: dict[str, Any]) -> str:
    if kind == "database":
        return f"CMDB {cfg['engine']} {cfg['host']}"
    if kind == "kubernetes":
        return "CMDB k8s " + (urlsplit(cfg["api_url"]).hostname or "cluster")
    return f"CMDB hsm {cfg.get('module')} {cfg.get('token_label') or ''}".strip()


def build_plan(session: Session, team_id: int, rows: list[dict[str, Any]], *, create_missing: bool = True,
               node_id: int | None = None, segment_nodes: dict[str, int] | None = None,
               vault_provider: str | None = None, windows_vault: dict[str, str] | None = None) -> Plan:
    """The preview. Raises ValueError (safe to show) for a bad ``segment_nodes`` choice."""
    plan = Plan(rows=len(rows))
    ctx = _context(session, team_id, node_id, segment_nodes, vault_provider, windows_vault)
    sources = list(session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id,
        CbomCollectionSource.kind.in_(SERVER_KINDS + ("network_range",) + SPECIAL_KINDS))  # type: ignore[attr-defined]
        .order_by(CbomCollectionSource.id)).all())
    by_id = {s.id: s for s in sources}
    index = _index(sources)
    proposals: dict[int, dict[str, dict[Any, list[int]]]] = {}  # source -> field -> value -> lines
    groups: dict[tuple, dict[str, Any]] = {}
    specials: dict[tuple[str, str], dict[str, Any]] = {}
    for n, row in enumerate(rows, start=1):
        line = row.get("line") or n
        label = row.get("label")
        family, ids, problems = _identities(row) if row.get("hosts") else (None, [], [])
        kind = _row_kind(row, family if ids else None)
        values: dict[str, str] = {}
        notes = []
        for name in FIELDS:
            value, problem = norm_field(name, row.get(name))
            if value is not None:
                values[name] = value
            if problem:
                notes.append(problem)
        if kind in SPECIAL_KINDS:
            # matched by what it is (engine + host + port, API URL, module + token), never by a server target
            label = label or (row.get("hosts") or [row.get("api_url") or row.get("module")])[0]
            identity = _row_identity(kind, row)
            matched = sorted(index.get((kind, identity), set())) if identity else []
        elif not ids:
            plan.skipped.append({"line": line, "ref": row.get("ref"), "label": label,
                                 "reason": problems[0] if problems else "no host, IP address or CIDR"})
            continue
        else:
            matched = sorted({sid for i in ids for sid in index.get((family, i.lower()), set())})
        if matched:
            for sid in matched:
                slot = proposals.setdefault(sid, {})
                for name, value in values.items():
                    slot.setdefault(name, {}).setdefault(value, []).append(line)
            if notes:
                plan.skipped.append({"line": line, "label": label, "reason": "; ".join(notes)[:300], "partial": True})
            continue
        if not create_missing:
            plan.skipped.append({"line": line, "label": label, "reason": "not a target of any source (creating is off)"})
            continue
        special_cfg = None
        if kind in SPECIAL_KINDS:
            special_cfg, problem = _special_config(ctx, kind, row)
            if special_cfg is None:
                plan.skipped.append({"line": line, "label": label, "reason": problem})
                continue
        node, problem = _row_node(ctx, row, kind)
        if problem:
            plan.skipped.append({"line": line, "label": label or (ids[0] if ids else None), "reason": problem})
            continue
        node_key = node.id if node else None
        if kind in SPECIAL_KINDS:
            identity = (kind, _special_identity(kind, special_cfg))  # type: ignore[arg-type]
            if identity in specials:
                plan.skipped.append({"line": line, "label": label,
                                     "reason": f"the same {KINDS[kind].label.lower()} as line {specials[identity]['lines'][0]}"})
                continue
            specials[identity] = {"kind": kind, "config": special_cfg, "metadata": values, "lines": [line],
                                  "node": node}
            continue
        extra: dict[str, Any] = {}
        if kind == "windows_servers":
            vault, problem = _vault(ctx, row, ctx.windows_vault)
            if vault is None:
                plan.skipped.append({"line": line, "label": label or ids[0], "reason": problem or (
                    "Windows server: a WinRM login is needed; choose the vault secret that holds it in the import "
                    "(or a vault_path column), or add it in the Servers tab")})
                continue
            extra = {"credential_type": "vault", "vault": vault}
            login = str(row.get("login") or "").strip()
            if login:
                extra["login_user"] = login
        key = (kind, node_key, ids[0] if kind == "network_range" else "", json.dumps(extra, sort_keys=True),
               *(values.get(f) for f in FIELDS))
        group = groups.setdefault(key, {"kind": kind, "targets": [], "metadata": values, "lines": [], "node": node,
                                        "extra": extra})
        group["targets"].append(ids[0])
        group["lines"].append(line)
    # updates and conflicts
    for sid in sorted(proposals):
        source = by_id[sid]
        cfg = source.config or {}
        changes: dict[str, list[Any]] = {}
        for name, options in sorted(proposals[sid].items()):
            if len(options) > 1:
                plan.conflicts.append({"source_id": sid, "source": source.name, "field": name,
                                       "values": {str(v): lines[:20] for v, lines in options.items()}})
                continue
            (value,) = options
            key = CONFIG_FIELD[name]
            if cfg.get(key) != value:
                changes[key] = [cfg.get(key), value]
        if changes:
            plan.updates.append({"source_id": sid, "source": source.name, "kind": source.kind, "changes": changes})
        else:
            plan.unchanged += 1
    # creates
    taken = {(s.kind, s.name_lower) for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    names: dict[str, set[str]] = {}

    def where(node: CbomScanNode | None) -> dict[str, Any]:
        shown = node or ctx.default_node
        return {"node_id": node.id if node else None, "node_name": shown.name if shown else None,
                "segment": (node.segment or None) if node else None}

    for key in sorted(groups, key=lambda k: tuple(str(x) for x in k)):
        group = groups[key]
        kind, meta = group["kind"], group["metadata"]
        used = names.setdefault(kind, {n for k, n in taken if k == kind})
        config_meta = {CONFIG_FIELD[f]: v for f, v in sorted(meta.items())}
        if kind == "network_range":
            cidr = group["targets"][0]
            plan.creates.append({"kind": kind, "name": _name(f"CMDB net {cidr.replace('/', '-')}", used), "cidr": cidr,
                                 "metadata": config_meta, "lines": group["lines"][:50], **where(group["node"])})
            continue
        targets = sorted(set(group["targets"]))
        segment = group["node"].segment if group["node"] is not None else None
        base = "CMDB " + " ".join(x for x in (meta.get("application") or ("windows" if kind == "windows_servers"
                                                                          else "servers"),
                                              meta.get("environment"), segment) if x)
        for start in range(0, len(targets), T.MAX_LINES):
            item = {"kind": kind, "name": _name(base, used), "targets": targets[start:start + T.MAX_LINES],
                    "metadata": config_meta, "lines": group["lines"][:50], **where(group["node"])}
            if group["extra"]:
                item["config"] = group["extra"]
            plan.creates.append(item)
    for identity in sorted(specials):
        item = specials[identity]
        kind = item["kind"]
        used = names.setdefault(kind, {n for k, n in taken if k == kind})
        plan.creates.append({"kind": kind, "name": _name(_special_name(kind, item["config"]), used),
                             "config": item["config"], "metadata": {CONFIG_FIELD[f]: v for f, v in
                                                                    sorted(item["metadata"].items())},
                             "lines": item["lines"], **where(item["node"])})
    _apply_cap(session, team_id, plan)
    return plan


def _apply_cap(session: Session, team_id: int, plan: Plan) -> None:
    """Split the planned creates at the team's remaining capacity: the rest go to ``over_limit`` with the reason."""
    plan.limit = SOURCE_CAP.usage(session, team_id)
    remaining = plan.limit["remaining"]
    if len(plan.creates) <= remaining:
        return
    planned = len(plan.creates)
    reason = (f"over the team's source limit: a team can have at most {plan.limit['max']:,} sources and this team has "
              f"{plan.limit['used']:,} ({remaining:,} more allowed); raise {plan.limit['setting']} or delete unused "
              "sources, then import again")
    plan.over_limit = [{**item, "reason": reason} for item in plan.creates[remaining:]]
    plan.creates = plan.creates[:remaining]
    plan.warnings.append(f"{len(plan.over_limit):,} of the {planned:,} new sources are over the team's source limit "
                         f"({plan.limit['used']:,} of {plan.limit['max']:,} used) and will not be created; "
                         f"{len(plan.creates):,} will be.")


# ----------------------------------------------------------------------------- apply
def _new_config(item: dict[str, Any]) -> dict[str, Any]:
    if item["kind"] == "network_range":
        return {"cidr": item["cidr"], **item["metadata"]}
    if item["kind"] == "linux_servers":
        return {"targets": item["targets"], "credential_type": "node_key", "host_key_policy": "tofu",
                **item["metadata"]}
    if item["kind"] == "windows_servers":
        return {"targets": item["targets"], **item.get("config", {}), **item["metadata"]}
    return {**item["config"], **item["metadata"]}


def apply_plan(session: Session, team_id: int, user_id: int, plan: Plan, *, node_id: int | None) -> dict[str, Any]:
    """Apply in the caller's transaction (the caller commits). Raises ValueError (safe to show)."""
    now = utcnow()
    nodes: dict[int | None, CbomScanNode | None] = {}
    if plan.creates:
        if any(item.get("node_id") is None and KINDS[item["kind"]].needs_node(None) for item in plan.creates):
            node = session.get(CbomScanNode, node_id) if node_id else None
            if node is None or node.team_id != team_id:
                raise ValueError("node_id: choose the scan node that reaches the new hosts")
            nodes[None] = node
        for nid in sorted({item["node_id"] for item in plan.creates if item.get("node_id")}):
            node = session.get(CbomScanNode, nid)
            if node is None or node.team_id != team_id:
                raise ValueError("The scan nodes changed since the preview. Preview again.")
            nodes[nid] = node
        # the source form's rule (agents.check_node_for_kind): an agent node collects only its own host
        for nid, kind in sorted({(item.get("node_id"), item["kind"]) for item in plan.creates}, key=str):
            problem = AG.kind_problem(nodes.get(nid), kind)
            if problem:
                raise ValueError(f"node_id: {problem}")
        cap = SOURCE_CAP.usage(session, team_id)
        if len(plan.creates) > cap["remaining"]:  # build_plan split at the cap; this guards its own transaction
            raise ValueError(SOURCE_CAP.refusal(cap, len(plan.creates)))
    updated = created = 0
    for item in plan.updates:
        source = session.get(CbomCollectionSource, item["source_id"])
        if source is None or source.team_id != team_id:
            continue
        cfg = {**(source.config or {}), **{k: v[1] for k, v in item["changes"].items()}}
        validated = KINDS[source.kind].model.model_validate(cfg)
        source.config = validated.model_dump(mode="json")
        source.row_version += 1  # edit version only: the connection version (what jobs check) is unchanged
        source.updated_by_user_id, source.last_updated = user_id, now
        session.add(source)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="source.cmdb_update",
              object_type="source", object_id=source.id, changed_fields=[f"config.{k}" for k in item["changes"]])
        updated += 1
    for item in plan.creates:
        spec = KINDS[item["kind"]]
        cfg = spec.model.model_validate(_new_config(item))
        node = nodes.get(item.get("node_id")) if spec.needs_node(cfg) else None
        source = CbomCollectionSource(
            team_id=team_id, owner_user_id=user_id, updated_by_user_id=user_id, kind=item["kind"], name=item["name"],
            name_lower=item["name"].lower(), node_id=node.id if node else None, enabled=True,
            config=cfg.model_dump(mode="json"), secret_encrypted=None, secret_fields=[], created_at=now,
            last_updated=now, last_test_status="never" if spec.collectable(cfg) else "not_available")
        session.add(source)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="source.cmdb_create",
              object_type="source", object_id=source.id, changed_fields=["kind", "name", "config", "node_id"])
        created += 1
    log("cmdb import applied", team=team_id, by=user_id, created=created, updated=updated,
        conflicts=len(plan.conflicts) or None, skipped=len(plan.skipped) or None,
        over_limit=len(plan.over_limit) or None, nodes=len({i.get("node_id") for i in plan.creates}) or None)
    return {"created": created, "updated": updated, "conflicts": len(plan.conflicts), "skipped": len(plan.skipped),
            "over_limit": len(plan.over_limit)}
