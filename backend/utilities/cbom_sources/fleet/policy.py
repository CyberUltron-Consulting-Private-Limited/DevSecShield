"""Tag policies: the selector grammar, action validation and the deterministic policy engine (F1 contract, section 3).

Evaluation rules, in order:
1. the team's never-scan list wins: any address of the target (or its host name) on the list → ``never_scan``
   (the T1 rule: one listed address excludes the whole target);
2. enabled, non-deleted policies by ``priority`` descending, then ``id`` ascending; the first match wins and every
   match is reported (``matched_policy_ids``), so the UI can show which policy won;
3. a winner whose action is never-scan → ``never_scan``; otherwise ``collect``, unless something it needs is not
   usable (a target a person removed from the inventory, a deleted credential, a transport or SSH CA that is
   missing, disabled, deleted or behind an off flag, a deleted scan node, a target that is not a Linux host or has no
   address, an SSM target without an instance id, or one a sync has missed for more than 7 days), which gives
   ``unmanaged`` with the reason;
4. no match → ``unmanaged`` ("No policy matches").

The same inputs always give the same Decision, whatever the order of the policies or targets.

Selector grammar: ``{"all": [...]}``, ``{"any": [...]}``, ``{"not": {...}}``, leaves ``{"tag": k, "op": op, "value": v}``
and ``{"field": "kind|account_id|region|platform", "op": op, "value": v}`` with ``op`` in eq, ne, in, exists, prefix.
No regular expressions; at most 20 leaves; tag keys are compared lower-cased, values exactly.
"""
from __future__ import annotations

import bisect
import datetime as _dt
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence

from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.fleet.models import TARGET_KINDS

OPS = ("eq", "ne", "in", "exists", "prefix")
FIELDS = ("kind", "account_id", "region", "platform")
TRANSPORTS = ("ssh", "awx", "salt", "ssm")
MAX_LEAVES = 20
MAX_DEPTH = 6
MAX_IN_VALUES = 50
MISSING_DAYS = 7
COLLECT_KINDS = ("linux_host",)
DEFAULT_BATCH = 100


class PolicyError(ValueError):
    """``str(err)`` is safe to show."""


# ----------------------------------------------------------------------------- selector
def validate_selector(selector: Any) -> dict[str, Any]:
    """The normalised selector (tag keys lower-cased, values as text).  An empty selector matches every target."""
    if selector in (None, {}):
        return {}
    leaves = [0]

    def walk(node: Any, depth: int) -> dict[str, Any]:
        if depth > MAX_DEPTH:
            raise PolicyError(f"selector: nested more than {MAX_DEPTH} levels")
        if not isinstance(node, Mapping) or not node:
            raise PolicyError("selector: each part must be an object")
        keys = set(node)
        if keys == {"all"} or keys == {"any"}:
            name = next(iter(keys))
            items = node[name]
            if not isinstance(items, list) or not items:
                raise PolicyError(f"selector: {name!r} needs a non-empty list")
            return {name: [walk(item, depth + 1) for item in items]}
        if keys == {"not"}:
            return {"not": walk(node["not"], depth + 1)}
        if "tag" in keys or "field" in keys:
            leaves[0] += 1
            if leaves[0] > MAX_LEAVES:
                raise PolicyError(f"selector: at most {MAX_LEAVES} conditions")
            allowed = {"tag", "op", "value"} if "tag" in keys else {"field", "op", "value"}
            if not keys <= allowed or "op" not in keys:
                raise PolicyError("selector: a condition is {tag|field, op, value}")
            op = node["op"]
            if op not in OPS:
                raise PolicyError(f"selector: op must be one of {', '.join(OPS)}")
            out: dict[str, Any] = {"op": op}
            if "tag" in keys:
                key = str(node["tag"] or "").strip().lower()
                if not key or len(key) > 128:
                    raise PolicyError("selector: a tag key is empty or longer than 128 characters")
                out["tag"] = key
            else:
                if node["field"] not in FIELDS:
                    raise PolicyError(f"selector: field must be one of {', '.join(FIELDS)}")
                out["field"] = node["field"]
            if op == "exists":
                if node.get("value") not in (None, True):
                    raise PolicyError("selector: 'exists' takes no value")
                return out
            value = node.get("value")
            if op == "in":
                if not isinstance(value, list) or not value or len(value) > MAX_IN_VALUES:
                    raise PolicyError(f"selector: 'in' needs a list of 1 to {MAX_IN_VALUES} values")
                out["value"] = sorted({_leaf_text(v) for v in value})
            else:
                out["value"] = _leaf_text(value)
                if op == "prefix" and out["value"] == "":
                    raise PolicyError("selector: 'prefix' needs a value")
            if out.get("field") == "kind":
                kinds = out["value"] if isinstance(out["value"], list) else [out["value"]]
                bad = [k for k in kinds if k not in TARGET_KINDS] if op in ("eq", "ne", "in") else []
                if bad:
                    raise PolicyError(f"selector: kind must be one of {', '.join(TARGET_KINDS)}")
            return out
        raise PolicyError("selector: use all, any, not, or a tag/field condition")

    return walk(selector, 0)


def _leaf_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if not isinstance(value, (str, int, float)):
        raise PolicyError("selector: values must be text")
    text = str(value).strip()
    if len(text) > 256:
        raise PolicyError("selector: a value is longer than 256 characters")
    return text


def _view(target: Any) -> tuple[Mapping[str, str], dict[str, str | None]]:
    tags = getattr(target, "tags", None) or {}
    fields = {name: getattr(target, name, None) for name in FIELDS}
    return tags, fields


def compile_selector(selector: Mapping[str, Any]) -> Callable[[Mapping[str, str], Any], bool]:
    """A normalised selector as a function of (tags, target): the same results as ``matches`` (a test compares them on
    random selectors), without walking the dict for every target."""
    if not selector:
        return lambda tags, target: True
    if "all" in selector:
        parts = [compile_selector(s) for s in selector["all"]]
        if len(parts) == 2:  # the common shapes without a generator per call
            a, b = parts
            return lambda tags, target: a(tags, target) and b(tags, target)
        if len(parts) == 3:
            a, b, c = parts
            return lambda tags, target: a(tags, target) and b(tags, target) and c(tags, target)
        return lambda tags, target: all(f(tags, target) for f in parts)
    if "any" in selector:
        parts = [compile_selector(s) for s in selector["any"]]
        if len(parts) == 2:
            a, b = parts
            return lambda tags, target: a(tags, target) or b(tags, target)
        return lambda tags, target: any(f(tags, target) for f in parts)
    if "not" in selector:
        inner = compile_selector(selector["not"])
        return lambda tags, target: not inner(tags, target)
    op, value = selector["op"], selector.get("value")
    if "tag" in selector:
        key = selector["tag"]
        if op == "exists":
            return lambda tags, target: key in tags
        if op == "ne":
            return lambda tags, target: key not in tags or tags[key] != value
        if op == "eq":
            return lambda tags, target: tags.get(key) == value
        if op == "in":
            values = frozenset(value)
            return lambda tags, target: tags.get(key) in values
        return lambda tags, target: key in tags and str(tags[key]).startswith(value)  # prefix
    name = selector["field"]
    if op == "exists":
        return lambda tags, target: getattr(target, name, None) is not None
    if op == "ne":
        return lambda tags, target: getattr(target, name, None) is None or getattr(target, name, None) != value
    if op == "eq":
        return lambda tags, target: getattr(target, name, None) == value
    if op == "in":
        values = frozenset(value)
        return lambda tags, target: getattr(target, name, None) in values
    return lambda tags, target: (getattr(target, name, None) is not None
                                 and str(getattr(target, name, None)).startswith(value))  # prefix


def required_tag(selector: Mapping[str, Any]) -> str | None:
    """A tag key every target the selector matches must carry (None when there is no such key): lets the engine skip
    a policy for a target without that tag before running its selector."""
    leaves = selector.get("all", [selector]) if selector else []
    for leaf in leaves:
        if "tag" in leaf and leaf["op"] in ("eq", "in", "exists", "prefix"):
            return leaf["tag"]
    return None


def index_entry(selector: Mapping[str, Any]) -> tuple[str, Any]:
    """Where the engine files a policy so that a target is only tested against policies it can match:
    ``("kv", [(key, value), ...])`` when every match carries one of those tag values (an ``eq`` or ``in`` leaf at the
    top or under ``all``), ``("key", key)`` when every match carries the tag (``exists`` or ``prefix``), else
    ``("all", None)``.  The selector still decides; the index only skips policies that cannot match."""
    leaves = selector.get("all", [selector]) if selector else []
    tagged = [leaf for leaf in leaves if "tag" in leaf]
    for leaf in tagged:
        if leaf["op"] == "eq":
            return "kv", [(leaf["tag"], leaf["value"])]
    ins = [leaf for leaf in tagged if leaf["op"] == "in"]
    if ins:
        leaf = min(ins, key=lambda x: len(x["value"]))
        return "kv", [(leaf["tag"], v) for v in leaf["value"]]
    for leaf in tagged:
        if leaf["op"] in ("exists", "prefix"):
            return "key", leaf["tag"]
    return "all", None


def matches(selector: Mapping[str, Any], tags: Mapping[str, str], fields: Mapping[str, str | None]) -> bool:
    if not selector:
        return True
    if "all" in selector:
        return all(matches(s, tags, fields) for s in selector["all"])
    if "any" in selector:
        return any(matches(s, tags, fields) for s in selector["any"])
    if "not" in selector:
        return not matches(selector["not"], tags, fields)
    present = (selector["tag"] in tags) if "tag" in selector else (fields.get(selector["field"]) is not None)
    actual = tags.get(selector["tag"]) if "tag" in selector else fields.get(selector["field"])
    op = selector["op"]
    if op == "exists":
        return present
    if op == "ne":
        return not present or actual != selector["value"]
    if not present or actual is None:
        return False
    if op == "eq":
        return actual == selector["value"]
    if op == "in":
        return actual in selector["value"]
    return str(actual).startswith(selector["value"])  # prefix


# ----------------------------------------------------------------------------- action
def validate_action(action: Any) -> dict[str, Any]:
    if not isinstance(action, Mapping):
        raise PolicyError("action must be an object")
    allowed = {"never_scan", "transport", "transport_id", "credential_id", "node_id", "node_segment", "tier",
               "batch_size", "schedule"}
    unknown = sorted(set(action) - allowed)
    if unknown:
        raise PolicyError(f"action: unknown field {unknown[0][:40]!r}")
    if action.get("never_scan") is True:
        return {"never_scan": True}
    if action.get("never_scan") not in (None, False):
        raise PolicyError("action: never_scan must be true or false")
    transport = action.get("transport") or "ssh"
    if transport not in TRANSPORTS:
        raise PolicyError(f"action: transport must be one of {', '.join(TRANSPORTS)}")
    out: dict[str, Any] = {"never_scan": False, "transport": transport}
    for name in ("transport_id", "credential_id", "node_id"):
        value = action.get(name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**31 - 1):
            raise PolicyError(f"action: {name} must be an id")
        out[name] = value
    segment = action.get("node_segment")
    if segment is not None:
        if not isinstance(segment, str) or not segment.strip() or len(segment.strip()) > 64:
            raise PolicyError("action: node_segment must be text of 1 to 64 characters")
        segment = segment.strip()
    out["node_segment"] = segment
    if transport == "ssh":
        if out["credential_id"] is None:
            raise PolicyError("action: choose the credential the SSH transport logs in with")
        out["transport_id"] = None
    else:
        if out["transport_id"] is None:
            raise PolicyError(f"action: choose the {transport.upper()} transport")
    if transport == "ssm":
        if out["node_id"] is not None or segment is not None:
            raise PolicyError("action: SSM runs from the ZeroShield cloud worker; leave the scan node empty")
    else:
        if (out["node_id"] is None) == (segment is None):
            raise PolicyError("action: choose either a scan node or a node segment")
    tier = action.get("tier", 1)
    if tier not in (1, 2) or isinstance(tier, bool):
        raise PolicyError("action: tier must be 1 or 2")
    out["tier"] = tier
    batch = action.get("batch_size", DEFAULT_BATCH)
    if isinstance(batch, bool) or not isinstance(batch, int) or not 25 <= batch <= 1000:
        raise PolicyError("action: batch_size must be 25 to 1000")
    out["batch_size"] = batch
    out["schedule"] = _schedule(action.get("schedule"))
    return out


def _schedule(value: Any) -> dict[str, Any] | None:
    if value in (None, {}):
        return None
    if not isinstance(value, Mapping):
        raise PolicyError("action: schedule must be an object")
    unknown = sorted(set(value) - {"frequency", "time_of_day", "weekday", "monthday"})
    if unknown:
        raise PolicyError(f"schedule: unknown field {unknown[0][:40]!r}")
    frequency = value.get("frequency")
    if frequency not in ("daily", "weekly", "monthly"):
        raise PolicyError("schedule: frequency must be daily, weekly or monthly")
    time_of_day = str(value.get("time_of_day") or "02:00")
    try:
        hh, mm = time_of_day.split(":")
        if len(hh) != 2 or len(mm) != 2 or not (0 <= int(hh) <= 23 and 0 <= int(mm) <= 59):
            raise ValueError
    except ValueError:
        raise PolicyError("schedule: time_of_day must be HH:MM (24 hour)") from None
    out: dict[str, Any] = {"frequency": frequency, "time_of_day": time_of_day, "weekday": None, "monthday": None}
    if frequency == "weekly":
        weekday = value.get("weekday")
        if isinstance(weekday, bool) or not isinstance(weekday, int) or not 0 <= weekday <= 6:
            raise PolicyError("schedule: weekday must be 0 (Monday) to 6")
        out["weekday"] = weekday
    if frequency == "monthly":
        monthday = value.get("monthday")
        if isinstance(monthday, bool) or not isinstance(monthday, int) or not 1 <= monthday <= 28:
            raise PolicyError("schedule: monthday must be 1 to 28")
        out["monthday"] = monthday
    return out


# ----------------------------------------------------------------------------- decision
@dataclass(frozen=True)
class Decision:
    action: Literal["collect", "never_scan", "unmanaged"]
    policy_id: int | None
    matched_policy_ids: tuple[int, ...]
    transport: Literal["ssh", "awx", "salt", "ssm"] | None
    transport_id: int | None
    credential_id: int | None
    node_id: int | None
    node_segment: str | None
    tier: int
    schedule: dict | None
    batch_size: int
    reason: str

    def to_dict(self) -> dict[str, Any]:  # not dataclasses.asdict: this runs for every target of an evaluation
        return {"action": self.action, "policy_id": self.policy_id, "matched_policy_ids": list(self.matched_policy_ids),
                "transport": self.transport, "transport_id": self.transport_id, "credential_id": self.credential_id,
                "node_id": self.node_id, "node_segment": self.node_segment, "tier": self.tier,
                "schedule": dict(self.schedule) if self.schedule else self.schedule, "batch_size": self.batch_size,
                "reason": self.reason}


def _decision(action: str, reason: str, *, policy_id: int | None = None, matched: tuple[int, ...] = (),
              act: Mapping[str, Any] | None = None) -> Decision:
    act = act or {}
    collect = action == "collect"
    return Decision(action=action, policy_id=policy_id, matched_policy_ids=matched,  # type: ignore[arg-type]
                    transport=act.get("transport") if collect else None,
                    transport_id=act.get("transport_id") if collect else None,
                    credential_id=act.get("credential_id") if collect else None,
                    node_id=act.get("node_id") if collect else None,
                    node_segment=act.get("node_segment") if collect else None,
                    tier=int(act.get("tier") or 1) if collect else 1,
                    schedule=act.get("schedule") if collect else None,
                    batch_size=int(act.get("batch_size") or DEFAULT_BATCH) if collect else DEFAULT_BATCH,
                    reason=reason[:300])


@dataclass(frozen=True)
class _Policy:
    id: int
    name: str
    priority: int
    selector: dict[str, Any]
    action: dict[str, Any]
    test: Callable[[Mapping[str, str], Any], bool] = field(compare=False, repr=False, default=lambda tags, target: True)
    needs_tag: str | None = None


@dataclass
class Refs:
    """What a decision needs to know about rows of other tables and parts: id → None (usable) or the reason it is
    not.  An id that is not in a map is "not found"."""
    credentials: dict[int, str | None] = field(default_factory=dict)
    credential_types: dict[int, str] = field(default_factory=dict)
    credential_cas: dict[int, int | None] = field(default_factory=dict)
    transports: dict[int, str | None] = field(default_factory=dict)
    cas: dict[int, str | None] = field(default_factory=dict)
    nodes: dict[int, str | None] = field(default_factory=dict)
    checked: bool = True  # False: references are not checked (a draft preview without them)


class _NeverScan:
    """The team's never-scan list as sorted intervals (binary search per address) plus host names."""

    def __init__(self, settings: Any):
        from backend.utilities.cbom_sources.settings import team_exclusions

        try:
            parsed = team_exclusions(settings) if settings is not None else T.ParsedTargets()
        except T.TargetError:
            parsed = T.ParsedTargets()
        self.by_version: dict[int, tuple[list[int], list[int]]] = {}
        for version, start, end in sorted(parsed.intervals):
            starts, ends = self.by_version.setdefault(version, ([], []))
            starts.append(start)
            ends.append(end)
        self.hosts = set(parsed.hostnames)

    def listed(self, addresses: Sequence[str], hostname: str | None) -> str | None:
        if not self.by_version and not self.hosts:
            return None  # an empty list: no address to parse
        for text in addresses:
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            starts, ends = self.by_version.get(address.version, ([], []))
            i = bisect.bisect_right(starts, int(address)) - 1
            if i >= 0 and ends[i] >= int(address):
                return str(address)
        if hostname and hostname.lower().rstrip(".") in self.hosts:
            return hostname
        return None


def _addresses_of(target: Any) -> tuple[list[str], str | None]:
    addresses = list(getattr(target, "addresses", None) or [])
    address = getattr(target, "address", None)
    if address and address not in addresses:
        addresses.insert(0, address)
    return addresses, getattr(target, "hostname", None)


class PolicyEngine:
    """Evaluate targets against a team's policies.  Pure: no database access after construction."""

    def __init__(self, policies: Sequence[Any], settings: Any, *, transports: Mapping[int, str | None] | None = None,
                 cas: Mapping[int, str | None] | None = None, refs: Refs | None = None,
                 now: _dt.datetime | None = None):
        usable = []
        for p in policies:
            if not getattr(p, "enabled", True) or getattr(p, "deleted_at", None) is not None or p.id is None:
                continue
            try:
                selector = validate_selector(p.selector or {})
                action = validate_action(p.action or {})
            except PolicyError:
                continue  # a row that no longer validates never matches (the API refuses to save one)
            usable.append(_Policy(int(p.id), str(p.name), int(p.priority or 0), selector, action,
                                  compile_selector(selector), required_tag(selector)))
        self.policies = sorted(usable, key=lambda p: (-p.priority, p.id))
        self.names = {p.id: p.name for p in self.policies}
        self.position = {p.id: i for i, p in enumerate(self.policies)}  # id -> place in the order (0 wins)
        self._always: list[int] = []  # positions in self.policies, by index_entry
        self._by_key: dict[str, list[int]] = {}
        self._by_kv: dict[tuple[str, Any], list[int]] = {}
        for i, p in enumerate(self.policies):
            kind, where = index_entry(p.selector)
            if kind == "kv":
                for pair in dict.fromkeys(where):
                    self._by_kv.setdefault(pair, []).append(i)
            elif kind == "key":
                self._by_key.setdefault(where, []).append(i)
            else:
                self._always.append(i)
        self.never = _NeverScan(settings)
        self.refs = refs or Refs(checked=False)
        if transports is not None:
            self.refs.transports = dict(transports)
        if cas is not None:
            self.refs.cas = dict(cas)
        self.now = now

    def matching(self, target: Any) -> list[_Policy]:
        """The policies that match, in order (the first one wins).  Only the policies the target's tags can satisfy
        are tested (index_entry); a test compares this with testing every policy."""
        tags = getattr(target, "tags", None) or {}
        found = list(self._always)
        for key, value in tags.items():
            hit = self._by_key.get(key)
            if hit:
                found.extend(hit)
            try:
                hit = self._by_kv.get((key, value))
            except TypeError:  # an unhashable value equals no selector value
                hit = None
            if hit:
                found.extend(hit)
        policies = self.policies
        return [policies[i] for i in sorted(set(found)) if policies[i].test(tags, target)]

    def evaluate(self, target: Any) -> Decision:
        return self.decide(target, self.matching(target))

    def decide(self, target: Any, hits: Sequence[_Policy]) -> Decision:
        """The decision for a target whose matching policies are ``hits``, in order (``matching`` gives them)."""
        matched = tuple(p.id for p in hits)
        addresses, hostname = _addresses_of(target)
        listed = self.never.listed(addresses, hostname)
        if listed:
            return _decision("never_scan", f"On the team's never-scan list ({listed})", matched=matched)
        if not hits:
            return _decision("unmanaged", "No policy matches", matched=matched)
        win = hits[0]
        label = f"Policy {win.name!r} (priority {win.priority})"
        if win.action.get("never_scan"):
            return _decision("never_scan", f"{label}: never scan", policy_id=win.id, matched=matched)
        problem = self._problem(target, win.action, addresses, hostname)
        if problem:
            return _decision("unmanaged", f"{label}: {problem}", policy_id=win.id, matched=matched)
        return _decision("collect", f"{label}: collect over {win.action['transport'].upper()}", policy_id=win.id,
                         matched=matched, act=win.action)

    def _problem(self, target: Any, action: Mapping[str, Any], addresses: list[str], hostname: str | None) -> str | None:
        if getattr(target, "deleted_at", None) is not None:
            return "removed from the inventory"  # by a person: unlike a target a sync missed, no grace period
        kind = getattr(target, "kind", None)
        if kind not in COLLECT_KINDS:
            return (f"{kind or 'this'} targets are not collected by fleet policies (Linux hosts are); its cloud "
                    "account source covers it")
        if not addresses and not hostname:
            return "the target has no address or host name to connect to"
        missing = getattr(target, "missing_since", None)
        if missing is not None and self.now is not None and (self.now - missing) > _dt.timedelta(days=MISSING_DAYS):
            return f"not seen by its inventory for more than {MISSING_DAYS} days"
        if action["transport"] == "ssm" and not (getattr(target, "handles", None) or {}).get("ssm"):
            return "no SSM instance id (handles.ssm) to send the command to"
        if not self.refs.checked:
            return None
        refs = self.refs
        if action["transport"] == "ssh":
            cid = action["credential_id"]
            if cid not in refs.credentials:
                return f"credential #{cid} not found"
            if refs.credentials[cid]:
                return str(refs.credentials[cid])
            if refs.credential_types.get(cid) == "ssh_ca":
                ca_id = refs.credential_cas.get(cid)
                if ca_id is None or ca_id not in refs.cas:
                    return f"the credential's SSH CA #{ca_id} is not available"
                if refs.cas[ca_id]:
                    return str(refs.cas[ca_id])
        else:
            tid = action["transport_id"]
            if tid not in refs.transports:
                return f"{action['transport'].upper()} transport #{tid} not found"
            if refs.transports[tid]:
                return str(refs.transports[tid])
        nid = action.get("node_id")
        if nid is not None:
            if nid not in refs.nodes:
                return f"scan node #{nid} not found"
            if refs.nodes[nid]:
                return str(refs.nodes[nid])
        return None

    def conflicts(self, targets: Sequence[Any]) -> list[dict[str, Any]]:
        """Pairs of policies that match the same targets (the higher one wins), with how many targets they share."""
        return self.overlaps(tuple(p.id for p in self.matching(t)) for t in targets)

    def overlaps(self, matched: Iterable[Sequence[int]], *, involving: int | None = None) -> list[dict[str, Any]]:
        """``conflicts`` from the ``matched_policy_ids`` of decisions already made (in order, the winner first);
        with ``involving``, only the pairs that policy is part of."""
        pairs: dict[tuple[int, int], int] = {}
        for hits in matched:
            for other in hits[1:]:
                if involving is None or involving in (hits[0], other):
                    pairs[(hits[0], other)] = pairs.get((hits[0], other), 0) + 1
        return [{"winner_policy_id": a, "winner": self.names.get(a), "loser_policy_id": b, "loser": self.names.get(b),
                 "targets": n} for (a, b), n in sorted(pairs.items())]
