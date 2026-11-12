"""Oracle matching (O-3, O-4): the product's assets against the lab's expected CBOM, per target.

* closed world: exact, one-to-one. Every product asset at the target's address must consume exactly one oracle asset;
  an oracle asset nothing consumed is ``missing``; a product asset that consumed nothing is ``extra``.
* open world: superset. Every oracle asset must be found; extras are listed and must stay within ``extras_ceiling``.
* a target whose independent self-check disagreed (lab/selfcheck.json) is NOT-JUDGED(lab), never a pass; a key whose
  self-check rows are all ``independent: false`` is NOT-JUDGED(lab-not-independent) (O-3; INTERFACES v2.1 #3).
* every product asset must be claimed: by a target's address, or as the single ``coverage`` row of an address the lab
  declares empty (``ranges[].empty_addresses``). Anything else is FAIL(unattributed) (O-1: no row passes without an
  oracle; INTERFACES v7 §A.1).
* fields a customer sees (quantum verdict, algorithm, key size) that the oracle does not state are derived from the
  oracle's own facts where a cited table makes that unambiguous (standards.py), otherwise NOT-RUN(no-expectation), so
  the ledger has to name what is not judged (v7 §A.2).
* sampled lists (suites, groups) are judged three ways: reported ⊆ accepted, reported ⊇ must-report, and exactly
  (``/complete``) (v7 §A.3).
* product correctness is judged on the API value (O-7); the export's completeness is the join's business.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from . import fieldmap as F
from . import standards as STD
from .checks import Checks
from .rundir import read_json, write_csv

GATE = "G11"
ORACLE_SCHEMA = "zs-cbom-oracle/1"


VISIBLE_FIELDS = ("quantum_vulnerable", "algorithm", "key_size")
ENDPOINT_TYPES = ("tls_endpoint", "database_tls", "ssh_endpoint")


def _location_key(value: Any) -> str:
    """The endpoint a location names: the product marks a chain position as a fragment (``host:443#chain[1]``)."""
    return str(value or "").split("#", 1)[0].strip().lower().rstrip(".")


def _address_of(location: str) -> str:
    loc = str(location or "").split("#", 1)[0].strip()
    if loc.startswith("["):  # [v6]:port
        return loc[1:].split("]", 1)[0].lower()
    host = loc.split("/", 1)[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.lower()


def belongs(item: dict[str, Any], target: dict[str, Any]) -> bool:
    """Is this product asset about this lab target (its address or one of its names)?"""
    keys = {str(target.get("address", "")).lower(), *[str(n).lower() for n in target.get("names") or []]}
    keys.discard("")
    return _address_of(item.get("location")) in keys or str(item.get("target") or "").lower() in keys


def product_value(key: str, item: dict[str, Any], component: dict[str, Any] | None) -> Any:
    """The product's value for an oracle ``expect`` key: the API value; for keys only the export carries
    (pqc_class), the export's."""
    if key in F.FIELDS and "api" in F.FIELDS[key]:
        return F.view_value(key, "api", item)
    if key in F.ORACLE_ONLY:
        return F.ORACLE_ONLY[key](item)
    if key in F.EXPORT_ALWAYS:
        if component is None:
            return F.MISSING
        values = F.props(component).get(F.EXPORT_ALWAYS[key])
        return F.MISSING if values is None else values[0]
    if key == "serial":
        return (item.get("facts") or {}).get("serial")
    if key == "fingerprint_sha256":
        return (item.get("facts") or {}).get("fingerprint_sha256")
    if key == "format":
        return (item.get("facts") or {}).get("format")
    if key == "path":
        return item.get("location")
    return F.MISSING


DISCRIMINATORS = ("fingerprint_sha256", "serial", "subject", "path")


def _has_discriminator(asset: dict[str, Any]) -> bool:
    return any((asset.get("expect") or {}).get(k) not in (None, "") for k in DISCRIMINATORS)


def _score(asset: dict[str, Any], item: dict[str, Any], comp: dict[str, Any] | None) -> int:
    """How well a product asset fits an oracle asset beyond (type, location): several certificates of one chain share
    an endpoint's location, so the fingerprint, serial, subject or path decides which is which."""
    score = 0
    for key in DISCRIMINATORS:
        want = (asset.get("expect") or {}).get(key)
        got = product_value(key, item, comp)
        if want in (None, "") or got is F.MISSING or got in (None, ""):
            continue
        norm = F.ORACLE_NORMALISERS[key]
        score += 1 if norm(got) == norm(want) else -1
    return score


def in_scope(target: dict[str, Any], scope: dict[str, Any] | None) -> bool:
    """Was this target part of what the customer configured in this run (by source name or by network range)?"""
    if scope is None:
        return True
    if target.get("source") in set(scope.get("sources") or []):
        return True
    try:
        addr = ipaddress.ip_address(str(target.get("address")))
    except ValueError:
        return False
    for cidr in scope.get("ranges") or []:
        try:
            if addr in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def load_oracle(run: Path, k: str) -> dict[str, Any] | None:
    doc = read_json(Path(run) / "oracle" / f"run{k}.json")
    if doc is not None and doc.get("schema") != ORACLE_SCHEMA:
        raise ValueError(f"oracle/run{k}.json: schema {doc.get('schema')!r}, expected {ORACLE_SCHEMA}")
    return doc


def not_independent(run: Path) -> set[tuple[str, str]]:
    """(oracle_id base, key) pairs whose self-check rows are ALL ``independent: false`` (the tool shares code with the
    prober, e.g. OpenSSL s_client): those keys have no independent oracle (O-3)."""
    doc = read_json(Path(run) / "lab" / "selfcheck.json") or {}
    flags: dict[tuple[str, str], set[bool]] = {}
    unverified: set[tuple[str, str]] = set()
    for target in doc.get("targets") or []:
        for c in target.get("checks") or []:
            if "independent" not in c:
                continue
            key = (str(c.get("oracle_id", "")).split("[", 1)[0], str(c.get("key", "")).split(" ", 1)[0])
            flags.setdefault(key, set()).add(bool(c.get("independent")))
        # INTERFACES v7.1 #5: the lab names every run-file key no agreeing independent row proves (this also covers
        # keys with no self-check row at all)
        for oid, keys in (target.get("unverified_keys") or {}).items():
            unverified |= {(str(oid).split("[", 1)[0], str(key)) for key in keys or []}
    return {k for k, v in flags.items() if v == {False}} | unverified


def derive(asset: dict[str, Any], key: str, item: dict[str, Any]) -> tuple[Any, str] | None:
    """An expectation for ``key`` derived from the oracle asset's own stated facts (never from the product), or None.
    Returns (expected value, how) where ``how`` names the rule (standards.py cites the tables)."""
    expect = asset.get("expect") or {}
    atype = asset.get("asset_type")
    if key == "quantum_vulnerable" and atype in ("tls_endpoint", "database_tls") and expect.get("groups"):
        qv = STD.kex_quantum_vulnerable(F.norm_groups(expect["groups"]) or [], STD.PQ_TLS_GROUPS)
        return None if qv is None else (qv, "derived: accepted TLS groups vs IANA ML-KEM groups")
    if key == "quantum_vulnerable" and atype == "ssh_endpoint" and expect.get("kex_algorithms"):
        qv = STD.kex_quantum_vulnerable(F.norm_ssh_list(expect["kex_algorithms"]) or [], STD.PQ_SSH_KEX)
        return None if qv is None else (qv, "derived: accepted SSH KEX vs PQ KEX table")
    if key == "algorithm" and atype in ("tls_endpoint", "database_tls") and expect.get("cipher_suites"):
        return ("one of " + ",".join(F.norm_suites(expect["cipher_suites"]) or []), "derived: negotiated suite is accepted")
    if key in ("algorithm", "key_size") and atype == "ssh_endpoint" and expect.get("host_keys"):
        keys = F.norm_host_keys(expect["host_keys"]) or []
        if key == "algorithm":
            return ("one of " + ",".join(sorted({t for t, _, _ in keys})), "derived: a host key the server holds")
        bits = {t: b for t, b, _ in keys}
        alg = str(item.get("algorithm") or "")
        return (bits.get(alg), f"derived: bits of the {alg or '?'} host key") if alg in bits else None
    return None


def _derived_ok(key: str, want: Any, item: dict[str, Any], asset: dict[str, Any]) -> bool:
    got = item.get(key)
    if isinstance(want, str) and want.startswith("one of "):
        allowed = set(want[len("one of "):].split(","))
        if asset.get("asset_type") in ("tls_endpoint", "database_tls"):
            return bool(got) and (F.norm_suites([got]) or [""])[0] in allowed
        return bool(got) and str(got) in allowed
    if key == "quantum_vulnerable":
        return F.norm_bool(got) is want
    return F.norm_int(got) == want


def selfcheck_disagreements(run: Path) -> dict[str, list[str]]:
    doc = read_json(Path(run) / "lab" / "selfcheck.json") or {}
    out: dict[str, list[str]] = {}
    for target in doc.get("targets") or []:
        if not target.get("agree", False):
            out[str(target.get("target_id"))] = [f"{c.get('oracle_id')}:{c.get('key')}"
                                                for c in target.get("checks") or [] if not c.get("agree", False)]
    return out


def match(run: Path, k: str, checks: Checks, api_items: dict[int, dict[str, Any]] | None,
          components: dict[int, dict[str, Any]] | None, scope: dict[str, Any] | None = None,
          pairs: dict[str, int] | None = None) -> list[dict[str, Any]]:
    """Judge run ``k`` against its oracle. ``pairs`` (if given) receives oracle_id -> matched product asset id."""
    prefix = f"{GATE}/oracle/run{k}"
    oracle = load_oracle(run, k)
    if oracle is None:
        checks.not_run(f"{prefix}", GATE, "oracle", f"oracle/run{k}.json not written (lab not run)", {"run": k})
        return []
    if api_items is None:
        checks.not_run(f"{prefix}/api", GATE, "oracle", "no API assets to judge", {"run": k})
        return []
    if not (Path(run) / "lab" / "selfcheck.json").is_file():
        checks.fail(f"{prefix}/selfcheck", GATE, "oracle", "selfcheck-missing", {"run": k},
                    expected="lab/selfcheck.json (O-3)", observed="absent")
    lab_bugs = selfcheck_disagreements(run)
    weak_keys = not_independent(run)
    components = components or {}
    rows: list[dict[str, Any]] = []
    claimed: set[int] = set()
    for target in oracle.get("targets") or []:
        tid = str(target["target_id"])
        world = target.get("world", "closed")
        tsubject = {"kind": "oracle", "run": k, "target_id": tid, "world": world}
        mine = {aid: item for aid, item in api_items.items() if belongs(item, target)}
        claimed |= set(mine)
        if not in_scope(target, scope):
            for asset in target.get("assets") or [{"oracle_id": f"{tid}/*"}]:
                checks.not_run(f"{prefix}/{asset['oracle_id']}", GATE, "oracle",
                               f"target not configured in this run (source {target.get('source')})",
                               {**tsubject, "oracle_id": asset["oracle_id"], "source": target.get("source"),
                                "field": "not-configured"})
            for aid, item in sorted(mine.items()):  # the customer did not ask for this target
                checks.fail(f"{prefix}/{tid}/out-of-scope/{aid}", GATE, "oracle", "out-of-scope-asset",
                            {**tsubject, "asset_type": item.get("type"), "field": "scope"},
                            expected="no asset for a target the customer did not configure",
                            observed=f"{item.get('type')} at {item.get('location')}")
            continue
        if tid in lab_bugs:
            for asset in target.get("assets") or []:
                checks.not_judged(f"{prefix}/{asset['oracle_id']}", GATE, "oracle",
                                  "lab self-check disagreed: " + ", ".join(lab_bugs[tid]),
                                  {**tsubject, "oracle_id": asset["oracle_id"]})
            continue
        consumed: dict[int, str] = {}
        for asset in target.get("assets") or []:
            oid = asset["oracle_id"]
            subject = {**tsubject, "oracle_id": oid, "asset_type": asset.get("asset_type"),
                       "location": asset.get("location")}
            candidates = [aid for aid, item in sorted(mine.items())
                          if aid not in consumed and item.get("type") == asset.get("asset_type")
                          and _location_key(item.get("location")) == _location_key(asset.get("location"))]
            scored = sorted((-_score(asset, api_items[a], components.get(a)), a) for a in candidates)
            if _has_discriminator(asset):  # a candidate that contradicts the fingerprint/serial/subject/path is not it
                scored = [(s, a) for s, a in scored if s <= 0]
            if not scored:
                checks.fail(f"{prefix}/{oid}/present", GATE, "oracle", "missing", {**subject, "field": "present"},
                            expected=f"{asset.get('asset_type')} at {asset.get('location')}", observed="no such asset")
                rows.append({"oracle_id": oid, "asset_id": "", "key": "present", "expected": "yes", "product": "no",
                             "verdict": "FAIL"})
                continue
            aid = scored[0][1]
            consumed[aid] = oid
            if pairs is not None:
                pairs[oid] = aid
            checks.ok(f"{prefix}/{oid}/present", GATE, "oracle", {**subject, "asset_id": aid, "field": "present"})
            item, comp = api_items[aid], components.get(aid)
            expect = asset.get("expect") or {}
            for key, want_raw in expect.items():
                cid = f"{prefix}/{oid}/{key}"
                ksubject = {**subject, "asset_id": aid, "field": key}
                norm = F.ORACLE_NORMALISERS.get(key)
                if norm is None:
                    checks.fail(cid, GATE, "oracle", "unknown-expect-key", ksubject, expected=want_raw)
                    continue
                if (oid.split("[", 1)[0], key) in weak_keys:
                    checks.not_judged(cid, GATE, "oracle", "lab-not-independent", ksubject, expected=want_raw,
                                      observed="the lab's only self-check of this key shares code with the prober")
                    continue
                got_raw = product_value(key, item, comp)
                want = norm(want_raw)
                got = None if got_raw is F.MISSING else norm(got_raw)
                shown = "<absent>" if got_raw is F.MISSING else got_raw
                if key in F.SAMPLED:
                    _sampled(checks, cid, ksubject, key, want, got, got_raw, asset, rows, oid, aid)
                    continue
                ok = got_raw is not F.MISSING and got == want
                checks.verdict(cid, GATE, "oracle", ok, "export-missing" if got_raw is F.MISSING else "wrong-value",
                               ksubject, expected=want_raw, observed=shown)
                rows.append({"oracle_id": oid, "asset_id": aid, "key": key, "expected": want_raw, "product": shown,
                             "verdict": "PASS" if ok else "FAIL"})
            # customer-visible fields the oracle does not state: derive from its own facts, else name the gap
            for key in VISIBLE_FIELDS:
                if key in expect:
                    # v7 §A.2: the lab states the value and wins; a derivation from its own facts must agree with it
                    derived = derive(asset, key, item) if key == "quantum_vulnerable" else None
                    if derived is not None and F.norm_bool(expect[key]) is not derived[0]:
                        checks.fail(f"{prefix}/{oid}/{key}/lab_vs_derivation", GATE, "oracle", "lab-vs-derivation",
                                    {**subject, "asset_id": aid, "field": key, "expectation": "lab-vs-derivation"},
                                    expected=f"{derived[0]} ({derived[1]})", observed=expect[key])
                    continue
                if world == "open" and asset.get("asset_type") not in ENDPOINT_TYPES:
                    continue
                cid = f"{prefix}/{oid}/{key}"
                ksubject = {**subject, "asset_id": aid, "field": key}
                derived = derive(asset, key, item)
                if derived is not None:
                    want, how = derived
                    ok = _derived_ok(key, want, item, asset)
                    checks.verdict(cid, GATE, "oracle", ok, "wrong-value", {**ksubject, "expectation": "derived"},
                                   expected=f"{want} ({how})", observed=item.get(key))
                    rows.append({"oracle_id": oid, "asset_id": aid, "key": key, "expected": f"{want} ({how})",
                                 "product": item.get(key), "verdict": "PASS" if ok else "FAIL"})
                elif item.get(key) not in (None, ""):
                    checks.not_run(cid, GATE, "oracle", "no-expectation", {**ksubject, "reason_detail": "oracle silent"})
            codes = set(F.norm_codes(item.get("finding_codes")))
            for code in asset.get("codes_include") or []:
                checks.verdict(f"{prefix}/{oid}/code/{code}", GATE, "oracle", code in codes, "code-missing",
                               {**subject, "asset_id": aid, "field": "finding_codes", "code": code},
                               expected=f"includes {code}", observed=sorted(codes))
            for code in asset.get("codes_exclude") or []:
                checks.verdict(f"{prefix}/{oid}/no-code/{code}", GATE, "oracle", code not in codes, "code-unexpected",
                               {**subject, "asset_id": aid, "field": "finding_codes", "code": code},
                               expected=f"excludes {code}", observed=sorted(codes))
            if asset.get("impact_max"):
                got = item.get("impact") or "Info"
                checks.verdict(f"{prefix}/{oid}/impact_max", GATE, "oracle",
                               F.IMPACT_RANK.get(got, 4) >= F.IMPACT_RANK.get(asset["impact_max"], 4), "impact-too-high",
                               {**subject, "asset_id": aid, "field": "impact"},
                               expected=f"<= {asset['impact_max']}", observed=got)
        extras = sorted(aid for aid in mine if aid not in consumed)
        if world == "closed":
            for aid in extras:
                checks.fail(f"{prefix}/{tid}/extra/{aid}", GATE, "oracle", "extra",
                            {**tsubject, "asset_id": aid, "asset_type": mine[aid].get("type"), "field": "extra",
                             "location": mine[aid].get("location")},
                            expected="no asset beyond the oracle (closed world)",
                            observed=f"{mine[aid].get('type')} at {mine[aid].get('location')}")
        else:
            ceiling = int(target.get("extras_ceiling", 0))
            checks.verdict(f"{prefix}/{tid}/extras", GATE, "oracle", len(extras) <= ceiling, "too-many-extras",
                           {**tsubject, "field": "extras"}, expected=f"<= {ceiling}",
                           observed=[f"{mine[a].get('type')} {mine[a].get('location')}" for a in extras])
        for i, banned in enumerate(target.get("must_not_appear") or []):
            hits = [aid for aid, item in api_items.items()
                    if item.get("type") == banned.get("asset_type")
                    and _location_key(item.get("location")) == _location_key(banned.get("location"))]
            checks.verdict(f"{prefix}/{tid}/must-not-appear/{i}", GATE, "oracle", not hits, "fabricated",
                           {**tsubject, "asset_type": banned.get("asset_type"), "location": banned.get("location"),
                            "field": "must_not_appear"},
                           expected="absent", observed=hits)
    claimed |= _empty_addresses(oracle, prefix, k, checks, api_items, scope)
    for aid, item in sorted(api_items.items()):
        if aid in claimed:
            continue
        checks.fail(f"{prefix}/unattributed/{aid}", GATE, "oracle", "unattributed",
                    {"kind": "oracle", "run": k, "field": "unattributed", "asset_type": item.get("type"),
                     "target_id": "-", "address": _address_of(item.get("location"))},
                    expected="every asset belongs to a lab target or to an address the lab declares empty",
                    observed=f"{item.get('type')} at {item.get('location')}")
    write_csv(Path(run) / "diff" / f"oracle-run{k}.csv", rows,
              ["oracle_id", "asset_id", "key", "expected", "product", "verdict"])
    return rows


def _sampled(checks: Checks, cid: str, subject: dict[str, Any], key: str, want: Any, got: Any, got_raw: Any,
             asset: dict[str, Any], rows: list[dict[str, Any]], oid: str, aid: int) -> None:
    """Suites and groups: the product reports what it negotiated and probed, a sample of what the server accepts.
    1. reported ⊆ accepted (nothing the server does not accept), non-empty;
    2. reported ⊇ must-report: the lab's ``must_report`` list when it states one, else one reported entry per class the
       accepted set contains (weak-suite classes; PQ / classical groups; standards.py);
    3. exact (``/complete``): reported == accepted. Today a known gap (the product samples), ledgered with an issue."""
    accepted = set(want or [])
    reported = set(got or [])
    shown = "<absent>" if got_raw is F.MISSING else got_raw
    if got_raw is F.MISSING:
        checks.fail(cid, GATE, "oracle", "export-missing", subject, expected=sorted(accepted), observed=shown)
        return
    ok = bool(reported) and reported <= accepted
    checks.verdict(cid, GATE, "oracle", ok, "not-accepted-by-server" if reported else "not-reported", subject,
                   expected=f"non-empty subset of {sorted(accepted)}", observed=sorted(reported))
    lab_list = (asset.get("must_report") or {}).get(key)
    if lab_list:
        norm = F.ORACLE_NORMALISERS[key]
        must = set(norm(lab_list) or [])
        missing = sorted(must - reported)
        how = "lab must_report"
    else:
        classes = STD.WEAK_SUITE_CLASSES if key == "cipher_suites" else STD.GROUP_CLASSES
        need = STD.classes_present(accepted, classes)
        have = STD.classes_present(reported, classes)
        missing = sorted(need - have)
        how = "one per class: " + ",".join(sorted(need))
    checks.verdict(f"{cid}/must_report", GATE, "oracle", not missing, "must-report-missing",
                   {**subject, "field": f"{key}/must_report"}, expected=how, observed={"missing": missing})
    exact = reported == accepted
    checks.verdict(f"{cid}/complete", GATE, "oracle", exact, "sample-not-enumeration",
                   {**subject, "field": f"{key}/complete"}, expected=sorted(accepted), observed=sorted(reported))
    rows.append({"oracle_id": oid, "asset_id": aid, "key": key, "expected": sorted(accepted), "product": shown,
                 "verdict": "PASS" if ok and not missing else "FAIL"})


def _empty_addresses(oracle: dict[str, Any], prefix: str, k: str, checks: Checks,
                     api_items: dict[int, dict[str, Any]], scope: dict[str, Any] | None) -> set[int]:
    """INTERFACES v7 §A.1: each address the lab declares empty must carry exactly one ``coverage`` row and nothing else.
    Returns the asset ids claimed this way."""
    claimed: set[int] = set()
    for rng in oracle.get("ranges") or []:
        if scope is not None and rng.get("source") not in set(scope.get("sources") or []) \
                and rng.get("cidr") not in set(scope.get("ranges") or []):
            continue
        for addr in rng.get("empty_addresses") or []:
            here = sorted(aid for aid, item in api_items.items() if _address_of(item.get("location")) == str(addr)
                          or str(item.get("target") or "") == str(addr))
            cov = [a for a in here if api_items[a].get("type") == "coverage"]
            other = [a for a in here if api_items[a].get("type") != "coverage"]
            claimed |= set(here)
            subject = {"kind": "oracle", "run": k, "target_id": f"empty:{addr}", "field": "empty_address",
                       "source": rng.get("source")}
            checks.verdict(f"{prefix}/empty/{addr}", GATE, "oracle", len(cov) == 1 and not other, "empty-address",
                           subject, expected="exactly one coverage row, nothing else",
                           observed=[f"{api_items[a].get('type')} {api_items[a].get('location')}" for a in here])
    return claimed


def closed_world_ids(run: Path, k: str, api_items: dict[int, dict[str, Any]]) -> set[int]:
    oracle = load_oracle(run, k) or {}
    out: set[int] = set()
    for target in oracle.get("targets") or []:
        if target.get("world", "closed") == "closed":
            out |= {aid for aid, item in api_items.items() if belongs(item, target)}
    return out


def in_lab(address: str, subnet: str = "10.231.0.0/24") -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(subnet)
    except ValueError:
        return False
