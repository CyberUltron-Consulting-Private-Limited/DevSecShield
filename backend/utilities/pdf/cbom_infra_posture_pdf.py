"""Infrastructure & Cloud Encryption Posture (SOW D6, CBOM-D06).

Reads a team view. A view with no posture block still renders the shell, empty
registers and the limits sentence.

Rule P: every number on the page comes from ``scope_facts`` (the facts this document is about: keys, key stores,
at-rest resources, cloud-managed TLS, secrets and private CAs, and the Kerberos / Active Directory posture), so a KPI
card always equals the rows listed under it.  Probed and server-config TLS endpoints belong to the Network, TLS and Crypto Protocol Assessment (SOW D7).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from reportlab.platypus import Flowable

import datetime as _dt

from backend.utilities.dashboard.cbom_team_rollup import PROBED_EVIDENCE, TeamCbomView
from backend.utilities.pdf import cbom_posture_common as common
from backend.utilities.pdf import cbom_posture_text as text
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    kpi_strip,
    manual_form,
    section_heading,
    signoff_block,
)
from backend.utilities.pdf.report_branding import REPORT_META

DOCUMENT_NUMBER = 6  # SOW D6 (REPORT_META sow_id; the Document ID reads it)
REPORT_KEY = "cbom_infra_posture"
_SIGNOFF = ("Prepared by", "Reviewed by", "Approved by")


_KEY_KINDS = frozenset({"kms_key"})
_SECRET_KINDS = frozenset({"secret_store", "secret", "certificate_policy"})
_SEVERITY_BANDS = ("Critical", "High", "Medium", "Low")


def _facts(view: object) -> list[dict[str, Any]]:
    return common.facts_of(view)


def _is_managed_tls(fact: Mapping[str, Any]) -> bool:
    return (
        common.kind_of(fact) == "tls_endpoint"
        and str(fact.get("provider") or "") in text.MANAGED_TLS_PROVIDERS
        and not common.is_verification(fact)
    )


def _is_identity(fact: Mapping[str, Any]) -> bool:
    """A Kerberos / Active Directory fact: the posture mapper's ``sources_identity`` lane (the lane the roll-up keeps on
    every Sources fact; the PDF modules may not import the mapper)."""
    return fact.get("lane") == "sources_identity"


def _is_at_rest(fact: Mapping[str, Any]) -> bool:
    return common.kind_of(fact) in text.AT_REST_KINDS and not common.is_evidence_only(fact)


# One document reads the scope seven times; at 50k facts the conversion (``facts_of``) dominated the build.  The
# scope is cached ON the view's posture object (attribute ``_SCOPE_ATTR``: (the posture fact tuple, its scope facts)),
# so it lives exactly as long as the view and nothing holds a finished request's facts.  Keyed by the fact tuple
# itself: a new fold, or ``replace(posture, facts=...)``, misses the cache.
_SCOPE_ATTR = "_d6_scope_cache"


def scope_facts(view: object) -> list[dict[str, Any]]:
    """The facts this document reports on, in view order.  Every KPI and register below reads this list (a fresh
    list each call; the fact dicts are shared and read only)."""
    block = common.posture_block(view)
    raw = common.grab(block, "facts", ())
    cacheable = isinstance(raw, tuple) and bool(raw) and hasattr(block, "__dict__")
    if cacheable:
        held = block.__dict__.get(_SCOPE_ATTR)
        if held is not None and held[0] is raw:
            return list(held[1])
    found = [
        fact
        for fact in _facts(view)
        if common.kind_of(fact) in _KEY_KINDS
        or common.kind_of(fact) == "key_store"
        or common.kind_of(fact) in _SECRET_KINDS
        or _is_at_rest(fact)
        or _is_managed_tls(fact)
        or _is_identity(fact)  # #488 review 6031264030 (D6); verdict None: not at rest
    ]
    if cacheable:
        block.__dict__[_SCOPE_ATTR] = (raw, found)  # not a dataclass field: replace() / asdict() never copy it
    return list(found)


def _at_rest_counts(facts: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    totals = {key: 0 for key in text.AT_REST_VERDICTS}
    for fact in facts:
        if not _is_at_rest(fact):
            continue
        verdict = common.layer_verdict(fact, "at_rest").upper() or "UNKNOWN"
        totals[verdict if verdict in totals else "UNKNOWN"] += 1
    return totals


def finding_rows(facts: Sequence[Mapping[str, Any]]) -> list[tuple[str, int, str]]:
    """``(code, occurrences, impact)`` over ``facts``: the findings table and the severity cards both read it.

    A code's impact is the worst impact the classifier gave THAT code on the facts carrying it (``code_impacts``, set
    by the posture mapper for Sources facts), else ``finding_impact`` (posture table, KB default, then the facts'
    impact).  A code whose impact depends on the facts (a domain's level, a key's size) is therefore never printed at
    the KB default (#493 review 6032906354 M1)."""
    counts: dict[str, int] = {}
    worst: dict[str, str] = {}
    judged: dict[str, str] = {}
    rank = {band: index for index, band in enumerate(_SEVERITY_BANDS)}
    for fact in facts:
        impact = str(fact.get("impact") or "")
        own = common.as_mapping(fact.get("code_impacts"))
        for code in common.as_rows(fact.get("finding_codes")):
            key = str(code)
            counts[key] = counts.get(key, 0) + 1
            if impact in rank and rank[impact] < rank.get(worst.get(key, ""), 9):
                worst[key] = impact
            mine = str(own.get(key) or "")
            if mine in rank and rank[mine] < rank.get(judged.get(key, ""), 9):
                judged[key] = mine
    rows = [(code, counts[code], judged.get(code) or text.finding_impact(code, worst.get(code))) for code in counts]
    rows.sort(key=lambda row: (rank.get(row[2], 9), -row[1], text.finding_label(row[0]).casefold(), row[0]))
    return rows


def _severity_counts(rows: Sequence[tuple[str, int, str]]) -> dict[str, int]:
    bands = {band: 0 for band in _SEVERITY_BANDS}
    for _code, count, impact in rows:
        bands[impact] = bands.get(impact, 0) + count
    return bands


def _rotation(fact: Mapping[str, Any]) -> str:
    """The rotation word of a key: the fact's own, else the engine's ``signals`` / ``attrs`` (what the counts read)."""
    for raw in (
        fact.get("rotation"),
        common.as_mapping(fact.get("signals")).get("rotation"),
        common.attrs_of(fact).get("rotation"),
    ):
        word = str(raw or "").strip().casefold()
        if word in ("enabled", "true", "yes"):
            return "enabled"
        if word in ("disabled", "false", "no"):
            return "disabled"
        if word in ("not_applicable", "not applicable", "n/a", "na"):
            return "not_applicable"
    return "unknown"


def _kms_summary(facts: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    buckets = {
        "keys": 0,
        "rotation_enabled": 0,
        "rotation_disabled": 0,
        "rotation_not_applicable": 0,
        "rotation_unknown": 0,
    }
    for fact in facts:
        if common.kind_of(fact) not in _KEY_KINDS:
            continue
        buckets["keys"] += 1
        buckets[f"rotation_{_rotation(fact)}"] += 1
    return buckets


def _kpi(view: object, width: float) -> Flowable:
    facts = scope_facts(view)
    at_rest = _at_rest_counts(facts)
    severity = _severity_counts(finding_rows(facts))
    kms = _kms_summary(facts)
    enabled = kms["rotation_enabled"]
    disabled = kms["rotation_disabled"]
    share = f"{enabled}/{enabled + disabled}" if enabled + disabled else "n/a"
    assessed, total, _missing, _partial = common.coverage_numbers(view)
    cards = [
        ("Facts", common.kpi_text(view, len(facts)), "Encryption facts in this document"),
        ("Encrypted (declared)", common.kpi_text(view, at_rest["ENCRYPTED_DECLARED"]), "At rest"),
        (
            "Encrypted (provider default)",
            common.kpi_text(view, at_rest["ENCRYPTED_PROVIDER_DEFAULT"]),
            "At rest",
        ),
        ("Not encrypted", common.kpi_text(view, at_rest["NOT_ENCRYPTED"]), "At rest"),
        ("Unknown", common.kpi_text(view, at_rest["UNKNOWN"]), "At rest, not evidenceable"),
    ]
    if severity["Critical"]:
        cards.append(("Findings Critical", common.kpi_text(view, severity["Critical"]), "By impact"))
    cards += [
        ("Findings High", common.kpi_text(view, severity["High"]), "By impact"),
        ("Findings Medium", common.kpi_text(view, severity["Medium"]), "By impact"),
        ("Findings Low", common.kpi_text(view, severity["Low"]), "By impact"),
        (
            "KMS keys",
            common.kpi_text(view, kms["keys"]),
            f"rotation {share}; not applicable {kms['rotation_not_applicable']}; "
            f"unknown {kms['rotation_unknown']}",
        ),
        ("Sources", common.kpi_text(view, f"{assessed}/{total}"), "assessed of current sources"),
    ]
    return kpi_strip(cards, width, max_per_row=5)


def _declared_rows(view: object) -> list[list[Any]]:
    raw = common.counts_of(view).get("declared_resources")
    rows: list[list[Any]] = []
    if isinstance(raw, Mapping):
        for key, count in raw.items():
            if isinstance(key, tuple) and len(key) >= 2:
                fmt, provider = key[0], key[1]
            else:
                fmt, _sep, provider = str(key).partition("|")
            rows.append([fmt, provider, common.as_int(count)])
    else:
        for item in common.as_rows(raw):
            mapped = common.as_mapping(item)
            rows.append(
                [mapped.get("format", ""), mapped.get("provider", ""), common.as_int(mapped.get("count"))]
            )
    rows.sort(key=lambda row: (str(row[0]).casefold(), str(row[1]).casefold()))
    return rows


def _coverage(view: object, styles: Styles, width: float) -> list[Flowable]:
    counts = common.counts_of(view)
    flow: list[Flowable] = [
        *section_heading("Coverage and method", styles),
        common.note(
            f"Out of scope resources: {common.as_int(counts.get('out_of_scope_resources'))}. "
            f"Disabled resources: {common.as_int(counts.get('disabled_resources'))}.",
            styles,
        ),
        *common.register(
            ("Format", "Provider", "Declared resources"),
            _declared_rows(view),
            (240, 240, 240),
            width,
            styles,
            view=view,
            cap_key="declared",
            noun="coverage rows",
        ),
    ]
    for line in common.data_file_lines(view):
        flow.append(common.note(line, styles))
    if not common.data_file_lines(view):
        flow.append(common.note("No reference data file was recorded.", styles))
    flow.extend(common.diagnostics_flow(view, styles, width))
    return flow


_ROTATION_WORDS = {
    "enabled": "enabled",
    "disabled": "disabled",
    "not_applicable": "not applicable",
    "unknown": "not reported",
}


def _rotation_cell(fact: Mapping[str, Any]) -> str:
    word = _ROTATION_WORDS[_rotation(fact)]
    detail = str(fact.get("rotation_detail") or "").strip()
    if not detail or detail.casefold() == word:
        return word
    return f"{word} ({detail})"


def _source_cell(fact: Mapping[str, Any]) -> str:
    return common.source_text(fact)


def _kms_rows(view: object) -> list[list[Any]]:
    rows = [fact for fact in scope_facts(view) if common.kind_of(fact) in _KEY_KINDS]
    rows.sort(
        key=lambda fact: (
            0 if str(fact.get("exposure") or "").casefold() == "public" else 1,
            common.impact_key(fact)[0],
            common.provider_of(fact).casefold(),
            common.address_of(fact).casefold(),
        )
    )
    return [
        [
            common.address_of(fact),
            common.provider_of(fact),
            fact.get("specification") or "",
            fact.get("algorithm") or "",
            fact.get("usage") or "",
            fact.get("protection") or "",
            fact.get("state") or "",
            _rotation_cell(fact),
            fact.get("deletion_protection") or "",
            common.codes_cell(fact),
            _source_cell(fact),
            common.location_of(fact),
            "",
            "",
        ]
        for fact in rows
    ]


_KMS_HEADERS = (
    "Key",
    "Provider",
    "Key type",
    "Algorithm and size",
    "Usage",
    "Protection",
    "State",
    "Rotation",
    "Deletion protection",
    "Finding codes",
    "Source",
    "Location",
    "Key custodian",
    "HSM or KMS custody evidence",
)


def _key_stores(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = [fact for fact in scope_facts(view) if common.kind_of(fact) == "key_store"]
    facts.sort(key=lambda fact: (common.provider_of(fact).casefold(), common.address_of(fact).casefold()))
    rows = [
        [
            common.address_of(fact),
            common.provider_of(fact),
            fact.get("vendor") or "",
            fact.get("version") or "",
            fact.get("state") or "",
            "" if fact.get("objects") is None else fact.get("objects"),
            _source_cell(fact),
            common.location_of(fact),
        ]
        for fact in facts
    ]
    return [
        *section_heading("Key stores, HSMs and key managers", styles),
        common.note(text.KEY_STORE_NOTE, styles),
        *common.register(
            ("Key store", "Provider", "Product", "Library or protocol version", "State", "Objects", "Source",
             "Location"),
            rows,
            (130, 90, 110, 80, 70, 50, 110, 130),
            width,
            styles,
            view=view,
            cap_key="key_stores",
            cap=text.REGISTER_ROW_CAP,
            more=text.FULL_LIST_POINTER,
            noun="key stores",
        ),
    ]


def _resource_rows(facts: Sequence[Mapping[str, Any]]) -> list[list[Any]]:
    return [
        [
            common.address_of(fact),
            fact.get("native_type") or "",
            text.verdict_label(common.layer_verdict(fact, "at_rest")),
            text.verdict_label(common.layer_verdict(fact, "transport")),
            fact.get("key_management") or "",
            fact.get("basis") or "",
            common.codes_cell(fact),
            common.location_of(fact),
            fact.get("path_context") or _source_cell(fact),
        ]
        for fact in facts
    ]


def _resources(view: object, styles: Styles, width: float) -> list[Flowable]:
    """At-rest resources grouped by provider and kind.  One cap for the whole register (not per group): the
    ``REGISTER_ROW_CAP`` worst rows are printed and the note above says exactly how many are left out."""
    facts = [fact for fact in scope_facts(view) if _is_at_rest(fact)]
    total = len(facts)
    if total > text.REGISTER_ROW_CAP:
        facts = sorted(facts, key=common.impact_key)[: text.REGISTER_ROW_CAP]
    facts.sort(
        key=lambda fact: (
            common.provider_of(fact).casefold(),
            common.kind_of(fact).casefold(),
            *common.impact_key(fact),
        )
    )
    headers = (
        "Resource",
        "Native type",
        "At rest",
        "Transport",
        "Key management",
        "Basis",
        "Finding codes",
        "Location",
        "Source or path context",
    )
    weights = (100, 70, 80, 70, 90, 90, 80, 90, 70)
    flow: list[Flowable] = [*section_heading("Resource encryption register", styles)]
    if not facts:
        flow.extend(common.register(headers, [], weights, width, styles))
        return flow
    if total > len(facts):
        flow.append(
            common.note(
                f"{total - len(facts)} further rows omitted: showing the {len(facts)} highest-impact of the "
                f"{total} resources (cap {text.REGISTER_ROW_CAP} rows). {text.FULL_LIST_POINTER}",
                styles,
            )
        )
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for fact in facts:
        groups.setdefault((common.provider_of(fact), common.kind_of(fact)), []).append(fact)
    for (provider, kind), group in groups.items():
        flow.append(common.note(f"{provider} / {kind}", styles))
        flow.extend(common.register(headers, _resource_rows(group), weights, width, styles))
    return flow


def _managed_tls(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = [fact for fact in scope_facts(view) if _is_managed_tls(fact)]
    facts.sort(key=common.impact_key)
    rows = []
    for fact in facts:
        net = common.net_of(fact)
        rows.append(
            [
                common.endpoint_label(fact),
                fact.get("policy") or net.get("policy") or "",
                net.get("min") or fact.get("protocol_version") or "",
                fact.get("listener") or net.get("listener") or "",
                text.verdict_label(common.layer_verdict(fact, "transport") or fact.get("verdict")),
                common.codes_cell(fact),
                _source_cell(fact),
                common.location_of(fact),
            ]
        )
    return [
        *section_heading("Managed TLS endpoints", styles),
        *common.register(
            (
                "Endpoint",
                "Policy",
                "Minimum version",
                "Listener",
                "Verdict",
                "Finding codes",
                "Source",
                "Location",
            ),
            rows,
            (120, 100, 70, 60, 90, 100, 100, 120),
            width,
            styles,
            view=view,
            cap_key="managed_tls",
            cap=text.REGISTER_ROW_CAP,
            more=text.FULL_LIST_POINTER,
            noun="endpoints",
        ),
    ]


def _secrets(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = [fact for fact in scope_facts(view) if common.kind_of(fact) in _SECRET_KINDS]
    facts.sort(  # worst first, so a capped register keeps the findings
        key=lambda fact: (common.impact_key(fact)[0], common.kind_of(fact), common.address_of(fact).casefold())
    )
    rows = [
        [
            common.address_of(fact),
            fact.get("service") or fact.get("native_type") or common.kind_of(fact),
            common.provider_of(fact),
            fact.get("key_algorithm") or fact.get("specification") or "",
            fact.get("key_management") or "",
            _rotation_cell(fact),
            fact.get("expires") or "",
            common.codes_cell(fact),
            _source_cell(fact),
            common.location_of(fact),
        ]
        for fact in facts
    ]
    return [
        *section_heading("Secrets services and certificate provisioning", styles),
        *common.register(
            (
                "Resource",
                "Service",
                "Provider",
                "Key algorithm",
                "Key management (KMS key)",
                "Rotation",
                "Expires",
                "Finding codes",
                "Source",
                "Location",
            ),
            rows,
            (110, 80, 45, 60, 110, 70, 60, 80, 90, 110),
            width,
            styles,
            view=view,
            cap_key="secrets",
            cap=text.REGISTER_ROW_CAP,
            more=text.FULL_LIST_POINTER,
            noun="secrets",
        ),
    ]


# ----------------------------------------------------------------------------- Kerberos and Active Directory
_NAMES_SHOWN = 5  # account names printed per check; the rest are counted


def _account_total(accounts: Mapping[str, Any], flag: str) -> int | None:
    """The domain-wide count the collector tallied for ``flag`` over every account type but krbtgt (judged by the
    functional level and its key age, never by its attribute); None when the domain row has no tally."""
    if not accounts:
        return None
    return sum(v for k, v in accounts.items() if k.endswith(f"_{flag}") and not k.startswith("krbtgt_")
               and isinstance(v, int) and not isinstance(v, bool))


def _names_cell(total: int | None, names: Sequence[str]) -> str:
    total = len(names) if total is None else max(total, len(names))
    shown = list(names[:_NAMES_SHOWN])
    if not total:
        return "0"
    cell = f"{total}: {', '.join(shown)}" if shown else str(total)
    if total > len(shown):
        cell += f" and {total - len(shown)} more not listed"
    return cell


def _key_age(view: object, last_set: str) -> str:
    try:
        moment = _dt.datetime.strptime(last_set, "%Y-%m-%dT%H:%M:%SZ").date()
    except ValueError:
        return "not read"
    as_of = common.grab(view, "as_of")
    if not isinstance(as_of, _dt.date):
        as_of = _dt.datetime.now(_dt.UTC).date()
    days = max(0, (as_of - moment).days)  # a pwdLastSet after the report date (clock skew) reads 0, never negative
    return f"{days} day{'' if days == 1 else 's'} (last set {moment.isoformat()})"


# the prober's weak-suite classes (``weak_ciphers_accepted`` keys), worst first; others follow by name
_WEAK_CLASSES = (("obsolete", "obsolete"), ("static_rsa", "static RSA key exchange"), ("cbc", "CBC"),
                 ("dhe", "finite-field DHE"))
_OBSOLETE_NAMES = 2  # obsolete suites printed by name


def _families(suites: Sequence[str]) -> list[str]:
    """The broken cipher families named by the suites (3DES and RC4 first): printed before any count."""
    found = []
    for family, hit in (("3DES", lambda n: "3DES" in n or "DES_CBC3" in n or "DES-CBC3" in n),
                        ("RC4", lambda n: "RC4" in n),
                        ("DES", lambda n: ("_DES_" in n or "DES_CBC_" in n or n.startswith("DES-")) and "3DES" not in n),
                        ("NULL", lambda n: "NULL" in n), ("EXPORT", lambda n: "EXPORT" in n)):
        if any(hit(name.upper()) for name in suites):
            found.append(family)
    return found


def _weak_summary(net: Mapping[str, Any]) -> str:
    """The weak suites an endpoint accepted, by class, worst first: the obsolete ones by family and name (3DES and RC4
    are always named before any "and N more"), the other classes by count (#493 review 6032906354 m2)."""
    by_class: dict[str, list[str]] = {}
    for item in common.as_rows(net.get("weak_suites")):
        if not isinstance(item, Mapping) or not item.get("suite"):
            continue
        for reason in common.as_rows(item.get("reasons")) or ["weak"]:
            names = by_class.setdefault(str(reason), [])
            if str(item["suite"]) not in names:
                names.append(str(item["suite"]))
    if not by_class:
        return "no weak suite accepted"
    every = [n for names in by_class.values() for n in names]
    families = _families(every)
    parts = []
    known = [key for key, _label in _WEAK_CLASSES]
    labels = dict(_WEAK_CLASSES)
    for key in known + sorted(k for k in by_class if k not in known):
        names = by_class.get(key)
        if not names:
            continue
        label = labels.get(key, key.replace("_", " "))
        if key == "obsolete":
            shown = ", ".join(names[:_OBSOLETE_NAMES])
            more = len(names) - _OBSOLETE_NAMES
            parts.append(f"{label} {len(names)}: {shown}" + (f" and {more} more" if more > 0 else ""))
        else:
            parts.append(f"{label} {len(names)}")
    lead = f"weak suites accepted ({', '.join(families)})" if families else "weak suites accepted"
    return f"{lead}: {'; '.join(parts)}"


def _ldaps_cell(view: object, source: str) -> str:
    """The LDAPS / StartTLS posture the AD collection probed: D7's endpoints of the same collection, summarised in
    D6's words.  Their finding codes are D7's (not in this document's findings), so none is printed here."""
    parts = []
    for fact in _facts(view):
        if common.kind_of(fact) != "tls_endpoint" or fact.get("evidence") != PROBED_EVIDENCE \
                or str(fact.get("location") or "") != source:
            continue
        net = common.net_of(fact)
        span = f"{net.get('min') or '?'} to {net.get('max') or '?'}"
        parts.append(f"{net.get('endpoint') or common.address_of(fact)}: {span}; {_weak_summary(net)}")
    if not parts:
        return "not probed in this collection"
    return "; ".join(sorted(parts)) + " (findings in SOW D7)"


_LEVEL_CODES = ("AD_FUNCTIONAL_LEVEL_PRE2008", "AD_FUNCTIONAL_LEVEL_LEGACY")


def _kerberos_rows(view: object) -> list[list[Any]]:
    """Five rows per domain and source: functional level, krbtgt key age, RC4-only accounts, accounts on the DC
    default and the LDAPS TLS posture.  Counts are the collector's domain-wide tally (computers are counted, not
    listed); names are the account rows of the SAME collection (two sources reading one domain each list their own,
    never both: #493 review 6032906354 M2)."""
    facts = scope_facts(view)
    accounts = [f for f in facts if common.kind_of(f) == "kerberos_account"]
    rows: list[list[Any]] = []
    for domain in sorted((f for f in facts if common.kind_of(f) == "ad_domain"),
                         key=lambda f: (common.address_of(f), _source_cell(f))):
        name, source = common.address_of(domain), _source_cell(domain)
        own = [a for a in accounts if _source_cell(a) == source
               and (str(a.get("domain") or "") == name or not a.get("domain"))]
        codes = {str(c) for c in common.as_rows(domain.get("finding_codes"))}

        def picked(rows_of: Sequence[Mapping[str, Any]], code: str) -> str:
            return code if any(code in common.as_rows(a.get("finding_codes")) for a in rows_of) else ""

        level, level_name = domain.get("domain_functional_level"), str(domain.get("domain_functional_level_name") or "")
        reading = (f"{level_name} (level {level})" if level_name and level is not None
                   else level_name or (f"level {level}" if level is not None else "not read"))
        tally = common.as_mapping(domain.get("accounts"))
        cut = [str(t) for t in common.as_rows(domain.get("truncated")) if t]
        partial = f" (tally truncated: {', '.join(cut)})" if cut else ""  # n4: the count is a lower bound
        rc4 = sorted(common.address_of(a) for a in own if a.get("rc4_only") is True)
        default = sorted(common.address_of(a) for a in own if a.get("dc_default") is True
                         and a.get("account_type") != "krbtgt")
        last_set = str(domain.get("krbtgt_password_last_set") or "")
        for check, value, code in (
            ("Domain functional level", reading, ", ".join(c for c in _LEVEL_CODES if c in codes)),
            ("krbtgt key age", _key_age(view, last_set) if last_set else "not read",
             "KRBTGT_KEY_OLD" if "KRBTGT_KEY_OLD" in codes else ""),
            ("Accounts with RC4 only", _names_cell(_account_total(tally, "rc4_only"), rc4) + partial,
             picked(own, "KERBEROS_RC4_ONLY")),
            ("Accounts on the DC default", _names_cell(_account_total(tally, "dc_default"), default) + partial,
             picked(own, "KERBEROS_ENCTYPES_DEFAULT")),
            ("LDAPS TLS posture", _ldaps_cell(view, source), ""),
        ):
            rows.append([name, check, value, code, source])
    return rows


def _kerberos(view: object, styles: Styles, width: float) -> list[Flowable]:
    return [
        *section_heading("Kerberos and Active Directory", styles),
        *common.register(
            ("Domain", "Check", "Reading", "Finding codes", "Source"),
            _kerberos_rows(view),
            (110, 120, 290, 120, 120),
            width,
            styles,
            view=view,
            cap_key="kerberos",
            cap=text.REGISTER_ROW_CAP,
            more=text.FULL_LIST_POINTER,
            noun="Kerberos and Active Directory rows",
        ),
    ]


def _has_kerberos(view: object) -> bool:
    return any(_is_identity(fact) for fact in scope_facts(view))


def _findings(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = scope_facts(view)
    rows = [
        [
            text.finding_label(code),
            count,
            impact,
            text.finding_anchor(code),
            text.finding_action(code),
        ]
        for code, count, impact in finding_rows(facts)
    ]
    ranked = [fact for fact in facts if common.as_rows(fact.get("finding_codes"))]
    ranked.sort(
        key=lambda fact: (
            common.impact_key(fact)[0],
            -len(common.as_rows(fact.get("finding_codes"))),
            common.address_of(fact).casefold(),
        )
    )
    top = [
        [
            common.address_of(fact),
            _source_cell(fact) or common.location_of(fact),
            fact.get("impact") or "",
            common.codes_cell(fact),
        ]
        for fact in ranked[:25]
    ]
    return [
        *section_heading("Findings", styles),
        common.note(text.INFRA_FINDINGS_NOTE, styles),
        *common.register(
            ("Label", "Count", "Impact", "Anchor", "Remediation"),
            rows,
            (140, 50, 60, 120, 350),
            width,
            styles,
            noun="findings",
        ),
        common.note("25 highest-impact resources", styles),
        *common.register(
            ("Resource", "Source", "Impact", "Finding codes"),
            top,
            (180, 180, 80, 280),
            width,
            styles,
            view=view,
            cap_key="finding_resources",
            noun="finding resources",
        ),
    ]


def build_story(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """Document body for SOW deliverable D6."""
    return [
        common.note(REPORT_META[REPORT_KEY]["how_to_read"], styles),
        common.gap(),
        _kpi(view, width),
        common.gap(),
        *common.source_status_flow(view, styles, width),
        *_coverage(view, styles, width),
        *section_heading("KMS key register", styles),
        *common.register(
            _KMS_HEADERS,
            _kms_rows(view),
            (72, 45, 55, 50, 50, 52, 48, 58, 50, 55, 58, 70, 42, 45),
            width,
            styles,
            manual=(12, 13),
            view=view,
            cap_key="kms",
            cap=text.REGISTER_ROW_CAP,
            more=text.FULL_LIST_POINTER,
            noun="keys",
        ),
        *_key_stores(view, styles, width),
        *_resources(view, styles, width),
        *_managed_tls(view, styles, width),
        *_secrets(view, styles, width),
        *_kerberos(view, styles, width),
        *_findings(view, styles, width),
        *common.unknown_flow(view, styles, width),
        *common.previously_seen_flow(view, styles, width),
        common.gap(),
        manual_form(
            "Cloud account, subscription and project inventory",
            ("Account or project", "Environment", "Owner"),
            4,
            width=width,
        ),
        common.gap(),
        manual_form(
            "Key custodian assignments",
            ("Key", "Custodian", "Evidence reference"),
            4,
            width=width,
        ),
        common.gap(),
        signoff_block(_SIGNOFF, title="Sign-off", width=width),
        common.gap(),
        *section_heading("Limits", styles, min_space=70),
        common.note(text.INFRA_LIMIT, styles),
        *([common.note(text.KERBEROS_DC_DEFAULT_LIMIT, styles)] if _has_kerberos(view) else []),
        common.note(text.posture_scope_of_method(view), styles, limit=900),
    ]


def build_pdf(view: TeamCbomView, *, ctx: Any = None) -> bytes:
    """Render SOW deliverable D6. Returns PDF bytes."""
    return build_document(ctx=ctx, 
        view=view,
        number=DOCUMENT_NUMBER,
        report_key=REPORT_KEY,
        title=REPORT_META[REPORT_KEY]["title"],
        landscape=True,
        body=lambda styles, width: build_story(view, styles, width),
        basis_extra=common.basis_lines(view),
        disclaimer_paragraphs=text.disclaimer_paragraphs(view),
        extra_banners=common.banner_pairs(view),
    )


__all__ = ["DOCUMENT_NUMBER", "REPORT_KEY", "build_pdf", "build_story", "finding_rows", "scope_facts"]
