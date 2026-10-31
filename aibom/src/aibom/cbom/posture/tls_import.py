"""TLS result import. An import never yields NOT_ENCRYPTED."""

from __future__ import annotations

import json
from dataclasses import dataclass

from aibom.cbom.posture.codec import make_fact_id
from aibom.cbom.posture.defaults import read_data_bytes
from aibom.cbom.posture.model import BasisEntry, EncryptionFact
from aibom.cbom.posture.safeio import sniff_tls_result
from aibom.cbom.posture.xmlsafe import parse_xml

_LIMIT = 20_971_520
_ALLOWED_HOSTS = ("example.com", "example.org")
_ALLOWED_SUFFIXES = (".test", ".invalid")
_DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
_UNSCORED = frozenset({"BEAST", "LUCKY13", "CRIME", "BREACH"})


@dataclass(frozen=True, slots=True)
class ImportNote:
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class ImportBatch:
    facts: tuple[EncryptionFact, ...]
    notes: tuple[ImportNote, ...]


def import_tls_result(data: bytes, path: str) -> ImportBatch:
    """Parse one result file. Connection errors stay UNKNOWN and raise nothing."""
    if len(data) > _LIMIT:
        return ImportBatch((), (ImportNote("size_cap", path),))
    tool = sniff_tls_result(data[:65536])
    if tool is None:
        return ImportBatch((), (ImportNote("unsupported_result_format", path),))
    text = data.decode("utf-8", errors="replace")
    if tool == "nmap":
        return _nmap(text, path)
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return ImportBatch((), (ImportNote("unsupported_result_format", tool),))
    if tool == "sslyze":
        return _sslyze(document, path)
    return _testssl(document, path, tool)


def _testssl_endpoint(row: dict[str, object]) -> tuple[str, str]:
    """Split ``host/ip``. An empty name uses the address."""
    raw = row.get("ip")
    if isinstance(raw, str) and "/" in raw:
        host, _, addr = raw.partition("/")
        chosen = host.strip() or addr.strip()
        alt = _host(addr.strip())
        if alt == "redacted":
            alt = ""
        return _host(chosen), alt
    return _host(row.get("targetHost") or raw), ""


def _host(value: object) -> str:
    text = value if isinstance(value, str) else ""
    if text in _ALLOWED_HOSTS or text.endswith(_ALLOWED_SUFFIXES):
        return text
    if any(text.startswith(prefix) for prefix in _DOC_PREFIXES):
        return text
    return "redacted"


def _fact(
    path: str,
    tool: str,
    host: str,
    port: str,
    *,
    reason: str | None,
    reported: tuple[str, ...],
    scored: tuple[str, ...],
    downgrade: bool = False,
    offered: tuple[str, ...] = (),
    alt: str = "",
) -> EncryptionFact:
    basis = [
        BasisEntry("tool", tool),
        BasisEntry("host", host),
        BasisEntry("port", port),
    ]
    if host and host != "redacted" and port.isdigit():
        basis.append(BasisEntry("endpoint", f"{host}:{port}"))
    if alt and alt != "redacted" and port.isdigit():
        basis.append(BasisEntry("endpoint_alt", f"{alt}:{port}"))
    if offered:
        basis.append(BasisEntry("offered", ",".join(offered)))
    if reported:
        basis.append(BasisEntry("reported", ",".join(reported)))
    if scored:
        basis.append(BasisEntry("signal", "KNOWN_TLS_VULNERABILITY"))
        basis.append(BasisEntry("vulnerabilities", ",".join(scored)))
    if downgrade:
        basis.append(BasisEntry("downgrade", "missing"))
        basis.append(BasisEntry("signal", "DOWNGRADE_PROTECTION_MISSING"))
    return EncryptionFact(
        id=make_fact_id("tls_endpoint", tool, host, f"{host}:{port}", path),
        kind="tls_endpoint",
        provider=tool,
        native_type="tls_result",
        address=f"{host}:{port}",
        path=path,
        line=1,
        format="tls_result",
        layers={"transport": "UNKNOWN"},
        verdict="UNKNOWN",
        unknown_reason=reason or "import_observation",
        basis=tuple(basis),
    )


def _split(names: list[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    scored_ids = _scored_ids()
    reported = tuple(name for name in names if name in _UNSCORED)
    scored = tuple(name for name in names if name in scored_ids)
    return reported, scored


def _scored_ids() -> frozenset[str]:
    document = json.loads(read_data_bytes("named_vulnerabilities.json"))
    return frozenset(
        row["id"]
        for row in document["rows"]
        if isinstance(row, dict) and row.get("scored") is True
    )


def _testssl(document: object, path: str, tool: str) -> ImportBatch:
    rows = document.get("scanResult") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        rows = [document] if isinstance(document, dict) else []
    facts: list[EncryptionFact] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        names = _finding_names(row)
        host, alt = _testssl_endpoint(row)
        port = str(row.get("port") or "")
        if _not_tested(row):
            facts.append(
                _fact(
                    path,
                    tool,
                    host,
                    port,
                    reason="import_not_tested",
                    reported=(),
                    scored=(),
                    alt=alt,
                )
            )
            continue
        reported, scored = _split(names)
        facts.append(
            _fact(
                path,
                tool,
                host,
                port,
                reason=None,
                reported=reported,
                scored=scored,
                downgrade=_fallback_missing(row),
                offered=_offered_versions(row),
                alt=alt,
            )
        )
    return ImportBatch(tuple(facts), ())


_OLD_PROTOCOLS = frozenset(
    {
        "SSLV3",
        "TLS1",
        "TLS1.0",
        "TLS1.1",
        "TLS1_0",
        "TLS1_1",
        "TLSV1",
        "TLSV1.0",
        "TLSV1.1",
    }
)


_PROTOCOL_LABELS = {
    "SSLV3": "SSLv3",
    "TLS1": "1.0",
    "TLS10": "1.0",
    "TLS1.0": "1.0",
    "TLSV1": "1.0",
    "TLSV1.0": "1.0",
    "TLS11": "1.1",
    "TLS1.1": "1.1",
    "TLSV1.1": "1.1",
    "TLS12": "1.2",
    "TLS1.2": "1.2",
    "TLSV1.2": "1.2",
    "TLS13": "1.3",
    "TLS1.3": "1.3",
    "TLSV1.3": "1.3",
}


def _offered_versions(row: dict[str, object]) -> tuple[str, ...]:
    labels: list[str] = []
    raw = row.get("protocols")
    if isinstance(raw, list):
        for item in raw:
            label = _protocol_label(item)
            if label:
                labels.append(label)
    findings = row.get("findings")
    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue
            text = str(item.get("finding") or item.get("severity") or "")
            if not text.casefold().startswith("offered"):
                continue
            label = _protocol_label(item.get("id"))
            if label:
                labels.append(label)
    return tuple(sorted(set(labels)))


def _protocol_label(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    key = value.strip().upper().replace(" ", "").replace("-", "").replace("_", "")
    return _PROTOCOL_LABELS.get(key)


def _old_protocol(value: object) -> bool:
    if isinstance(value, str):
        return value.upper().replace(" ", "") in _OLD_PROTOCOLS
    if isinstance(value, dict):
        if value.get("id") == "TLS_FALLBACK_SCSV":
            others = [item for key, item in value.items() if key != "id"]
            return any(_old_protocol(item) for item in others)
        return any(_old_protocol(item) for item in value.values())
    if isinstance(value, list):
        return any(_old_protocol(item) for item in value)
    return False


def _fallback_missing(row: dict[str, object]) -> bool:
    """Missing when an old protocol is offered and fallback SCSV is not OK."""
    raw = row.get("findings") or row.get("finding") or []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list) or not _old_protocol(row):
        return False
    for item in raw:
        if not isinstance(item, dict) or item.get("id") != "TLS_FALLBACK_SCSV":
            continue
        severity = str(item.get("severity") or "").upper()
        if severity not in {"OK", "INFO"}:
            return True
    return False


def _finding_names(row: dict[str, object]) -> list[str]:
    raw = row.get("findings") or row.get("finding") or []
    if isinstance(raw, dict):
        raw = [raw]
    names: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                names.append(item["id"])
    return names


def _not_tested(row: dict[str, object]) -> bool:
    severity = str(row.get("severity") or "")
    return severity == "not_tested" or row.get("scanProblem") is not None


def _sslyze(document: object, path: str) -> ImportBatch:
    rows = document.get("server_scan_results") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        return ImportBatch((), (ImportNote("unsupported_result_format", "sslyze"),))
    facts: list[EncryptionFact] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        location = row.get("server_location")
        host = ""
        port = ""
        if isinstance(location, dict):
            host = _host(location.get("hostname"))
            port = str(location.get("port") or "")
        reason = "import_not_tested" if row.get("connectivity_error") else None
        facts.append(
            _fact(path, "sslyze", host, port, reason=reason, reported=(), scored=())
        )
    return ImportBatch(tuple(facts), ())


def _nmap(text: str, path: str) -> ImportBatch:
    if "<!DOCTYPE" in text and "nmaprun" not in text.split("<!DOCTYPE", 1)[-1][:40]:
        return ImportBatch((), (ImportNote("unsafe_xml", path),))
    parsed = parse_xml(text, path=path)
    if parsed is None:
        return ImportBatch((), (ImportNote("unsupported_result_format", "nmap"),))
    name, addr, port = _nmap_fields(parsed.root)
    alt = _host(addr)
    if alt == "redacted":
        alt = ""
    return ImportBatch(
        (
            _fact(
                path,
                "nmap",
                _host(name),
                port,
                reason=None,
                reported=(),
                scored=(),
                alt=alt,
            ),
        ),
        (),
    )


def _nmap_fields(root: object) -> tuple[str, str, str]:
    name = ""
    addr = ""
    port = ""
    for child in list(getattr(root, "iter", lambda: [])()):
        tag = getattr(child, "tag", None)
        attrib = getattr(child, "attrib", {})
        if tag == "hostname" and not name:
            name = str(attrib.get("name", ""))
        elif tag == "address" and not addr:
            addr = str(attrib.get("addr", ""))
        elif tag == "port" and not port:
            port = str(attrib.get("portid", ""))
    return name, addr, port


def _attr(node: object, tag: str, name: str) -> str:
    for child in list(getattr(node, "iter", lambda: [])()):
        if getattr(child, "tag", None) == tag:
            value = child.attrib.get(name, "")
            if value:
                return value
    return ""
