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
) -> EncryptionFact:
    basis = [
        BasisEntry("tool", tool),
        BasisEntry("host", host),
        BasisEntry("port", port),
    ]
    if reported:
        basis.append(BasisEntry("reported", ",".join(reported)))
    if scored:
        basis.append(BasisEntry("signal", "KNOWN_TLS_VULNERABILITY"))
        basis.append(BasisEntry("vulnerabilities", ",".join(scored)))
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
        if _not_tested(row):
            facts.append(
                _fact(
                    path,
                    tool,
                    _host(row.get("targetHost") or row.get("ip")),
                    str(row.get("port") or ""),
                    reason="import_not_tested",
                    reported=(),
                    scored=(),
                )
            )
            continue
        reported, scored = _split(names)
        facts.append(
            _fact(
                path,
                tool,
                _host(row.get("targetHost") or row.get("ip")),
                str(row.get("port") or ""),
                reason=None,
                reported=reported,
                scored=scored,
            )
        )
    return ImportBatch(tuple(facts), ())


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
    host = _host(_attr(parsed.root, "host", "name"))
    port = _attr(parsed.root, "port", "portid")
    return ImportBatch(
        (_fact(path, "nmap", host, port, reason=None, reported=(), scored=()),),
        (),
    )


def _attr(node: object, tag: str, name: str) -> str:
    for child in list(getattr(node, "iter", lambda: [])()):
        if getattr(child, "tag", None) == tag:
            value = child.attrib.get(name, "")
            if value:
                return value
    return ""
