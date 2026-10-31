"""Jetty SSL facts. IncludeProtocols is the protocol floor."""

from __future__ import annotations

from xml.etree import ElementTree

from aibom.cbom.posture.model import BasisEntry, EncryptionFact, fact_id, path_context
from aibom.cbom.posture.xmlsafe import parse_xml

_ORDER = ("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_RANK = {token: index for index, token in enumerate(_ORDER)}


def jetty_facts(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """One fact when a Jetty SSL context names protocols or cipher suites."""
    doc = parse_xml(text, path=path)
    if doc is None:
        return _properties(text, path)
    protocols: list[str] = []
    excluded_protocols: list[str] = []
    suites: list[str] = []
    excluded_suites: list[str] = []
    settings: dict[str, str] = {}
    for element in doc.root.iter():
        if _local(element.tag) != "Set":
            continue
        name = element.attrib.get("name", "")
        items = _items(element)
        if name == "IncludeProtocols":
            protocols.extend(items)
        elif name == "ExcludeProtocols":
            excluded_protocols.extend(items)
        elif name == "IncludeCipherSuites":
            suites.extend(items)
        elif name == "ExcludeCipherSuites":
            excluded_suites.extend(items)
        elif name in {"host", "port"} and items:
            settings.setdefault(name, items[0])
    kept_protocols = _kept(protocols, excluded_protocols)
    kept_suites = [item for item in suites if item not in set(excluded_suites)]
    empty = not kept_protocols and not kept_suites and not excluded_protocols
    if empty and not settings:
        return ()
    basis: list[BasisEntry] = [BasisEntry("server", "jetty")]
    floor = _floor(kept_protocols)
    if floor:
        basis.append(BasisEntry("protocol_min", floor))
    if kept_suites:
        basis.append(BasisEntry("cipher_suite", ",".join(kept_suites[:8])))
    _jetty_endpoint(settings, basis)
    address = "jetty.ssl[1]"
    return (
        EncryptionFact(
            id=fact_id("tls_endpoint", "self_hosted", "jetty", address, path),
            kind="tls_endpoint",
            provider="self_hosted",
            native_type="jetty",
            address=address,
            path=path,
            line=1,
            format="server_config",
            layers={"transport": "ENCRYPTED_DECLARED"},
            verdict="ENCRYPTED_DECLARED",
            basis=tuple(basis),
            path_context=path_context(path),
        ),
    )


def _properties(text: str, path: str) -> tuple[EncryptionFact, ...]:
    settings: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        name = key.strip()
        if name == "jetty.ssl.host":
            settings["host"] = value.strip()
        elif name == "jetty.ssl.port":
            settings["port"] = value.strip()
    if not settings:
        return ()
    basis: list[BasisEntry] = [BasisEntry("server", "jetty")]
    _jetty_endpoint(settings, basis)
    address = "jetty.ssl[1]"
    return (
        EncryptionFact(
            id=fact_id("tls_endpoint", "self_hosted", "jetty", address, path),
            kind="tls_endpoint",
            provider="self_hosted",
            native_type="jetty",
            address=address,
            path=path,
            line=1,
            format="server_config",
            layers={"transport": "ENCRYPTED_DECLARED"},
            verdict="ENCRYPTED_DECLARED",
            basis=tuple(basis),
            path_context=path_context(path),
        ),
    )


def _jetty_endpoint(settings: dict[str, str], basis: list[BasisEntry]) -> None:
    from aibom.cbom.posture.extract_common import listen_label, valid_host

    host = valid_host(settings.get("host", ""))
    written = _port(settings["port"]) if "port" in settings else None
    if host and written is not None:
        endpoint = f"{host}:{written}"
        basis.append(BasisEntry("endpoint", endpoint))
        basis.append(BasisEntry("endpoints", endpoint))
        basis.append(BasisEntry("listen_declared", endpoint))
        return
    if host:
        endpoint = f"{host}:8443"
        basis.append(BasisEntry("endpoint", endpoint))
        basis.append(BasisEntry("endpoints", endpoint))
        basis.append(BasisEntry("port_default", "8443"))
        return
    if written is not None:
        label = listen_label([str(written)])
        if label:
            basis.append(BasisEntry("listen_declared", label))


def _port(raw: str) -> int | None:
    text = raw.strip()
    if not text.isdigit() or (len(text) > 1 and text.startswith("0")):
        return None
    value = int(text)
    if 1 <= value <= 65535:
        return value
    return None


def _items(element: ElementTree.Element) -> list[str]:
    found = [
        (child.text or "").strip()
        for child in element.iter()
        if _local(child.tag) == "Item" and (child.text or "").strip()
    ]
    if found:
        return found
    text = (element.text or "").strip()
    return [text] if text else []


def _kept(included: list[str], excluded: list[str]) -> list[str]:
    blocked = set(excluded)
    if included:
        return [token for token in included if token not in blocked]
    if not blocked:
        return []
    return [token for token in _ORDER if token not in blocked]


def _floor(tokens: list[str]) -> str | None:
    known = [token for token in tokens if token in _RANK]
    if not known:
        return None
    return min(known, key=lambda token: _RANK[token])


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
