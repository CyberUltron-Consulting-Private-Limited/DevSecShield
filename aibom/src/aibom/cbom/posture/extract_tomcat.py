"""Tomcat Connector facts. A connector without SSL is a plaintext listener."""

from __future__ import annotations

from xml.etree import ElementTree

from aibom.cbom.posture.extract_common import listener_reader
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, fact_id, path_context
from aibom.cbom.posture.xmlsafe import parse_xml

_RANK = {
    "SSLv3": 0,
    "TLSv1": 1,
    "TLSv1.0": 1,
    "TLSv1.1": 2,
    "TLSv1.2": 3,
    "TLSv1.3": 4,
}


def tomcat_facts(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """One fact per HTTP Connector."""
    doc = parse_xml(text, path=path)
    if doc is None:
        return ()
    hosts = [element for element in doc.root.iter() if _local(element.tag) == "Host"]
    fallback = hosts[0].attrib.get("name") if len(hosts) == 1 else None
    facts: list[EncryptionFact] = []
    index = 0
    for element in doc.root.iter():
        if _local(element.tag) != "Connector":
            continue
        fact = _connector(element, path, index + 1, fallback)
        if fact is None:
            continue
        index += 1
        facts.append(fact)
    return tuple(facts)


def _connector(
    element: ElementTree.Element, path: str, index: int, host_name: str | None
) -> EncryptionFact | None:
    attrs = {key.casefold(): value for key, value in element.attrib.items()}
    protocol = attrs.get("protocol", "")
    if "ajp" in protocol.casefold():
        return None
    enabled = attrs.get("sslenabled", "").casefold() in {"true", "yes"}
    if enabled:
        verdict, reason, codes = "ENCRYPTED_DECLARED", None, ()
    else:
        result = listener_reader(plaintext=True, redirect=False)
        verdict = result.verdict
        reason = result.reason
        codes = ("PLAINTEXT_LISTENER",) if verdict == "NOT_ENCRYPTED" else ()
    basis: list[BasisEntry] = [BasisEntry("server", "tomcat")]
    if verdict == "NOT_ENCRYPTED":
        basis.append(BasisEntry("listener", "plaintext"))
    host = _host_config(element)
    floor = _floor(host.get("protocols") or attrs.get("sslenabledprotocols", ""))
    if floor:
        basis.append(BasisEntry("protocol_min", floor))
    suites = _ciphers(host.get("ciphers") or attrs.get("ciphers", ""))
    if suites:
        basis.append(BasisEntry("cipher_suite", suites))
    verify = host.get("certificateverification", "")
    if verify.casefold() in {"none", "optional", "required"}:
        basis.append(BasisEntry("client_auth", verify.casefold()))
    _tomcat_endpoint(attrs, host_name, basis)
    address = f"tomcat.connector[{index}]"
    return EncryptionFact(
        id=fact_id("tls_endpoint", "self_hosted", "tomcat", address, path),
        kind="tls_endpoint",
        provider="self_hosted",
        native_type="tomcat",
        address=address,
        path=path,
        line=1,
        format="server_config",
        layers={"transport": verdict},
        verdict=verdict,
        basis=tuple(basis),
        unknown_reason=reason if verdict == "UNKNOWN" else None,
        path_context=path_context(path),
        finding_codes=codes,
    )


def _tomcat_endpoint(
    attrs: dict[str, str], host_name: str | None, basis: list[BasisEntry]
) -> None:
    from aibom.cbom.posture.extract_common import listen_label, valid_host

    raw_address = attrs.get("address", "").strip()
    port = _port(attrs.get("port", ""))
    host = valid_host(raw_address) if raw_address else valid_host(host_name or "")
    if host and port is not None:
        endpoint = f"{host}:{port}"
        basis.append(BasisEntry("endpoint", endpoint))
        basis.append(BasisEntry("endpoints", endpoint))
    if raw_address and port is not None:
        label = listen_label([f"{raw_address}:{port}"])
    elif port is not None:
        label = listen_label([str(port)])
    else:
        label = None
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


def _host_config(element: ElementTree.Element) -> dict[str, str]:
    found: dict[str, str] = {}
    for child in element:
        if _local(child.tag) != "SSLHostConfig":
            continue
        for key, value in child.attrib.items():
            found.setdefault(key.casefold(), value)
    return found


def _ciphers(raw: str) -> str | None:
    text = raw.strip()
    if not text:
        return None
    if "TLS_" in text:
        parts = [part.strip() for part in text.split(",") if part.strip()]
        return ",".join(parts[:8]) or None
    from aibom.cbom.posture.ciphers import evaluate_cipher_list
    from aibom.cbom.posture.defaults import load_registry

    result = evaluate_cipher_list(text, load_registry())
    names = result.explicit or result.suites
    if not names:
        return None
    return ",".join(names[:8])


def _floor(raw: str) -> str | None:
    tokens = [part.strip() for part in raw.split(",") if part.strip() in _RANK]
    if not tokens:
        return None
    return min(tokens, key=lambda token: _RANK[token])


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
