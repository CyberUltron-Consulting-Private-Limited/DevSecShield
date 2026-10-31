"""Spring Boot SSL facts. A disabled server.ssl connector is plaintext."""

from __future__ import annotations

from aibom.cbom.posture.extract_common import listener_reader
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, fact_id, path_context
from aibom.cbom.posture.yamlsafe import parse_yaml

_RANK = {
    "SSLv3": 0,
    "TLSv1": 1,
    "TLSv1.0": 1,
    "TLSv1.1": 2,
    "TLSv1.2": 3,
    "TLSv1.3": 4,
}


def spring_facts(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """Facts for ``server.ssl`` and ``management.server.ssl``."""
    values = _values(text, path)
    facts: list[EncryptionFact] = []
    main = _one(values, "server.ssl", "spring.server[1]", path)
    if main is not None:
        facts.append(main)
    management = _one(values, "management.server.ssl", "spring.management[1]", path)
    if management is not None:
        facts.append(management)
    return tuple(facts)


def _one(
    values: dict[str, str], prefix: str, address: str, path: str
) -> EncryptionFact | None:
    keys = {key for key in values if key == prefix or key.startswith(prefix + ".")}
    if not keys:
        return None
    enabled = values.get(f"{prefix}.enabled", "").casefold()
    protocols = values.get(f"{prefix}.enabled-protocols", "")
    ciphers = values.get(f"{prefix}.ciphers", "")
    if enabled in {"false", "no", "off"}:
        result = listener_reader(plaintext=True, redirect=False)
        verdict, reason = result.verdict, result.reason
        codes = ("PLAINTEXT_LISTENER",) if verdict == "NOT_ENCRYPTED" else ()
    else:
        verdict, reason, codes = "ENCRYPTED_DECLARED", None, ()
    basis: list[BasisEntry] = [BasisEntry("server", "spring")]
    if verdict == "NOT_ENCRYPTED":
        basis.append(BasisEntry("listener", "plaintext"))
    floor = _floor(protocols)
    if floor:
        basis.append(BasisEntry("protocol_min", floor))
    if ciphers:
        basis.append(BasisEntry("cipher_suite", ciphers))
    auth = values.get(f"{prefix}.client-auth", "").casefold()
    if auth in {"none", "want", "need"}:
        basis.append(BasisEntry("client_auth", auth))
    if prefix == "server.ssl":
        _spring_endpoint(values, basis)
    return EncryptionFact(
        id=fact_id("tls_endpoint", "self_hosted", "spring_boot", address, path),
        kind="tls_endpoint",
        provider="self_hosted",
        native_type="spring_boot",
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


def _spring_endpoint(values: dict[str, str], basis: list[BasisEntry]) -> None:
    from aibom.cbom.posture.extract_common import listen_label, valid_host

    host = valid_host(values.get("server.address", ""))
    written = _spring_port(values["server.port"]) if "server.port" in values else None
    if host and written is not None:
        endpoint = f"{host}:{written}"
        basis.append(BasisEntry("endpoint", endpoint))
        basis.append(BasisEntry("endpoints", endpoint))
        basis.append(BasisEntry("listen_declared", endpoint))
        return
    if host:
        endpoint = f"{host}:8080"
        basis.append(BasisEntry("endpoint", endpoint))
        basis.append(BasisEntry("endpoints", endpoint))
        basis.append(BasisEntry("port_default", "8080"))
        return
    if written is not None:
        label = listen_label([str(written)])
        if label:
            basis.append(BasisEntry("listen_declared", label))


def _spring_port(raw: str) -> int | None:
    text = raw.strip()
    if not text.isdigit() or (len(text) > 1 and text.startswith("0")):
        return None
    value = int(text)
    if 1 <= value <= 65535:
        return value
    return None


def _values(text: str, path: str) -> dict[str, str]:
    docs = parse_yaml(text, path=path)
    if docs and isinstance(docs[0], dict):
        found: dict[str, str] = {}
        _walk(docs[0], "", found)
        if found:
            return found
    return _properties(text)


def _walk(node: object, prefix: str, found: dict[str, str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            _walk(value, path, found)
        return
    if isinstance(node, list):
        parts = [str(item) for item in node if not isinstance(item, (dict, list))]
        if parts and prefix:
            found[prefix] = ",".join(parts)
        return
    if prefix:
        found[prefix] = str(node)


def _properties(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip():
            found[key.strip()] = value.strip()
    return found


def _floor(raw: str) -> str | None:
    tokens = [part.strip() for part in raw.split(",") if part.strip() in _RANK]
    if not tokens:
        return None
    return min(tokens, key=lambda token: _RANK[token])
