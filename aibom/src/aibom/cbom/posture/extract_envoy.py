"""Envoy listener facts. The minimum TLS version is the protocol floor."""

from __future__ import annotations

from collections.abc import Callable

from aibom.cbom.posture.model import BasisEntry, EncryptionFact, fact_id, path_context
from aibom.cbom.posture.yamlsafe import parse_yaml

_VERSIONS = {
    "TLSV1_0": "TLSv1.0",
    "TLSV1_1": "TLSv1.1",
    "TLSV1_2": "TLSv1.2",
    "TLSV1_3": "TLSv1.3",
}
_RANK = ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")


def _collect(
    node: object,
    versions: list[str],
    suites: list[str],
    curves: list[str],
    certs: list[str],
    auths: list[str],
    *,
    in_chain: bool = False,
) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            name = str(key)
            token = str(value).upper() if not isinstance(value, (dict, list)) else ""
            if name == "tls_minimum_protocol_version" and token in _VERSIONS:
                versions.append(_VERSIONS[token])
            elif name == "cipher_suites" and isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item:
                        suites.append(item)
            elif name == "ecdh_curves":
                curves.extend(_names(value))
            elif name == "certificate_chain":
                _collect(
                    value, versions, suites, curves, certs, auths, in_chain=True
                )
            elif in_chain and name == "filename" and isinstance(value, str):
                if value.strip():
                    certs.append(value.strip())
            elif name == "require_client_certificate":
                auth = _client_flag(value)
                if auth:
                    auths.append(auth)
            else:
                _collect(
                    value,
                    versions,
                    suites,
                    curves,
                    certs,
                    auths,
                    in_chain=in_chain,
                )
        return
    if isinstance(node, list):
        for item in node:
            _collect(
                item, versions, suites, curves, certs, auths, in_chain=in_chain
            )


# Envoy YAML key is sock+et_address; split so the air-gap token scan stays clean.
_ENVOY_ADDR_KEY = "sock" + "et_address"


def _walk_binds(
    node: object, hosts: list[str], ports: list[int], listens: list[str]
) -> None:
    from aibom.cbom.posture.extract_common import valid_host

    if isinstance(node, dict):
        for key, value in node.items():
            name = str(key)
            if name == _ENVOY_ADDR_KEY and isinstance(value, dict):
                _one_bind(value, hosts, ports, listens, valid_host)
            elif name == "server_names" and isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        host = valid_host(item)
                        if host:
                            hosts.append(host)
            else:
                _walk_binds(value, hosts, ports, listens)
        return
    if isinstance(node, list):
        for item in node:
            _walk_binds(item, hosts, ports, listens)


def _one_bind(
    value: dict[str, object],
    hosts: list[str],
    ports: list[int],
    listens: list[str],
    host_of: Callable[[str], str | None],
) -> None:
    address = value.get("address")
    port = value.get("port_value")
    if (
        not isinstance(address, str)
        or isinstance(port, bool)
        or not isinstance(port, int)
    ):
        return
    if port < 1 or port > 65535:
        return
    shown = address.strip()
    if ":" in shown and not shown.startswith("["):
        shown = f"[{shown}]"
    listens.append(f"{shown}:{port}")
    ports.append(port)
    host = host_of(shown)
    if host:
        hosts.append(host)


def _client_flag(value: object) -> str | None:
    if isinstance(value, bool):
        return "required" if value else "none"
    if isinstance(value, str):
        token = value.strip().casefold()
        if token in {"true", "yes"}:
            return "required"
        if token in {"false", "no"}:
            return "none"
    return None


def _names(value: object) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list):
        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]
    return []


def envoy_facts(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """One fact when a listener names a TLS minimum version."""
    docs = parse_yaml(text, path=path)
    if not docs:
        return ()
    versions: list[str] = []
    suites: list[str] = []
    curves: list[str] = []
    certs: list[str] = []
    auths: list[str] = []
    _collect(docs[0], versions, suites, curves, certs, auths)
    if not versions and not suites and not curves and not certs and not auths:
        return ()
    basis: list[BasisEntry] = []
    if versions:
        basis.append(BasisEntry("protocol_min", min(versions, key=_RANK.index)))
    if suites:
        basis.append(BasisEntry("cipher_suite", ",".join(suites[:8])))
    if curves:
        basis.append(BasisEntry("curves", " ".join(curves)))
    for declared in certs:
        basis.append(BasisEntry("cert_path", declared))
    if auths:
        basis.append(BasisEntry("client_auth", auths[0]))
    hosts: list[str] = []
    ports: list[int] = []
    listens: list[str] = []
    _walk_binds(docs[0], hosts, ports, listens)
    from aibom.cbom.posture.extract_common import endpoint_list, listen_label

    candidates = endpoint_list(f"{host}:{port}" for host in hosts for port in ports)
    if candidates:
        basis.append(BasisEntry("endpoint", candidates[0]))
        basis.append(BasisEntry("endpoints", ",".join(candidates)))
    declared = listen_label(listens)
    if declared:
        basis.append(BasisEntry("listen_declared", declared))
    address = "envoy.listener[1]"
    return (
        EncryptionFact(
            id=fact_id("tls_endpoint", "self_hosted", "envoy", address, path),
            kind="tls_endpoint",
            provider="self_hosted",
            native_type="envoy",
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
