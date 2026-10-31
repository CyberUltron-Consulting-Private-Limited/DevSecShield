"""Traefik TLS option facts. minVersion is the protocol floor."""

from __future__ import annotations

from aibom.cbom.posture.model import BasisEntry, EncryptionFact, fact_id, path_context
from aibom.cbom.posture.yamlsafe import parse_yaml

_VERSIONS = {
    "VERSIONTLS10": "TLSv1.0",
    "VERSIONTLS11": "TLSv1.1",
    "VERSIONTLS12": "TLSv1.2",
    "VERSIONTLS13": "TLSv1.3",
}
_RANK = ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")


def traefik_facts(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """One fact when a TLS option names a minimum version or cipher list."""
    docs = parse_yaml(text, path=path)
    if not docs:
        return ()
    versions: list[str] = []
    suites: list[str] = []
    curves: list[str] = []
    ages: list[str] = []
    flags: list[str] = []
    _collect(docs[0], versions, suites, curves, ages, flags)
    listens = _entry_listens(docs[0])
    if (
        not versions
        and not suites
        and not curves
        and not ages
        and not listens
        and "verification" not in flags
    ):
        return ()
    basis: list[BasisEntry] = []
    if versions:
        basis.append(BasisEntry("protocol_min", min(versions, key=_RANK.index)))
    if suites:
        basis.append(BasisEntry("cipher_suite", ",".join(suites[:8])))
    if curves:
        basis.append(BasisEntry("curves", " ".join(curves)))
    if "verification" in flags:
        basis.append(BasisEntry("verification", "disabled"))
    if ages:
        from aibom.cbom.posture.hsts import entries_from_value

        basis.extend(entries_from_value(ages[0]))
    from aibom.cbom.posture.extract_common import listen_label

    declared = listen_label(listens)
    if declared:
        basis.append(BasisEntry("listen_declared", declared))
    only_hsts = (
        not versions
        and not suites
        and not curves
        and "verification" not in flags
    )
    address = "traefik.tls[1]"
    return (
        EncryptionFact(
            id=fact_id("tls_endpoint", "self_hosted", "traefik", address, path),
            kind="tls_endpoint",
            provider="self_hosted",
            native_type="traefik",
            address=address,
            path=path,
            line=1,
            format="server_config",
            layers={
                "transport": "UNKNOWN" if only_hsts else "ENCRYPTED_DECLARED"
            },
            verdict="UNKNOWN" if only_hsts else "ENCRYPTED_DECLARED",
            basis=tuple(basis),
            unknown_reason="layer_not_observable" if only_hsts else None,
            path_context=path_context(path),
        ),
    )


def _entry_listens(node: object) -> list[str]:
    if not isinstance(node, dict):
        return []
    points = node.get("entryPoints")
    if not isinstance(points, dict):
        return []
    found: list[str] = []
    for value in points.values():
        if not isinstance(value, dict):
            continue
        http = value.get("http")
        if not isinstance(http, dict) or "tls" not in http:
            continue
        raw = value.get("address")
        if isinstance(raw, str) and raw.strip():
            found.append(raw.strip())
    return found


def _collect(
    node: object,
    versions: list[str],
    suites: list[str],
    curves: list[str],
    ages: list[str],
    flags: list[str],
) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            name = str(key)
            token = str(value).upper() if not isinstance(value, (dict, list)) else ""
            if name == "minVersion" and token in _VERSIONS:
                versions.append(_VERSIONS[token])
            elif name == "cipherSuites" and isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item:
                        suites.append(item)
            elif name == "curvePreferences" and isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        curves.append(item.strip())
            elif name == "stsSeconds" and _whole_number(value):
                ages.append(str(int(value)))
            elif name.casefold() == "strict-transport-security" and isinstance(
                value, str
            ):
                ages.append(value)
            elif name == "insecureSkipVerify" and _on(value):
                flags.append("verification")
            else:
                _collect(value, versions, suites, curves, ages, flags)
        return
    if isinstance(node, list):
        for item in node:
            _collect(item, versions, suites, curves, ages, flags)


def _whole_number(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    return isinstance(value, str) and value.strip().isdigit()


def _on(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"
