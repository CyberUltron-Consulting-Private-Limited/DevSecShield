"""HAProxy frontend facts. A bind without ssl is a plaintext listener."""

from __future__ import annotations

from aibom.cbom.posture.directives import parse_haproxy
from aibom.cbom.posture.extract_common import listener_reader
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, fact_id, path_context

_SECTIONS = ("frontend", "listen", "backend")


def haproxy_facts(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """One fact per frontend or listen section that binds a port."""
    doc = parse_haproxy(text, path=path)
    if doc is None:
        return ()
    shared = _inherited(doc.entries, "ssl-dh-param-file")
    default_ciphers = _inherited(doc.entries, "ssl-default-bind-ciphers")
    default_options = _inherited(doc.entries, "ssl-default-bind-options")
    server_options = _inherited(doc.entries, "ssl-default-server-options")
    groups: dict[str, list] = {}
    for entry in doc.entries:
        parent = entry.parent or ""
        if parent.startswith(_SECTIONS):
            groups.setdefault(parent, []).append(entry)
    facts: list[EncryptionFact] = []
    for index, (parent, entries) in enumerate(groups.items(), start=1):
        fact = _section(
            parent,
            entries,
            path,
            index,
            shared,
            default_ciphers,
            default_options,
            server_options,
        )
        if fact is not None:
            facts.append(fact)
    return tuple(facts)


def _inherited(entries: list, name: str) -> str | None:
    found: str | None = None
    for item in entries:
        parent = item.parent or ""
        named = item.name.casefold() == name and bool(item.args)
        if parent.startswith(("global", "defaults")) and named:
            found = " ".join(item.args)
    return found


def _section(
    parent: str,
    entries: list,
    path: str,
    index: int,
    shared: str | None,
    default_ciphers: str | None,
    default_options: str | None,
    server_options: str | None,
) -> EncryptionFact | None:
    binds = [item for item in entries if item.name.casefold() == "bind" and item.args]
    servers = [
        item for item in entries if item.name.casefold() == "server" and item.args
    ]
    if not binds and not servers:
        return None
    tls = False
    plaintext = False
    for item in binds:
        words = [arg.casefold() for arg in item.args]
        if "ssl" in words:
            tls = True
        else:
            plaintext = True
    redirect = _https_redirect(entries)
    if redirect or plaintext:
        result = listener_reader(plaintext=plaintext, redirect=redirect)
        verdict = result.verdict
        reason = result.reason
        codes = ("PLAINTEXT_LISTENER",) if verdict == "NOT_ENCRYPTED" else ()
    elif tls or _server_ssl(servers):
        verdict, reason, codes = "ENCRYPTED_DECLARED", None, ()
    else:
        verdict, reason, codes = "UNKNOWN", "attribute_not_modeled", ()
    basis: list[BasisEntry] = [BasisEntry("server", "haproxy")]
    if verdict == "NOT_ENCRYPTED":
        basis.append(BasisEntry("listener", "plaintext"))
    dh_path = _section_dh(entries) or shared
    if dh_path:
        basis.append(BasisEntry("dh_path", dh_path))
    cipher = _cipher_basis(_bind_ciphers(binds) or default_ciphers)
    if cipher is not None:
        basis.append(cipher)
    curves = _bind_option(binds, "curves")
    if curves:
        basis.append(BasisEntry("curves", curves))
    basis.extend(_hsts(entries))
    for declared in _bind_certs(binds):
        basis.append(BasisEntry("cert_path", declared))
    declared_listen = _listen_label(binds)
    if declared_listen:
        basis.append(BasisEntry("listen_declared", declared_listen))
    candidates = _endpoints(binds)
    if candidates:
        basis.append(BasisEntry("endpoint", candidates[0]))
        basis.append(BasisEntry("endpoints", ",".join(candidates)))
    if _verify_disabled(servers, server_options):
        basis.append(BasisEntry("verification", "disabled"))
    floor = _bind_floor(binds) or _option_floor(default_options)
    if floor:
        basis.append(BasisEntry("protocol_min", floor))
    address = f"haproxy.{parent.split()[0]}[{index}]"
    return EncryptionFact(
        id=fact_id("tls_endpoint", "self_hosted", "haproxy", address, path),
        kind="tls_endpoint",
        provider="self_hosted",
        native_type="haproxy",
        address=address,
        path=path,
        line=(binds or servers)[0].line or 1,
        format="server_config",
        layers={"transport": verdict},
        verdict=verdict,
        basis=tuple(basis),
        unknown_reason=reason if verdict == "UNKNOWN" else None,
        path_context=path_context(path),
        finding_codes=codes,
    )


def _server_ssl(servers: list) -> bool:
    return any("ssl" in [arg.casefold() for arg in item.args] for item in servers)


def _verify_word(words: list[str]) -> str | None:
    if "verify" not in words:
        return None
    index = words.index("verify")
    if index + 1 >= len(words):
        return None
    return words[index + 1]


def _verify_disabled(servers: list, default_options: str | None) -> bool:
    explicit = [
        word
        for item in servers
        if (word := _verify_word([arg.casefold() for arg in item.args])) is not None
    ]
    if explicit:
        return "none" in explicit
    inherited = _verify_word((default_options or "").casefold().split())
    return inherited == "none"


_ORDER = ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_MIN = {
    "sslv3": "SSLv3",
    "tlsv1.0": "TLSv1.0",
    "tlsv1.1": "TLSv1.1",
    "tlsv1.2": "TLSv1.2",
    "tlsv1.3": "TLSv1.3",
}
_REMOVE = {
    "no-sslv3": "SSLv3",
    "no-tlsv10": "TLSv1.0",
    "no-tlsv11": "TLSv1.1",
    "no-tlsv12": "TLSv1.2",
}


def _bind_floor(binds: list) -> str | None:
    found: str | None = None
    for item in binds:
        floor = _option_floor(" ".join(item.args))
        if floor:
            found = floor
    return found


def _option_floor(raw: str | None) -> str | None:
    words = (raw or "").casefold().split()
    if "force-tlsv12" in words:
        return "TLSv1.2"
    if "ssl-min-ver" in words:
        index = words.index("ssl-min-ver")
        if index + 1 < len(words):
            return _MIN.get(words[index + 1])
    removed = {proto for token, proto in _REMOVE.items() if token in words}
    if not removed:
        return None
    kept = [proto for proto in _ORDER if proto not in removed]
    return kept[0] if kept else None


def _bind_ciphers(binds: list) -> str | None:
    return _bind_option(binds, "ciphers")


def _endpoints(binds: list) -> tuple[str, ...]:
    from aibom.cbom.posture.extract_common import endpoint_list, listen_endpoint

    pairs: list[str] = []
    for item in binds:
        if not any(arg.casefold() == "ssl" for arg in item.args):
            continue
        for piece in item.args[0].split(","):
            host, port = listen_endpoint(piece)
            if host and port is not None:
                pairs.append(f"{host}:{port}")
    return endpoint_list(pairs)


def _listen_label(binds: list) -> str | None:
    from aibom.cbom.posture.extract_common import listen_label

    tokens: list[str] = []
    for item in binds:
        if not any(arg.casefold() == "ssl" for arg in item.args):
            continue
        for piece in item.args[0].split(","):
            tokens.append(piece)
    return listen_label(tokens)


def _bind_certs(binds: list) -> tuple[str, ...]:
    found: list[str] = []
    for item in binds:
        folded = [arg.casefold() for arg in item.args]
        if "crt" not in folded:
            continue
        index = folded.index("crt")
        if index + 1 < len(item.args):
            found.append(item.args[index + 1])
    return tuple(found)


def _bind_option(binds: list, name: str) -> str | None:
    for item in binds:
        folded = [arg.casefold() for arg in item.args]
        if name not in folded:
            continue
        index = folded.index(name)
        if index + 1 < len(item.args):
            return item.args[index + 1]
    return None


def _cipher_basis(raw: str | None) -> BasisEntry | None:
    if not raw:
        return None
    from aibom.cbom.posture.ciphers import evaluate_cipher_list
    from aibom.cbom.posture.defaults import load_registry

    result = evaluate_cipher_list(raw, load_registry())
    names = result.explicit or result.suites
    if not names:
        return None
    return BasisEntry("cipher_suite", ",".join(names[:8]))


def _hsts(entries: list) -> tuple[BasisEntry, ...]:
    from aibom.cbom.posture.hsts import entries_from_value

    for item in entries:
        if item.name.casefold() != "http-response":
            continue
        folded = [arg.casefold() for arg in item.args]
        if "set-header" not in folded or "strict-transport-security" not in folded:
            continue
        index = folded.index("strict-transport-security")
        return entries_from_value(" ".join(item.args[index + 1 :]))
    return ()


def _https_redirect(entries: list) -> bool:
    for item in entries:
        if item.name.casefold() != "redirect":
            continue
        words = [arg.casefold() for arg in item.args]
        if "scheme" in words and "https" in words:
            return True
    return False


def _section_dh(entries: list) -> str | None:
    for item in entries:
        if item.name.casefold() == "ssl-dh-param-file" and item.args:
            return item.args[0]
    return None
