"""nginx, Apache, and OpenSSH encryption facts. Detail stays on BasisEntry."""

from __future__ import annotations

import re

from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.directives import (
    Directive,
    parse_apache,
    parse_nginx,
    parse_openssh,
)
from aibom.cbom.posture.extract_common import listener_reader
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, fact_id, path_context

_STREAM_RE = re.compile(r"\bstream\b\s*\{")
_REDIRECT_CODES = frozenset({"301", "302", "307", "308"})
_APACHE_MAIN = frozenset(
    {"listen", "sslengine", "redirect", "redirectmatch", "rewriterule"}
)
_SSH_FILES = frozenset({"sshd_config", "ssh_config"})
_APACHE_FILES = frozenset({"httpd.conf", "apache2.conf", "ssl.conf"})
_ON = frozenset({"on"})
_ENGINE_ON = frozenset({"on", "optional"})


def extract_servers(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """Facts for one inline server file. A redirect is not a plaintext listener."""
    kind = _kind(path, text)
    if kind == "nginx":
        return _nginx(text, path)
    if kind == "apache":
        return _apache(text, path)
    if kind == "openssh":
        return _openssh(text, path)
    return ()


def _kind(path: str, text: str) -> str:
    name = path.replace("\\", "/").casefold()
    base = name.rsplit("/", 1)[-1]
    wrapped = f"/{name}/"
    ssh_dir = "/sshd_config.d/" in wrapped or "/ssh_config.d/" in wrapped
    if base in _SSH_FILES or ssh_dir:
        return "openssh"
    if base in _APACHE_FILES or "/apache2/" in wrapped or "/httpd/" in wrapped:
        return "apache"
    if base == "nginx.conf" or any(
        token in wrapped
        for token in ("/nginx/", "/conf.d/", "/sites-available/", "/sites-enabled/")
    ):
        return "nginx"
    sample = f"\n{text.casefold()}"
    if "<virtualhost" in sample or "\nsslengine " in sample:
        return "apache"
    if "passwordauthentication" in sample:
        return "openssh"
    if any(token in sample for token in ("listen ", "server {", "stream {", "http {")):
        return "nginx"
    return ""


def _nginx(text: str, path: str) -> tuple[EncryptionFact, ...]:
    doc = parse_nginx(text, path=path)
    if doc is None:
        return ()
    groups: dict[tuple[str, str], list[Directive]] = {}
    for entry in doc.entries:
        unit = _nginx_unit(entry.parent)
        if unit is None:
            continue
        groups.setdefault(unit, []).append(entry)
    facts: list[EncryptionFact] = []
    counts = {"http": 0, "stream": 0}
    saw_stream = False
    for (lane, _unit), entries in groups.items():
        if lane == "stream":
            saw_stream = True
        counts[lane] += 1
        label = "stream" if lane == "stream" else "server"
        facts.append(
            _nginx_fact(entries, path, lane, f"nginx.{label}[{counts[lane]}]")
        )
    if _declares_stream(text) and not saw_stream:
        facts.append(_empty_stream(text, path))
    return tuple(facts)


def _nginx_unit(parent: str | None) -> tuple[str, str] | None:
    if not parent:
        return None
    parts = parent.split(".")
    lane = "stream" if parts[0].split(" ", 1)[0] == "stream" else "http"
    acc: list[str] = []
    for part in parts:
        acc.append(part)
        if part.split(" ", 1)[0] == "server":
            return lane, ".".join(acc)
    if lane == "stream":
        return "stream", "stream"
    return None


def _nginx_fact(
    entries: list[Directive], path: str, lane: str, address: str
) -> EncryptionFact:
    plaintext, tls, listen = _listen_flags(entries)
    redirect = any(_nginx_redirect(item) for item in entries)
    passthrough = lane == "stream" or _flag_on(entries, "ssl_preread")
    verdict: str
    reason: str | None
    codes: tuple[str, ...]
    if passthrough:
        verdict, reason, codes = "UNKNOWN", "layer_not_observable", ()
    else:
        verdict, reason, codes = _transport(plaintext, redirect, tls)
    basis: list[BasisEntry] = []
    if lane == "stream":
        basis.append(BasisEntry("context", "stream"))
    if passthrough:
        basis.append(BasisEntry("passthrough", "tcp"))
    if listen:
        basis.append(BasisEntry("listen", listen))
    if redirect:
        basis.append(BasisEntry("redirect", "https"))
    return _make(
        kind="tls_endpoint",
        native="nginx",
        address=address,
        path=path,
        line=_named_line(entries, "listen"),
        form="server_config",
        verdict=verdict,
        reason=reason,
        basis=tuple(basis),
        codes=codes,
    )


def _listen_flags(entries: list[Directive]) -> tuple[bool, bool, str]:
    plaintext = False
    tls = _flag_on(entries, "ssl")
    tokens: list[str] = []
    for item in entries:
        if item.name.casefold() != "listen":
            continue
        if item.args:
            tokens.append(item.args[0])
        if any(arg.casefold() == "ssl" for arg in item.args):
            tls = True
        else:
            plaintext = True
    return plaintext, tls, ",".join(tokens)


def _nginx_redirect(item: Directive) -> bool:
    name = item.name.casefold()
    if name == "return" and item.args and item.args[0] in _REDIRECT_CODES:
        return any(arg.casefold().startswith("https://") for arg in item.args[1:])
    if name == "rewrite":
        return any("https://" in arg.casefold() for arg in item.args)
    return False


def _apache(text: str, path: str) -> tuple[EncryptionFact, ...]:
    doc = parse_apache(text, path=path)
    if doc is None:
        return ()
    groups: dict[str, list[Directive]] = {}
    for entry in doc.entries:
        parent = entry.parent or ""
        key = parent if parent.startswith("virtualhost") else ""
        groups.setdefault(key, []).append(entry)
    facts: list[EncryptionFact] = []
    vhosts = 0
    for key, entries in groups.items():
        if key == "" and not any(item.name in _APACHE_MAIN for item in entries):
            continue
        if key:
            vhosts += 1
            address = f"apache.virtualhost[{vhosts}]"
        else:
            address = "apache.main[1]"
        facts.append(_apache_fact(entries, path, address, key))
    return tuple(facts)


def _apache_fact(
    entries: list[Directive], path: str, address: str, key: str
) -> EncryptionFact:
    tls = _flag_on(entries, "sslengine", _ENGINE_ON)
    redirect = any(_apache_redirect(item) for item in entries)
    hosted = key.startswith("virtualhost")
    listened = any(item.name == "listen" for item in entries)
    verdict, reason, codes = _transport((hosted or listened) and not tls, redirect, tls)
    basis: list[BasisEntry] = [BasisEntry("server", "apache")]
    if hosted:
        basis.append(BasisEntry("virtualhost", key))
    if redirect:
        basis.append(BasisEntry("redirect", "https"))
    return _make(
        kind="tls_endpoint",
        native="apache_httpd",
        address=address,
        path=path,
        line=_named_line(entries, "sslengine"),
        form="server_config",
        verdict=verdict,
        reason=reason,
        basis=tuple(basis),
        codes=codes,
    )


def _apache_redirect(item: Directive) -> bool:
    if item.name not in {"redirect", "redirectmatch", "rewriterule"}:
        return False
    return any("https://" in arg.casefold() for arg in item.args)


def _openssh(text: str, path: str) -> tuple[EncryptionFact, ...]:
    sink = DiagnosticSink()
    doc = parse_openssh(text, path=path, sink=sink)
    if doc is None or not doc.entries:
        return ()
    basis: list[BasisEntry] = [BasisEntry("transport", "encrypted")]
    auth = doc.lookup("PasswordAuthentication")
    if auth:
        value = auth[0].casefold()
        basis.append(BasisEntry("PasswordAuthentication", value))
        if value == "yes":
            basis.append(BasisEntry("signal", "disabling"))
    if any(item.code == "duplicate_key" for item in sink.stored()):
        basis.append(BasisEntry("duplicate_key", "first"))
    base = path.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    native = base if base in _SSH_FILES else "sshd_config"
    return (
        _make(
            kind="ssh_service",
            native=native,
            address=f"{native}[1]",
            path=path,
            line=_named_line(list(doc.entries), "passwordauthentication"),
            form="ssh_config",
            verdict="ENCRYPTED_DECLARED",
            reason=None,
            basis=tuple(basis),
        ),
    )


def _transport(
    plaintext: bool, redirect: bool, tls: bool
) -> tuple[str, str | None, tuple[str, ...]]:
    if plaintext or redirect:
        result = listener_reader(plaintext=plaintext, redirect=redirect)
        codes = ("PLAINTEXT_LISTENER",) if result.verdict == "NOT_ENCRYPTED" else ()
        return result.verdict, result.reason, codes
    if tls:
        return "ENCRYPTED_DECLARED", None, ()
    return "UNKNOWN", "attribute_not_modeled", ()


def _empty_stream(text: str, path: str) -> EncryptionFact:
    return _make(
        kind="tls_endpoint",
        native="nginx",
        address="nginx.stream[1]",
        path=path,
        line=_stream_line(text),
        form="server_config",
        verdict="UNKNOWN",
        reason="layer_not_observable",
        basis=(
            BasisEntry("context", "stream"),
            BasisEntry("passthrough", "tcp"),
        ),
    )


def _make(
    *,
    kind: str,
    native: str,
    address: str,
    path: str,
    line: int,
    form: str,
    verdict: str,
    reason: str | None,
    basis: tuple[BasisEntry, ...],
    codes: tuple[str, ...] = (),
) -> EncryptionFact:
    unknown = reason if verdict == "UNKNOWN" else None
    return EncryptionFact(
        id=fact_id(kind, "self_hosted", native, address, path),
        kind=kind,
        provider="self_hosted",
        native_type=native,
        address=address,
        path=path,
        line=line if line > 0 else 1,
        format=form,
        layers={"transport": verdict},
        verdict=verdict,
        basis=basis,
        unknown_reason=unknown,
        path_context=path_context(path),
        finding_codes=codes,
    )


def _flag_on(
    entries: list[Directive],
    name: str,
    values: frozenset[str] = _ON,
) -> bool:
    for item in entries:
        if item.name.casefold() != name or not item.args:
            continue
        if item.args[0].casefold() in values:
            return True
    return False


def _named_line(entries: list[Directive], name: str) -> int:
    for item in entries:
        if item.name.casefold() == name and item.line > 0:
            return item.line
    if entries and entries[0].line > 0:
        return entries[0].line
    return 1


def _declares_stream(text: str) -> bool:
    kept = [line.split("#", 1)[0] for line in text.splitlines()]
    return _STREAM_RE.search("\n".join(kept)) is not None


def _stream_line(text: str) -> int:
    for number, line in enumerate(text.splitlines(), 1):
        if _STREAM_RE.search(line.split("#", 1)[0]):
            return number
    return 1
