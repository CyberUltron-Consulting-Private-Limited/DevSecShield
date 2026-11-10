"""nginx, Apache, and OpenSSH encryption facts. Detail stays on BasisEntry."""

from __future__ import annotations

import re
from collections.abc import Callable

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
_TLS_ORDER = (
    "SSLv2",
    "SSLv3",
    "TLSv1",
    "TLSv1.0",
    "TLSv1.1",
    "TLSv1.2",
    "TLSv1.3",
)


def included_paths(text: str, path: str) -> tuple[str, ...]:
    """Relative nginx include targets that can name another indexed file."""
    if _kind(path, text) != "nginx":
        return ()
    doc = parse_nginx(text, path=path)
    if doc is None:
        return ()
    base = path.rsplit("/", 1)[0] if "/" in path else ""
    found: list[str] = []
    for raw in doc.includes:
        token = raw.strip().strip("\"'")
        if not token or "*" in token or token.startswith("/"):
            continue
        rel = f"{base}/{token}" if base else token
        if rel != path:
            found.append(rel)
    return tuple(found)


def _expanded(path: str, files: dict[str, str], seen: set[str]) -> str:
    if path in seen or path not in files:
        return ""
    seen.add(path)
    parts = [files[path]]
    for rel in included_paths(files[path], path):
        if rel in files:
            parts.append(_expanded(rel, files, seen))
    return "\n".join(parts)


_NGINX_FLOOR = ((1, 27, 3), "TLSv1.2")


def _image_floor(files: dict[str, str], config: str) -> str | None:
    """Compose bind mount, else a sibling Dockerfile. ``latest`` is not a pin."""
    mounted = _compose_floor(files, config)
    if mounted:
        return mounted
    parent = config.rsplit("/", 1)[0] if "/" in config else ""
    names = [f"{parent}/Dockerfile" if parent else "Dockerfile"]
    names.append(f"{parent}/dockerfile" if parent else "dockerfile")
    text = next((files[name] for name in names if name in files), None)
    if text is None:
        return None
    pinned: tuple[int, int, int] | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line.lower().startswith("from "):
            continue
        image = line.split()[1] if len(line.split()) > 1 else ""
        repo, _, tag = image.partition(":")
        repo_name = repo.rsplit("/", 1)[-1].lower()
        if repo_name != _software(config):
            continue
        match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", tag)
        if match is None:
            pinned = None
            continue
        pinned = (
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3) or 0),
        )
    if pinned is None:
        return None
    return _default_floor(_software(config), pinned)


def _compose_floor(files: dict[str, str], config: str) -> str | None:
    from aibom.cbom.posture.yamlsafe import parse_yaml

    found: str | None = None
    for path, text in files.items():
        name = path.rsplit("/", 1)[-1].casefold()
        if not name.startswith(("docker-compose", "compose.")):
            continue
        docs = parse_yaml(text, path=path)
        if not docs or not isinstance(docs[0], dict):
            continue
        services = docs[0].get("services")
        if not isinstance(services, dict):
            continue
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        for service in services.values():
            if not isinstance(service, dict):
                continue
            image = service.get("image")
            software = _software(config)
            version = (
                _image_tag(image, software) if isinstance(image, str) else None
            )
            if version is None or software is None:
                continue
            if not _mounts(service.get("volumes"), parent, config):
                continue
            found = _default_floor(software, version)
    return found


def _software(config: str) -> str | None:
    kind = _kind(config, "")
    if kind == "nginx":
        return "nginx"
    if kind == "apache":
        return "httpd"
    return None


def _default_floor(software: str, version: tuple[int, int, int]) -> str:
    if software == "nginx":
        return "TLSv1.2" if version >= (1, 27, 3) else "TLSv1"
    return "TLSv1" if version >= (2, 4, 17) else "SSLv3"


def _image_tag(image: str, software: str) -> tuple[int, int, int] | None:
    _repo, _, tag = image.partition(":")
    name = image.rsplit("/", 1)[-1].split(":", 1)[0].lower()
    if name != software:
        return None
    match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", tag)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _mounts(volumes: object, parent: str, config: str) -> bool:
    if not isinstance(volumes, list):
        return False
    for item in volumes:
        host = ""
        if isinstance(item, str) and ":" in item:
            host = item.split(":", 1)[0].strip()
        elif isinstance(item, dict):
            source = item.get("source")
            host = source.strip() if isinstance(source, str) else ""
        if host.startswith("./"):
            host = host[2:]
        rel = f"{parent}/{host}" if parent and host else host
        if rel == config:
            return True
    return False


def server_facts(
    files: dict[str, str], *, analyse_included: bool = False
) -> tuple[EncryptionFact, ...]:
    """One entry per file. A file named by an include is not a second entry."""
    included: set[str] = set()
    for path, text in files.items():
        for rel in included_paths(text, path):
            if rel in files:
                included.add(rel)
    facts: list[EncryptionFact] = []
    for path in sorted(files):
        if path in included and not analyse_included:
            continue
        body = files[path] if path in included else _expanded(path, files, set())
        facts.extend(
            extract_servers(body, path, pinned_floor=_image_floor(files, path))
        )
    return tuple(facts)


def extract_servers(
    text: str, path: str, *, pinned_floor: str | None = None
) -> tuple[EncryptionFact, ...]:
    """Facts for one inline server file. A redirect is not a plaintext listener."""
    kind = _kind(path, text)
    if kind == "nginx":
        return _nginx(text, path, pinned_floor)
    if kind == "apache":
        return _apache(text, path, pinned_floor)
    if kind == "openssh":
        return _openssh(text, path)
    if kind == "haproxy":
        from aibom.cbom.posture.extract_haproxy import haproxy_facts

        return haproxy_facts(text, path)
    if kind == "envoy":
        from aibom.cbom.posture.extract_envoy import envoy_facts

        return envoy_facts(text, path)
    if kind == "traefik":
        from aibom.cbom.posture.extract_traefik import traefik_facts

        return traefik_facts(text, path)
    if kind == "tomcat":
        from aibom.cbom.posture.extract_tomcat import tomcat_facts

        return tomcat_facts(text, path)
    if kind == "spring":
        from aibom.cbom.posture.extract_spring import spring_facts

        return spring_facts(text, path)
    if kind == "jetty":
        from aibom.cbom.posture.extract_jetty import jetty_facts

        return jetty_facts(text, path)
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
    if base == "haproxy.cfg":
        return "haproxy"
    if base.startswith("envoy"):
        return "envoy"
    if base == "server.xml":
        return "tomcat"
    if base.startswith("application."):
        return "spring"
    if base.startswith("jetty") or base == "ssl.ini":
        return "jetty"
    folded = f"\n{text.casefold()}"
    named = base.startswith("traefik") or "entrypoints:" in folded
    if named or "\nminversion:" in folded:
        return "traefik"
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


def _nginx(
    text: str, path: str, nginx_floor: str | None = None
) -> tuple[EncryptionFact, ...]:
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
    inherited = [entry for entry in doc.entries if entry.parent == "http"]
    for (lane, _unit), entries in groups.items():
        if lane == "stream":
            saw_stream = True
        counts[lane] += 1
        label = "stream" if lane == "stream" else "server"
        facts.append(
            _nginx_fact(
                entries,
                path,
                lane,
                f"nginx.{label}[{counts[lane]}]",
                inherited,
                nginx_floor,
            )
        )
    if _declares_stream(text) and not saw_stream:
        facts.append(_empty_stream(text, path))
    if not counts["http"]:
        defaults = _nginx_http_defaults(inherited, path)
        if defaults is not None:
            facts.append(defaults)
    return tuple(facts)


def _nginx_http_defaults(inherited: list[Directive], path: str) -> EncryptionFact | None:
    """An http block that sets ``ssl_protocols`` with no server block in this file (Ubuntu's stock nginx.conf: the
    sites come from include files).  The setting is every server's default, so its protocol floor is reported
    (the line is the directive's own)."""
    floor, protocols = _protocol_floor(inherited, "ssl_protocols")
    if not protocols:
        return None
    basis = [BasisEntry("context", "http"), BasisEntry("protocols", protocols), BasisEntry("protocol_min", floor)]
    cipher = _cipher_basis(inherited)
    if cipher is not None:
        basis.append(cipher)
    return _make(
        kind="tls_endpoint",
        native="nginx",
        address="nginx.http",
        path=path,
        line=_named_line(inherited, "ssl_protocols"),
        form="server_config",
        verdict="UNKNOWN",
        reason="layer_not_observable",
        basis=tuple(basis),
    )


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
    entries: list[Directive],
    path: str,
    lane: str,
    address: str,
    inherited: list[Directive] | None = None,
    nginx_floor: str | None = None,
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
    declared = _nginx_listen(entries)
    if declared:
        basis.append(BasisEntry("listen_declared", declared))
    _store_endpoints(basis, _nginx_endpoints(entries))
    if verdict == "NOT_ENCRYPTED" and listen:
        basis.append(BasisEntry("listener", "plaintext"))
    cipher = _cipher_basis(entries)
    if cipher is not None:
        basis.append(cipher)
    if _verification_off(entries):
        basis.append(BasisEntry("verification", "disabled"))
    auth = _client_auth(entries)
    if auth is not None:
        basis.append(BasisEntry("client_auth", auth))
    floor, protocols = _protocol_floor(entries, "ssl_protocols")
    if not protocols and inherited:
        floor, protocols = _protocol_floor(inherited, "ssl_protocols")
    if protocols:
        basis.append(BasisEntry("protocols", protocols))
        basis.append(BasisEntry("protocol_min", floor))
    elif tls and not any(item.name == "protocol_min" for item in basis):
        if nginx_floor:
            basis.append(BasisEntry("protocol_min", nginx_floor))
        else:
            basis.append(
                BasisEntry("protocol_min", None, "provider_version_dependent")
            )
    tickets = _on_off(entries, "ssl_session_tickets")
    if tickets:
        basis.append(BasisEntry("session_tickets", tickets))
    prefer = _on_off(entries, "ssl_prefer_server_ciphers")
    if prefer:
        basis.append(BasisEntry("prefer_server_ciphers", prefer))
    if redirect:
        basis.append(BasisEntry("redirect", "https"))
    dh_path = _dh_declared(entries)
    if dh_path:
        basis.append(BasisEntry("dh_path", dh_path))
    curves = _joined(entries, "ssl_ecdh_curve")
    if curves:
        basis.append(BasisEntry("curves", curves))
    basis.extend(_nginx_hsts(entries))
    for declared in _cert_args(entries, "ssl_certificate"):
        basis.append(BasisEntry("cert_path", declared))
    for declared in _cert_args(entries, "ssl_certificate_key"):
        basis.append(BasisEntry("key_file_declared", declared))
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


def _cert_args(entries: list[Directive], name: str) -> tuple[str, ...]:
    found: list[str] = []
    for item in entries:
        if item.name.casefold() != name or not item.args:
            continue
        found.append(item.args[0])
    return tuple(found)


def _nginx_hsts(entries: list[Directive]) -> tuple[BasisEntry, ...]:
    from aibom.cbom.posture.hsts import entries_from_value

    for item in entries:
        if item.name.casefold() != "add_header" or not item.args:
            continue
        if item.args[0].casefold() != "strict-transport-security":
            continue
        return entries_from_value(" ".join(item.args[1:]))
    return ()


def _apache_hsts(entries: list[Directive]) -> tuple[BasisEntry, ...]:
    from aibom.cbom.posture.hsts import entries_from_value

    for item in entries:
        if item.name.casefold() != "header" or not item.args:
            continue
        folded = [arg.casefold() for arg in item.args]
        if "strict-transport-security" not in folded:
            continue
        if "set" not in folded and "append" not in folded:
            continue
        index = folded.index("strict-transport-security")
        return entries_from_value(" ".join(item.args[index + 1 :]))
    return ()


def _joined(entries: list[Directive], name: str) -> str | None:
    for item in entries:
        if item.name.casefold() == name and item.args:
            return " ".join(item.args)
    return None


def _openssl_curves(entries: list[Directive]) -> str | None:
    parts: list[str] = []
    for item in entries:
        if item.name.casefold() != "sslopensslconfcmd" or len(item.args) < 2:
            continue
        if item.args[0].casefold() == "curves":
            parts.append(" ".join(item.args[1:]))
    return " ".join(parts) or None


def _dh_declared(entries: list[Directive]) -> str | None:
    for item in entries:
        name = item.name.casefold()
        if name == "ssl_dhparam" and item.args:
            return item.args[0]
        command = name == "sslopensslconfcmd" and len(item.args) >= 2
        if command and item.args[0].casefold() == "dhparameters":
            return item.args[1]
    return None


def _client_auth(entries: list[Directive]) -> str | None:
    nginx = {"off": "none", "optional": "optional", "on": "required"}
    apache = {
        "none": "none",
        "optional": "optional",
        "require": "required",
        "required": "required",
    }
    for item in entries:
        if not item.args:
            continue
        name = item.name.casefold()
        value = item.args[0].casefold()
        if name == "ssl_verify_client":
            return nginx.get(value)
        if name == "sslverifyclient":
            return apache.get(value)
    return None


def _verification_off(entries: list[Directive]) -> bool:
    https_proxy = any(
        item.name.casefold() == "proxy_pass"
        and item.marker != "unresolved_expression"
        and any(arg.casefold().startswith("https://") for arg in item.args)
        for item in entries
    )
    proxy_engine = any(
        item.name.casefold() == "sslproxyengine"
        and item.marker != "unresolved_expression"
        and item.args
        and item.args[0].casefold() in {"on", "optional"}
        for item in entries
    )
    for item in entries:
        if item.marker == "unresolved_expression" or not item.args:
            continue
        name = item.name.casefold()
        value = item.args[0].casefold()
        if name == "proxy_ssl_verify" and value == "off" and https_proxy:
            return True
        if name == "sslproxyverify" and value in {"off", "none"} and proxy_engine:
            return True
    return False


def _cipher_basis(entries: list[Directive]) -> BasisEntry | None:
    names = {"ssl_ciphers", "sslciphersuite"}
    chosen = next(
        (
            item
            for item in entries
            if item.name.casefold() in names
            and item.args
            and item.marker != "unresolved_expression"
        ),
        None,
    )
    if chosen is None:
        conditional = any(
            item.name.casefold() in names and item.marker == "unresolved_expression"
            for item in entries
        )
        if conditional:
            return BasisEntry("cipher_suite", None, "unresolved_expression")
        return None
    raw = " ".join(chosen.args)
    if chosen.name.casefold() == "sslciphersuite":
        raw = _strip_protocol_word(raw)
    from aibom.cbom.posture.ciphers import evaluate_cipher_list
    from aibom.cbom.posture.defaults import load_registry

    result = evaluate_cipher_list(raw, load_registry())
    names = result.explicit or result.suites
    if not names:
        if result.unresolved:
            return BasisEntry("cipher_suite", None, "unresolved_expression")
        return None
    return BasisEntry("cipher_suite", ",".join(names[:8]))


_PROTOCOL_WORDS = frozenset(
    {"all", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3"}
)


def _strip_protocol_word(raw: str) -> str:
    parts = raw.split()
    if parts and parts[0].casefold() in _PROTOCOL_WORDS:
        return " ".join(parts[1:])
    return raw


def _listen_flags(entries: list[Directive]) -> tuple[bool, bool, str]:
    plaintext = False
    ssl_on = _flag_on(entries, "ssl")
    tls = ssl_on
    tokens: list[str] = []
    for item in entries:
        if item.name.casefold() != "listen":
            continue
        if item.args:
            tokens.append(item.args[0])
        if any(arg.casefold() == "ssl" for arg in item.args) or ssl_on:
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


def _apache(
    text: str, path: str, pinned_floor: str | None = None
) -> tuple[EncryptionFact, ...]:
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
        facts.append(_apache_fact(entries, path, address, key, pinned_floor))
    return tuple(facts)


def _apache_fact(
    entries: list[Directive],
    path: str,
    address: str,
    key: str,
    pinned_floor: str | None = None,
) -> EncryptionFact:
    tls = _flag_on(entries, "sslengine", _ENGINE_ON)
    redirect = any(_apache_redirect(item) for item in entries)
    hosted = key.startswith("virtualhost")
    listened = any(item.name == "listen" for item in entries)
    verdict, reason, codes = _transport((hosted or listened) and not tls, redirect, tls)
    basis: list[BasisEntry] = [BasisEntry("server", "apache")]
    if hosted:
        basis.append(BasisEntry("virtualhost", key))
    if tls:
        declared = _apache_listen(key)
        if declared:
            basis.append(BasisEntry("listen_declared", declared))
        _store_endpoints(basis, _apache_endpoints(entries, key))
    if redirect:
        basis.append(BasisEntry("redirect", "https"))
    _apply_apache_protocol(entries, "sslprotocol", "protocol_min", basis)
    _apply_apache_protocol(entries, "sslproxyprotocol", "proxy_protocol_min", basis)
    if tls and not any(item.name == "protocol_min" for item in basis):
        if pinned_floor:
            basis.append(BasisEntry("protocol_min", pinned_floor))
        else:
            basis.append(
                BasisEntry("protocol_min", None, "provider_version_dependent")
            )
    tickets = _on_off(entries, "sslsessiontickets")
    if tickets:
        basis.append(BasisEntry("session_tickets", tickets))
    prefer = _on_off(entries, "sslhonorcipherorder")
    if prefer:
        basis.append(BasisEntry("prefer_server_ciphers", prefer))
    compression = _on_off(entries, "sslcompression")
    if compression:
        basis.append(BasisEntry("compression", compression))
    cipher = _cipher_basis(entries)
    if cipher is not None:
        basis.append(cipher)
    if _verification_off(entries):
        basis.append(BasisEntry("verification", "disabled"))
    auth = _client_auth(entries)
    if auth is not None:
        basis.append(BasisEntry("client_auth", auth))
    if verdict == "NOT_ENCRYPTED":
        basis.append(BasisEntry("listener", "plaintext"))
    dh_path = _dh_declared(entries)
    if dh_path:
        basis.append(BasisEntry("dh_path", dh_path))
    curves = _openssl_curves(entries)
    if curves:
        basis.append(BasisEntry("curves", curves))
    basis.extend(_apache_hsts(entries))
    for declared in _cert_args(entries, "sslcertificatefile"):
        basis.append(BasisEntry("cert_path", declared))
    for declared in _cert_args(entries, "sslcertificatekeyfile"):
        basis.append(BasisEntry("key_file_declared", declared))
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


def _store_endpoints(basis: list[BasisEntry], candidates: tuple[str, ...]) -> None:
    if not candidates:
        return
    basis.append(BasisEntry("endpoint", candidates[0]))
    basis.append(BasisEntry("endpoints", ",".join(candidates)))


def _nginx_endpoints(entries: list[Directive]) -> tuple[str, ...]:
    from aibom.cbom.posture.extract_common import (
        endpoint_list,
        listen_endpoint,
        valid_host,
    )

    hosts: list[str] = []
    ports: list[int] = []
    for item in entries:
        if item.name.casefold() == "server_name":
            for arg in item.args:
                host = valid_host(arg)
                if host:
                    hosts.append(host)
            continue
        if item.name.casefold() != "listen" or not item.args:
            continue
        has_ssl = any(arg.casefold() == "ssl" for arg in item.args[1:])
        if not has_ssl and not _flag_on(entries, "ssl"):
            continue
        host, port = listen_endpoint(item.args[0])
        if host:
            hosts.append(host)
        if port is not None:
            ports.append(port)
    return endpoint_list(f"{host}:{port}" for host in hosts for port in ports)


def _apache_endpoints(entries: list[Directive], key: str) -> tuple[str, ...]:
    from aibom.cbom.posture.extract_common import (
        endpoint_list,
        listen_endpoint,
        valid_host,
    )

    head = key.split(".", 1)[0]
    parts = head.split(" ", 1)
    if len(parts) < 2:
        return ()
    _host, port = listen_endpoint(parts[1])
    if port is None:
        return ()
    hosts: list[str] = []
    for item in entries:
        if item.name not in {"servername", "serveralias"}:
            continue
        for arg in item.args:
            host = _apache_host(arg, valid_host, listen_endpoint)
            if host:
                hosts.append(host)
    return endpoint_list(f"{host}:{port}" for host in hosts)


def _apache_host(
    arg: str,
    host_of: Callable[[str], str | None],
    endpoint_of: Callable[[str], tuple[str | None, int | None]],
) -> str | None:
    text = arg.strip()
    lowered = text.lower()
    if lowered.startswith("https://"):
        text = text[8:]
    elif lowered.startswith("http://"):
        text = text[7:]
    if ":" in text or text.startswith("["):
        host, _port = endpoint_of(text)
        return host
    return host_of(text)


def _nginx_listen(entries: list[Directive]) -> str | None:
    from aibom.cbom.posture.extract_common import listen_label

    ssl_on = _flag_on(entries, "ssl")
    tokens: list[str] = []
    for item in entries:
        if item.name.casefold() != "listen" or not item.args:
            continue
        has_ssl = any(arg.casefold() == "ssl" for arg in item.args[1:])
        if not has_ssl and not ssl_on:
            continue
        tokens.append(item.args[0])
    return listen_label(tokens)


def _apache_listen(key: str) -> str | None:
    from aibom.cbom.posture.extract_common import listen_label

    head = key.split(".", 1)[0]
    parts = head.split(" ", 1)
    if len(parts) < 2:
        return None
    return listen_label(parts[1].split())


_APACHE_ALL = ("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_APACHE_RANK = {name: index for index, name in enumerate(_APACHE_ALL)}
_APACHE_NAMES = {name.casefold(): name for name in ("SSLv2", *_APACHE_ALL)}


def _apache_protocol_tokens(
    entries: list[Directive], name: str
) -> tuple[list[str], bool]:
    tokens: list[str] = []
    conditional = False
    for item in entries:
        if item.name.casefold() != name:
            continue
        if item.marker == "unresolved_expression":
            conditional = True
            continue
        tokens.extend(item.args)
    return tokens, conditional


def _apache_protocols(entries: list[Directive]) -> tuple[str, str]:
    """Floor and offered CSV for ``SSLProtocol``. Mutant M46 patches this."""
    tokens, _conditional = _apache_protocol_tokens(entries, "sslprotocol")
    if not tokens:
        return "", ""
    floor, _bound, unknown, offered = _evaluate_apache(tokens)
    if unknown or floor is None:
        return "", ""
    return floor, ",".join(offered)


def _apply_apache_protocol(
    entries: list[Directive], name: str, field: str, basis: list[BasisEntry]
) -> None:
    tokens, conditional = _apache_protocol_tokens(entries, name)
    if name == "sslprotocol" and field == "protocol_min":
        floor, protocols = _apache_protocols(entries)
        if not floor and not protocols:
            if conditional:
                basis.append(BasisEntry(field, None, "unresolved_expression"))
            return
        if not floor:
            basis.append(BasisEntry(field, None, "unresolved_expression"))
            return
        basis.append(BasisEntry(field, floor))
        if protocols:
            basis.append(BasisEntry("protocols", protocols))
        if tokens:
            _floor, bound, unknown, _offered = _evaluate_apache(tokens)
            if not unknown and bound:
                basis.append(BasisEntry("floor_is_bound", "true"))
        return
    if not tokens:
        if conditional:
            basis.append(BasisEntry(field, None, "unresolved_expression"))
        return
    floor, bound, unknown, _offered = _evaluate_apache(tokens)
    if unknown or floor is None:
        basis.append(BasisEntry(field, None, "unresolved_expression"))
        return
    basis.append(BasisEntry(field, floor))
    if bound:
        basis.append(BasisEntry("floor_is_bound", "true"))


def _evaluate_apache(
    tokens: list[str],
) -> tuple[str | None, bool, bool, tuple[str, ...]]:
    """Apache ``SSLProtocol`` arithmetic. Returns floor, bound, unknown, offered."""
    if any("$" in token for token in tokens):
        return None, False, True, ()
    current: set[str] = set()
    started = False
    unprefixed: list[str] = []
    ambiguous = False
    for raw in tokens:
        prefix = raw[0] if raw[:1] in "+-" else ""
        body = raw[1:] if prefix else raw
        folded = body.casefold()
        name = "all" if folded == "all" else _APACHE_NAMES.get(folded)
        if name is None:
            return None, False, True, ()
        if name == "SSLv2":
            if prefix == "-":
                continue
            return None, False, True, ()
        if prefix == "+":
            if body.casefold() == "all":
                current.update(_APACHE_ALL)
            else:
                current.add(name)
            continue
        if prefix == "-":
            if body.casefold() == "all":
                current.clear()
            else:
                current.discard(name)
            continue
        added = set(_APACHE_ALL) if body.casefold() == "all" else {name}
        if body.casefold() != "all":
            unprefixed.append(name)
        if not started:
            current = added
            started = True
            continue
        if current | added != added:
            ambiguous = True
        else:
            current = added
        started = True
    if ambiguous:
        if not unprefixed:
            return None, False, True, ()
        floor = min(unprefixed, key=_APACHE_RANK.__getitem__)
        if _APACHE_RANK[floor] < _APACHE_RANK["TLSv1.2"]:
            return None, False, True, ()
        seen: list[str] = []
        for token in unprefixed:
            if token not in seen:
                seen.append(token)
        return floor, True, False, tuple(seen)
    if not current:
        return None, False, True, ()
    ordered = tuple(sorted(current, key=_APACHE_RANK.__getitem__))
    return ordered[0], False, False, ordered


def _on_off(entries: list[Directive], name: str) -> str | None:
    for item in entries:
        if item.name.casefold() != name or not item.args:
            continue
        value = item.args[0].casefold()
        if value in {"on", "off"}:
            return value
    return None


def _protocol_floor(entries: list[Directive], name: str) -> tuple[str, str]:
    """Minimum named protocol token. ``all`` and ``+``/``-`` tokens are skipped."""
    tokens: list[str] = []
    for item in entries:
        if item.name.casefold() != name:
            continue
        for arg in item.args:
            word = arg.strip()
            if not word or word[0] in "+-":
                continue
            if word.casefold() == "all":
                continue
            tokens.append(word)
    if not tokens:
        return "", ""
    rank = {name: index for index, name in enumerate(_TLS_ORDER)}
    floor = min(tokens, key=lambda token: rank.get(token, len(rank)))
    seen: list[str] = []
    for token in tokens:
        if token not in seen:
            seen.append(token)
    return floor, ",".join(seen)


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
    algorithms = _ssh_algorithms(doc.entries)
    if algorithms:
        basis.append(BasisEntry("cipher_suite", ",".join(algorithms[:8])))
    version = doc.lookup("Protocol")
    if version and version[0].split(",")[0].strip() == "1":
        basis.append(BasisEntry("protocol_min", "SSH-1"))
    declared = _ssh_listen(doc.entries)
    if declared:
        basis.append(BasisEntry("listen_declared", declared))
    required = doc.lookup("RequiredRSASize")
    if required and required[0].isdigit():
        basis.append(BasisEntry("required_rsa_size", str(int(required[0]))))
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


_SSH_LISTS = (
    "ciphers",
    "macs",
    "kexalgorithms",
    "hostkeyalgorithms",
    "pubkeyacceptedalgorithms",
    "casignaturealgorithms",
)


def _ssh_listen(entries: list[Directive]) -> str | None:
    from aibom.cbom.posture.extract_common import listen_label

    addresses: list[str] = []
    ports: list[str] = []
    for item in entries:
        parent = (item.parent or "").casefold()
        if parent.startswith("match"):
            continue
        if item.name.casefold() == "listenaddress" and item.args:
            addresses.append(item.args[0])
        elif item.name.casefold() == "port" and item.args:
            ports.append(item.args[0])
    return listen_label(addresses or ports)


def _ssh_algorithms(entries: list[Directive]) -> list[str]:
    found: list[str] = []
    for item in entries:
        if item.name.casefold() not in _SSH_LISTS:
            continue
        for arg in item.args:
            found.extend(part.strip() for part in arg.split(",") if part.strip())
    return found


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
