"""Literal OpenSSL cipher-string reference.

One pass per token, plain lists and sets, no cache. This module does not
import the product evaluator.
"""

from __future__ import annotations

_MAX_CHARS = 4096
_MAX_TOKENS = 512
_MAX_UNRESOLVED = 20
_TOKEN_CHARS = 64
_LIST_SEPS = set(":, \t\r\n")
_TLS13_SEPS = set(": \t\r\n")


def evaluate_cipher_list(spec, document):
    """Return the uncapped TLS 1.2 cipher-list expansion."""
    catalog = _catalog(document)
    text, limited = _clip(spec)
    tokens = _tokenize(text, _LIST_SEPS)
    if len(tokens) > _MAX_TOKENS:
        tokens = tokens[:_MAX_TOKENS]
        limited = True
    chosen = []
    present = set()
    deleted = set()
    explicit = []
    unresolved = []
    seclevel = None
    complete = not limited
    for index, token in enumerate(tokens):
        if token == "@STRENGTH":
            continue
        if token.startswith("@SECLEVEL="):
            level = _seclevel_value(token)
            if level is None:
                complete = _unresolved(token, unresolved)
            else:
                seclevel = level
            continue
        if token.startswith("@"):
            complete = _unresolved(token, unresolved)
            continue
        prefix, body = _split_prefix(token)
        if body == "DEFAULT":
            if index == 0 and prefix == "":
                _expand_default(catalog, chosen, present, deleted)
            else:
                complete = _unresolved(token, unresolved)
            continue
        matched = _match_body(body, catalog)
        if matched is None:
            complete = _unresolved(token, unresolved)
            continue
        if prefix == "" and body in catalog["by_name"]:
            _remember(explicit, catalog["by_name"][body]["iana"])
        _apply_prefix(prefix, matched, chosen, present, deleted)
    if seclevel is not None:
        _apply_seclevel(seclevel, chosen, present, catalog)
    chosen = [name for name in chosen if not catalog["by_iana"][name]["tls13"]]
    present = set(chosen)
    ordered = sorted(chosen, key=lambda name: catalog["by_iana"][name]["code"])
    named = [name for name in explicit if name in present]
    return {
        "suites": ordered,
        "explicit": named,
        "unresolved": unresolved,
        "complete": complete,
        "seclevel": seclevel,
    }


def evaluate_tls13_suites(spec, document):
    catalog = _catalog(document)
    text, limited = _clip(spec)
    tokens = _tokenize(text, _TLS13_SEPS)
    if len(tokens) > _MAX_TOKENS:
        tokens = tokens[:_MAX_TOKENS]
        limited = True
    chosen = []
    seen = set()
    explicit = []
    unresolved = []
    complete = not limited
    allowed = {
        suite["iana"]: suite for suite in catalog["suites"] if suite["tls13"]
    }
    for token in tokens:
        suite = allowed.get(token)
        if suite is None:
            complete = _unresolved(token, unresolved)
            continue
        _remember(explicit, suite["iana"])
        if suite["iana"] not in seen:
            seen.add(suite["iana"])
            chosen.append(suite)
    ordered = [suite["iana"] for suite in sorted(chosen, key=lambda item: item["code"])]
    return {
        "suites": ordered,
        "explicit": explicit,
        "unresolved": unresolved,
        "complete": complete,
        "seclevel": None,
    }


def classify_groups(spec, document):
    groups = _groups(document)
    text, limited = _clip(spec)
    tokens = _tokenize(text, _LIST_SEPS)
    if len(tokens) > _MAX_TOKENS:
        tokens = tokens[:_MAX_TOKENS]
        limited = True
    found = {}
    unresolved = []
    complete = not limited
    for token in tokens:
        if token.casefold() == "auto":
            continue
        group = groups.get(token.casefold())
        if group is None:
            complete = _unresolved(token, unresolved)
            continue
        found.setdefault(group["name"], group)
    names = sorted(found)
    weak = [
        {"name": group["name"], "bits": group["bits"]}
        for group in sorted(
            (item for item in found.values() if item["bits"] < 224),
            key=lambda item: item["name"],
        )
    ]
    return {
        "groups": names,
        "weak": weak,
        "unresolved": unresolved,
        "complete": complete,
    }


def _catalog(document):
    suites = []
    by_name = {}
    by_iana = {}
    for raw in document.get("rows") or []:
        if not isinstance(raw, dict) or raw.get("kind") == "suite_set":
            continue
        iana = raw.get("iana")
        code = raw.get("code")
        if not isinstance(iana, str) or not _whole(code):
            continue
        suite = {
            "iana": iana,
            "code": code,
            "kx": _text(raw.get("kx")),
            "au": _text(raw.get("au")),
            "enc": _text(raw.get("enc")),
            "enc_mode": _text(raw.get("enc_mode")),
            "enc_bits": _number(raw.get("enc_bits")),
            "mac": _text(raw.get("mac")),
            "min": _text(raw.get("min")),
            "classes": {
                item for item in raw.get("classes") or [] if isinstance(item, str)
            },
            "bits": _number(raw.get("bits")),
            "tls13": raw.get("tls13") is True,
        }
        suites.append(suite)
        by_iana[iana] = suite
        for name in [iana, *(raw.get("openssl") or []), *(raw.get("aliases") or [])]:
            if isinstance(name, str) and name and name not in by_name:
                by_name[name] = suite
    keywords = {}
    for name, spec in (document.get("keywords") or {}).items():
        if not isinstance(spec, dict):
            continue
        fields = {}
        for key, allowed in spec.items():
            if isinstance(allowed, list):
                fields[key] = tuple(allowed)
        if fields:
            keywords[name] = fields
    seclevels = {}
    for key, spec in (document.get("seclevels") or {}).items():
        if not isinstance(key, str) or not key.isdigit() or not isinstance(spec, dict):
            continue
        floor = spec.get("min_bits")
        if isinstance(floor, bool) or not isinstance(floor, int):
            floor = 0
        deny = {item for item in spec.get("deny") or [] if isinstance(item, str)}
        seclevels[int(key)] = (floor, deny)
    return {
        "suites": suites,
        "by_name": by_name,
        "by_iana": by_iana,
        "keywords": keywords,
        "seclevels": seclevels,
    }


def _groups(document):
    found = {}
    for raw in document.get("rows") or []:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        bits = raw.get("bits")
        if not isinstance(name, str) or not _whole(bits):
            continue
        group = {"name": name, "bits": bits}
        found.setdefault(name.casefold(), group)
        for alias in raw.get("aliases") or []:
            if isinstance(alias, str):
                found.setdefault(alias.casefold(), group)
    return found


def _expand_default(catalog, chosen, present, deleted):
    for token in ("ALL", "!COMPLEMENTOFDEFAULT", "!eNULL"):
        prefix, body = _split_prefix(token)
        matched = _match_body(body, catalog)
        if matched is None:
            continue
        _apply_prefix(prefix, matched, chosen, present, deleted)


def _apply_prefix(prefix, matched, chosen, present, deleted):
    matched_ids = {suite["iana"] for suite in matched}
    if prefix == "!":
        deleted.update(matched_ids)
        _drop(chosen, present, matched_ids)
        return
    if prefix == "-":
        _drop(chosen, present, matched_ids)
        return
    if prefix == "+":
        moved = [name for name in chosen if name in matched_ids]
        if not moved:
            return
        staying = [name for name in chosen if name not in matched_ids]
        chosen[:] = staying + moved
        return
    for suite in matched:
        if suite["tls13"] or suite["iana"] in deleted or suite["iana"] in present:
            continue
        chosen.append(suite["iana"])
        present.add(suite["iana"])


def _apply_seclevel(level, chosen, present, catalog):
    rule = catalog["seclevels"].get(level)
    if rule is None:
        return
    floor, deny = rule
    blocked = set()
    for name in chosen:
        suite = catalog["by_iana"].get(name)
        if suite is None:
            continue
        if suite["bits"] < floor or suite["classes"] & deny:
            blocked.add(name)
    _drop(chosen, present, blocked)


def _match_body(body, catalog):
    if not body:
        return None
    exact = catalog["by_name"].get(body)
    if exact is not None:
        return (exact,)
    keyword = catalog["keywords"].get(body)
    if keyword is not None:
        return tuple(
            suite for suite in catalog["suites"] if _keyword_match(suite, keyword)
        )
    if "+" not in body:
        return None
    specs = []
    for part in body.split("+"):
        spec = catalog["keywords"].get(part)
        if spec is None:
            return None
        specs.append(spec)
    return tuple(
        suite
        for suite in catalog["suites"]
        if all(_keyword_match(suite, spec) for spec in specs)
    )


def _keyword_match(suite, spec):
    for key, allowed in spec.items():
        have = suite["classes"] if key == "classes" else suite.get(key)
        if isinstance(have, set):
            if not any(item in allowed for item in have):
                return False
        elif have not in allowed:
            return False
    return True


def _text(value):
    if isinstance(value, str):
        return value
    return ""


def _number(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def _whole(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _clip(spec):
    if not isinstance(spec, str):
        return "", True
    if len(spec) > _MAX_CHARS:
        return spec[:_MAX_CHARS], True
    return spec, False


def _tokenize(text, separators):
    tokens = []
    buf = []
    for char in text:
        if char in separators:
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(char)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _split_prefix(token):
    if token[:1] in "!-+":
        return token[0], token[1:]
    return "", token


def _seclevel_value(token):
    raw = token[len("@SECLEVEL=") :]
    if not raw.isdigit() or len(raw) > 4:
        return None
    value = int(raw)
    if value > 5:
        return None
    return value


def _unresolved(token, found):
    if len(found) < _MAX_UNRESOLVED:
        found.append(_sanitize(token))
    return False


def _sanitize(token):
    chars = []
    for char in token:
        chars.append(char if 32 <= ord(char) <= 126 else "?")
        if len(chars) == _TOKEN_CHARS:
            break
    return "".join(chars)


def _remember(found, name):
    if name not in found:
        found.append(name)


def _drop(chosen, present, blocked):
    if not blocked:
        return
    chosen[:] = [name for name in chosen if name not in blocked]
    present.difference_update(blocked)
