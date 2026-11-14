"""Domain names for Certificate Transparency discovery: one normalised form, and the set of queries a list needs.

* Stored and queried as A-labels (punycode), the form CT logs and the providers use for internationalised names.
  Conversion is UTS #46 non-transitional processing (the ``idna`` package, IDNA 2008), as CB-09 plans for every
  name in the product: ``faß.de`` is ``xn--fa-hia.de``. Names with a zero-width joiner or non-joiner are refused.
* ``*.example.com`` means "example.com and its subdomains": CT search by domain already returns wildcard names.
* An IP address, a single label, an empty label, a label longer than 63 octets or a name longer than 253 is refused.
* ``query_set`` drops names covered by another listed name when subdomains are included (``www.example.com`` is in
  ``example.com``'s answer), so a customer is never charged twice for one search.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata

MAX_DOMAINS = 1_000
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_JOINERS = ("\u200c", "\u200d")


class DomainError(ValueError):
    """``str(err)`` is safe to show to the customer."""


def normalise(raw: str) -> tuple[str, bool]:
    """(A-label name, was_wildcard).  Raises DomainError with a sentence the form can show."""
    if not isinstance(raw, str):
        raise DomainError("must be text")
    text = unicodedata.normalize("NFC", raw.strip())
    if not text:
        raise DomainError("is empty")
    if "://" in text or "/" in text or "@" in text or " " in text:
        raise DomainError(f"{raw.strip()[:80]!r} is not a domain name (enter only the name, e.g. example.com)")
    wildcard = text.startswith("*.")
    if wildcard:
        text = text[2:]
    text = text.rstrip(".")
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        pass
    else:
        raise DomainError(f"{text!r} is an IP address; CT logs are searched by domain name")
    if any(ch in text for ch in _JOINERS):
        raise DomainError("contains a zero-width joiner or non-joiner; enter the name without it")
    if text.isascii():
        name = text.lower()
    else:
        try:
            import idna

            name = idna.encode(text, uts46=True, transitional=False).decode("ascii")
        except (idna.IDNAError, UnicodeError) as exc:
            raise DomainError(f"{text!r} is not a valid internationalised domain name") from exc
    if len(name) > 253:
        raise DomainError("is longer than 253 characters")
    labels = name.split(".")
    if len(labels) < 2:
        raise DomainError(f"{name!r} needs at least two labels (e.g. example.com)")
    for label in labels:
        if not _LABEL.match(label):
            raise DomainError(f"{name!r} has an invalid label {label[:63]!r}")
    if labels[-1].isdigit():
        raise DomainError(f"{name!r} does not end in a top-level domain")
    if name.startswith("xn--") or ".xn--" in name:  # an A-label must decode (a typo in punycode is not a name)
        try:
            import idna

            idna.decode(name)
        except (idna.IDNAError, UnicodeError) as exc:
            raise DomainError(f"{name!r} is not valid punycode") from exc
    return name, wildcard


def normalise_list(values: list[str]) -> list[str]:
    """Normalised, de-duplicated, in the order given.  Raises DomainError naming the first bad entry."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if isinstance(value, str) and not value.strip():
            continue
        try:
            name, _wild = normalise(value)
        except DomainError as exc:
            shown = str(value).strip()[:80]
            raise DomainError(str(exc) if shown.lower().lstrip("*.").rstrip(".") in str(exc).lower()
                              else f"{shown!r} {exc}") from None
        if name not in seen:
            seen.add(name)
            out.append(name)
    if len(out) > MAX_DOMAINS:
        raise DomainError(f"at most {MAX_DOMAINS} domains (got {len(out)})")
    return out


def covered_by(name: str, other: str) -> bool:
    return name == other or name.endswith("." + other)


def query_set(domains: list[str], include_subdomains: bool) -> list[str]:
    """The names to search, sorted: each listed name once, minus names another listed name already covers."""
    unique = sorted(set(domains), key=lambda d: (d.count("."), d))
    if not include_subdomains:
        return sorted(unique)
    kept: list[str] = []
    for name in unique:  # shortest first, so a parent is always kept before its children are checked
        if not any(covered_by(name, parent) for parent in kept):
            kept.append(name)
    return sorted(kept)


def display(name: str) -> str:
    """The U-label form for display (the stored A-label when it does not decode)."""
    if "xn--" not in name:
        return name
    try:
        import idna

        return idna.decode(name)
    except (idna.IDNAError, UnicodeError):
        return name


__all__ = ["DomainError", "MAX_DOMAINS", "covered_by", "display", "normalise", "normalise_list", "query_set"]
