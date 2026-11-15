"""Internationalised host names: one rule for every name the product stores, compares or sends (CB-09).

UTS #46 non-transitional processing with the ``idna`` package (IDNA 2008).  Python's own ``"idna"`` codec is
IDNA 2003: it turns ``faß.de`` into ``fass.de`` (a different, separately registered name) and drops a zero-width
joiner, so it reaches a host the customer never named.

* ``to_a_label`` gives the stored form (the A-label, ``xn--fa-hia.de``); ASCII names are only lower-cased, and an
  ASCII ``xn--`` label must be valid punycode.  It refuses:
  * a zero-width joiner or non-joiner (IDNA 2003 drops it, IDNA 2008 keeps it: two different names);
  * anything IDNA 2008 does not allow (``☃.net``, which IDNA 2003 took).
* The deviation letters ``ß`` and ``ς`` are kept (``faß.de`` stays ``faß.de``).  ``idna2003_form`` names the other
  host older software reaches for such a name (``fass.de``), so the customer is told before saving and the
  never-scan list keeps both forms out.
* ``to_u_label`` gives the form to show.

The backend keeps the same module (``backend/utilities/cbom_sources/idn.py``);
``backend/tests/test_cbom_cb09_idna2008.py`` keeps the two in agreement.  On the node every name goes through it before getaddrinfo, the never-scan list, and
the SNI bytes (ClientHello, ``openssl -servername``, Python ``ssl``), which would otherwise use the IDNA 2003 codec.
"""
from __future__ import annotations

import unicodedata

import idna

JOINERS = ("‌", "‍")
DEVIATIONS = ("ß", "ς")  # UTS #46 deviation letters: IDNA 2003 maps them away (ß -> ss, ς -> σ), IDNA 2008 keeps them


class IdnError(ValueError):
    """``str(err)`` is safe to show to the customer (without the name, which the caller adds)."""


def to_a_label(text: str) -> str:
    """The A-label form of a host name already stripped of spaces and a trailing dot.  Raises IdnError."""
    text = unicodedata.normalize("NFC", str(text))
    if any(ch in text for ch in JOINERS):
        raise IdnError("contains a zero-width joiner or non-joiner, which older (IDNA 2003) software drops, reaching "
                       "a different name; enter the name without it")
    if text.isascii():
        name = text.lower()
        if name.startswith("xn--") or ".xn--" in name:
            try:
                idna.decode(name)
            except (idna.IDNAError, UnicodeError) as exc:
                raise IdnError("has an xn-- label that is not valid punycode") from exc
        return name
    try:
        return idna.encode(text, uts46=True, transitional=False).decode("ascii")
    except (idna.IDNAError, UnicodeError) as exc:
        raise IdnError("is not a valid internationalised host name under IDNA 2008") from exc


def to_u_label(name: str) -> str:
    """The form to show (the stored A-label when it does not decode)."""
    if "xn--" not in name:
        return name
    try:
        return idna.decode(name)
    except (idna.IDNAError, UnicodeError):
        return name


def idna2003_form(name: str) -> str | None:
    """For a stored A-label whose name has ``ß`` or ``ς``: the different name IDNA 2003 software reaches for it
    (``xn--fa-hia.de`` -> ``fass.de``).  None for every other name."""
    if "xn--" not in name:
        return None
    unicode_name = to_u_label(name)
    if not any(ch in unicode_name for ch in DEVIATIONS):
        return None
    try:
        other = unicode_name.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    return other if other != name else None


__all__ = ["DEVIATIONS", "IdnError", "JOINERS", "idna2003_form", "to_a_label", "to_u_label"]
