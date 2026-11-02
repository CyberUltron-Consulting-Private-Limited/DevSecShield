"""PowerShell crypto: the ``SecureString`` cmdlets and the .NET classes scripts call.

``ConvertFrom-SecureString -Key`` / ``ConvertTo-SecureString -Key`` (and ``-SecureKey``) encrypt or decrypt with AES
under the given 128-, 192- or 256-bit key ("If an encryption key is specified by using the Key or SecureKey
parameters, the Advanced Encryption Standard (AES) encryption algorithm is used",
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring). A key
written into the script as bytes (``$key = [byte[]](1..16)``, ``-Key (1,2,…,16)``) is a hard-coded key. The .NET
classes (``[System.Security.Cryptography.MD5]::Create()``, ``New-Object …TripleDESCryptoServiceProvider``) are the
.NET literal lane's, shared with C# and VB.NET.
"""

from __future__ import annotations

import re

from aibom.cbom.misuse import MaterialMisuse

_I = re.IGNORECASE
_SECURESTRING_KEY = re.compile(r"\b(?:ConvertTo|ConvertFrom)-SecureString\b[^\n]{0,400}?\s-(?:Secure)?Key\b", _I)

# The algorithm lane's PowerShell-only spellings (registered in ``detect.LITERAL_BY_LANG``).
POWERSHELL_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (("aes", _SECURESTRING_KEY),)

_KEY_ARG = re.compile(r"\s-(?:Secure)?Key\s+(\$[A-Za-z_]\w{0,63}|\(|\[byte\[\]\]|@\()", _I)
# a byte literal: [byte[]](1,2,…) / [byte[]]@(…) / (1,2,…) with at least 8 numbers, or a range (1..16)
_BYTES = re.compile(
    r"^\s*(?:\[byte\[\]\]\s*)?@?\(\s*(?:\d{1,3}\s*\.\.\s*\d{1,3}|(?:0x[0-9a-f]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-f]{1,2}|\d{1,3})){7,})\s*\)",
    _I,
)
_ASSIGN = re.compile(r"^\s*\$([A-Za-z_]\w{0,63})\s*=\s*(.{1,2000})$")
_COMMENT = re.compile(r"(?:^|\s)#.*$")


def securestring_key_facts(text: str) -> list[MaterialMisuse]:
    """A hard-coded key handed to a ``SecureString`` cmdlet: at the line the bytes are written."""
    lines = [_COMMENT.sub("", raw) for raw in text.splitlines()]
    literal_vars: dict[str, int] = {}
    facts: list[MaterialMisuse] = []
    seen: set[int] = set()
    for number, line in enumerate(lines, start=1):
        assigned = _ASSIGN.match(line)
        if assigned and _BYTES.match(assigned.group(2)):
            literal_vars[assigned.group(1).casefold()] = number
        elif assigned:
            literal_vars.pop(assigned.group(1).casefold(), None)
        if not _SECURESTRING_KEY.search(line):
            continue
        arg = _KEY_ARG.search(line)
        if arg is None:
            continue
        token = arg.group(1)
        if token.startswith("$"):
            where = literal_vars.get(token[1:].casefold())
            var: str | None = token[1:]
        else:
            where = number if _BYTES.match(line[arg.start(1):]) else None
            var = None
        if where is not None and where not in seen:
            seen.add(where)
            facts.append(MaterialMisuse(kind="secret-key", var=var, line=where, hardcoded=True))
    return facts


__all__ = ["POWERSHELL_LITERALS", "securestring_key_facts"]
