"""CB-28: line detectors for .NET, C (OpenSSL) and Terraform crypto misuse.

Each detector reads one file's text and returns :class:`LangFact` rows (line, what,
detail). The scanner (:mod:`aibom.cbom.scanners.lang_misuse_scan`) turns them into
crypto assets that the existing predicates already flag (``weak_finding``,
``weak_padding_finding``, ``cipher_suite_findings``, ``material_misuse_findings``), so
each finding lands on the line that carries it:

* .NET (C#, VB.NET, PowerShell):
  - ``SecurityProtocolType`` / ``SslProtocols`` ``Ssl2``, ``Ssl3``, ``Tls``, ``Tls11``
    set or passed (not compared or mapped): a TLS protocol asset (``WEAK_PROTOCOL``);
  - ``RSAEncryptionPadding.Pkcs1`` (and ``rsa.Encrypt(data, false)``): RSA encryption
    with PKCS#1 v1.5 padding (``WEAK_PADDING``);
  - ``Rfc2898DeriveBytes`` with fewer than 100,000 iterations, or the two-argument
    constructors whose default is 1,000 (Microsoft rule CA5387):
    ``WEAK_KDF_ITERATIONS``;
  - a key set from ``Encoding.*.GetBytes("<16+ characters>")``: ``HARDCODED_KEY``;
  - ``.IV = new byte[n]`` (n zero bytes) or a literal: ``STATIC_IV``;
* C / C++ (OpenSSL):
  - ``SSL_CTX_set_cipher_list`` / ``SSL_set_cipher_list`` with a literal list: what it
    enables, as a TLS cipher-suite bag on that line (``WEAK_CIPHER_SUITE`` when it
    names RC4, 3DES, NULL, EXPORT ... suites);
  - RSA public exponent 3 (``BN_set_word(e, 3)``, ``RSA_3``,
    ``RSA_generate_key(bits, 3, ...)``) in a file that generates RSA keys
    (``WEAK_RSA_EXPONENT``; FIPS 186-5 requires 2^16 < e < 2^256);
  - ``unsigned char key[16] = "..."``, a key- or IV-named byte array with a literal
    value: ``HARDCODED_KEY`` / ``STATIC_IV``;
* Terraform: ``resource "tls_private_key"`` with ``algorithm = "RSA"`` and
  ``rsa_bits = <n>``: an RSA-<n> algorithm asset on the ``rsa_bits`` line
  (``WEAK_KEY_SIZE`` / ``WEAK_ALGORITHM`` below 2048).

Comments are blanked before matching, so a commented-out call is not a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DOTNET_LANGS = frozenset({"csharp", "vbnet", "powershell"})
C_LANGS = frozenset({"c", "cpp"})


@dataclass(frozen=True)
class LangFact:
    line: int
    what: str  # protocol, cipher_list, rsa_padding, material, rsa_exponent, rsa_key
    detail: str = ""  # protocol label / cipher list / material kind / exponent
    var: str | None = None
    iterations: int | None = None
    key_size: int | None = None
    static_iv: bool = False
    api: str = ""


# ----------------------------------------------------------------------------- comments
_BLOCK = re.compile(r"/\*.*?\*/", re.S)
_LINE_C = re.compile(r"(?<![:\"'])//[^\n]*")
_LINE_VB = re.compile(r"(?m)^((?:[^\"'\n]|\"[^\"\n]*\")*)'[^\n]*$")
_LINE_PS = re.compile(r"(?m)(?:^|(?<=\s))#[^\n]*")


def _blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def _code(text: str, lang: str) -> list[str]:
    """Lines with comments blanked (line numbers kept)."""
    if lang == "vbnet":
        code = _LINE_VB.sub(
            lambda m: m.group(1) + " " * (len(m.group(0)) - len(m.group(1))), text
        )
    elif lang == "powershell":
        code = _LINE_PS.sub(_blank, text)
    else:
        code = _LINE_C.sub(_blank, _BLOCK.sub(_blank, text))
    return code.split("\n")


def _args(line: str, open_paren: int) -> list[str] | None:
    """Top-level arguments of the call whose ``(`` is at ``open_paren`` (None if it"
      " does not close on the line)."""
    depth, start, out = 0, open_paren + 1, []
    in_str = None
    for i in range(open_paren, len(line)):
        ch = line[i]
        if in_str:
            if ch == in_str and line[i - 1] != "\\":
                in_str = None
            continue
        if ch in "\"'":
            in_str = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                out.append(line[start:i].strip())
                return [a for a in out if a] if out != [""] else []
        elif ch == "," and depth == 1:
            out.append(line[start:i].strip())
            start = i + 1
    return None


def _int(text: str) -> int | None:
    t = text.strip().replace("_", "")
    return int(t) if re.fullmatch(r"\d{1,9}", t) else None


# ----------------------------------------------------------------------------- .NET
_DOTNET_PROTOCOL = re.compile(
    r"\b(?:SecurityProtocolType|SslProtocols)\s*\.\s*(Ssl2|Ssl3|Tls11|Tls12|Tls13|Tls)\b"
)
_DOTNET_LABEL = {
    "Ssl2": ("SSLv2", True),
    "Ssl3": ("SSLv3", True),
    "Tls": ("1.0", True),
    "Tls11": ("1.1", True),
    "Tls12": ("1.2", False),
    "Tls13": ("1.3", False),
}
# a protocol that is configured: assigned (``SecurityProtocol = ...``, ``|=``), or
# passed as an argument
# (``AuthenticateAsClient(host, certs, SslProtocols.Tls, false)``,
# ``enabledSslProtocols: SslProtocols.Tls``)
_DOTNET_SETS_PROTOCOL = re.compile(
    r"(?:(?<![=!<>])=(?!=)|\|=|\(|,|:)\s*(?:\(?\s*(?:System\.Net\.|System\.Security\.Authentication\.)?"
    r"(?:SecurityProtocolType|SslProtocols)\s*\.\s*\w+\s*\|?\s*)+"
)
_DOTNET_PKCS1 = re.compile(r"\bRSAEncryptionPadding\s*\.\s*Pkcs1\b")
_DOTNET_ENCRYPT_FALSE = re.compile(r"\.\s*(?:Encrypt|Decrypt)\s*\([^;]*,\s*false\s*\)")
_RFC2898 = re.compile(
    r"\bnew\s+Rfc2898DeriveBytes\s*(\()|\bRfc2898DeriveBytes\s*\.\s*Pbkdf2\s*(\()"
)
_DOTNET_KEY_BYTES = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:System\.Text\.)?Encoding\s*\.\s*\w+\s*\.\s*GetBytes\s*\(\s*"
    r"\"(?P<val>[^\"\\]{16,})\"\s*\)"
)
_DOTNET_IV = re.compile(
    r"\.\s*IV\s*=\s*(?:new\s+byte\s*\[\s*\w*\s*\]\s*(?:\{[^}]*\})?|(?:System\.Text\.)?Encoding\s*\.\s*\w+\s*\.\s*"
    r"GetBytes\s*\(\s*\"[^\"\\]*\"\s*\)|Convert\s*\.\s*From(?:Base64|Hex)String\s*\(\s*\"[^\"\\]*\"\s*\))\s*;"
)
_KDF_MIN_DOTNET = 100_000  # Microsoft CA5387
_KDF_DEFAULT_DOTNET = 1_000  # the constructors without an iteration count


def _key_name(var: str) -> bool:
    from aibom.cbom.misuse import _strict_key_name

    return _strict_key_name(var) or _strict_key_name(
        re.sub(r"(?<=[a-z])(?=[A-Z])", "_", var)
    )


def dotnet_facts(text: str, lang: str) -> list[LangFact]:
    out: list[LangFact] = []
    has_rsa = "RSA" in text
    for no, line in enumerate(_code(text, lang), start=1):
        if _DOTNET_SETS_PROTOCOL.search(
            line
        ):  # set, not compared or mapped (``case``, ``==``, ``HasFlag``)
            for m in _DOTNET_PROTOCOL.finditer(line):
                label, weak = _DOTNET_LABEL[m.group(1)]
                if weak:
                    out.append(
                        LangFact(no, "protocol", label, api=m.group(0).replace(" ", ""))
                    )
        if _DOTNET_PKCS1.search(line) or (
            has_rsa and _DOTNET_ENCRYPT_FALSE.search(line)
        ):
            out.append(
                LangFact(
                    no, "rsa_padding", "pkcs1v15", api="RSAEncryptionPadding.Pkcs1"
                )
            )
        for m in _RFC2898.finditer(line):
            paren = m.start(1) if m.group(1) else m.start(2)
            args = _args(line, paren)
            if args is None:
                continue
            static = m.group(2) is not None
            if (
                static
            ):  # Pbkdf2(password, salt, iterations, hashAlgorithm, outputLength)
                count = _int(args[2]) if len(args) >= 3 else None
            elif (
                len(args) == 2
            ):  # (password, salt) / (password, saltSize): the default count
                count = _KDF_DEFAULT_DOTNET
            else:
                count = _int(args[2]) if len(args) >= 3 else None
            if count is not None and count < _KDF_MIN_DOTNET:
                out.append(
                    LangFact(
                        no,
                        "material",
                        "other",
                        iterations=count,
                        api="Rfc2898DeriveBytes.Pbkdf2"
                        if static
                        else "Rfc2898DeriveBytes",
                    )
                )
        key = _DOTNET_KEY_BYTES.search(line)
        if key and _key_name(key.group("var")):
            out.append(
                LangFact(
                    no,
                    "material",
                    "secret-key",
                    var=key.group("var"),
                    api="Encoding.GetBytes",
                )
            )
        if _DOTNET_IV.search(line):
            out.append(
                LangFact(
                    no,
                    "material",
                    "initialization-vector",
                    var="IV",
                    static_iv=True,
                    api="SymmetricAlgorithm.IV",
                )
            )
    return out


# ----------------------------------------------------------------------------- C /
# OpenSSL
_CIPHER_LIST = re.compile(
    r"\bSSL(?:_CTX)?_set_cipher_list\s*\(\s*[^,()]+,\s*\"(?P<list>[^\"\\]+)\"\s*\)"
)
_RSA_GEN = re.compile(
    r"\bRSA_generate_key(?:_ex)?\s*\(|\bEVP_PKEY_CTX_set_rsa_keygen_pubexp\b|\bRSA_new\s*\("
)
_E3 = re.compile(
    r"\bBN_set_word\s*\(\s*\w+\s*,\s*(?:3|RSA_3)\s*\)|\bRSA_generate_key\s*\(\s*[^,()]+,\s*(?:3|RSA_3)\b"
    r"|\bRSA_3\b"
)
_C_ARRAY = re.compile(
    r"^\s*(?:static\s+)?(?:const\s+)?(?:unsigned\s+char|uint8_t|u_char|u8|char|BYTE|byte)\s+"
    r"(?P<var>[A-Za-z_]\w*)\s*\[\s*\w*\s*\]\s*=\s*(?P<val>\"[^\"\\]{8,}\"|\{\s*(?:0[xX][0-9a-fA-F]{1,2}|\d{1,3})"
    r"(?:\s*,\s*(?:0[xX][0-9a-fA-F]{1,2}|\d{1,3})){7,}\s*,?\s*\})\s*;"
)


def c_facts(text: str, lang: str) -> list[LangFact]:
    from aibom.cbom.misuse import _CRYPTO_CTX_RE, _material_kind

    out: list[LangFact] = []
    lines = _code(text, lang)
    rsa_gen = any(_RSA_GEN.search(line) for line in lines)
    crypto_ctx = bool(_CRYPTO_CTX_RE.search(text))
    for no, line in enumerate(lines, start=1):
        m = _CIPHER_LIST.search(line)
        if m:
            # what the list enables: ``!RC4`` / ``-3DES`` remove, ``+X`` only moves,
            # ``@STRENGTH`` sorts
            enabled = [
                t
                for t in re.split(r"[:,\s]+", m.group("list"))
                if t and t[0] not in "!-+@"
            ]
            if enabled:
                out.append(
                    LangFact(
                        no,
                        "cipher_list",
                        ":".join(enabled),
                        api="SSL_CTX_set_cipher_list",
                    )
                )
        if rsa_gen and _E3.search(line):
            out.append(
                LangFact(
                    no,
                    "rsa_exponent",
                    "3",
                    api="BN_set_word" if "BN_set_word" in line else "RSA_3",
                )
            )
        m = _C_ARRAY.match(line)
        if m and crypto_ctx:
            kind = _material_kind(m.group("var"))
            if kind == "secret-key" and _key_name(m.group("var")):
                out.append(
                    LangFact(
                        no,
                        "material",
                        "secret-key",
                        var=m.group("var"),
                        api="byte array",
                    )
                )
            elif kind in ("initialization-vector", "nonce"):
                out.append(
                    LangFact(
                        no,
                        "material",
                        kind,
                        var=m.group("var"),
                        static_iv=True,
                        api="byte array",
                    )
                )
    return out


# -----------------------------------------------------------------------------
# Terraform
_TLS_PRIVATE_KEY = re.compile(
    r"(?m)^\s*resource\s+\"tls_private_key\"\s+\"[^\"]+\"\s*\{"
)
_TF_ATTR = re.compile(r"(?m)^\s*(algorithm|rsa_bits)\s*=\s*\"?([A-Za-z0-9_]+)\"?")


def terraform_facts(text: str) -> list[LangFact]:
    """``tls_private_key`` RSA keys with a literal ``rsa_bits`` (the block's own"
      " attributes, not nested ones)."""
    out: list[LangFact] = []
    for m in _TLS_PRIVATE_KEY.finditer(text):
        depth, end = 0, len(text)
        for i in range(m.end() - 1, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        body = text[m.end() : end]
        base = text.count("\n", 0, m.end()) + 1
        attrs = {}
        for a in _TF_ATTR.finditer(body):
            attrs[a.group(1)] = (a.group(2), base + body.count("\n", 0, a.start(2)))
        algorithm = attrs.get("algorithm", ("", 0))[0].upper()
        bits = attrs.get("rsa_bits")
        if algorithm == "RSA" and bits and _int(bits[0]):
            out.append(
                LangFact(
                    bits[1],
                    "rsa_key",
                    "RSA",
                    key_size=_int(bits[0]),
                    api="tls_private_key",
                )
            )
    return out


__all__ = [
    "C_LANGS",
    "DOTNET_LANGS",
    "LangFact",
    "c_facts",
    "dotnet_facts",
    "terraform_facts",
]
