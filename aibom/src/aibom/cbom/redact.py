"""Code windows for CBOM findings, with secrets removed before they leave the scan worker.

A finding row may carry a few lines of the source around the occurrence so the remediation panel can show the
vulnerable code and a concrete fix. Those lines can hold the very secret the finding is about (a hard-coded
key, an IV, a password next to a cipher call), so this module masks them here, in the worker, before the row is
returned, stored in the task backend, copied to Mongo or printed in a PDF:

* PEM blocks (also partial ones) and long base64 runs;
* well-known token formats (AWS keys, GitHub/Slack/Google tokens, JWTs, private-key headers);
* high-entropy strings of 20+ characters;
* every string/bytes literal of 6+ characters on a line that names a key/secret/password/token/IV/nonce/salt or
  builds a cipher/key object - unless the literal is an algorithm or transformation name
  ("AES/GCM/NoPadding", "sha256", "des-ede3-cbc"), which the fix needs and is not secret;
* on rows that ARE secret material (hard-coded key, static IV) every literal in the window.

Bidirectional and zero-width characters are shown as visible escapes (Trojan Source). Windows are capped in
lines and bytes; minified or generated files get no window.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

WINDOW = 3                 # lines before and after the occurrence
MAX_LINE = 240             # characters kept per line (centred on the match for long lines)
MAX_SNIPPET = 2048         # bytes per snippet
SCAN_BUDGET = 1_500_000    # bytes of snippets per scan (the task result must stay far below 16 MB)

_ALGO_WORDS = re.compile(
    r"(aes|des|rsa|dsa|ecdsa|ecdh|ec|sha|md[245]|hmac|pbkdf|bcrypt|scrypt|argon|gcm|cbc|ecb|ctr|cfb|ofb|ccm|"
    r"padding|pkcs|oaep|pss|tls|ssl|ssh|rc[24]|blowfish|chacha|poly1305|x25519|ed25519|curve|secp|prime256|"
    r"brainpool|kyber|mlkem|ml-kem|dilithium|mldsa|ml-dsa|sphincs|falcon|camellia|seed|sm[234]|gost|idea|"
    r"whirlpool|ripemd|blake|keccak|sha3|crc|nopadding|with|none|jwt|hs256|rs256|es256|ps256)", re.I)
_ALGO_LITERAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/_\-.+]{0,48}$")
_SECRETY = re.compile(
    r"(key|secret|passw|pwd|token|credential|private|\biv\b|_iv\b|\biv_|nonce|salt|seed|apikey|api_key|auth|"
    r"bearer|cipher|aes\.new|des\.new|createcipher|secretkeyspec|ivparameterspec|gcmparameterspec|\.init\(|"
    r"newcipher|getinstance)", re.I)
# a backslash is only ever an escape pair here, so a run of backslashes has one parse (no exponential backtracking)
_LITERAL = re.compile(r"""(?P<prefix>\b[bBrRuUfF]{0,2})(?P<q>["'`])(?P<body>(?:\\.|(?!(?P=q))[^\\]){1,4096}?)(?P=q)""")
_TOKENS = [
    re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}"),
]
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_ENTROPY_CAND = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]+-----")
_INVISIBLE = re.compile("[‪-‮⁦-⁩​-‏  ﻿­]")
_GENERATED = re.compile(r"(\.min\.(js|css)$|_pb2\.py$|\.pb\.go$|\.g\.dart$|(^|/)(third_party|Pods|vendor|"
                        r"node_modules|dist|build)/|\.bundle\.js$|-bundle\.js$)", re.I)


def _entropy(text: str) -> float:
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _mask(n: int) -> str:
    return f"<redacted:{n}>"


_ALGO_VOCAB = frozenset("""
aes des ede tdes triple rsa dsa ecdsa ecdh ecdhe dhe ec dh sha md hmac pbkdf kdf bcrypt scrypt argon id gcm cbc ecb ctr
cfb ofb ccm xts siv padding pkcs oaep pss mgf tls ssl ssh rc arc arcfour four blowfish chacha poly x ed curve secp sect
prime brainpool p r v k t kyber ml kem dilithium sphincs falcon slh camellia seed sm gost idea whirlpool ripemd blake keccak
shake crc no with and none jwt hs rs es ps aead hkdf nist aesgcm aescbc cast null anon export rsassa rsaes v1 cmac gmac
salsa xchacha xsalsa nacl box sign hash digest cipher shared key mlkem mldsa slhdsa fndsa hqc""".split())
_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


def _is_algorithm_literal(body: str) -> bool:
    """True for an algorithm / transformation name ("AES/GCM/NoPadding", "PBKDF2WithHmacSHA256", "des-ede3-cbc",
    "secp256r1"): every alphabetic word in it is crypto vocabulary. A key such as "supersecretkey16" is not."""
    if not _ALGO_LITERAL.match(body):
        return False
    words = [w.lower() for w in _TOKEN.findall(body) if not w.isdigit()]
    return bool(words) and all(w in _ALGO_VOCAB for w in words)


def redact_line(line: str, strict: bool = False) -> tuple[str, int]:
    """Masked line and the number of masks applied. ``strict`` masks every literal of 4+ characters."""
    hits = 0

    def lit(m: re.Match) -> str:
        nonlocal hits
        body = m.group("body")
        limit = 4 if strict else 6
        if len(body) < limit or (not strict and _is_algorithm_literal(body)):
            return m.group(0)
        hits += 1
        return f"{m.group('prefix')}{m.group('q')}{_mask(len(body))}{m.group('q')}"

    out = line
    if strict or _SECRETY.search(line):
        out = _LITERAL.sub(lit, out)
        if strict:  # hex byte arrays / numeric key tables
            out, k = re.subn(r"(0x[0-9a-fA-F]{2}\s*,\s*){8,}0x[0-9a-fA-F]{2}", lambda m: _mask(len(m.group(0))), out)
            hits += k
    for rx in _TOKENS:
        out, k = rx.subn(lambda m: _mask(len(m.group(0))), out)
        hits += k

    def ent(m: re.Match) -> str:
        nonlocal hits
        tok = m.group(0)
        if "redacted" in tok or _is_algorithm_literal(tok) or not re.search(r"\d", tok):
            return tok
        if _B64_RUN.fullmatch(tok) or _entropy(tok) >= 3.6:
            hits += 1
            return _mask(len(tok))
        return tok

    out = _ENTROPY_CAND.sub(ent, out)
    out = _INVISIBLE.sub(lambda m: f"\\u{ord(m.group(0)):04x}", out)
    return out, hits


def _clip(line: str, needle_col: int | None) -> str:
    end = "\r" if line.endswith("\r") else ""
    body = line[:-1] if end else line
    if len(body) <= MAX_LINE:
        return line
    col = needle_col if needle_col is not None else 0
    start = max(0, col - MAX_LINE // 2)
    return ("…" if start else "") + body[start:start + MAX_LINE] + "…" + end


def code_window(text: str, line_no: int, *, strict: bool = False, needle: str | None = None,
                window: int = WINDOW) -> dict | None:
    """Redacted window around 1-based ``line_no``: ``{snippet, snippet_start, redactions}`` or None."""
    lines = text.split("\n")
    if len(lines) > 1 and lines[-1] == "":
        lines.pop()  # the final newline does not start another line
    if not 1 <= line_no <= len(lines):
        return None
    lo, hi = max(1, line_no - window), min(len(lines), line_no + window)
    col = None
    if needle:
        target = lines[line_no - 1].lower()
        pos = target.find(needle.lower())
        col = pos if pos >= 0 else None
    out_lines, total = [], 0
    pem = False
    for n in range(lo, hi + 1):
        raw = lines[n - 1]
        if _PEM_BEGIN.search(raw):
            pem = True
            out_lines.append(_PEM_BEGIN.search(raw).group(0) + "  <redacted PEM body>")
            total += 1
            if _PEM_END.search(raw):
                pem = False
            continue
        if pem:
            if _PEM_END.search(raw):
                pem = False
                out_lines.append(_PEM_END.search(raw).group(0))
            continue
        masked, k = redact_line(_clip(raw, col if n == line_no else None), strict=strict)
        total += k
        out_lines.append(masked)
    snippet = "\n".join(out_lines)
    if len(snippet.encode()) > MAX_SNIPPET:
        snippet = snippet.encode()[:MAX_SNIPPET].decode(errors="ignore") + "\n…"
    return {"snippet": snippet, "snippet_start": lo, "redactions": total}


def is_generated(rel: str, text: str) -> bool:
    if _GENERATED.search(rel):
        return True
    lines = text.split("\n")
    longest = max((len(x) for x in lines[:200]), default=0)
    return longest > 2000 or (len(text) > 50_000 and len(lines) < 20)


def attach_snippets(rows: list[dict], root: Path) -> dict[str, int]:
    """Fill ``snippet`` / ``snippet_start`` on code-scan rows that know their file and line. Reads only files that
    resolve inside ``root``; never copies private-key material; stops at the per-scan budget."""
    from aibom.cbom.occurrences import read_text, safe_file

    stats = {"snippets": 0, "skipped_generated": 0, "skipped_material": 0, "skipped_budget": 0, "redactions": 0}
    cache: dict[str, str | None] = {}
    used = 0
    for row in rows:
        line = row.get("line")
        rel = str(row.get("location") or "")
        rel = re.sub(r":\d+$", "", rel)
        if not line or not rel:
            continue
        codes = set(row.get("finding_codes") or [])
        kind = str(row.get("material_kind") or "").lower()
        in_source = bool(row.get("language")) and row.get("language") not in ("pem", "text", "unknown")
        if row.get("asset_type") in ("certificate",) or kind in ("private-key", "private_key", "key-pair",
                                                                  "keystore", "pkcs12") or (
                kind == "secret-key" and not in_source):
            # key files are never copied; a key literal inside source code gets a strictly redacted window below
            row["snippet_note"] = "Key or certificate material is not copied into findings."
            stats["skipped_material"] += 1
            continue
        if rel not in cache:
            path = safe_file(root, rel)
            cache[rel] = read_text(path) if path else None
        text = cache[rel]
        if text is None:
            continue
        if is_generated(rel, text):
            row["snippet_note"] = "Generated or minified file: no code window."
            stats["skipped_generated"] += 1
            continue
        strict = bool(codes & {"HARDCODED_KEY", "STATIC_IV", "REUSED_NONCE"}) or kind in ("key", "secret-key", "iv", "nonce",
                                                                                              "salt", "seed")
        needle = re.split(r"[\s(@-]", str(row.get("title") or ""), maxsplit=1)[0] or None
        win = code_window(text, int(line), strict=strict, needle=needle)
        if not win:
            continue
        size = len(win["snippet"].encode())
        if used + size > SCAN_BUDGET:
            row["snippet_note"] = "Snippet budget for this scan reached."
            stats["skipped_budget"] += 1
            continue
        used += size
        row["snippet"] = win["snippet"]
        row["snippet_start"] = win["snippet_start"]
        row["snippet_redactions"] = win["redactions"]
        stats["snippets"] += 1
        stats["redactions"] += win["redactions"]
    return stats


__all__ = ["attach_snippets", "code_window", "redact_line", "is_generated", "SCAN_BUDGET"]


def _ci_canary() -> None:
    """CI canary for PR #16 (never merged): one new ruff finding, F841."""
    unused = 1
