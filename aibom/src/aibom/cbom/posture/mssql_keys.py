"""SQL Server column encryption: which algorithm protects the data ``EncryptByKey`` writes.

``EncryptByKey(Key_GUID('sk'), col)`` names a symmetric key, not an algorithm; the algorithm was fixed when the key
was created (``CREATE SYMMETRIC KEY sk WITH ALGORITHM = TRIPLE_DES ENCRYPTION BY CERTIFICATE c``), often in another
migration file. This pass reads every SQL file of the scan, resolves each key name to its declaration and inventories
the algorithm at the use site too, so a weak algorithm is flagged where the data is encrypted as well as where the
key is declared (the declaration line itself is the algorithm lane's ``TRIPLE_DES`` match). ``DecryptByKey`` uses
the key the session opened last (``OPEN SYMMETRIC KEY sk …``). A key declared outside the scanned files is still
inventoried at the use site, as a secret key whose algorithm is not known.

Algorithm names: https://learn.microsoft.com/en-us/sql/t-sql/statements/create-symmetric-key-transact-sql
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from aibom.cbom.rules import ALGORITHM_NORMALIZE, algo_info
from aibom.model.component import CryptoAssetComponent

_ALGORITHMS: dict[str, tuple[str, int | None]] = {
    "DES": ("des", None),
    "DESX": ("des", None),
    "TRIPLE_DES": ("3des", None),
    "TRIPLE_DES_3KEY": ("3des", None),
    "RC2": ("rc2", None),
    "RC4": ("rc4", None),
    "RC4_128": ("rc4", None),
    "AES_128": ("aes-128", 128),
    "AES_192": ("aes-192", 192),
    "AES_256": ("aes-256", 256),
}
# a key name, optionally [bracketed]
_DECLARE = re.compile(
    r"\bCREATE\s+SYMMETRIC\s+KEY\s+\[?([A-Za-z_#@][\w#@$]{0,127})\]?[^;]{0,600}?\bALGORITHM\s*=\s*(\w{1,32})",
    re.IGNORECASE,
)
_OPEN = re.compile(r"\bOPEN\s+SYMMETRIC\s+KEY\s+\[?([A-Za-z_#@][\w#@$]{0,127})\]?", re.IGNORECASE)
_ENCRYPT = re.compile(r"\bEncryptByKey\s*\(\s*Key_GUID\s*\(\s*N?'([^']{1,128})'\s*\)", re.IGNORECASE)
_DECRYPT = re.compile(r"\bDecryptByKey\s*\(", re.IGNORECASE)
_LINE_COMMENT = re.compile(r"--[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


@dataclass(frozen=True, slots=True)
class _Declared:
    algorithm: str
    path: str
    line: int


def _code(text: str) -> str:
    """Comments blanked, line numbers kept."""
    text = _BLOCK_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    return _LINE_COMMENT.sub(lambda m: " " * len(m.group(0)), text)


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def declared_keys(files: Mapping[str, str]) -> dict[str, _Declared]:
    """Key name (case-insensitive) -> declared algorithm, over every SQL file (first declaration wins)."""
    found: dict[str, _Declared] = {}
    for rel in sorted(files):
        code = _code(files[rel])
        for match in _DECLARE.finditer(code):
            name, algorithm = match.group(1).casefold(), match.group(2).upper()
            if algorithm in _ALGORITHMS and name not in found:
                found[name] = _Declared(algorithm, rel, _line_at(code, match.start(2)))
    return found


def _uses(text: str) -> list[tuple[str, int]]:
    """(key name, line) for each EncryptByKey / DecryptByKey call, in file order."""
    code = _code(text)
    events: list[tuple[int, str, str]] = []
    events += [(m.start(), "open", m.group(1)) for m in _OPEN.finditer(code)]
    events += [(m.start(), "use", m.group(1)) for m in _ENCRYPT.finditer(code)]
    events += [(m.start(), "decrypt", "") for m in _DECRYPT.finditer(code)]
    opened: str | None = None
    uses: list[tuple[str, int]] = []
    for offset, kind, name in sorted(events):
        if kind == "open":
            opened = name
        elif kind == "use":
            uses.append((name, _line_at(code, offset)))
        elif opened is not None:
            uses.append((opened, _line_at(code, offset)))
    return uses


def key_use_assets(files: Mapping[str, str]) -> tuple[CryptoAssetComponent, ...]:
    """One asset per (file, key) used by EncryptByKey / DecryptByKey, at its first use line."""
    declared = declared_keys(files)
    assets: list[CryptoAssetComponent] = []
    seen: set[str] = set()
    for rel in sorted(files):
        for name, line in _uses(files[rel]):
            decl = declared.get(name.casefold())
            if decl is None:
                ref = f"crypto-material-secret-key-mssql-{_slug(name)}-{_slug(rel)}"
                if ref in seen:
                    continue
                seen.add(ref)
                assets.append(
                    CryptoAssetComponent(
                        bom_ref=ref,
                        name=f"secret-key ({name}, {rel.rsplit('/', 1)[-1]})",
                        properties={
                            "crypto:assetType": "related-crypto-material",
                            "crypto:materialKind": "secret-key",
                            "discovery:source": f"{rel}:{line}",
                        },
                    )
                )
                continue
            key, size = _ALGORITHMS[decl.algorithm]
            display = ALGORITHM_NORMALIZE.get(key, key.upper())
            ref = f"crypto-algo-{_slug(display)}-{_slug(rel)}-mssql-{_slug(name)}"
            if ref in seen:
                continue
            seen.add(ref)
            info = algo_info(key) or {}
            props = {
                "crypto:assetType": "algorithm",
                "crypto:primitive": str(info.get("primitive") or "block-cipher"),
                "crypto:strength": str(info.get("strength", "unknown")),
                "crypto:quantumVulnerable": str(bool(info.get("quantum_vulnerable", False))).lower(),
                "discovery:source": f"{rel}:{line}",
            }
            if size:
                props["crypto:keySize"] = str(size)
            assets.append(CryptoAssetComponent(bom_ref=ref, name=display, properties=props))
    return tuple(assets)


__all__ = ["declared_keys", "key_use_assets"]
