"""A key literal written straight into a key-taking constructor is a hardcoded key (HARDCODED_KEY), like the same
literal bound to a name.  Only the KEY argument is read: an IV / nonce literal in the IV position never becomes a key,
a variable or a value read at run time is not a literal, and a short placeholder is not a key."""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.cbom.misuse import detect_material_misuse
from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

FERNET = "q2xFzO9Tz1w2pTqgZ6vC3v8Ka3E1yJ0mT9hQ4dR7bXs="

POSITIVE = {
    ("python", 2): f'from cryptography.fernet import Fernet\nf = Fernet(b"{FERNET}")\n',
    ("python", 2, "aes"): 'from Crypto.Cipher import AES\nc = AES.new(b"0123456789abcdef", AES.MODE_GCM)\n',
    ("python", 3, "aesgcm"): "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\n"
                             "aead = AESGCM(b'0123456789abcdef0123456789abcdef')\n",
    ("python", 2, "hmac"): "import hmac, hashlib\nmac = hmac.new(b'super-secret-signing-key', msg, hashlib.sha256)\n",
    ("java", 3): 'import javax.crypto.spec.SecretKeySpec;\nclass K {\n'
                 '  SecretKeySpec k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");\n}\n',
    ("javascript", 2): 'const crypto = require("crypto");\n'
                       'const c = crypto.createCipheriv("aes-128-cbc", Buffer.from("0123456789abcdef"), iv);\n',
    ("javascript", 2, "plain"): 'const crypto = require("crypto");\n'
                                'const d = crypto.createDecipheriv("aes-256-gcm", "0123456789abcdef0123456789abcdef", iv);\n',
    ("go", 4): 'package p\n\nimport "crypto/aes"\nvar block, _ = aes.NewCipher([]byte("0123456789abcdef"))\n',
    ("csharp", 3): 'using System.Security.Cryptography;\nvar aes = Aes.Create();\n'
                   'aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef");\n',
}

NEGATIVE = {
    "python": [
        "from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_CBC, b'0123456789abcdef')\n",  # IV literal
        "from Crypto.Cipher import AES\nc = AES.new(os.environ['K'].encode(), AES.MODE_GCM, nonce=b'0123456789ab')\n",
        "from cryptography.fernet import Fernet\nf = Fernet(Fernet.generate_key())\n",
        "from cryptography.fernet import Fernet\nf = Fernet(b'')\n",
        "from Crypto.Cipher import AES\nc = AES.new(b'key', AES.MODE_GCM)\n",  # a short placeholder
    ],
    "java": [
        'class K {\n  IvParameterSpec iv = new IvParameterSpec("0123456789abcdef".getBytes());\n}\n',
        'class K {\n  SecretKeySpec k = new SecretKeySpec(keyBytes, "AES");\n}\n',
    ],
    "javascript": [
        'const c = crypto.createCipheriv("aes-128-cbc", key, Buffer.from("0123456789abcdef"));\n',  # IV literal
        'const c = crypto.createCipheriv("aes-128-cbc", process.env.KEY, iv);\n',
    ],
    "go": ['package p\nvar block, _ = aes.NewCipher(key)\nvar iv = []byte("0123456789abcdef")\n'],
    "csharp": ['var aes = Aes.Create();\naes.IV = Encoding.UTF8.GetBytes("0123456789abcdef");\n'],
}


@pytest.mark.parametrize("case", sorted(POSITIVE, key=str), ids=lambda c: "-".join(map(str, c)))
def test_inline_literal_key_is_a_hardcoded_key(case) -> None:
    lang, line = case[0], case[1]
    facts = [f for f in detect_material_misuse(POSITIVE[case], lang) if f.hardcoded and f.kind == "secret-key"]
    assert [f.line for f in facts] == [line], facts


@pytest.mark.parametrize(("lang", "src"), [(lang, src) for lang, srcs in NEGATIVE.items() for src in srcs])
def test_iv_variables_and_placeholders_are_not_keys(lang: str, src: str) -> None:
    keys = [f for f in detect_material_misuse(src, lang) if f.hardcoded and f.kind == "secret-key"]
    assert keys == []


def test_inline_key_reaches_the_export_as_hardcoded_key(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(POSITIVE[("python", 2)])
    (tmp_path / "K.java").write_text(POSITIVE[("java", 3)])
    run = normalize_crypto(scan_crypto(tmp_path), duration_of_scan=0.0)
    keyed = {(r["location"], r["line"]) for r in run["results"] if "HARDCODED_KEY" in (r.get("finding_codes") or [])}
    assert keyed == {("tool.py", 2), ("K.java", 3)}
    assert FERNET not in str(run)  # the key value itself is never stored
