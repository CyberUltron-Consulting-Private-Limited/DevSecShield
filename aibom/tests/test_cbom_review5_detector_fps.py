"""Round-5 review: code-scan detector false positives (reviewer 1, corpora fp1-fp7) and their negative twins.

Each test turns one reviewer corpus into a product-path check (``scan_crypto(level=4)`` + ``normalize_crypto``, the
rows and impacts the UI shows) and keeps a twin that must still be reported, so a fix cannot simply switch a lane
off.
"""

from __future__ import annotations

import json
from pathlib import Path

from aibom.cbom.custom_crypto import detect_custom_constructions, detect_custom_crypto
from aibom.cbom.gate import failing_flags
from aibom.cbom.misuse import detect_material_misuse
from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

_HEX = "8d1f6e3c2b9a4f7e0d5c6b1a2f3e4d5c"


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def _scan(tmp_path: Path, files: dict[str, str]):
    _write(tmp_path, files)
    result = scan_crypto(tmp_path, level=4, scan_history=False)
    rows = normalize_crypto(result, duration_of_scan=0.0)["results"]
    return rows, result


def _found(rows: list[dict]) -> dict[tuple[str, str], tuple[str | None, list[str]]]:
    """(file, title) -> (impact, finding codes) for every row."""
    return {(r["location"], r["title"]): (r["impact"], sorted(r.get("finding_codes") or [])) for r in rows}


def _weak(rows: list[dict]) -> set[tuple[str, str]]:
    """(file, title) of every row with a finding other than QUANTUM_VULNERABLE."""
    return {k for k, (_, codes) in _found(rows).items() if set(codes) - {"QUANTUM_VULNERABLE"}}


# --------------------------------------------------------------------------- #
# 1. RSA-OAEP over SHA-1 is encryption, not a signature over a SHA-1 digest (fp2, fp7)
# --------------------------------------------------------------------------- #

_OAEP_PY = ("from cryptography.hazmat.primitives import hashes\n"
            "from cryptography.hazmat.primitives.asymmetric import padding\n\n\n"
            "def wrap(public_key, dek: bytes) -> bytes:\n    return public_key.encrypt(\n        dek,\n"
            "        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None),\n"
            "    )\n")
_OAEP_WEBCRYPTO = ("export async function wrapForImport(spkiDer, dataKey) {\n"
                   '  const pub = await crypto.subtle.importKey("spki", spkiDer, { name: "RSA-OAEP", hash: "SHA-1" },'
                   ' false, ["encrypt"]);\n'
                   '  return crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, dataKey);\n}\n')
_OAEP_NODE = ("const crypto = require('crypto');\n\nfunction wrap(publicKeyPem, dek) {\n"
              "  return crypto.publicEncrypt({ key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, "
              "oaepHash: 'sha1' }, dek);\n}\n")


def test_rsa_oaep_with_sha1_is_not_a_sha1_signature(tmp_path: Path) -> None:
    rows, _ = _scan(tmp_path, {"oaep_py.py": _OAEP_PY, "wrap.js": _OAEP_WEBCRYPTO, "oaep.js": _OAEP_NODE})
    found = _found(rows)
    assert _weak(rows) == set(), sorted(_weak(rows))
    for path in ("oaep_py.py", "wrap.js", "oaep.js"):
        assert found[(path, "RSA")] == ("Medium", ["QUANTUM_VULNERABLE"]), path
    # the OAEP hash is still inventoried, as a parameter of the RSA-OAEP row
    assert found[("oaep_py.py", "SHA-1")] == (None, [])
    assert found[("wrap.js", "SHA-1")] == (None, [])


def test_signatures_over_sha1_keep_their_finding(tmp_path: Path) -> None:
    rows, _ = _scan(tmp_path, {
        "Sig.java": "import java.security.Signature;\nclass Sig {\n"
                    '  Object s() throws Exception { return Signature.getInstance("SHA1withRSA"); }\n}\n',
        "pss.py": "from cryptography.hazmat.primitives import hashes\n"
                  "from cryptography.hazmat.primitives.asymmetric import padding\n"
                  "def sign(key, data):\n"
                  "    return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=20), "
                  "hashes.SHA1())\n",
        "pss.js": "export async function k() {\n"
                  '  return crypto.subtle.importKey("jwk", j, { name: "RSA-PSS", hash: "SHA-1" }, false, ["sign"]);\n'
                  "}\n",
        # one file: OAEP encryption first, then a SHA-1 signature: the signature still carries the finding
        "Mixed.java": "import javax.crypto.Cipher;\nimport java.security.Signature;\nclass Mixed {\n"
                      "  Object c() throws Exception {\n"
                      '    return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");\n  }\n'
                      '  Object s() throws Exception { return Signature.getInstance("SHA1withRSA"); }\n}\n',
    })
    found = _found(rows)
    for path in ("Sig.java", "pss.py", "pss.js", "Mixed.java"):
        assert "WEAK_ALGORITHM" in found[(path, "RSA")][1], path


# --------------------------------------------------------------------------- #
# 2. Inferred Java algorithms (fp3 svc): a guess is inventory, never a High finding
# --------------------------------------------------------------------------- #

_SVC = {
    "svc/src/main/java/com/acme/PaymentService.java":
        "package com.acme;\n\nimport javax.crypto.SecretKey;\n\npublic class PaymentService {\n"
        "    public byte[] seal(SecretKey key, byte[] iv, byte[] card) throws Exception {\n"
        '        return CryptoUtil.encrypt("AES/GCM/NoPadding", key, iv, card);\n    }\n}\n',
    "svc/src/main/java/com/acme/LegacyImport.java":
        "package com.acme;\n\nimport javax.crypto.Cipher;\nimport javax.crypto.SecretKey;\n"
        "import org.springframework.beans.factory.annotation.Value;\n\npublic class LegacyImport {\n"
        '    @Value("${legacy.import.cipher}")\n    private String cipherName;\n\n'
        "    public byte[] decrypt(SecretKey k, byte[] data) throws Exception {\n"
        "        Cipher c = Cipher.getInstance(cipherName);\n        c.init(Cipher.DECRYPT_MODE, k);\n"
        "        return c.doFinal(data);\n    }\n}\n",
    "svc/src/main/java/com/acme/CryptoUtil.java":
        "package com.acme;\n\nimport javax.crypto.Cipher;\nimport javax.crypto.SecretKey;\n"
        "import javax.crypto.spec.GCMParameterSpec;\n\npublic final class CryptoUtil {\n"
        "    public static byte[] encrypt(String transformation, SecretKey key, byte[] iv, byte[] data) "
        "throws Exception {\n        Cipher c = Cipher.getInstance(transformation);\n"
        "        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));\n        return c.doFinal(data);\n"
        "    }\n}\n",
    "svc/src/main/java/com/acme/Encryptor.java":
        "package com.acme;\n\nimport javax.crypto.Cipher;\nimport javax.crypto.spec.SecretKeySpec;\n\n"
        'public class Encryptor {\n    private String algorithm = "DES";\n\n'
        "    public void setAlgorithm(String algorithm) {\n        this.algorithm = algorithm;\n    }\n\n"
        "    public byte[] encrypt(byte[] key, byte[] data) throws Exception {\n"
        "        SecretKeySpec spec = new SecretKeySpec(key, algorithm);\n"
        '        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n        c.init(Cipher.ENCRYPT_MODE, spec);\n'
        "        return c.doFinal(data);\n    }\n}\n",
    "svc/src/main/resources/beans.xml":
        '<beans>\n  <bean id="encryptor" class="com.acme.Encryptor">\n'
        '    <property name="algorithm" value="AES"/>\n  </bean>\n</beans>\n',
    "svc/src/main/resources/application.properties":
        "# Only the nightly import of files from the 2009 mainframe uses this; see LegacyImport.java\n"
        "legacy.import.cipher=DESede/ECB/PKCS5Padding\n",
}


def test_inferred_java_algorithms_raise_no_high_finding(tmp_path: Path) -> None:
    rows, _ = _scan(tmp_path, _SVC)
    found = _found(rows)
    base = "svc/src/main/java/com/acme/"
    # the class that reads the configured transformation reports it (resolved, not inferred) ...
    assert "WEAK_ALGORITHM" in found[(base + "LegacyImport.java", "3DES-ECB")][1]
    # ... and a generic helper whose transformation comes from its caller does not inherit it
    assert not [k for k in found if k[0] == base + "CryptoUtil.java"]
    # a key specification whose algorithm is only a field default is the key of the file's AES-GCM cipher
    assert not [k for k in found if k[0] == base + "Encryptor.java" and k[1].startswith("DES")]
    assert found[(base + "Encryptor.java", "AES-GCM")] == (None, [])
    assert _weak(rows) == {(base + "LegacyImport.java", "3DES-ECB")}


def test_an_inferred_algorithm_is_inventory_marked_for_review(tmp_path: Path) -> None:
    rows, result = _scan(tmp_path, {
        # nothing references app.cipher: the module's one configured transformation is the guess for the parameter
        "pay/src/main/java/eva/FromProps3.java":
            "package eva;\nimport javax.crypto.Cipher;\npublic class FromProps3 {\n"
            "  public Cipher c(String fromProps) throws Exception {\n    return Cipher.getInstance(fromProps);\n"
            "  }\n}\n",
        "pay/src/main/resources/application.properties": "app.cipher=AES/ECB/PKCS5Padding\n",
        # a field default only a setter overrides, and no cipher in the file
        "B.java": "import javax.crypto.spec.SecretKeySpec;\nclass B {\n  protected String alg = \"DES\";\n"
                  "  void setAlg(String alg) {\n    this.alg = alg;\n  }\n"
                  "  Object k(byte[] s) { return new SecretKeySpec(s, alg); }\n}\n",
    })
    found = _found(rows)
    assert found[("pay/src/main/java/eva/FromProps3.java", "AES-ECB")] == (None, [])
    assert found[("B.java", "DES")] == (None, [])
    for comp in result.components:
        if comp.name in ("AES-ECB", "DES"):
            assert comp.properties["crypto:confidence"] == "medium"
            assert "needs review" in comp.properties["crypto:resolution"]


# --------------------------------------------------------------------------- #
# 3. Hard-coded key lane: public / wrapped / non-crypto keys (fp5, fp6)
# --------------------------------------------------------------------------- #

_SETTINGS = (
    "# Public, browser-side identifiers (shipped to every visitor by design)\n"
    'ALGOLIA_APP_ID = "latency"\n'
    'ALGOLIA_SEARCH_KEY = "6be0576ff61c053d5f9a3225e2a90f76"   # search-only key, Algolia docs: safe to expose\n'
    'SENTRY_KEY = "a3f1c9e27b4d4e8f9c0d1e2f3a4b5c6d"           # the public key of the Sentry DSN\n\n'
    "# Envelope encryption: the data key below is KMS ciphertext, decrypted at start-up by kms:Decrypt\n"
    f'WRAPPED_KEY = "{_HEX}{_HEX}"\n'
)


def _keys(text: str, lang: str = "python") -> list[str | None]:
    return [f.var for f in detect_material_misuse(text, lang) if f.kind == "secret-key" and f.hardcoded]


def test_public_and_wrapped_key_constants_are_not_hardcoded_keys(tmp_path: Path) -> None:
    rows, _ = _scan(tmp_path, {"web/settings.py": _SETTINGS})
    assert rows == []
    # without a cipher in the file only a name that says crypto key is key material ...
    assert _keys(f'AES_KEY = "{_HEX}"\n') == ["AES_KEY"]
    assert _keys(f'SECRET_KEY = "{_HEX}"\n') == ["SECRET_KEY"]
    assert _keys(f'KEY = "{_HEX}"\n') == ["KEY"]
    assert _keys(f'PUSHER_KEY = "{_HEX}"\n') == []
    # ... and next to a cipher a key-named literal is, unless the name says it is public, wrapped or a lookup key
    ctx = "from cryptography.fernet import Fernet\n"
    assert _keys(ctx + f'PUSHER_KEY = "{_HEX}"\n') == ["PUSHER_KEY"]
    assert _keys(ctx + f'enc_key = "{_HEX}"\n') == ["enc_key"]
    for name in ("STRIPE_PUBLISHABLE_KEY", "recaptcha_site_key", "site_key", "ENCRYPTED_KEY", "WRAPPED_DATA_KEY",
                 "idempotency_key", "cache_key", "search_key"):
        assert _keys(ctx + f'{name} = "{_HEX}"\n') == [], name


def _notebook(outputs: list[str]) -> str:
    cells = [{"cell_type": "code", "metadata": {}, "execution_count": n, "source": ["print(x)\n"],
              "outputs": [{"output_type": "stream", "name": "stdout", "text": [out + "\n"]}]}
             for n, out in enumerate(outputs, start=1)]
    return json.dumps({"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": cells})


def test_notebook_output_keys_take_the_same_name_rules(tmp_path: Path) -> None:
    rows, _ = _scan(tmp_path, {"analysis.ipynb": _notebook([
        "Idempotency key: 9f1c2b7e4a6d4c3b8e5f0a1d2c3b4a59", "cache key: 0d6e4079e36703ebd37c00722f5891d2",
        "request key = 0d6e4079e36703ebd37c00722f5891d2"])})
    assert rows == []
    rows, _ = _scan(tmp_path / "pos", {"explore.ipynb": _notebook([f"AES key = {_HEX}"])})
    assert {r["title"]: r["finding_codes"] for r in rows} == {
        "secret-key (notebook output, explore.ipynb)": ["HARDCODED_KEY"]}


# --------------------------------------------------------------------------- #
# 4. A constant imported from another module is read only where a crypto call takes it (fp3 py)
# --------------------------------------------------------------------------- #


def test_imported_constant_in_a_non_crypto_call_is_not_a_usage(tmp_path: Path) -> None:
    rows, _ = _scan(tmp_path, {
        "app/__init__.py": "",
        "app/consts.py": '# Digests we refuse in uploaded manifests.\nREJECTED_DIGEST = "md5"\n'
                         'DEFAULT_DIGEST = "sha256"\nWEAK = "sha1"\n',
        "app/manifest.py": "import hashlib\nimport hmac\n\n"
                           "from .consts import DEFAULT_DIGEST, REJECTED_DIGEST, WEAK\n\n\n"
                           "class UnsupportedDigest(ValueError):\n    pass\n\n\n"
                           "def digest_of(data: bytes, name: str) -> str:\n    if name == REJECTED_DIGEST:\n"
                           "        raise UnsupportedDigest(REJECTED_DIGEST)\n"
                           "    return hashlib.new(DEFAULT_DIGEST, data).hexdigest()\n\n\n"
                           "def tag(key, data):\n    return hmac.new(key, data, digestmod=WEAK).digest()\n",
    })
    found = _found(rows)
    assert not [k for k in found if k[0] == "app/manifest.py" and k[1] == "MD5"]
    assert ("app/manifest.py", "SHA-256") in found  # hashlib.new(DEFAULT_DIGEST, ...) still resolves
    assert ("app/manifest.py", "HMAC-SHA1") in found or ("app/manifest.py", "SHA-1") in found


# --------------------------------------------------------------------------- #
# 5. Private constructions: WebSocket masking, xorshift, shared MD-family IVs (fp4)
# --------------------------------------------------------------------------- #


def test_masking_xorshift_and_sha1_ivs_are_not_custom_ciphers(tmp_path: Path) -> None:
    ws = ("import os\nimport struct\n\n\ndef mask_payload(payload: bytes) -> bytes:\n    mask = os.urandom(4)\n"
          "    masked = bytes(b ^ mask[i % len(mask)] for i, b in enumerate(payload))\n"
          '    return struct.pack("!4s", mask) + masked\n')
    prng = ("MASK64 = (1 << 64) - 1\n\n\ndef xorshift128plus(s0: int, s1: int):\n"
            "    s1 ^= (s1 << 23) & MASK64\n    s0, s1 = s1, s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26)\n"
            "    return s0, s1, (s0 + s1) & MASK64\n")
    sha1 = ("final class Sha1Impl {\n    private int h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, "
            "h3 = 0x10325476, h4 = 0xC3D2E1F0;\n}\n")
    assert detect_custom_constructions(ws) == []
    assert detect_custom_constructions(ws.replace("mask", "masking_key")) == []
    assert detect_custom_constructions(prng) == []
    assert detect_custom_crypto(sha1) is None
    rows, _ = _scan(tmp_path, {"ws_frame.py": ws, "prng.py": prng, "Sha1Impl.java": sha1})
    assert rows == []
    # twins: a repeating-key XOR over a key, a Feistel round with a round function, MD5 by its T table
    assert detect_custom_constructions(ws.replace("mask[i % len(mask)]", "key[i % len(key)]"))
    assert detect_custom_constructions("def f(L, R, k):\n    for i in range(16):\n        L, R = R, L ^ F(R, k[i])\n")
    md5 = "static final int[] S = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};\nint t0 = 0xd76aa478;\n"
    assert detect_custom_crypto(md5) == ("md5", "MD5 (custom implementation)", "hash")


# --------------------------------------------------------------------------- #
# 6. Deny-lists of algorithm names are policy, not use (fp1)
# --------------------------------------------------------------------------- #

_DENY = {
    "src/denylist.py": '"""Policy checks for user-supplied algorithm names."""\n\n'
                       'WEAK_ALGORITHMS = frozenset({"MD5", "SHA1", "DES", "RC4", "3DES"})\n\n\n'
                       "def validate_algorithm(name: str) -> str:\n    if name.upper() in WEAK_ALGORITHMS:\n"
                       '        raise ValueError("algorithm not allowed")\n    return name\n',
    "src/Policy.java": "package com.acme.policy;\n\nimport java.util.Set;\n\npublic final class Policy {\n"
                       "    private static final Set<String> FORBIDDEN = "
                       'Set.of("DES", "DESede", "RC4", "MD5", "SHA-1");\n\n'
                       "    public static void check(String transformation) {\n"
                       '        String alg = transformation.split("/")[0];\n        if (FORBIDDEN.contains(alg)) {\n'
                       '            throw new IllegalArgumentException("forbidden cipher: " + alg);\n        }\n'
                       '        if (transformation.contains("/ECB/")) {\n'
                       '            throw new IllegalArgumentException("ECB mode is not allowed");\n        }\n'
                       "    }\n}\n",
    "src/policy.js": "const DISALLOWED_HASHES = ['md5', 'sha1'];\n\nfunction assertStrongHash(name) {\n"
                     "  if (DISALLOWED_HASHES.includes(name.toLowerCase())) {\n"
                     "    throw new Error('weak hash rejected');\n"
                     "  }\n}\nmodule.exports = { assertStrongHash };\n",
    "src/multi.py": "CHECKED = (\n    'md5',\n    'sha1',\n)\n\n\ndef check(name):\n"
                    "    if name in CHECKED: raise ValueError(name)\n",
    # a predicate over a list its name calls weak
    "src/classify.py": "WEAK_HASHES = ('md5', 'sha1')\n\n\ndef is_weak(name):\n"
                       "    return name.lower() in WEAK_HASHES\n",
}


def test_deny_lists_of_algorithm_names_are_not_usage(tmp_path: Path) -> None:
    rows, result = _scan(tmp_path, _DENY)
    assert rows == [], sorted(_found(rows))
    assert failing_flags(result.flags) == []


def test_lists_whose_names_are_used_or_accepted_stay_findings(tmp_path: Path) -> None:
    rows, _ = _scan(tmp_path, {
        # an allow-list that accepts MD5: the code hashes with whatever passed it
        "allow.py": "import hashlib\nALLOWED = {'md5', 'sha256'}\n\n\ndef h(name, data):\n"
                    "    if name not in ALLOWED:\n        raise ValueError(name)\n    return hashlib.new(name, data)\n",
        # the names are iterated, not compared: each reaches hashlib
        "loop.py": "import hashlib\nHASHES = ['md5', 'sha1']\n\n\ndef all_digests(data):\n"
                   "    return [hashlib.new(h, data).hexdigest() for h in HASHES]\n",
        # a deny-list name, but the list is also handed to a negotiation call
        "Neg.java": "import java.util.List;\nclass Neg {\n"
                    '  static final List<String> WEAK = List.of("MD5", "SHA-1");\n'
                    "  boolean bad(String a) { return WEAK.contains(a); }\n"
                    "  void offer(Engine e) { e.setDigests(WEAK); }\n}\n",
        # a weak name only warned about: the work goes on with it
        "warn.py": "import logging\nWEAK = {'md5'}\n\n\ndef pick(name):\n    if name in WEAK:\n"
                   "        logging.warning('weak hash %s', name)\n    return name\n",
    })
    weak = _weak(rows)
    assert ("allow.py", "MD5") in weak
    assert ("loop.py", "MD5") in weak and ("loop.py", "SHA-1") in weak
    assert ("Neg.java", "MD5") in weak
    assert ("warn.py", "MD5") in weak
