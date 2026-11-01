"""Detector gaps found by scoring the code-scan engine against the AWS lab's own
code corpus (``crypto-zoo``, ground truth ``zs-cbom-gt/1``).

Each case is a minimal inline source modelled on a planted lab item we missed,
driven through the real detectors (or the full :func:`scan_crypto` pipeline).
Every rule has a negative twin: prose, comments, UI randomness and unrelated
identifiers must not become findings.
"""

from __future__ import annotations

from pathlib import Path

from aibom.cbom.detect import detect_crypto
from aibom.cbom.misuse import detect_material_misuse
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.posture.verification import detect_verification
from aibom.cbom.rules import read_source, source_language
from aibom.cbom.weakness import weak_finding


def _keys(text: str, lang: str) -> set[tuple[str, int]]:
    return {(d.key, d.line_no) for d in detect_crypto(text, lang)}


def _dets(text: str, lang: str) -> dict[str, object]:
    return {d.key: d for d in detect_crypto(text, lang)}


def _misuse(text: str, lang: str) -> list[tuple[str, str | None, int, str | None, bool]]:
    return [(f.kind, f.var, f.line, f.weak_rng, f.hardcoded) for f in detect_material_misuse(text, lang)]


def _scan(tmp_path: Path, files: dict[str, str | bytes]) -> dict[str, dict[str, dict]]:
    """file -> {asset name -> properties} for every crypto asset the pipeline emits."""
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(text, encoding="utf-8")
    out: dict[str, dict[str, dict]] = {}
    for c in scan_crypto(tmp_path).components:
        if c.kind != "crypto_asset":
            continue
        props = c.properties or {}
        out.setdefault(props.get("discovery:source", ""), {})[c.name] = props
    return out


# --------------------------------------------------------------------------- #
# 1. .NET hash provider classes
# --------------------------------------------------------------------------- #


def test_dotnet_hash_provider_classes() -> None:
    assert ("sha1", 1) in _keys("return new SHA1Managed();", "csharp")
    assert ("sha1", 1) in _keys("var h = new SHA1CryptoServiceProvider();", "csharp")
    assert ("sha1", 1) in _keys("using var h = new SHA1Cng();", "csharp")
    assert ("md5", 1) in _keys("var h = new MD5CryptoServiceProvider();", "csharp")
    assert ("md5", 1) in _keys("var h = new MD5Cng();", "csharp")
    assert ("sha1", 1) in _keys("var h = SHA1.Create();", "csharp")
    assert ("md5", 1) in _keys("var h = MD5.Create();", "csharp")


def test_dotnet_hash_provider_negative_twins() -> None:
    assert _keys("// legacy: new SHA1Managed() was removed", "csharp") == set()
    assert _keys("int SHA1ManagedCount = 0; var MD5CngLabel = \"x\";", "csharp") == set()
    # HMACSHA1 is the HMAC lane, not a bare SHA-1 hash.
    assert ("sha1", 1) not in _keys("var m = new HMACSHA1(key);", "csharp")


# --------------------------------------------------------------------------- #
# 2. OpenSSL cipher names in PHP / Ruby
# --------------------------------------------------------------------------- #


def test_php_openssl_method_names() -> None:
    d = _dets("<?php\nreturn openssl_encrypt($d, 'des-ecb', $k, OPENSSL_RAW_DATA);\n", "php")
    assert d["des"].line_no == 2 and d["des"].mode == "ECB"
    d = _dets("<?php\n$p = openssl_decrypt($c, 'des-ede3-cbc', $k);\n", "php")
    assert d["3des"].mode == "CBC" and "des" not in d
    assert "blowfish" in _dets("<?php\nopenssl_encrypt($d, 'bf-cbc', $k);\n", "php")
    assert "rc4" in _dets("<?php\nopenssl_encrypt($d, 'rc4', $k);\n", "php")


def test_ruby_openssl_cipher_name() -> None:
    d = _dets("require 'openssl'\ndef cipher\n  OpenSSL::Cipher.new('des-ede3-cbc')\nend\n", "ruby")
    assert d["3des"].line_no == 3 and d["3des"].mode == "CBC"


def test_openssl_names_negative_twins() -> None:
    # A bare 'des' / 'bf' string is not an OpenSSL cipher name (array keys, labels).
    assert _keys("<?php\n$row = ['des' => $desc, 'bf' => 1];\n", "php") == set()
    # Comments never count.
    assert _keys("<?php\n// we dropped openssl_encrypt($d, 'des-ecb', $k)\n# 'bf-cbc' too\n", "php") == set()
    assert _keys("# OpenSSL::Cipher.new('des-ede3-cbc') is gone\n", "ruby") == set()


# --------------------------------------------------------------------------- #
# 3. Weak RNG returned from a material-named function (no file crypto context)
# --------------------------------------------------------------------------- #


def test_weak_rng_returned_from_material_function() -> None:
    py = "import random\ndef token():\n    return ''.join(random.choice('0123456789abcdef') for _ in range(32))\n"
    assert _misuse(py, "python") == [("token", "token()", 3, "random.choice", False)]
    js = "function token() {\n  return Math.random().toString(36).slice(2);\n}\n"
    assert _misuse(js, "javascript") == [("token", "token()", 2, "Math.random", False)]
    java = "import java.util.Random;\nclass T {\n  public long token() {\n    return new Random().nextLong();\n  }\n}\n"
    assert _misuse(java, "java") == [("token", "token()", 4, "new Random", False)]
    php = "<?php\nfunction token() {\n    return mt_rand();\n}\n"
    assert _misuse(php, "php") == [("token", "token()", 3, "mt_rand", False)]
    go = ("package x\nimport \"math/rand\"\nfunc Key(n int) []byte {\n\tb := make([]byte, n)\n"
          "\tfor i := range b { b[i] = byte(rand.Intn(256)) }\n\treturn b\n}\n")
    assert _misuse(go, "go") == [("secret-key", "Key()", 5, "rand.Intn", False)]
    arrow = "export const generateSalt = () => Math.random().toString(16);\n"
    assert _misuse(arrow, "javascript") == [("salt", "generateSalt()", 1, "Math.random", False)]


def test_weak_rng_function_rule_negative_twins() -> None:
    ui = (
        "function jitter() { return Math.random() * 10; }\n"
        "const shuffle = (a) => a.sort(() => Math.random() - 0.5);\n"
        "function randomKey() { return Math.random().toString(36); }\n"  # a React list key
        "function cacheKey() { return Math.random(); }\n"
        "function randomColor() {\n  return '#' + Math.floor(Math.random() * 16777215).toString(16);\n}\n"
    )
    assert _misuse(ui, "javascript") == []
    # Secure sources and non-returned randomness stay clean.
    assert _misuse("import secrets\ndef token():\n    return secrets.token_hex(16)\n", "python") == []
    assert _misuse("function token() {\n  return crypto.randomUUID();\n}\n", "javascript") == []
    assert _misuse("function token() {\n  log(Math.random());\n  return fetchToken();\n}\n", "javascript") == []
    # Commented-out code is prose.
    assert _misuse("function token() {\n  // return Math.random();\n  return api.token;\n}\n", "javascript") == []
    assert _misuse("package x\nimport \"crypto/rand\"\nfunc SafeKey(n int) ([]byte, error) {\n"
                   "\tb := make([]byte, n)\n\t_, err := rand.Read(b)\n\treturn b, err\n}\n", "go") == []


def test_rand_pseudo_bytes_is_always_weak() -> None:
    c = "#include <openssl/rand.h>\nint fill(unsigned char *buf, int n) {\n    return RAND_pseudo_bytes(buf, n);\n}\n"
    assert _misuse(c, "c") == [("unknown", None, 3, "RAND_pseudo_bytes", False)]
    assert _misuse("int fill(unsigned char *b, int n) { return RAND_bytes(b, n); }\n", "c") == []
    assert _misuse("/* RAND_pseudo_bytes(buf, n) is deprecated */\nint x;\n", "c") == []


def test_constant_seed_on_secure_random() -> None:
    java = ("import java.security.SecureRandom;\nclass S {\n  SecureRandom r() throws Exception {\n"
            "    SecureRandom r = SecureRandom.getInstance(\"SHA1PRNG\");\n    r.setSeed(123456789L);\n"
            "    return r;\n  }\n}\n")
    assert _misuse(java, "java") == [("seed", "r", 5, "setSeed(constant)", True)]
    live = java.replace("r.setSeed(123456789L);", "r.setSeed(System.nanoTime());")
    assert _misuse(live, "java") == []
    no_secure = "class G {\n  void s(java.util.Random g) { g.setSeed(42L); }\n}\n"
    assert _misuse(no_secure, "java") == []


def test_weak_rng_function_flag_through_pipeline(tmp_path: Path) -> None:
    for rel, text in {
        "svc/tokens.py": "import random\ndef token():\n    return str(random.getrandbits(64))\n",
        "web/ui.js": "function jitter() { return Math.random() * 3; }\n",
    }.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    result = scan_crypto(tmp_path)
    weak = [c for c in result.components if any(f.code == "WEAK_RNG" for f in result.flags_for(c.bom_ref))]
    assert [(c.properties["discovery:source"], c.properties["crypto:line"]) for c in weak] == [("svc/tokens.py", "3")]


def test_material_function_returning_constant_key() -> None:
    go = "package eva\nfunc Key() []byte {\n\treturn []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}\n}\n"
    assert _misuse(go, "go") == [("secret-key", "Key()", 3, None, True)]
    js = "function key() {\n  return Buffer.from('c3VwZXJzZWNyZXRhZXNrZXkxMjM0NTY3OA==', 'base64');\n}\n"
    assert _misuse(js, "javascript") == [("secret-key", "key()", 2, None, True)]
    # Negative twins: a sort key returning a column name, a non-material function returning bytes.
    assert _misuse("def key(row):\n    return 'username'\n", "python") == []
    assert _misuse("def checksum():\n    return bytes.fromhex('00112233445566778899aabbccddeeff')\n", "python") == []


# --------------------------------------------------------------------------- #
# 4. JWT alg header
# --------------------------------------------------------------------------- #

_JS_JWT = "import jwt from 'jsonwebtoken';\n"


def test_jwt_alg_none_sign_and_verify() -> None:
    d = _dets(_JS_JWT + "export const s = (p) => jwt.sign(p, '', { algorithm: 'none' });\n", "javascript")
    assert d["jwt-none"].line_no == 2
    d = _dets(_JS_JWT + "jwt.verify(t, k, { algorithms: ['HS256', 'none'] });\n", "javascript")
    assert "jwt-none" in d and d["hmac"].variant == "SHA256"
    d = _dets("import * as jose from 'jose';\nconst h = { alg: \"none\" };\n", "javascript")
    assert "jwt-none" in d
    d = _dets("import jwt\nclaims = jwt.decode(tok, options={\"verify_signature\": False})\n", "python")
    assert d["jwt-none"].line_no == 2
    assert "jwt-none" in _dets("import jwt\nt = jwt.encode(p, None, algorithm=\"none\")\n", "python")


def test_jwt_signed_algorithms_inventory() -> None:
    d = _dets(_JS_JWT + "return jwt.sign(p, 'secret', { algorithm: 'HS256' });\n", "javascript")
    assert d["hmac"].variant == "SHA256" and "jwt-none" not in d
    d = _dets("import jwt\nt = jwt.encode(p, k, algorithm=\"RS256\")\n", "python")
    assert {"rsa", "sha256"} <= set(d)
    d = _dets("import io.jsonwebtoken.Jwts;\nclass A { String s() { return Jwts.builder()"
              ".signWith(SignatureAlgorithm.ES384, k).compact(); } }\n", "java")
    assert {"ecdsa", "sha384"} <= set(d)


def test_jwt_negative_twins() -> None:
    # Not a JWT file: an 'algorithm: none' option of something else.
    assert _dets("const zip = compress(buf, { algorithm: 'none' });\n", "javascript") == {}
    # A JWT file whose only mention is a comment.
    assert "jwt-none" not in _dets(_JS_JWT + "// never use { algorithm: 'none' }\n", "javascript")
    # verify_signature True is fine.
    assert "jwt-none" not in _dets("import jwt\njwt.decode(t, k, options={\"verify_signature\": True}, "
                                   "algorithms=[\"ES256\"])\n", "python")


def test_jwt_none_weakness_message(tmp_path: Path) -> None:
    (tmp_path / "s.ts").write_text(_JS_JWT + "export const s = (p) => jwt.sign(p, '', { algorithm: 'none' });\n")
    comp = next(c for c in scan_crypto(tmp_path).components if c.name == "JWT-none")
    code, _sev, msg = weak_finding(comp)
    assert code == "WEAK_ALGORITHM" and "CWE-347" in msg


# --------------------------------------------------------------------------- #
# 5. TLS versions pinned through API constants (Go / OpenSSL)
# --------------------------------------------------------------------------- #


def test_tls_version_api_constants(tmp_path: Path) -> None:
    out = _scan(tmp_path, {
        "go/min.go": "package x\nimport \"crypto/tls\"\nfunc C() *tls.Config {\n"
                     "\treturn &tls.Config{MinVersion: tls.VersionTLS10}\n}\n",
        "c/tls1.c": "#include <openssl/ssl.h>\nconst SSL_METHOD *m(void) {\n    return TLSv1_method();\n}\n",
        "c/min.c": "#include <openssl/ssl.h>\nvoid f(SSL_CTX *c) { SSL_CTX_set_min_proto_version(c, TLS1_1_VERSION); }\n",
        "go/ok.go": "package x\nimport \"crypto/tls\"\nfunc C() *tls.Config {\n"
                    "\treturn &tls.Config{MinVersion: tls.VersionTLS13}\n}\n",
    })
    assert out["go/min.go"]["TLS 1.0"]["crypto:strength"] == "weak"
    assert out["go/min.go"]["TLS 1.0"]["crypto:line"] == "4"
    assert out["c/tls1.c"]["TLS 1.0"]["crypto:line"] == "3"
    assert out["c/min.c"]["TLS 1.1"]["crypto:strength"] == "weak"
    assert out["go/ok.go"]["TLS 1.3"]["crypto:strength"] == "strong"


def test_tls_version_api_negative_twin(tmp_path: Path) -> None:
    out = _scan(tmp_path, {"c/doc.c": "/* TLSv1_method() is banned here */\nint x;\n"})
    assert "c/doc.c" not in out


# --------------------------------------------------------------------------- #
# 6. Languages and files the code scan did not read
# --------------------------------------------------------------------------- #


def test_more_languages(tmp_path: Path) -> None:
    out = _scan(tmp_path, {
        "groovy/C.groovy": "import java.security.MessageDigest\ndef h(x) {\n    MessageDigest.getInstance('MD5').digest(x)\n}\n",
        "swift/C.swift": "import CryptoKit\nfunc d(_ x: Data) -> Data {\n    let h = Insecure.SHA1.hash(data: x)\n"
                         "    return Data(h)\n}\n",
        "perl/d.pl": "use Digest::MD5 qw(md5_hex);\nsub h {\n    return md5_hex($_[0]);\n}\n1;\n",
        "vb/C.vb": "Public Class C\n  Public Function M() As SymmetricAlgorithm\n    Return New DESCryptoServiceProvider()\n"
                   "  End Function\nEnd Class\n",
        "db/m.sql": "CREATE TABLE c (\n  ssn VARBINARY(64) DEFAULT (AES_ENCRYPT('x', 'k'))\n);\n",
        "db/pg.sql": "INSERT INTO v(s) VALUES (\n  encrypt('d'::bytea, 'k'::bytea, 'bf')\n);\n",
        "scripts/enc.sh": "#!/usr/bin/env bash\nset -e\nopenssl enc -des3 -k \"$P\" -in a -out b\n",
        "ci/Dockerfile.build": "FROM alpine:3.19\nRUN openssl enc -aes-128-ecb -K 0011 -in a -out b\n",
        "scripts/helper": "#!/usr/bin/env python3\nfrom Crypto.Cipher import ARC4\ndef c(k):\n    return ARC4.new(k)\n",
    })
    assert out["groovy/C.groovy"]["MD5"]["crypto:line"] == "3"
    assert "SHA-1" in out["swift/C.swift"]
    assert out["perl/d.pl"]["MD5"]["crypto:line"] == "3"
    assert out["vb/C.vb"]["DES"]["crypto:line"] == "3"
    assert out["db/m.sql"]["AES"]["crypto:line"] == "2"
    assert out["db/pg.sql"]["Blowfish"]["crypto:line"] == "2"
    assert out["scripts/enc.sh"]["3DES"]["crypto:line"] == "3"
    assert "AES-ECB" in out["ci/Dockerfile.build"]
    assert out["scripts/helper"]["RC4"]["crypto:line"] == "4"


def test_more_languages_negative_twins(tmp_path: Path) -> None:
    out = _scan(tmp_path, {
        "perl/c.pl": "# md5_hex($x) was removed\nmy $md5_label = 'x';\n",
        "vb/C.vb": "' New DESCryptoServiceProvider() is banned\nREM MD5 too\nDim s = \"it's fine\"\n",
        "db/c.sql": "-- AES_ENCRYPT() and encrypt(x, k, 'des') are banned\nSELECT 1;\n",
        "scripts/c.sh": "#!/bin/sh\n# openssl enc -des3 is banned\necho done\n",
        "notes/README": "openssl enc -des3 -in a\n",  # no #! line: not a script
        "Makefile": "enc:\n\topenssl enc -des3 -in a\n",
    })
    assert out == {}


def test_source_language_resolution(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM x\n")
    (tmp_path / "tool").write_text("#!/usr/bin/env node\nconsole.log(1)\n")
    (tmp_path / "LICENSE").write_text("MIT\n")
    assert source_language(tmp_path / "Dockerfile") == "shell"
    assert source_language(tmp_path / "tool") == "javascript"
    assert source_language(tmp_path / "LICENSE") is None
    assert source_language(tmp_path / "a.py") == "python"


def test_utf16_source_is_decoded(tmp_path: Path) -> None:
    src = "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n" \
          "def build(key):\n    return Cipher(algorithms.AES(key), modes.ECB())\n"
    raw = b"\xff\xfe" + src.encode("utf-16-le")
    (tmp_path / "u.py").write_bytes(raw)
    assert read_source(tmp_path / "u.py") == src
    out = _scan(tmp_path, {})
    assert out["u.py"]["AES-ECB"]["crypto:line"] == "3"
    # A plain UTF-8 file reads exactly as before (universal newlines).
    (tmp_path / "w.py").write_bytes(b"a = 1\r\nb = 2\r")
    assert read_source(tmp_path / "w.py") == "a = 1\nb = 2\n"


# --------------------------------------------------------------------------- #
# 7. Constant folding and import aliases (evasion spellings)
# --------------------------------------------------------------------------- #


def test_folded_algorithm_spellings() -> None:
    assert ("md5", 3) in _keys("import hashlib\ndef h(x):\n    name = 'md' + '5'\n"
                               "    return getattr(hashlib, name)(x).hexdigest()\n", "python")
    assert ("md5", 3) in _keys("import base64, hashlib\ndef h(x):\n    name = base64.b64decode('bWQ1').decode()\n"
                               "    return hashlib.new(name, x).hexdigest()\n", "python")
    d = _dets("function h(x) {\n  const n = 'bce-821-sea'.split('').reverse().join('');\n"
              "  return crypto.createCipheriv(n, k, null);\n}\n", "javascript")
    assert d["aes-128"].mode == "ECB"
    assert ("des", 3) in _keys("<?php\nfunction e($k, $d) {\n  $a = 'des' . '-' . 'ecb';\n"
                               "  return openssl_encrypt($d, $a, $k);\n}\n", "php")
    assert ("md5", 2) in _keys("<?php\n$fn = 'm' . 'd5';\nreturn $fn($x);\n", "php")
    java_chars = ("import javax.crypto.Cipher;\nclass C {\n  Cipher c() throws Exception {\n"
                  "    char[] n = {'D','E','S'};\n    return Cipher.getInstance(new String(n));\n  }\n}\n")
    assert ("des", 5) in _keys(java_chars, "java")
    java_concat = ("import java.security.MessageDigest;\nclass C {\n  MessageDigest d() throws Exception {\n"
                   "    String a = \"M\"; String bb = \"D\"; String c = \"5\";\n"
                   "    return MessageDigest.getInstance(a + bb + c);\n  }\n}\n")
    assert ("md5", 5) in _keys(java_concat, "java")


def test_folding_negative_twins() -> None:
    # Pieces that do not spell an algorithm, a runtime piece, and base64 of plain text stay clean.
    assert _keys("x = 'hel' + 'lo'\ny = 'md' + suffix\n", "python") == set()
    assert _keys("import base64\nt = base64.b64decode('aGVsbG8gd29ybGQ=')\n", "python") == set()
    assert _keys("const s = 'olleh'.split('').reverse().join('');\n", "javascript") == set()
    assert _keys("<?php\n$label = 'm' . 'y';\n", "php") == set()
    # Folding never reaches comments.
    assert _keys("# name = 'md' + '5'\n", "python") == set()


def test_import_aliases() -> None:
    assert ("des", 4) in _keys("import importlib\ndef c(key):\n    des = importlib.import_module('Crypto.Cipher.DES')\n"
                               "    return des.new(key, des.MODE_ECB)\n", "python")
    assert ("des", 4) in _keys("package eva\nimport d \"crypto/des\"\nfunc N(k []byte) (interface{}, error) {\n"
                               "\treturn d.NewCipher(k)\n}\n", "go")
    assert ("rc4", 3) in _keys("from Crypto.Cipher import ARC4 as streamer\ndef c(k):\n    return streamer.new(k)\n",
                               "python")
    # Non-crypto aliases are left alone.
    assert _keys("import numpy as np\nx = np.new(3)\n", "python") == set()


# --------------------------------------------------------------------------- #
# 8. Disabled certificate / hostname verification
# --------------------------------------------------------------------------- #


def _verif(text: str) -> list[tuple[str, int]]:
    return [(f.native_type, f.line) for f in detect_verification(text, "x")]


def test_verification_disabled_patterns() -> None:
    java = ("public class AllowAllHosts implements HostnameVerifier {\n"
            "  public boolean verify(String h, SSLSession s) {\n    return true;\n  }\n}\n")
    assert _verif(java) == [("java.hostname_verify_all", 2)]
    assert _verif("conn.setHostnameVerifier((h, s) -> true);\n") == [("java.hostname_verifier_lambda", 1)]
    cs = "ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;\n"
    assert _verif(cs) == [("dotnet.validation_callback_true", 1)]
    handler = ("var h = new HttpClientHandler {\n"
               "  ServerCertificateCustomValidationCallback = (m, c, ch, e) => true\n};\n")
    assert ("dotnet.custom_validation_callback_true", 2) in _verif(handler)
    assert _verif("SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);\n") == [("openssl.verify_none", 1)]


def test_verification_negative_twins() -> None:
    java = ("class V implements HostnameVerifier {\n  public boolean verify(String h, SSLSession s) {\n"
            "    return h.equals(\"api.example.com\");\n  }\n}\n")
    assert _verif(java) == []
    cs = "ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => e == SslPolicyErrors.None;\n"
    assert _verif(cs) == []
    assert _verif("SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, cb);\n") == []
    # A non-TLS verify() returning true is not hostname verification.
    assert _verif("class Sig {\n  public boolean verify(byte[] sig) {\n    return true;\n  }\n}\n") == []


# --------------------------------------------------------------------------- #
# 9. Inventory additions
# --------------------------------------------------------------------------- #


def test_node_forge_rsa_keygen() -> None:
    d = _dets("const forge = require('node-forge');\nfunction kp() {\n"
              "  return forge.pki.rsa.generateKeyPair({ bits: 1024 });\n}\n", "javascript")
    assert d["rsa"].line_no == 3 and d["rsa"].key_size == 1024
    assert _dets("const forge = require('node-forge');\nconst c = forge.pki.certificateFromPem(p);\n",
                 "javascript") == {}


def test_backslash_runs_do_not_backtrack_exponentially(tmp_path):
    # a configure-script line with a long run of backslashes hung the scans of keycloak and DependencyCheck
    # (the string-literal patterns let each backslash parse two ways)
    import time

    from aibom.cbom import detect, redact

    line = 'as_echo="' + "\\" * 400 + "x"
    t0 = time.monotonic()
    detect._fold_strings(line, "shell")
    detect.blank_prose(line, "javascript")
    redact._LITERAL.search('k = "' + "\\" * 400 + "x")
    assert time.monotonic() - t0 < 1.0
    (tmp_path / "configure").write_text("#!/bin/sh\n" + line + "\nopenssl enc -rc4 -in a -out b\n")
    t0 = time.monotonic()
    from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

    rows = scan_crypto_to_devsecshield(tmp_path)["results"]
    assert time.monotonic() - t0 < 30 and any(r["title"].startswith("RC4") for r in rows)
    assert detect._fold_strings("h = hashlib.new('md' + '5')", "python") == "h = hashlib.new('md5')"
