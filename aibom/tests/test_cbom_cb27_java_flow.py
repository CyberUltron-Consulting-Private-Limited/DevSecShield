"""CB-27: Java literal flow (constants reaching JCA/JCE crypto APIs) and no-op trust
managers.

Each case is a small Java project written to a temporary directory and scanned with the
real pipeline (:func:`aibom.cbom.pipeline.scan_crypto`): the finding code, the file and
the line are asserted. The shapes follow CryptoAPI-Bench's classes (basic, field-
sensitive, interprocedural, multiple classes, path-sensitive); the negative cases are
the ones a lexical reader gets wrong (a constant that a later call replaces, a value
read from outside the source, a known-answer self test, HKDF's all-zero default salt, a
unit test that passes a literal to production code).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.cbom.pipeline import scan_crypto

# the codes as strings: these tests run (and fail) on a build that has neither the
# codes nor the Java reader
HARDCODED_KEY, STATIC_IV, WEAK_RNG = "HARDCODED_KEY", "STATIC_IV", "WEAK_RNG"
STATIC_SALT, WEAK_KDF_ITERATIONS = "STATIC_SALT", "WEAK_KDF_ITERATIONS"

IMPORTS = """import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.nio.ByteBuffer;
"""


def _scan(tmp_path: Path, files: dict[str, str]) -> set[tuple[str, int, str]]:
    for rel, body in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(IMPORTS + body, encoding="utf-8")
    result = scan_crypto(str(tmp_path))
    src = {c.bom_ref: c.properties or {} for c in result.components}
    out = set()
    for f in result.flags:
        props = src.get(f.target) or {}
        if (
            props.get("crypto:assetType") == "related-crypto-material"
            or f.code == "TLS_VERIFICATION_DISABLED"
        ):
            out.add(
                (
                    Path(props.get("discovery:source", "")).name,
                    int(props.get("crypto:line", 0) or 0),
                    f.code,
                )
            )
    return out


def _codes(found) -> set[str]:
    return {code for _, _, code in found}


L = len(IMPORTS.splitlines())  # the line offset of the bodies below


# ------------------------------------------------------------------ basic (one method)
@pytest.mark.parametrize(
    "body,line,code",
    [
        (
            "class A { void go(SecretKey k) throws Exception {\n"
            '  byte[] bytes = "abcde".getBytes();\n'
            "  IvParameterSpec iv = new IvParameterSpec(bytes);\n"
            '  Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");'
            ' c.init(Cipher.ENCRYPT_MODE, k, iv); } }\n',
            3,
            STATIC_IV,
        ),
        (
            "class A { void go() {\n"
            '  String defaultKey = "defaultkey";\n'
            "  byte[] keyBytes = defaultKey.getBytes();\n"
            "  keyBytes = java.util.Arrays.copyOf(keyBytes, 16);\n"
            '  SecretKeySpec ks = new SecretKeySpec(keyBytes, "AES"); } }\n',
            5,
            HARDCODED_KEY,
        ),
        (
            "class A { void go() {\n"
            "  byte[] salt = {(byte) 0xa2};\n"
            "  int count = 1020;\n"
            "  PBEParameterSpec p = new PBEParameterSpec(salt, count); } }\n",
            4,
            STATIC_SALT,
        ),
        (
            "class A { void go() {\n"
            "  SecureRandom r = new SecureRandom(); byte[] salt = new byte[32];"
            " r.nextBytes(salt);\n"
            "  int count = 20;\n"
            "  PBEParameterSpec p = new PBEParameterSpec(salt, count); } }\n",
            4,
            WEAK_KDF_ITERATIONS,
        ),
        (
            "class A { void go() {\n"
            "  char[] pw = {'s'};\n"
            "  PBEKeySpec spec = new PBEKeySpec(pw, new byte[0], 11010, 16); } }\n",
            3,
            HARDCODED_KEY,
        ),
        (
            "class A { void go(java.io.InputStream in) throws Exception {\n"
            '  KeyStore ks = KeyStore.getInstance("JKS");\n'
            '  String defaultKey = "changeit";\n'
            "  ks.load(in, defaultKey.toCharArray()); } }\n",
            4,
            HARDCODED_KEY,
        ),
        (
            "class A { void go() {\n"
            "  SecureRandom sr = new SecureRandom();\n"
            "  byte[] bytes = {(byte) 100, (byte) 200};\n"
            "  sr.setSeed(bytes); } }\n",
            4,
            WEAK_RNG,
        ),
        (
            "class A { void go() {\n"
            "  byte seed = 100;\n"
            "  SecureRandom sr = new SecureRandom(new byte[]{seed}); } }\n",
            3,
            WEAK_RNG,
        ),
    ],
)
def test_a_constant_reaching_the_api_is_reported_on_the_call(
    tmp_path, body, line, code
):
    assert ("A.java", L + line, code) in _scan(tmp_path, {"A.java": body})


def test_the_pbe_salt_and_iteration_count_are_two_findings_on_one_call(tmp_path):
    found = _scan(
        tmp_path,
        {
            "A.java": "class A { void go() {\n"
            '  PBEKeySpec s = new PBEKeySpec(System.getenv("P").toCharArray(), '
            '"NaCl".getBytes(), 100, 256); } }\n'
        },
    )
    assert found == {
        ("A.java", L + 2, STATIC_SALT),
        ("A.java", L + 2, WEAK_KDF_ITERATIONS),
    }


# -------------------------------------------------------------------- through the code
def test_interprocedural_through_two_methods(tmp_path):
    body = (
        "class A {\n"
        "  public static void main(String[] a) { byte[] seed = {(byte) 100, (byte)"
        " 200}; method1(seed); }\n"
        "  public static void method1(byte[] s) { byte[] seed2 = s; method2(seed2); }\n"
        "  private static void method2(byte[] seed) { SecureRandom sr = new"
        " SecureRandom(); sr.setSeed(seed); }\n"
        "}\n"
    )
    assert ("A.java", L + 4, WEAK_RNG) in _scan(tmp_path, {"A.java": body})


def test_fields_set_in_other_methods(tmp_path):
    body = (
        "class A {\n"
        '  public static final String DEFAULT_ENCRYPT_KEY = "changeit";\n'
        "  private static char[] ENCRYPT_KEY; private static char[] encryptKey;\n"
        "  static void go2() { ENCRYPT_KEY = DEFAULT_ENCRYPT_KEY.toCharArray(); }\n"
        "  static void go3() { encryptKey = ENCRYPT_KEY; }\n"
        "  void go() { PBEKeySpec s = new PBEKeySpec(encryptKey); }\n"
        "}\n"
    )
    assert ("A.java", L + 6, HARDCODED_KEY) in _scan(tmp_path, {"A.java": body})


def test_another_class_in_another_file(tmp_path):
    files = {
        "Main.java": "class Main { public static void main(String[] a) throws"
                     " Exception {\n"
        '  Crypto c = new Crypto(); byte[] bytes = "abcde".getBytes(); c.go(bytes); }'
        ' }\n',
        "Crypto.java": "class Crypto { void go(byte[] ivBytes) throws Exception {\n"
        "  IvParameterSpec iv = new IvParameterSpec(ivBytes); } }\n",
    }
    assert ("Crypto.java", L + 2, STATIC_IV) in _scan(tmp_path, files)


def test_a_constructor_field_and_a_later_method(tmp_path):
    body = (
        'class A { Holder h; A() { byte[] b = "abcde".getBytes(); h = new Holder(b);'
        ' h.use(null); } }\n'
        "class Holder { byte[] defIV;\n"
        "  Holder(byte[] bytes) { defIV = bytes; }\n"
        "  void use(byte[] passed) { passed = defIV; IvParameterSpec s = new"
        " IvParameterSpec(passed); } }\n"
    )
    assert ("A.java", L + 4, STATIC_IV) in _scan(tmp_path, {"A.java": body})


# ------------------------------------------------------------------------ not reported
@pytest.mark.parametrize(
    "body",
    [
        # path-sensitive (CryptoAPI-Bench labels it secure): the constant may be
        # replaced before the call
        'class A { void go(int choice) { SecureRandom sr = new SecureRandom(); byte[]'
        ' bytes = "abcde".getBytes();\n'
        "  if (choice > 1) { bytes = new byte[16]; sr.nextBytes(bytes); }\n"
        "  IvParameterSpec iv = new IvParameterSpec(bytes); } }\n",
        # a buffer filled by a call
        "class A { void go(ByteBuffer buf) { byte[] iv = new byte[12]; buf.get(iv);\n"
        "  GCMParameterSpec s = new GCMParameterSpec(128, iv); } }\n",
        # read from outside the source
        'class A { void go() { byte[] k = System.getenv("KEY").getBytes();'
        ' SecretKeySpec s = new SecretKeySpec(k, "AES"); } }\n',
        # a parameter whose callers pass something not constant
        'class A { void use(byte[] key) { SecretKeySpec s = new SecretKeySpec(key,'
        ' "AES"); }\n'
        "  void run(java.io.DataInputStream in) throws Exception { byte[] k = new"
        " byte[16]; in.readFully(k); use(k); } }\n",
        # a known-answer self test
        'class A { private static final byte[] testKey ='
        ' "0123456789abcdef".getBytes();\n'
        '  static boolean isValid() { SecretKeySpec s = new SecretKeySpec(testKey,'
        ' "AES"); return true; } }\n',
        # HKDF's default salt (RFC 5869): an all-zero HMAC key
        'class A { void extract(Mac mac) throws Exception { mac.init(new'
        ' SecretKeySpec(new byte[32], "HmacSHA256")); } }\n',
        # 1,000 iterations and more: not below NIST SP 800-132's minimum
        "class A { void go(char[] pw, byte[] salt) { PBEKeySpec s = new"
        " PBEKeySpec(pw, salt, 1000, 256); } }\n",
        # setSeed on java.util.Random: not a SecureRandom
        "class A { void go() { java.util.Random r = new java.util.Random(); byte[] b"
        " = {1}; r.setSeed(42L); } }\n",
    ],
)
def test_not_reported(tmp_path, body):
    assert (
        _codes(_scan(tmp_path, {"A.java": body}))
        & {STATIC_IV, HARDCODED_KEY, STATIC_SALT, WEAK_KDF_ITERATIONS, WEAK_RNG}
        == set()
    )


def test_a_unit_test_passing_a_literal_does_not_make_production_code_constant(tmp_path):
    files = {
        "src/main/java/Crypto.java": 'class Crypto { void go(byte[] key) {'
                                     ' SecretKeySpec s = new SecretKeySpec(key,'
                                     ' "AES"); } }\n',
        "src/test/java/CryptoTest.java": 'class CryptoTest { void t() { new'
                                         ' Crypto().go("0123456789abcdef".getBytes());'
                                         ' } }\n',
    }
    assert HARDCODED_KEY not in _codes(_scan(tmp_path, files))


# ---------------------------------------------------------------------- trust managers
def test_an_empty_check_server_trusted_is_verification_disabled(tmp_path):
    body = (
        "public class T implements javax.net.ssl.X509TrustManager {\n"
        "  public void checkClientTrusted(java.security.cert.X509Certificate[] c,"
        " String s) {}\n"
        "  public void checkServerTrusted(java.security.cert.X509Certificate[] c,"
        " String s)\n"
        "      throws java.security.cert.CertificateException {\n"
        "    // trust any server\n"
        "  }\n"
        "  public java.security.cert.X509Certificate[] getAcceptedIssuers() { return"
        " null; } }\n"
    )
    assert "TLS_VERIFICATION_DISABLED" in _codes(_scan(tmp_path, {"T.java": body}))
    from aibom.cbom import java_flow

    assert java_flow.noop_trust_checks(IMPORTS + body) == [L + 3]


def test_a_delegating_trust_manager_is_not(tmp_path):
    body = (
        "public class T implements javax.net.ssl.X509TrustManager {"
        " javax.net.ssl.X509TrustManager d;\n"
        "  public void checkServerTrusted(java.security.cert.X509Certificate[] c,"
        " String s)\n"
        "      throws java.security.cert.CertificateException {"
        " d.checkServerTrusted(c, s); } }\n"
    )
    from aibom.cbom import java_flow

    assert java_flow.noop_trust_checks(IMPORTS + body) == []
    assert "TLS_VERIFICATION_DISABLED" not in _codes(_scan(tmp_path, {"T.java": body}))


# -------------------------------------------------------------------------- robustness
def test_broken_or_hostile_source_never_breaks_the_scan(tmp_path):
    deep = "(" * 3000 + "1" + ")" * 3000
    files = {
        "A.java": f"class A {{ void go() {{ int x = {deep}; "
        'IvParameterSpec s = new IvParameterSpec("a".getBytes()); }',
        "B.java": 'class B { void go( { new SecretKeySpec("k".getBytes(), "AES") ;;;'
                  ' }}}}}} (((',
    }
    _scan(tmp_path, files)  # no exception
    from aibom.cbom import java_flow

    assert (
        java_flow.analyze({"x.java": "class X { void m() { new IvParameterSpec(" * 200})
        is not None
    )
