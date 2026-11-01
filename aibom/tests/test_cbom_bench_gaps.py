"""Detector gaps found by benchmarking the code-scan engine against CBOMkit /
sonar-cryptography, cdxgen and SCANOSS reference CBOMs (keycloak, nifi, kafka,
bisq, sonarqube, Chat2DB, zaproxy, DependencyCheck).

Every case is a minimal inline source modelled on the code the references
reported and we missed (or reported wrongly), driven through the real pipeline
(:func:`aibom.cbom.pipeline.scan_crypto`). Each rule has its negative twin: prose,
comments and unrelated identifiers must not become findings.
"""

from __future__ import annotations

import base64
import struct
from pathlib import Path

from aibom.cbom.detect import detect_crypto, jca_assets
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.strength import canonical_algorithm_family, is_approved_algorithm
from aibom.emit.cyclonedx import _family_of
from aibom.model.component import CryptoAssetComponent

_JCA_IMPORTS = "import javax.crypto.Cipher;\nimport java.security.KeyFactory;\n"


def _scan(tmp_path: Path, files: dict[str, str]) -> dict[str, dict[str, dict]]:
    """file -> {asset name -> properties} for every crypto asset the pipeline emits."""
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    out: dict[str, dict[str, dict]] = {}
    for c in scan_crypto(tmp_path).components:
        if c.kind != "crypto_asset":
            continue
        props = c.properties or {}
        out.setdefault(props.get("discovery:source", ""), {})[c.name] = props
    return out


def _names(tmp_path: Path, rel: str, text: str) -> set[str]:
    return set(_scan(tmp_path, {rel: text}).get(rel, {}))


def _java(body: str, imports: str = _JCA_IMPORTS) -> str:
    return f"{imports}class T {{\n{body}\n}}\n"


# --------------------------------------------------------------------------- #
# 1. new SecretKeySpec(bytes, "<algorithm>")
# --------------------------------------------------------------------------- #


def test_secret_key_spec_names_the_key_algorithm(tmp_path: Path) -> None:
    src = _java(
        "import javax.crypto.spec.SecretKeySpec;\n"
        'Object a(byte[] k) { return new SecretKeySpec(k, "AES"); }\n'
        'Object d(byte[] k) { return new SecretKeySpec(k, 0, 24, "DESede"); }\n'
        'Object m(byte[] k) { return new SecretKeySpec(k, "HmacSHA256"); }\n',
        imports="import javax.crypto.spec.SecretKeySpec;\n",
    )
    assert _names(tmp_path, "K.java", src) == {"AES", "3DES", "HMAC-SHA256"}


def test_secret_key_spec_via_field_default_and_raw_label(tmp_path: Path) -> None:
    src = _java(
        'protected String encryptionAlgorithm = "AES";\n'
        'Object a(byte[] k) { return new SecretKeySpec(k, encryptionAlgorithm); }\n'
        'Object r(byte[] k) { return new SecretKeySpec(k, "RAW"); }\n',
        imports="import javax.crypto.spec.SecretKeySpec;\n",
    )
    assert _names(tmp_path, "K.java", src) == {"AES"}


def test_secret_key_spec_never_from_comment_or_unresolvable_arg(tmp_path: Path) -> None:
    src = _java(
        '// new SecretKeySpec(bytes, "AES") would be the obvious choice\n'
        "/* new SecretKeySpec(k, \"DES\") */\n"
        "Object a(byte[] k, String alg) { return new SecretKeySpec(k, alg); }\n"
        "Object b(byte[] k, Algo a) { return new SecretKeySpec(k, a.getJavaAlgorithm()); }\n",
        imports="import javax.crypto.spec.SecretKeySpec;\n",
    )
    assert _names(tmp_path, "K.java", src) == set()


# --------------------------------------------------------------------------- #
# 2. ASCII-armored OpenPGP key files
# --------------------------------------------------------------------------- #


def _pgp_block(kind: str, algo_id: int, mpi_bits: int | None) -> str:
    """A minimal RFC 9580 v4 key packet (legacy header), ASCII-armored."""
    body = bytes([4]) + struct.pack(">I", 1445000000) + bytes([algo_id])
    if mpi_bits:
        body += struct.pack(">H", mpi_bits) + b"\x80" * 8
    tag = 6 if kind == "PUBLIC" else 5
    packet = bytes([0x80 | (tag << 2) | 1]) + struct.pack(">H", len(body)) + body
    b64 = base64.b64encode(packet).decode()
    return (f"-----BEGIN PGP {kind} KEY BLOCK-----\nComment: test key\n\n{b64}\n=abcd\n"
            f"-----END PGP {kind} KEY BLOCK-----\n")


def test_openpgp_public_key_file_is_inventoried_with_algorithm_and_size(tmp_path: Path) -> None:
    found = _scan(tmp_path, {
        "keys/sipa.gpg": _pgp_block("PUBLIC", 1, 4096),
        "keys/dev.asc": _pgp_block("PUBLIC", 22, None),
    })
    rsa = found["keys/sipa.gpg"]["public-key (sipa.gpg)"]
    assert rsa["crypto:assetType"] == "related-crypto-material"
    assert rsa["crypto:materialKind"] == "public-key"
    assert rsa["crypto:algorithm"] == "RSA"
    assert rsa["crypto:keySize"] == "4096"
    assert rsa["crypto:containerFormat"] == "openpgp"
    ed = found["keys/dev.asc"]["public-key (dev.asc)"]
    assert ed["crypto:algorithm"] == "EdDSA"
    assert "crypto:keySize" not in ed


def test_openpgp_private_key_block_and_garbage_body(tmp_path: Path) -> None:
    found = _scan(tmp_path, {
        "secring.asc": _pgp_block("PRIVATE", 17, 3072),
        "broken.gpg": ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!notbase64!!\n"
                       "-----END PGP PUBLIC KEY BLOCK-----\n"),
    })
    dsa = found["secring.asc"]["private-key (secring.asc)"]
    assert dsa["crypto:materialKind"] == "private-key"
    assert dsa["crypto:algorithm"] == "DSA" and dsa["crypto:keySize"] == "3072"
    broken = found["broken.gpg"]["public-key (broken.gpg)"]  # still key material, no invented algorithm
    assert "crypto:algorithm" not in broken


def test_openpgp_signature_and_message_files_are_not_key_material(tmp_path: Path) -> None:
    found = _scan(tmp_path, {
        "release.tar.gz.asc": ("-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEE\n=abcd\n"
                               "-----END PGP SIGNATURE-----\n"),
        "note.asc": "-----BEGIN PGP MESSAGE-----\n\nhQEMA\n=abcd\n-----END PGP MESSAGE-----\n",
        "README.asc": "Import the key with gpg --import KEYS (PGP PUBLIC KEY BLOCK inside).\n",
    })
    assert found == {}


# --------------------------------------------------------------------------- #
# 3. getInstance(<same-file String constant>)
# --------------------------------------------------------------------------- #


def test_jca_constant_arguments_resolve(tmp_path: Path) -> None:
    src = _java(
        'private static final String SYM_CIPHER = "AES";\n'
        'private static final String DES_CBC_PKCS5PADDING = "DES/CBC/PKCS5Padding";\n'
        'static final String ASYM_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1PADDING";\n'
        'private static final String ELGAMAL_KEY_ALGORITHM = "ELGAMAL";\n'
        "void f() throws Exception {\n"
        "  Cipher.getInstance(SYM_CIPHER);\n"
        "  javax.crypto.Cipher.getInstance(DES_CBC_PKCS5PADDING);\n"
        "  Cipher.getInstance(T.ASYM_CIPHER);\n"
        "  KeyPairGenerator.getInstance(ELGAMAL_KEY_ALGORITHM, new BouncyCastleProvider());\n"
        "}\n"
    )
    found = _scan(tmp_path, {"C.java": src})["C.java"]
    assert set(found) == {"AES", "DES-CBC", "RSA", "MGF1", "ElGamal"}
    assert found["AES"]["crypto:line"] == "9"  # the call site, not the constant
    assert found["ElGamal"]["crypto:primitive"] == "pke"
    assert found["ElGamal"]["crypto:quantumVulnerable"] == "true"


def test_kotlin_const_val_resolves(tmp_path: Path) -> None:
    src = ("import javax.crypto.KeyGenerator\n"
           'private const val CRYPTO_KEY = "AES"\n'
           "fun k() = KeyGenerator.getInstance(CRYPTO_KEY)\n")
    assert _names(tmp_path, "K.kt", src) == {"AES"}


def test_jca_constant_not_resolved_when_ambiguous_or_foreign(tmp_path: Path) -> None:
    src = _java(
        'private String alg = "AES";\n'
        "void set(String a) { alg = a; }\n"                        # reassigned: unknown at the call
        'private static final String KEY = "RSA";\n'
        "Object g(String KEY) throws Exception { return KeyFactory.getInstance(KEY); }\n"  # shadowed
        "Object h() throws Exception { return Cipher.getInstance(alg); }\n"
        "Object i() throws Exception { return Cipher.getInstance(Other.SYM); }\n"  # another class
    )
    assert _names(tmp_path, "A.java", src) == set()


def test_constant_outside_jca_api_or_without_jca_import_is_nothing(tmp_path: Path) -> None:
    unrelated = _java(
        'private static final String AES = "AES";\n'
        'private static final String TZ = "RSA";\n'
        "void f() { log(AES); Calendar.getInstance(TZ); }\n"
    )
    no_import = 'class N { static final String A = "AES"; Object f() { return Cipher.getInstance(A); } }\n'
    found = _scan(tmp_path, {"U.java": unrelated, "N.java": no_import})
    assert found == {}


# --------------------------------------------------------------------------- #
# 4. Bouncy Castle AES key wrap + Concatenation KDF
# --------------------------------------------------------------------------- #


def test_bouncycastle_aes_wrap_and_concat_kdf(tmp_path: Path) -> None:
    src = _java(
        "Object w() { Wrapper encrypter = new AESWrapEngine(); return encrypter; }\n"
        "Object k() { ConcatenationKDFGenerator kdf = "
        "new ConcatenationKDFGenerator(DigestFactory.createSHA256()); return kdf; }\n",
        imports="import org.bouncycastle.crypto.engines.AESWrapEngine;\n",
    )
    found = _scan(tmp_path, {"B.java": src})["B.java"]
    assert set(found) == {"AES-KW", "ConcatenationKDF", "SHA-256"}
    assert found["AES-KW"]["crypto:primitive"] == "block-cipher"
    assert found["ConcatenationKDF"]["crypto:primitive"] == "kdf"


def test_bouncycastle_class_names_only_as_constructors(tmp_path: Path) -> None:
    src = _java("// new AESWrapEngine()\nAESWrapEngine engine;\nString s = \"ConcatenationKDFGenerator\";\n",
                imports="import org.bouncycastle.crypto.engines.AESWrapEngine;\n")
    assert _names(tmp_path, "B.java", src) == set()


# --------------------------------------------------------------------------- #
# 5. JCA standard-name aliases
# --------------------------------------------------------------------------- #


def test_jca_aliases_eddsa_and_sha(tmp_path: Path) -> None:
    src = _java(
        'Object a() throws Exception { return KeyFactory.getInstance("EdDSA"); }\n'
        'Object b() throws Exception { return MessageDigest.getInstance("SHA"); }\n'
    )
    found = _scan(tmp_path, {"A.java": src})["A.java"]
    assert set(found) == {"EdDSA", "SHA-1"}
    assert found["EdDSA"]["crypto:primitive"] == "signature"
    assert found["EdDSA"]["crypto:quantumVulnerable"] == "true"


def test_sha_alias_only_inside_message_digest(tmp_path: Path) -> None:
    src = _java('String SHA = "SHA"; Object f() { return Mapper.getInstance("SHA"); }\n')
    assert _names(tmp_path, "A.java", src) == set()


# --------------------------------------------------------------------------- #
# 6. MGF1 in RSA-OAEP / RSA-PSS
# --------------------------------------------------------------------------- #


def test_mgf1_in_oaep_and_pss_parameter_specs(tmp_path: Path) -> None:
    src = _java(
        "import java.security.spec.MGF1ParameterSpec;\n"
        'Object o() { return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, '
        "PSource.PSpecified.DEFAULT); }\n"
        "Object p(MGF1ParameterSpec ps) {\n"
        "  return new PSSParameterSpec(\n"
        '      ps.getDigestAlgorithm(), "MGF1", ps, 32, 1);\n'
        "}\n"
    )
    found = _scan(tmp_path, {"M.java": src})["M.java"]
    assert {"MGF1", "SHA-256"} <= set(found)
    assert found["MGF1"]["crypto:occurrences"] == "5,6,8"


def test_mgf1_word_in_prose_is_not_an_asset(tmp_path: Path) -> None:
    src = _java('String help = "Uses MGF1 with SHA-256 for the mask";\n// MGF1 here\n')
    assert "MGF1" not in _names(tmp_path, "M.java", src)


# --------------------------------------------------------------------------- #
# 8. a literal passed through a same-file helper
# --------------------------------------------------------------------------- #


def test_literal_through_same_file_helper(tmp_path: Path) -> None:
    src = _java(
        'static final Object F = keyFactory("RSA");\n'
        'static final Object G = keyFactory("EC");\n'
        "private static KeyFactory keyFactory(String algorithm) {\n"
        "    try { return KeyFactory.getInstance(algorithm); } "
        "catch (Exception e) { throw new RuntimeException(e); }\n"
        "}\n"
        'static final Object H = describe("DES");\n'
        "private static String describe(String name) { return name.toUpperCase(); }\n"
    )
    found = _scan(tmp_path, {"W.java": src})["W.java"]
    assert set(found) == {"RSA", "ECDSA"}
    assert found["RSA"]["crypto:line"] == "4"


# --------------------------------------------------------------------------- #
# Naming: keep the hash of HMAC / PBKDF2 / signature names
# --------------------------------------------------------------------------- #


def test_composite_names_keep_their_hash(tmp_path: Path) -> None:
    src = _java(
        'Object m() throws Exception { return Mac.getInstance("HmacSHA512"); }\n'
        'Object s() throws Exception { return Signature.getInstance("SHA256withDSA"); }\n'
        'Object k() throws Exception { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512"); }\n'
        'Object r() throws Exception { return Signature.getInstance("SHA1withRSA"); }\n'
    )
    found = _scan(tmp_path, {"N.java": src})["N.java"]
    assert set(found) == {"HMAC-SHA512", "DSA", "SHA-256", "PBKDF2-HMAC-SHA512", "RSA", "SHA-1"}
    assert found["HMAC-SHA512"]["crypto:primitive"] == "mac"
    assert found["PBKDF2-HMAC-SHA512"]["crypto:primitive"] == "kdf"
    assert found["SHA-1"]["crypto:strength"] == "weak"  # SHA-1 in a signature is a real weakness


def test_unqualified_mentions_fold_into_the_single_variant(tmp_path: Path) -> None:
    one = _java(
        'private static final String HMAC = "HmacSHA256";\n'
        "Object m() throws Exception { return Mac.getInstance(HMAC); }\n"
        "byte[] hmac(byte[] d) { return d; }\n"
    )
    two = _java(
        'Object a() throws Exception { return Mac.getInstance("HmacSHA256"); }\n'
        'Object b() throws Exception { return Mac.getInstance("HmacSHA512"); }\n'
    )
    found = _scan(tmp_path, {"One.java": one, "Two.java": two})
    assert set(found["One.java"]) == {"HMAC-SHA256"}
    assert set(found["Two.java"]) == {"HMAC-SHA256", "HMAC-SHA512"}


def test_bouncycastle_hmac_takes_its_digest(tmp_path: Path) -> None:
    src = _java("Object m() { return new HMac(new SHA384Digest()); }\n",
                imports="import org.bouncycastle.crypto.macs.HMac;\n")
    assert _names(tmp_path, "H.java", src) == {"HMAC-SHA384", "SHA-384"}


def test_composite_names_keep_the_construction_family() -> None:
    """HMAC-SHA1 is a FIPS-approved MAC, not a SHA-1 hash; PBKDF2-HMAC-SHA512 is a
    KDF (outside BSI TR-02102), not a SHA-2 hash."""
    def algo(name: str, primitive: str) -> CryptoAssetComponent:
        return CryptoAssetComponent(bom_ref=f"r-{name}", name=name, properties={
            "crypto:assetType": "algorithm", "crypto:primitive": primitive})

    hmac_sha1 = algo("HMAC-SHA1", "mac")
    pbkdf2 = algo("PBKDF2-HMAC-SHA512", "kdf")
    assert canonical_algorithm_family(hmac_sha1) == "hmac"
    assert is_approved_algorithm("fips_140_3", hmac_sha1) is True
    assert canonical_algorithm_family(pbkdf2) == "pbkdf2"
    assert is_approved_algorithm("bsi_tr_02102", pbkdf2) is False
    assert canonical_algorithm_family(algo("SHA-256", "hash")) == "sha2"
    assert _family_of("HMAC-SHA256") == "hmac"
    assert _family_of("PBKDF2-HMAC-SHA512") == "pbkdf2"
    assert _family_of("SHA-256") == "sha2"


def test_jca_standard_name_table() -> None:
    assert jca_assets("Cipher", "AES_256/GCM/NoPadding") == [("aes", None, "GCM", 256)]
    assert jca_assets("Cipher", "AESWrap") == [("aes", "KW", None, None)]
    assert jca_assets("Signature", "SHA384withECDSAinP1363Format") == [
        ("ecdsa", None, None, None), ("sha384", None, None, None)]
    assert jca_assets("Signature", "SHA256withRSAandMGF1") == [
        ("rsa", None, None, None), ("sha256", None, None, None), ("mgf1", None, None, None)]
    assert jca_assets("Signature", "sha256WithRSAEncryption") == [
        ("rsa", None, None, None), ("sha256", None, None, None)]
    assert jca_assets("Signature", "notwithstanding") == []
    assert jca_assets("KeyAgreement", "ECDH") == [("ecdh", None, None, None)]
    assert jca_assets("SecretKeySpec", "RSA") == []
    assert jca_assets("SecretKeyFactory", "PBEWithMD5AndDES") == []
    assert jca_assets("MessageDigest", "SHA-512/256") == []


# --------------------------------------------------------------------------- #
# False positives fixed in the same pass
# --------------------------------------------------------------------------- #


def test_setkey_calls_are_not_ipsec(tmp_path: Path) -> None:
    found = _scan(tmp_path, {
        "Coordinator.java": "class C { void f(Node n) { request.setKey(n.id()); cfg.setkey(1); } }\n",
        "table.tsx": "export const T = () => { const [k, setKey] = useState(0); setKey(1); return null; };\n",
        "crypt.c": "#include <crypt.h>\nvoid f(char *k) { setkey(k); }\n",
        "vpn.py": 'import subprocess\nsubprocess.run(["setkey", "-f", "/etc/ipsec-tools.conf"])\n',
    })
    protocols = {f: [n for n, p in v.items() if p.get("crypto:assetType") == "protocol"] for f, v in found.items()}
    assert protocols.get("vpn.py") == ["IPsec"]
    assert not any(protocols.get(f) for f in ("Coordinator.java", "table.tsx", "crypt.c"))


def test_rc2_versions_and_identifiers_are_not_the_cipher(tmp_path: Path) -> None:
    noise = _java(
        'String v = DependencyVersionUtil.parseVersion("1.0.0-RC2");\n'
        'String cpe = "cpe:/a:apache:struts:1.1:rc2";\n'
        'String w = "2.0.RC2";\n'
        "int rc2 = rc + 2;\n"
    )
    real = _java('Object c() throws Exception { return Cipher.getInstance("RC2/CBC/PKCS5Padding"); }\n')
    node = "const c = crypto.createCipheriv('rc2-cbc', key, iv);\n"
    found = _scan(tmp_path, {"V.java": noise, "R.java": real, "n.js": node})
    assert "V.java" not in found
    assert set(found["R.java"]) == {"RC2-CBC"}
    assert "RC2" in "".join(found["n.js"])


def test_lowercase_hss_identifier_is_not_the_signature_scheme() -> None:
    assert not [d for d in detect_crypto("HttpSessionsSite hss = sessions.get(site);\n", "java") if d.key == "hss"]
    assert [d for d in detect_crypto('Signer s = Signers.get("HSS");\n', "java") if d.key == "hss"]


def test_sql_keyword_table_is_not_crypto_usage(tmp_path: Path) -> None:
    words = ["max", "md5", "min", "min_scale", "mod", "mode", "now", "nullif", "octet_length", "overlay",
             "pg_backend_pid", "sha224", "sha256", "sha384", "sha512", "shobj_description", "sign", "sin", "sqrt"]
    table = "export const fns = [\n" + "".join(f"    '{w}',\n" for w in words) + "];\n"
    config = "export const allowedHashes = [\n    'sha256',\n    'sha384',\n];\n"
    found = _scan(tmp_path, {"pgsql.ts": table, "hashes.ts": config})
    assert "pgsql.ts" not in found
    assert {"SHA-256", "SHA-384"} <= set(found["hashes.ts"])
