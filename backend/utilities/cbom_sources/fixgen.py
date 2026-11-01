"""Code-level fixes for CBOM findings, generated in-house: deterministic rewrite rules, no model, no network.

Input is a stored code-scan finding (``snippet``/``snippet_start``/``line``/``language``/``location`` captured and
redacted by the scan worker, plus ``finding_codes``, title and description). The engine rewrites ONLY the
detected line (and, when a rule needs it, the matching import line inside the same window), keeps the file's
line endings, and returns the fixed window, a unified diff with the real line numbers, a confidence that comes
from the rule (a drop-in API swap scores higher than a structural change like ECB -> GCM), validation notes and
any commands (lock files are never edited; the package manager regenerates them).

When no rule matches, it says so (``available: False``) and the caller shows the knowledge-base steps instead:
no invented code. A few patterns are deliberately left alone: MD5 used for non-security purposes (ETag,
Content-MD5, ``usedforsecurity=False``, UUIDv3) and stored password hashes, which need a migration, not a swap.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any, Callable

FIXGEN_VERSION = "1"

Repl = str | Callable[[re.Match], str]


@dataclass(frozen=True)
class Rule:
    rid: str
    langs: frozenset[str]
    codes: frozenset[str]
    pattern: re.Pattern
    repl: Repl
    confidence: int
    summary: str
    notes: tuple[str, ...] = ()
    algo: re.Pattern | None = None              # asset text must match (e.g. md5|sha1) when set
    imports: tuple[tuple[re.Pattern, Repl], ...] = ()  # paired rewrites applied to other lines of the window
    warning: str = ""
    block: bool = False  # also look below the reported line (a Terraform resource block, an XML element)


def _r(rx: str, flags: int = 0) -> re.Pattern:
    return re.compile(rx, flags)


PY = frozenset({"python"})
JAVA = frozenset({"java"})
JS = frozenset({"javascript", "typescript"})
GO = frozenset({"go"})
CS = frozenset({"csharp"})
C = frozenset({"c"})
PHP = frozenset({"php"})
RB = frozenset({"ruby"})
TF = frozenset({"terraform"})
WEAK = frozenset({"WEAK_ALGORITHM", "WEAK_CIPHER_SUITE", "WEAK_CERTIFICATE_SIGNATURE"})
MODE = frozenset({"WEAK_CIPHER_MODE", "WEAK_ALGORITHM"})
KEYSZ = frozenset({"WEAK_KEY_SIZE", "WEAK_CERTIFICATE_KEY"})
TLSOFF = frozenset({"TLS_VERIFICATION_DISABLED"})
PROTO = frozenset({"WEAK_PROTOCOL", "KNOWN_TLS_VULNERABILITY", "DOWNGRADE_PROTECTION_MISSING"})
RNG = frozenset({"WEAK_RNG"})
PAD = frozenset({"WEAK_PADDING"})
REST = frozenset({"UNENCRYPTED_AT_REST", "AT_REST_ENCRYPTION_WEAK"})
HASHES = _r(r"md5|md2|md4|sha-?1\b|sha1|\bsha\b", re.I)
BLOCK64 = _r(r"des|blowfish|rc2|rc4|arc4|arcfour|cast|idea", re.I)

N_HASH = ("SHA-256 output is 32 bytes (64 hex characters) instead of 16/20: widen any column, buffer or "
          "comparison that stores the digest.",
          "Values already stored (checksums, signatures, cache keys) were computed with the old hash: keep a "
          "read path for them or recompute them once.")
N_GCM = ("AES-GCM needs a fresh random 12-byte nonce for every message and produces a 16-byte tag: store the nonce "
         "and tag with the ciphertext and verify the tag on decryption.",
         "Data encrypted with the old mode cannot be read with the new code: decrypt with the old settings once and "
         "re-encrypt (migration), or keep a versioned read path.",
         "Use a 128- or 256-bit key from a KMS or a KDF, never a password or a hard-coded literal.")
N_KEY = ("Existing keys and certificates keep their old size: generate new keys, re-issue certificates and rotate.",
         "3072-bit RSA is the NIST minimum for use beyond 2030; for new designs consider ECDSA P-384 now and ML-DSA "
         "(FIPS 204) / ML-KEM (FIPS 203) in the post-quantum migration.")
N_TLS = ("Make sure the trust store contains the CA that issued the server certificate (for internal CAs, load it "
         "explicitly instead of disabling verification).",)
N_PROTO = ("Peers that only speak TLS 1.0/1.1 will stop connecting: check the clients first.",)
N_RENAME = ("Function and variable names that still say md5/sha1 are left as they are; rename them separately if "
            "you want the code to read accurately.",)

RULES: tuple[Rule, ...] = (
    # ------------------------------------------------------------------------------------------ Python
    Rule("py-hashlib-call", PY, WEAK, _r(r"\bhashlib\.(md5|sha1)\("), "hashlib.sha256(", 85,
         "Use hashlib.sha256 instead of {old}.", N_HASH + N_RENAME, HASHES),
    Rule("py-hashlib-new", PY, WEAK, _r(r"""\bhashlib\.new\(\s*(['"])(md5|sha1)\1""", re.I),
         lambda m: f"hashlib.new({m.group(1)}sha256{m.group(1)}", 85, "Use SHA-256 in hashlib.new.", N_HASH, HASHES),
    Rule("py-hashlib-ref", PY, WEAK, _r(r"\bhashlib\.(md5|sha1)\b(?!\()"), "hashlib.sha256", 80,
         "Pass hashlib.sha256 as the digest.", N_HASH, HASHES),
    Rule("py-hash-from-import", PY, WEAK, _r(r"(?<![\w.])(md5|sha1)\("), "sha256(", 75,
         "Use sha256 (imported from hashlib) instead of {old}.", N_HASH, HASHES,
         imports=((_r(r"^(\s*from\s+hashlib\s+import\s+.*?)\b(md5|sha1)\b"), r"\1sha256"),)),
    Rule("py-pycryptodome-hash", PY, WEAK, _r(r"\b(MD5|SHA1|SHA)\.new\("), "SHA256.new(", 80,
         "Use Crypto.Hash.SHA256 instead of {old}.", N_HASH, HASHES,
         imports=((_r(r"^(\s*from\s+Crypto(?:dome)?\.Hash\s+import\s+.*?)\b(MD5|SHA1|SHA)\b"), r"\1SHA256"),)),
    Rule("py-cryptography-hash", PY, WEAK, _r(r"\bhashes\.(MD5|SHA1)\(\)"), "hashes.SHA256()", 85,
         "Use hashes.SHA256() instead of {old}.", N_HASH, HASHES),
    Rule("py-aes-mode", PY, MODE, _r(r"\bAES\.MODE_(ECB|CBC)\b"), "AES.MODE_GCM", 55,
         "Use authenticated AES-GCM instead of {old}.",
         N_GCM + ("With PyCryptodome: ciphertext, tag = cipher.encrypt_and_digest(data); keep cipher.nonce; "
                  "decrypt with AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag).",)),
    Rule("py-pycryptodome-cipher", PY, WEAK, _r(r"\b(DES3|DES|ARC4|Blowfish|ARC2|CAST)\.new\("), "AES.new(", 45,
         "Replace {old} with AES (GCM mode).", N_GCM, BLOCK64,
         imports=((_r(r"^(\s*from\s+Crypto(?:dome)?\.Cipher\s+import\s+.*?)\b(DES3|DES|ARC4|Blowfish|ARC2|CAST)\b"),
                   r"\1AES"),
                  (_r(r"\b(DES3|DES|Blowfish|ARC2|CAST)\.MODE_\w+"), "AES.MODE_GCM")),
         warning="Key and block sizes change (AES needs a 16/24/32-byte key): update key handling and migrate data."),
    Rule("py-cryptography-cipher", PY, WEAK, _r(r"\balgorithms\.(TripleDES|Blowfish|ARC4|CAST5|IDEA|SEED)\("),
         "algorithms.AES(", 45, "Replace {old} with AES.", N_GCM, BLOCK64,
         warning="Use the AESGCM recipe (cryptography.hazmat.primitives.ciphers.aead.AESGCM) for authenticated "
                 "encryption; key size must be 128/192/256 bits."),
    Rule("py-rsa-size", PY, KEYSZ, _r(r"(\bkey_size\s*=\s*)(512|768|1024|1536)\b"), r"\g<1>3072", 85,
         "Generate 3072-bit RSA keys instead of {old}-bit.", N_KEY),
    Rule("py-rsa-generate", PY, KEYSZ, _r(r"\b(RSA\.generate|rsa\.newkeys)\(\s*(512|768|1024|1536)\b"),
         lambda m: f"{m.group(1)}(3072", 85, "Generate 3072-bit RSA keys.", N_KEY),
    Rule("py-ssl-unverified", PY, TLSOFF, _r(r"\bssl\._create_unverified_context\(\)"),
         "ssl.create_default_context()", 90, "Use a verifying TLS context.", N_TLS),
    Rule("py-ssl-cert-none", PY, TLSOFF, _r(r"\bssl\.CERT_NONE\b"), "ssl.CERT_REQUIRED", 85,
         "Require a valid server certificate.", N_TLS),
    Rule("py-check-hostname", PY, TLSOFF, _r(r"(\.check_hostname\s*=\s*)False\b"), r"\1True", 85,
         "Turn hostname checking back on.", N_TLS),
    Rule("py-verify-false", PY, TLSOFF, _r(r"\bverify\s*=\s*False\b"), "verify=True", 90,
         "Verify server certificates (requests/httpx verify=True).", N_TLS),
    Rule("py-ssl-protocol", PY, PROTO, _r(r"\bssl\.PROTOCOL_(TLSv1(?:_1)?|SSLv2|SSLv3|SSLv23)\b"),
         "ssl.PROTOCOL_TLS_CLIENT", 75, "Negotiate TLS 1.2+ instead of {old}.",
         N_PROTO + ("Then set ctx.minimum_version = ssl.TLSVersion.TLSv1_2 on the context.",)),
    Rule("py-rng", PY, RNG, _r(r"\brandom\.(getrandbits|choice)\("), lambda m: {
        "getrandbits": "secrets.randbits(", "choice": "secrets.choice("}[m.group(1)], 70,
         "Use the secrets module (CSPRNG) instead of random.{old}.", ("Add `import secrets`.",)),
    Rule("py-jwt-verify", PY, frozenset({"WEAK_ALGORITHM", "TLS_VERIFICATION_DISABLED", "WEAK_PROTOCOL"}),
         _r(r"""(["']verify_signature["']\s*:\s*)False"""), r"\1True", 70, "Verify JWT signatures.",
         ("Also pin the accepted algorithms, e.g. algorithms=['RS256'].",)),
    # ------------------------------------------------------------------------------------------ Java
    Rule("java-digest", JAVA, WEAK, _r(r"""(MessageDigest\.getInstance\(\s*")(MD5|MD2|MD4|SHA-1|SHA1|SHA)(")"""),
         r"\1SHA-256\3", 85, "Use SHA-256 in MessageDigest.", N_HASH, HASHES),
    Rule("java-cipher-sym", JAVA, MODE | WEAK,
         _r(r"""(Cipher\.getInstance\(\s*")((?:DES|DESede|TripleDES|RC4|ARCFOUR|Blowfish|RC2)(?:/[^"]*)?|AES(?:/(?:ECB|CBC)/[^"]*)?)(")"""),
         r"\1AES/GCM/NoPadding\3", 50, "Use AES/GCM/NoPadding instead of {old}.",
         N_GCM + ("Initialise with new GCMParameterSpec(128, iv) where iv is 12 random bytes from SecureRandom.",
                  "Cipher.getInstance(\"AES\") alone means AES/ECB/PKCS5Padding on most providers.")),
    Rule("java-cipher-rsa-pad", JAVA, PAD, _r(r"""(Cipher\.getInstance\(\s*")(RSA(?:/ECB/(?:PKCS1Padding|NoPadding))?)(")"""),
         r"\1RSA/ECB/OAEPWithSHA-256AndMGF1Padding\3", 70, "Use RSA-OAEP padding.",
         ("Both sides must switch together: OAEP and PKCS#1 v1.5 ciphertexts are not interchangeable.",)),
    Rule("java-keygen", JAVA, WEAK, _r(r"""(KeyGenerator\.getInstance\(\s*")(DES|DESede|TripleDES|Blowfish|RC4|RC2)(")"""),
         r"\1AES\3", 60, "Generate AES keys instead of {old}.", ("Then call keyGenerator.init(256).",), BLOCK64),
    Rule("java-keypair-size", JAVA, KEYSZ, _r(r"(\.initialize\(\s*)(512|768|1024|1536)\b"), r"\g<1>3072", 85,
         "Use 3072-bit keys.", N_KEY),
    Rule("java-signature", JAVA, WEAK, _r(r"""(Signature\.getInstance\(\s*")(?:MD5|SHA1|SHA)with(RSA|ECDSA|DSA)(")""", re.I),
         r"\1SHA256with\2\3", 85, "Sign with SHA-256.", N_HASH, HASHES),
    Rule("java-mac", JAVA, WEAK, _r(r"""(Mac\.getInstance\(\s*")Hmac(MD5|SHA1)(")""", re.I), r"\1HmacSHA256\3", 80,
         "Use HmacSHA256.", N_HASH, HASHES),
    Rule("java-sslcontext", JAVA, PROTO, _r(r"""(SSLContext\.getInstance\(\s*")(SSL|SSLv2|SSLv3|TLSv1|TLSv1\.1)(")"""),
         r"\1TLSv1.3\3", 80, "Use TLS 1.3.", N_PROTO),
    Rule("java-pbkdf2", JAVA, WEAK, _r(r"""(SecretKeyFactory\.getInstance\(\s*")PBKDF2WithHmacSHA1(")"""),
         r"\1PBKDF2WithHmacSHA256\2", 70, "Use PBKDF2 with HMAC-SHA256.",
         ("Stored derived keys/password hashes need a re-hash on next login.",)),
    Rule("java-random", JAVA, RNG, _r(r"\bnew\s+Random\(\s*\)"), "new SecureRandom()", 70,
         "Use SecureRandom.", ("Import java.security.SecureRandom.",),
         imports=((_r(r"^(\s*import\s+)java\.util\.Random\s*;"), r"\1java.security.SecureRandom;"),)),
    # ------------------------------------------------------------------------------------------ JavaScript / TypeScript
    Rule("js-hash", JS, WEAK, _r(r"""(create(?:Hash|Hmac)\(\s*)(['"`])(md5|sha1)\2""", re.I), r"\1\2sha256\2", 85,
         "Use SHA-256 in createHash/createHmac.", N_HASH, HASHES),
    Rule("js-cipheriv", JS, MODE | WEAK,
         _r(r"""(create(?:Cipheriv|Decipheriv)\(\s*)(['"`])(des[\w-]*|rc4[\w-]*|bf[\w-]*|blowfish[\w-]*|rc2[\w-]*|aes-(?:128|192|256)-(?:ecb|cbc))\2""", re.I),
         r"\1\2aes-256-gcm\2", 50, "Use aes-256-gcm instead of {old}.",
         N_GCM + ("Node: call cipher.getAuthTag() after final() and decipher.setAuthTag(tag) before final(); use a "
                  "12-byte iv from crypto.randomBytes(12) and a 32-byte key.",)),
    Rule("js-reject-unauthorized", JS, TLSOFF, _r(r"(rejectUnauthorized\s*:\s*)false\b"), r"\1true", 90,
         "Verify server certificates.", N_TLS),
    Rule("js-strict-ssl", JS, TLSOFF, _r(r"(strictSSL\s*:\s*)false\b"), r"\1true", 85, "Verify server certificates.",
         N_TLS),
    Rule("js-node-tls-env", JS, TLSOFF,
         _r(r"""^(\s*)(process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"`]?0['"`]?\s*;?)"""),
         r"\1// removed: \2 (certificate verification must stay on)", 85,
         "Stop disabling TLS verification for the whole process.", N_TLS),
    Rule("js-cryptojs-hash", JS, WEAK, _r(r"\bCryptoJS\.(MD5|SHA1)\("), "CryptoJS.SHA256(", 85,
         "Use CryptoJS.SHA256.", N_HASH, HASHES),
    Rule("js-cryptojs-cipher", JS, WEAK, _r(r"\bCryptoJS\.(DES|TripleDES|RC4|Rabbit)\.(encrypt|decrypt)\("),
         lambda m: f"CryptoJS.AES.{m.group(2)}(", 40, "Replace {old} with AES.",
         N_GCM + ("CryptoJS AES defaults to CBC without authentication; prefer the Web Crypto API AES-GCM.",), BLOCK64),
    Rule("js-forge-md", JS, WEAK, _r(r"\bforge\.md\.(md5|sha1)\.create\(\)"), "forge.md.sha256.create()", 85,
         "Use forge.md.sha256.", N_HASH, HASHES),
    Rule("js-modulus", JS, KEYSZ, _r(r"((?:modulusLength|bits)\s*:\s*)(512|768|1024|1536)\b"), r"\g<1>3072", 85,
         "Use 3072-bit RSA keys.", N_KEY),
    Rule("js-webcrypto-hash", JS, WEAK, _r(r"""(hash\s*:\s*(?:\{\s*name\s*:\s*)?)(['"`])SHA-1\2"""), r"\1\2SHA-256\2", 75,
         "Use SHA-256 in the Web Crypto parameters.", N_HASH, HASHES),
    Rule("js-secure-protocol", JS, PROTO, _r(r"""secureProtocol\s*:\s*(['"`])(TLSv1_method|TLSv1_1_method|SSLv3_method|SSLv23_method)\1"""),
         "minVersion: 'TLSv1.2'", 70, "Require TLS 1.2+.", N_PROTO),
    # ------------------------------------------------------------------------------------------ Go
    Rule("go-hash", GO, WEAK, _r(r"\b(md5|sha1)\.(New|Sum)\("),
         lambda m: "sha256.New(" if m.group(2) == "New" else "sha256.Sum256(", 80, "Use crypto/sha256.",
         N_HASH + ("sha256.Sum256 returns [32]byte.",), HASHES,
         imports=((_r(r'"crypto/(md5|sha1)"'), '"crypto/sha256"'),),
         warning="If the crypto/md5 or crypto/sha1 import is outside this window, change it too (Go rejects unused "
                 "imports)."),
    Rule("go-des", GO, WEAK, _r(r"\bdes\.(NewCipher|NewTripleDESCipher)\("), "aes.NewCipher(", 45,
         "Use AES (with cipher.NewGCM) instead of {old}.", N_GCM, BLOCK64,
         imports=((_r(r'"crypto/des"'), '"crypto/aes"'),)),
    Rule("go-skip-verify", GO, TLSOFF, _r(r"(InsecureSkipVerify\s*:\s*)true\b"), r"\1false", 90,
         "Verify server certificates.", N_TLS),
    Rule("go-min-version", GO, PROTO, _r(r"(MinVersion\s*:\s*)tls\.Version(SSL30|TLS10|TLS11)\b"),
         r"\1tls.VersionTLS12", 85, "Require TLS 1.2+.", N_PROTO),
    Rule("go-rsa-size", GO, KEYSZ, _r(r"(rsa\.GenerateKey\(\s*[\w.]+\s*,\s*)(512|768|1024|1536)\b"), r"\g<1>3072", 85,
         "Use 3072-bit RSA keys.", N_KEY),
    # ------------------------------------------------------------------------------------------ C#
    Rule("cs-hash-create", CS, WEAK, _r(r"\b(MD5|SHA1)\.Create\(\)"), "SHA256.Create()", 80, "Use SHA-256.",
         N_HASH, HASHES),
    Rule("cs-hash-new", CS, WEAK, _r(r"\bnew\s+(MD5CryptoServiceProvider|SHA1Managed|SHA1CryptoServiceProvider|MD5Cng|SHA1Cng)\(\s*\)"),
         "SHA256.Create()", 80, "Use SHA-256.", N_HASH, HASHES),
    Rule("cs-hmac", CS, WEAK, _r(r"\bnew\s+HMAC(MD5|SHA1)\("), "new HMACSHA256(", 85, "Use HMACSHA256.", N_HASH,
         HASHES),
    Rule("cs-sym", CS, WEAK, _r(r"\b(?:(DES|TripleDES|RC2)\.Create\(\)|new\s+(DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider)\(\s*\))"),
         "Aes.Create()", 45, "Use AES instead of {old}.",
         N_GCM + ("For authenticated encryption use System.Security.Cryptography.AesGcm.",), BLOCK64),
    Rule("cs-ecb", CS, MODE, _r(r"\bCipherMode\.ECB\b"), "CipherMode.CBC", 40,
         "Stop using ECB.", N_GCM + ("CBC needs a random IV per message (aes.GenerateIV()); AesGcm is better still.",)),
    Rule("cs-rsa-size", CS, KEYSZ, _r(r"\b(new\s+RSACryptoServiceProvider|RSA\.Create)\(\s*(512|768|1024|1536)\s*\)"),
         lambda m: f"{m.group(1)}(3072)", 85, "Use 3072-bit RSA keys.", N_KEY),
    Rule("cs-cert-callback", CS, TLSOFF,
         _r(r"^(\s*)(.*ServerCertificate(?:Custom)?ValidationCallback\s*\+?=\s*(?:\([^)]*\)\s*=>\s*true|HttpClientHandler\.DangerousAcceptAnyServerCertificateValidator).*)$"),
         r"\1// removed: \2  (never accept every certificate)", 80, "Stop accepting every certificate.", N_TLS),
    Rule("cs-ssl-protocols", CS, PROTO, _r(r"\bSslProtocols\.(Ssl2|Ssl3|Tls11|Tls)\b(?!1[23])"),
         "SslProtocols.Tls12 | SslProtocols.Tls13", 70, "Use TLS 1.2/1.3.", N_PROTO),
    # ------------------------------------------------------------------------------------------ C / C++ (OpenSSL)
    Rule("c-evp-md", C, WEAK, _r(r"\bEVP_(md5|sha1)\(\)"), "EVP_sha256()", 85, "Use EVP_sha256().", N_HASH, HASHES),
    Rule("c-oneshot", C, WEAK, _r(r"\b(MD5|SHA1)\("), "SHA256(", 60, "Use SHA256().", N_HASH, HASHES,
         imports=((_r(r"\b(MD5|SHA)_DIGEST_LENGTH\b"), "SHA256_DIGEST_LENGTH"),)),
    Rule("c-evp-cipher", C, MODE | WEAK, _r(r"\bEVP_(des_\w+|des_ede3?\w*|rc4|bf_\w+|rc2_\w+|aes_(?:128|192|256)_ecb)\(\)"),
         "EVP_aes_256_gcm()", 45, "Use AES-256-GCM.",
         N_GCM + ("Set the IV length (EVP_CTRL_GCM_SET_IVLEN, 12) and get/set the 16-byte tag (EVP_CTRL_GCM_GET_TAG / "
                  "SET_TAG).",)),
    Rule("c-rsa-size", C, KEYSZ, _r(r"(\bRSA_generate_key(?:_ex)?\(\s*(?:[^,()]+,\s*)?)(512|768|1024|1536)\b"),
         r"\g<1>3072", 80, "Use 3072-bit RSA keys.", N_KEY),
    Rule("c-verify-none", C, TLSOFF, _r(r"\bSSL_VERIFY_NONE\b"), "SSL_VERIFY_PEER", 85, "Verify the peer.", N_TLS),
    Rule("c-method", C, PROTO, _r(r"\b(?:TLSv1_1|TLSv1|SSLv3|SSLv23|SSLv2)_(client_|server_)?method\(\)"),
         lambda m: f"TLS_{m.group(1) or ''}method()", 70, "Use the version-flexible TLS method.",
         N_PROTO + ("Then call SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION).",)),
    # ------------------------------------------------------------------------------------------ PHP
    Rule("php-hash-fn", PHP, WEAK, _r(r"(?<![\w>$:])(md5|sha1)\(\s*"), "hash('sha256', ", 75, "Use hash('sha256', ...).",
         N_HASH + ("For passwords use password_hash()/password_verify() instead of any plain hash.",), HASHES),
    Rule("php-hash-algo", PHP, WEAK, _r(r"""(\bhash(?:_hmac)?\(\s*)(['"])(md5|sha1)\2""", re.I), r"\1\2sha256\2", 85,
         "Use SHA-256.", N_HASH, HASHES),
    Rule("php-openssl", PHP, MODE | WEAK,
         _r(r"""(openssl_(?:en|de)crypt\([^,]+,\s*)(['"])(des[\w-]*|bf[\w-]*|rc4[\w-]*|rc2[\w-]*|aes-(?:128|192|256)-ecb)\2""", re.I),
         r"\1\2aes-256-gcm\2", 40, "Use aes-256-gcm.", N_GCM + ("Pass the $tag argument (by reference) and store it.",)),
    Rule("php-curl-verify", PHP, TLSOFF, _r(r"(CURLOPT_SSL_VERIFYPEER\s*,\s*)(?:false|0)\b", re.I), r"\1true", 90,
         "Verify the peer certificate.", N_TLS),
    Rule("php-curl-host", PHP, TLSOFF, _r(r"(CURLOPT_SSL_VERIFYHOST\s*,\s*)(?:false|0)\b", re.I), r"\g<1>2", 90,
         "Verify the host name.", N_TLS),
    # ------------------------------------------------------------------------------------------ Ruby
    Rule("rb-digest", RB, WEAK, _r(r"\b((?:OpenSSL::)?Digest::)(MD5|SHA1)\b"), r"\1SHA256", 85, "Use SHA-256.", N_HASH,
         HASHES),
    Rule("rb-digest-new", RB, WEAK, _r(r"""(OpenSSL::Digest\.new\(\s*)(['"])(md5|sha1)\2""", re.I), r"\1\2SHA256\2", 85,
         "Use SHA-256.", N_HASH, HASHES),
    Rule("rb-cipher", RB, MODE | WEAK, _r(r"""(OpenSSL::Cipher\.new\(\s*)(['"])(des[\w-]*|bf[\w-]*|rc4|aes-\d+-ecb)\2""", re.I),
         r"\1\2aes-256-gcm\2", 40, "Use aes-256-gcm.", N_GCM),
    Rule("rb-verify-none", RB, TLSOFF, _r(r"\bOpenSSL::SSL::VERIFY_NONE\b"), "OpenSSL::SSL::VERIFY_PEER", 90,
         "Verify the peer.", N_TLS),
    # ------------------------------------------------------------------------------------------ Terraform
    Rule("tf-storage-encrypted", TF, REST, _r(r"(\b(?:storage_)?encrypted\s*=\s*)false\b"), r"\1true", 40,
         "Encrypt the storage.", ("Set kms_key_id to a customer-managed key if your policy requires one.",),
         block=True, warning="Changing encryption on an existing RDS instance or EBS volume forces replacement: snapshot, "
                 "copy the snapshot with encryption, restore, then switch traffic. Plan it; do not apply blindly."),
    Rule("tf-elb-policy", TF, PROTO | REST | WEAK,
         _r(r"""(ssl_policy\s*=\s*")ELBSecurityPolicy-(?:2015-05|2016-08|TLS-1-0-2015-04|TLS-1-1-2017-01|2015-03|2014-\d\d|FS-2018-06)(")"""),
         r"\1ELBSecurityPolicy-TLS13-1-2-2021-06\2", 80, "Use a TLS 1.2/1.3 listener policy.", N_PROTO, block=True),
    Rule("tf-cloudfront-min", TF, PROTO, _r(r"""(minimum_protocol_version\s*=\s*")(?:SSLv3|TLSv1|TLSv1_2016|TLSv1\.1_2016)(")"""),
         r"\1TLSv1.2_2021\2", 85, "Require TLS 1.2 at the edge.", N_PROTO, block=True),
)

_NON_SECURITY_MD5 = _r(r"usedforsecurity\s*=\s*False|etag|content[-_]?md5|uuid3|uuid\.uuid3|cache[-_]?key|"
                       r"\bchecksum_for_dedup\b|s3.*md5|md5.*etag", re.I)
_PASSWORD = _r(r"passw|pwd|credential", re.I)


def _algo_text(f: dict[str, Any]) -> str:
    return " ".join(str(f.get(k) or "") for k in ("title", "algorithm_name", "description", "mode")).lower()


def _split_keep(text: str) -> list[tuple[str, str]]:
    """[(content, ending)] with ending "\\r" when the file used CRLF on that line."""
    out = []
    for raw in text.split("\n"):
        out.append((raw[:-1], "\r") if raw.endswith("\r") else (raw, ""))
    return out


def _quote_path(path: str) -> str:
    """Path for a diff header: control characters escaped, C-quoted when not plain."""
    clean = "".join(ch if ch.isprintable() and ch not in "‪‫‬‭‮⁦⁧⁨⁩"
                    else f"\\x{ord(ch):02x}" for ch in path)
    if re.fullmatch(r"[A-Za-z0-9._/+@-]+", clean):
        return clean
    return '"' + clean.replace("\\", "\\\\").replace('"', '\\"') + '"'


def unified_diff(path: str, start: int, before: list[str], after: list[str]) -> str:
    """One hunk over the whole window with the real line numbers. Lines are given without their ending."""
    if before == after:
        return ""
    qp = _quote_path(path or "file")
    a = f"a/{qp}" if not qp.startswith('"') else '"a/' + qp[1:]
    b = f"b/{qp}" if not qp.startswith('"') else '"b/' + qp[1:]
    body = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes():
        if tag == "equal":
            body += [" " + x for x in before[i1:i2]]
        else:
            body += ["-" + x for x in before[i1:i2]] + ["+" + x for x in after[j1:j2]]
    return "\n".join([f"--- {a}", f"+++ {b}", f"@@ -{start},{len(before)} +{start},{len(after)} @@", *body]) + "\n"


def _fixed_version(f: dict[str, Any]) -> str | None:
    m = re.search(r"Fixed in ([0-9][\w.\-+]*)", str(f.get("description") or ""))
    return m.group(1).rstrip(".") if m else None


def _dependency_fix(f: dict[str, Any], lines: list[tuple[str, str]], idx: int, path: str) -> dict[str, Any] | None:
    """Version bump in the manifest line, or the package-manager command for a lock file."""
    title = str(f.get("title") or "")
    name, _, current = title.partition("@")
    fixed = _fixed_version(f)
    if not name or not fixed:
        return None
    if current.startswith("v") and not fixed.startswith("v"):
        fixed = "v" + fixed
    base = path.rsplit("/", 1)[-1].lower()
    lang = str(f.get("language") or "")
    commands: list[str] = []
    eco_cmd = {
        "package-lock.json": f"npm install {name}@^{fixed}", "yarn.lock": f"yarn add {name}@^{fixed}",
        "pnpm-lock.yaml": f"pnpm add {name}@^{fixed}", "go.sum": f"go get {name}@v{fixed.lstrip('v')} && go mod tidy",
        "cargo.lock": f"cargo update -p {name} (and set {name} = \"{fixed}\" in Cargo.toml)",
        "packages.lock.json": f"dotnet add package {name} --version {fixed}",
        "poetry.lock": f"poetry add {name}@^{fixed}", "pipfile.lock": f"pipenv install '{name}>={fixed}'",
        "composer.lock": f"composer require {name}:^{fixed}", "gemfile.lock": f"bundle update {name}",
    }
    notes = [f"{title} matches a published advisory; {fixed} is the first fixed release."]
    if "bcprov-jdk15on" in name:
        notes.append("Bouncy Castle renamed the artifact: versions after 1.70 ship as bcprov-jdk18on.")
    if base in eco_cmd or lang == "lockfile":
        commands.append(eco_cmd.get(base, f"upgrade {name} to {fixed} with your package manager"))
        return {"kind": "dependency", "commands": commands, "fixed_lines": None, "confidence": 80,
                "summary": f"Upgrade {name} from {current or 'the current version'} to {fixed} (lock files are "
                           "regenerated by the package manager, not edited by hand).", "notes": notes, "rules": [
                    "dep-command"]}
    content, ending = lines[idx]
    esc_cur = re.escape(current.lstrip("v")) if current else r"[\w.\-+]+"
    new = content
    if base.startswith("requirements") or lang == "pip-requirements":
        new = re.sub(rf"(?i)^(\s*{re.escape(name)}\s*(?:\[[^\]]*\])?\s*)(==|~=|<=|<)\s*{esc_cur}", rf"\1>={fixed}", content)
    elif base == "package.json":
        new = re.sub(rf'("{re.escape(name)}"\s*:\s*")[~^]?{esc_cur}(")', rf"\g<1>^{fixed}\2", content)
    elif base == "go.mod":
        new = re.sub(rf"({re.escape(name)}\s+)v{esc_cur}\b", rf"\g<1>v{fixed.lstrip('v')}", content)
    elif base == "cargo.toml":
        new = re.sub(rf'(^\s*{re.escape(name)}\s*=\s*(?:\{{[^}}]*version\s*=\s*)?")[~^=]?{esc_cur}(")', rf"\g<1>{fixed}\2",
                     content)
    elif base == "pom.xml" or base.endswith(".gradle") or base.endswith(".kts"):
        new = re.sub(rf"(<version>\s*){esc_cur}(\s*</version>)", rf"\g<1>{fixed}\2", content)
        new = re.sub(rf"(:{re.escape(name.split(':')[-1])}:){esc_cur}\b", rf"\g<1>{fixed}", new)
    elif base.endswith(".csproj"):
        new = re.sub(rf'(Version\s*=\s*"){esc_cur}(")', rf"\g<1>{fixed}\2", content)
    if new == content and base == "pom.xml":  # the <version> sits a line or two below the artifactId
        for j in range(idx, min(len(lines), idx + 4)):
            c2, e2 = lines[j]
            n2 = re.sub(rf"(<version>\s*){esc_cur}(\s*</version>)", rf"\g<1>{fixed}\2", c2)
            if n2 != c2:
                fixed_lines = list(lines)
                fixed_lines[j] = (n2, e2)
                if "bcprov-jdk15on" in name:
                    for k in range(max(0, j - 3), j + 1):
                        ck, ek = fixed_lines[k]
                        fixed_lines[k] = (ck.replace("bcprov-jdk15on", "bcprov-jdk18on"), ek)
                return {"kind": "dependency", "commands": [], "fixed_lines": fixed_lines, "confidence": 75,
                        "summary": f"Upgrade {name} to {fixed}.", "notes": notes, "rules": ["dep-pom"]}
    if new == content:
        commands.append(f"upgrade {name} to {fixed} with your package manager")
        return {"kind": "dependency", "commands": commands, "fixed_lines": None, "confidence": 70,
                "summary": f"Upgrade {name} to {fixed}.", "notes": notes, "rules": ["dep-command"]}
    fixed_lines = list(lines)
    fixed_lines[idx] = (new, ending)
    return {"kind": "dependency", "commands": commands, "fixed_lines": fixed_lines, "confidence": 85,
            "summary": f"Upgrade {name} from {current} to {fixed}.", "notes": notes, "rules": ["dep-manifest"]}


def generate(finding: dict[str, Any]) -> dict[str, Any]:
    """The code-level fix for one finding. Always returns a dict; ``available`` says whether code was produced."""
    snippet = finding.get("snippet") or ""
    start = finding.get("snippet_start")
    line = finding.get("line")
    lang = str(finding.get("language") or "").lower()
    path = re.sub(r":\d+$", "", str(finding.get("location") or ""))
    codes = set(finding.get("finding_codes") or [])
    base = {"version": FIXGEN_VERSION, "language": lang or "text", "original_code": snippet, "fixed_code": "",
            "diff": "", "confidence": 0, "rules": [], "notes": [], "commands": [], "warnings": [], "kind": "manual",
            "available": False, "summary": ""}
    if not snippet or not isinstance(start, int) or not isinstance(line, int) or not (start <= line):
        base["summary"] = ("No source window was stored for this finding (an older scan, a non-code source, or key "
                           "material that is never copied). Rescan the repository to get a code-level fix.")
        return base
    lines = _split_keep(snippet)
    idx = line - start
    if not 0 <= idx < len(lines):
        base["summary"] = "The stored window does not contain the reported line."
        return base
    if "<redacted" in lines[idx][0] and not codes & {"VULNERABLE_CRYPTO_LIBRARY"}:
        base["warnings"].append("Secret values on this line are redacted in the finding; the fix is shown around "
                                "them and must be applied by hand.")

    if "VULNERABLE_CRYPTO_LIBRARY" in codes:
        dep = _dependency_fix(finding, lines, idx, path)
        if dep:
            return _finish(base, dep, lines, start, path)
        base["summary"] = "Upgrade the library to the fixed release named in the advisory."
        return base

    text = _algo_text(finding)
    occ_line = lines[idx][0]
    if codes & {"WEAK_ALGORITHM"} and re.search(r"md5|sha-?1", text) and _NON_SECURITY_MD5.search(
            occ_line + " " + text):
        base["kind"] = "non-security-use"
        base["summary"] = ("This MD5/SHA-1 call looks like a non-security use (ETag, Content-MD5, de-duplication, "
                           "UUIDv3, usedforsecurity=False). No rewrite is proposed; mark it as accepted if the value "
                           "never protects integrity or authenticity, or switch to SHA-256 if it does.")
        return base
    applied: list[Rule] = []
    new_lines = list(lines)
    for rule in RULES:
        if lang not in rule.langs or not (codes & rule.codes):
            continue
        if rule.algo is not None and not rule.algo.search(text + " " + occ_line):
            continue
        targets = [idx] + (list(range(idx + 1, len(new_lines))) if rule.block else [])
        hit = None
        for t in targets:
            content, ending = new_lines[t]
            if rule.pattern.search(content):
                hit = t
                break
            if rule.block and t > idx and re.match(r"^\s*(resource|data|module)\s+\"", content):
                break  # the next block starts: stop
        if hit is None:
            continue
        content, ending = new_lines[hit]
        new_lines[hit] = (rule.pattern.sub(rule.repl, content), ending)
        for rx, repl in rule.imports:
            for j, (c2, e2) in enumerate(new_lines):
                if j != hit and rx.search(c2):
                    new_lines[j] = (rx.sub(repl, c2), e2)
        applied.append(rule)
    if not applied:
        base["summary"] = ("No safe automatic rewrite matches this code; follow the knowledge-base steps for the "
                           "change.")
        return base
    if codes & {"WEAK_ALGORITHM"} and _PASSWORD.search(text + " " + occ_line):
        base["warnings"].append("This hash appears to protect passwords: switch to a password KDF (Argon2id, scrypt, "
                                "bcrypt or PBKDF2-SHA256 with a salt) and re-hash on next login; a faster hash is "
                                "not a fix.")
    old = str(finding.get("algorithm_name") or finding.get("title") or "the weak setting")
    res = {"kind": "code", "fixed_lines": new_lines, "commands": [], "confidence": min(r.confidence for r in applied),
           "summary": " ".join(dict.fromkeys(r.summary.format(old=old) for r in applied)),
           "notes": [n for r in applied for n in r.notes], "rules": [r.rid for r in applied],
           "warnings": [r.warning for r in applied if r.warning]}
    return _finish(base, res, lines, start, path)


def _finish(base: dict[str, Any], res: dict[str, Any], lines: list[tuple[str, str]], start: int,
            path: str) -> dict[str, Any]:
    out = dict(base)
    out["kind"] = res["kind"]
    out["confidence"] = res["confidence"]
    out["summary"] = res["summary"]
    out["notes"] = list(dict.fromkeys(res.get("notes") or []))
    out["rules"] = res.get("rules") or []
    out["commands"] = res.get("commands") or []
    out["warnings"] = list(dict.fromkeys(base.get("warnings", []) + (res.get("warnings") or [])))
    fixed = res.get("fixed_lines")
    if fixed:
        out["fixed_code"] = "\n".join(c + e for c, e in fixed)
        out["diff"] = unified_diff(path, start, [c for c, _ in lines], [c for c, _ in fixed])
        out["available"] = bool(out["diff"])
    else:
        out["available"] = bool(out["commands"])
    if any("<redacted" in c for c, _ in (fixed or [])):
        out["warnings"].append("The window contains redacted values: apply the change by hand rather than with "
                               "`git apply`.")
    return out


__all__ = ["generate", "unified_diff", "RULES", "FIXGEN_VERSION"]
