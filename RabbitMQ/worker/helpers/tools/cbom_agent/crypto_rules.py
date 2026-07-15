"""
Crypto detection rules for 7 programming languages.
Each rule maps import patterns / function calls to cryptographic asset metadata.
"""

from typing import Literal

# Language detection by file extension
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cpp": "c",
    ".cc": "c",
    ".cxx": "c",
    ".hpp": "c",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
    ".phtml": "php",
    ".kt": "java",
    ".kts": "java",
    ".scala": "java",
}

# Weak / deprecated algorithms — flagged as vulnerabilities
WEAK_ALGORITHMS = {
    # Hashes
    "md5": {"type": "hash", "strength": "weak", "impact": "High", "quantum_safe": False},
    "md4": {"type": "hash", "strength": "weak", "impact": "Critical", "quantum_safe": False},
    "sha1": {"type": "hash", "strength": "weak", "impact": "High", "quantum_safe": False},
    "sha-1": {"type": "hash", "strength": "weak", "impact": "High", "quantum_safe": False},
    # Symmetric
    "des": {"type": "symmetric_cipher", "strength": "weak", "impact": "Critical", "quantum_safe": False},
    "3des": {"type": "symmetric_cipher", "strength": "moderate", "impact": "High", "quantum_safe": False},
    "triple_des": {"type": "symmetric_cipher", "strength": "moderate", "impact": "High", "quantum_safe": False},
    "tripledes": {"type": "symmetric_cipher", "strength": "moderate", "impact": "High", "quantum_safe": False},
    "rc2": {"type": "symmetric_cipher", "strength": "weak", "impact": "Critical", "quantum_safe": False},
    "rc4": {"type": "symmetric_cipher", "strength": "weak", "impact": "Critical", "quantum_safe": False},
    "blowfish": {"type": "symmetric_cipher", "strength": "moderate", "impact": "Medium", "quantum_safe": False},
    # Asymmetric with small key sizes
    "rsa-512": {"type": "asymmetric_cipher", "strength": "weak", "impact": "Critical", "quantum_safe": False, "key_size": 512},
    "rsa-1024": {"type": "asymmetric_cipher", "strength": "weak", "impact": "High", "quantum_safe": False, "key_size": 1024},
}

# Strong / standard algorithms — inventoried but not flagged as vulnerabilities
STANDARD_ALGORITHMS = {
    # Hashes
    "sha256": {"type": "hash", "strength": "strong", "quantum_safe": False},
    "sha-256": {"type": "hash", "strength": "strong", "quantum_safe": False},
    "sha384": {"type": "hash", "strength": "strong", "quantum_safe": False},
    "sha-384": {"type": "hash", "strength": "strong", "quantum_safe": False},
    "sha512": {"type": "hash", "strength": "strong", "quantum_safe": False},
    "sha-512": {"type": "hash", "strength": "strong", "quantum_safe": False},
    "sha3_256": {"type": "hash", "strength": "strong", "quantum_safe": True},
    "sha3_384": {"type": "hash", "strength": "strong", "quantum_safe": True},
    "sha3_512": {"type": "hash", "strength": "strong", "quantum_safe": True},
    "blake2b": {"type": "hash", "strength": "strong", "quantum_safe": False},
    "blake2s": {"type": "hash", "strength": "strong", "quantum_safe": False},
    # Symmetric
    "aes": {"type": "symmetric_cipher", "strength": "strong", "quantum_safe": False},
    "aes-128": {"type": "symmetric_cipher", "strength": "strong", "quantum_safe": False, "key_size": 128},
    "aes-192": {"type": "symmetric_cipher", "strength": "strong", "quantum_safe": False, "key_size": 192},
    "aes-256": {"type": "symmetric_cipher", "strength": "strong", "quantum_safe": False, "key_size": 256},
    "aes-gcm": {"type": "symmetric_cipher", "strength": "strong", "quantum_safe": False},
    "chacha20": {"type": "symmetric_cipher", "strength": "strong", "quantum_safe": False},
    "chacha20-poly1305": {"type": "symmetric_cipher", "strength": "strong", "quantum_safe": False},
    # Asymmetric
    "rsa": {"type": "asymmetric_cipher", "strength": "strong", "quantum_safe": False},
    "rsa-2048": {"type": "asymmetric_cipher", "strength": "strong", "quantum_safe": False, "key_size": 2048},
    "rsa-4096": {"type": "asymmetric_cipher", "strength": "strong", "quantum_safe": False, "key_size": 4096},
    "ecdsa": {"type": "asymmetric_cipher", "strength": "strong", "quantum_safe": False},
    "ed25519": {"type": "signature", "strength": "strong", "quantum_safe": False},
    "ed448": {"type": "signature", "strength": "strong", "quantum_safe": False},
    "x25519": {"type": "asymmetric_cipher", "strength": "strong", "quantum_safe": False},
    "dh": {"type": "asymmetric_cipher", "strength": "strong", "quantum_safe": False},
    "ecdh": {"type": "asymmetric_cipher", "strength": "strong", "quantum_safe": False},
    "dsa": {"type": "signature", "strength": "moderate", "quantum_safe": False},
    # KDF
    "pbkdf2": {"type": "key_derivation", "strength": "strong", "quantum_safe": False},
    "scrypt": {"type": "key_derivation", "strength": "strong", "quantum_safe": False},
    "argon2": {"type": "key_derivation", "strength": "strong", "quantum_safe": False},
    "hkdf": {"type": "key_derivation", "strength": "strong", "quantum_safe": False},
    "bcrypt": {"type": "key_derivation", "strength": "strong", "quantum_safe": False},
    # MAC
    "hmac": {"type": "mac", "strength": "strong", "quantum_safe": False},
    "cmac": {"type": "mac", "strength": "strong", "quantum_safe": False},
    "poly1305": {"type": "mac", "strength": "strong", "quantum_safe": False},
    # Protocols
    "tls": {"type": "protocol", "strength": "strong", "quantum_safe": False},
    "ssl": {"type": "protocol", "strength": "weak", "quantum_safe": False},
    "sslv3": {"type": "protocol", "strength": "weak", "quantum_safe": False},
    "tls1.0": {"type": "protocol", "strength": "weak", "quantum_safe": False},
    "tls1.1": {"type": "protocol", "strength": "weak", "quantum_safe": False},
    "tls1.2": {"type": "protocol", "strength": "strong", "quantum_safe": False},
    "tls1.3": {"type": "protocol", "strength": "strong", "quantum_safe": False},
    # PQC
    "kyber": {"type": "asymmetric_cipher", "strength": "quantum_safe", "quantum_safe": True},
    "dilithium": {"type": "signature", "strength": "quantum_safe", "quantum_safe": True},
    "sphincs+": {"type": "signature", "strength": "quantum_safe", "quantum_safe": True},
    "falcon": {"type": "signature", "strength": "quantum_safe", "quantum_safe": True},
    # RNG
    "csprng": {"type": "random_number_generator", "strength": "strong", "quantum_safe": False},
    "urandom": {"type": "random_number_generator", "strength": "strong", "quantum_safe": False},
    "securerandom": {"type": "random_number_generator", "strength": "strong", "quantum_safe": False},
}


# Language-specific import/usage patterns (regex patterns)
LANGUAGE_PATTERNS = {
    "python": [
        # hashlib
        r"hashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_384|sha3_512|blake2b|blake2s|new)\s*\(",
        r"from\s+hashlib\s+import",
        # cryptography library
        r"from\s+cryptography\.",
        r"cryptography\.(fernet|hazmat|x509)",
        r"(AES|DES|TripleDES|Blowfish|ARC4|ChaCha20|AESGCM|AESCCM)\s*[\.(]",
        r"(RSA|EllipticCurve|ECDSA|Ed25519|Ed448|X25519|X448|DH|DSA)\s*[\.(]",
        r"(PBKDF2HMAC|Scrypt|HKDF|ConcatKDFHash|X963KDF)\s*[\.(]",
        r"(HMAC|CMAC|Poly1305)\s*[\.(]",
        # PyCryptodome
        r"from\s+Crypto\.",
        r"from\s+Cryptodome\.",
        r"Crypto\.(Cipher|Hash|PublicKey|Signature|Protocol|Random)",
        # ssl/tls
        r"import\s+ssl",
        r"ssl\.(SSLContext|PROTOCOL_TLS|PROTOCOL_SSLv23|PROTOCOL_TLSv1)",
        # secrets/random
        r"import\s+secrets",
        r"os\.urandom\s*\(",
        r"secrets\.(token_bytes|token_hex|token_urlsafe)\s*\(",
        # bcrypt/passlib
        r"import\s+bcrypt",
        r"from\s+passlib\.",
        # jwt
        r"import\s+jwt",
        r"from\s+jose\s+import",
        r"PyJWT|python-jose",
    ],
    "javascript": [
        r"require\s*\(\s*['\"]crypto['\"]\s*\)",
        r"from\s+['\"]crypto['\"]",
        r"crypto\.(createHash|createHmac|createCipheriv|createCipher|createDecipheriv|createDecipher|createSign|createVerify|createDiffieHellman|randomBytes|randomFillSync|generateKeyPairSync|generateKeyPair|generateKeySync|generateKey|createPublicKey|createPrivateKey|createSecretKey|scryptSync|scrypt|pbkdf2Sync|pbkdf2)\s*\(",
        r"\b(createHash|createHmac|createCipheriv|createSign|createVerify|generateKeyPairSync|generateKeyPair|createPublicKey|createPrivateKey|createSecretKey|pbkdf2|scrypt|randomBytes)\s*\(",
        r"crypto\.subtle\.(encrypt|decrypt|sign|verify|digest|generateKey|deriveKey|deriveBits|importKey|wrapKey|unwrapKey)\s*\(",
        r"require\s*\(\s*['\"](bcrypt|bcryptjs|argon2|jsonwebtoken|jose|jws|jwa|crypto-js|node-forge|tweetnacl|elliptic|sshpk)['\"]",
        r"from\s+['\"](bcrypt|bcryptjs|argon2|jsonwebtoken|jose|jws|jwa|crypto-js|node-forge|tweetnacl|elliptic|sshpk)['\"]",
        r"CryptoJS\.(AES|DES|TripleDES|Rabbit|RC4|MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3|RIPEMD160|PBKDF2|HmacMD5|HmacSHA1|HmacSHA256|HmacSHA512)\s*[\.(]",
        r"forge\.(cipher|md|pki|hmac|random|rsa|pkcs5|pkcs7)\b",
        r"new\s+(TextEncoder|SubtleCrypto)\s*\(",
        r"(tls|https)\.(createServer|connect|request)\s*\(",
    ],
    "php": [
        r"openssl_(sign|verify|encrypt|decrypt|seal|open|digest|pkey_new|pkey_get_public|pkey_get_private|pkey_get_details|pkey_export|csr_new|csr_sign|x509_(read|parse|verify)|random_pseudo_bytes)\s*\(",
        r"\bhash_hmac(_algos)?\s*\(",
        r"\bhash(_init|_pbkdf2|_equals)?\s*\(",
        r"\b(crypt|password_hash|password_verify|sodium_crypto_[a-z_]+|mcrypt_[a-z_]+|random_bytes|mt_rand)\s*\(",
        r"new\s+phpseclib3?\\\\Crypt",
        r"phpseclib3?\\\\(Crypt|Net)\\\\",
        r"['\"](RS256|RS384|RS512|ES256|ES384|ES512|HS256|HS384|HS512|PS256|EdDSA)['\"]",
    ],
    "java": [
        r"import\s+javax\.crypto\.",
        r"import\s+java\.security\.",
        r"import\s+javax\.net\.ssl\.",
        r"import\s+org\.bouncycastle\.",
        r"MessageDigest\.getInstance\s*\(",
        r"Cipher\.getInstance\s*\(",
        r"KeyGenerator\.getInstance\s*\(",
        r"KeyPairGenerator\.getInstance\s*\(",
        r"SecretKeyFactory\.getInstance\s*\(",
        r"Mac\.getInstance\s*\(",
        r"Signature\.getInstance\s*\(",
        r"SSLContext\.getInstance\s*\(",
        r"KeyStore\.getInstance\s*\(",
        r"SecureRandom\s*\(",
        r"TrustManagerFactory\.getInstance\s*\(",
    ],
    "go": [
        r"\"crypto/(md5|sha1|sha256|sha512|aes|des|rc4|rsa|ecdsa|ed25519|elliptic|cipher|hmac|rand|tls|x509)\"",
        r"crypto/(md5|sha1|sha256|sha512|aes|des|rc4)\.(New|Sum)\s*\(",
        r"rsa\.(GenerateKey|EncryptOAEP|DecryptOAEP|SignPKCS1v15|VerifyPKCS1v15)\s*\(",
        r"ecdsa\.(GenerateKey|Sign|Verify)\s*\(",
        r"ed25519\.(GenerateKey|Sign|Verify)\s*\(",
        r"tls\.(Config|LoadX509KeyPair|Dial|Listen)\s*[{(]",
        r"x509\.(ParseCertificate|CreateCertificate|ParsePKCS1|ParsePKCS8|ParseECPrivateKey)\s*\(",
        r"argon2\.(IDKey|Key)\s*\(",
        r"bcrypt\.(GenerateFromPassword|CompareHashAndPassword)\s*\(",
        r"pbkdf2\.Key\s*\(",
    ],
    "c": [
        r"#include\s+<openssl/",
        r"EVP_(DigestInit|EncryptInit|DecryptInit|SignInit|VerifyInit|PKEY_CTX_new|MD5|sha1|sha256|aes_256_cbc)\s*\(",
        r"(AES_set_encrypt_key|AES_set_decrypt_key|AES_encrypt|AES_decrypt)\s*\(",
        r"(RSA_generate_key|RSA_public_encrypt|RSA_private_decrypt)\s*\(",
        r"(DES_set_key|DES_ecb_encrypt|DES_cbc_encrypt)\s*\(",
        r"(SHA1|SHA256|SHA512|MD5)_Init\s*\(",
        r"(HMAC|HMAC_Init|HMAC_Update|HMAC_Final)\s*\(",
        r"(SSL_CTX_new|SSL_new|SSL_connect|SSL_accept|TLS_method|SSLv23_method)\s*\(",
        r"RAND_bytes\s*\(",
        r"(mbedtls_|wolfSSL_|gnutls_)",
    ],
    "ruby": [
        r"require\s+['\"]openssl['\"]",
        r"require\s+['\"]digest['\"]",
        r"OpenSSL::(Cipher|Digest|HMAC|PKey|X509|SSL|Random|KDF)",
        r"Digest::(MD5|SHA1|SHA2|SHA256|SHA384|SHA512)\s*\.",
        r"(bcrypt|scrypt|argon2)",
        r"OpenSSL::PKey::(RSA|EC|DH|DSA)\s*\.",
        r"OpenSSL::SSL::(SSLContext|SSLSocket)\s*\.",
        r"SecureRandom\.(hex|random_bytes|uuid|alphanumeric)\s*",
    ],
    "rust": [
        r"use\s+(ring|rustls|openssl|sodiumoxide|sha2|md5|aes|des|rsa|ed25519|x25519|chacha20|hmac|pbkdf2|scrypt|argon2|blake2|hkdf)",
        r"(Sha256|Sha512|Md5|Aes128|Aes256|Des|TripleDes|Rsa|Ed25519|X25519|ChaCha20Poly1305|HmacSha256|Pbkdf2|Scrypt|Argon2)\s*::",
        r"ring::(digest|hmac|aead|signature|rand|agreement|pbkdf2|hkdf)",
        r"rustls::(ClientConfig|ServerConfig|Certificate|PrivateKey)",
        r"OsRng|SystemRandom|thread_rng",
    ],
}

# Map detected algorithm names to normalized names
ALGORITHM_NORMALIZE = {
    "md5": "MD5",
    "md4": "MD4",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
    "aes": "AES",
    "aes-128": "AES-128",
    "aes-192": "AES-192",
    "aes-256": "AES-256",
    "aes-gcm": "AES-GCM",
    "des": "DES",
    "3des": "3DES",
    "triple_des": "3DES",
    "tripledes": "3DES",
    "blowfish": "Blowfish",
    "rc2": "RC2",
    "rc4": "RC4",
    "chacha20": "ChaCha20",
    "chacha20-poly1305": "ChaCha20-Poly1305",
    "rsa": "RSA",
    "rsa-512": "RSA-512",
    "rsa-1024": "RSA-1024",
    "rsa-2048": "RSA-2048",
    "rsa-4096": "RSA-4096",
    "ecdsa": "ECDSA",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "x25519": "X25519",
    "dh": "Diffie-Hellman",
    "ecdh": "ECDH",
    "dsa": "DSA",
    "pbkdf2": "PBKDF2",
    "scrypt": "scrypt",
    "argon2": "Argon2",
    "bcrypt": "bcrypt",
    "hkdf": "HKDF",
    "hmac": "HMAC",
    "cmac": "CMAC",
    "poly1305": "Poly1305",
    "tls": "TLS",
    "ssl": "SSL",
    "sslv3": "SSLv3",
    "tls1.0": "TLS 1.0",
    "tls1.1": "TLS 1.1",
    "tls1.2": "TLS 1.2",
    "tls1.3": "TLS 1.3",
    "kyber": "CRYSTALS-Kyber",
    "dilithium": "CRYSTALS-Dilithium",
    "sphincs+": "SPHINCS+",
    "falcon": "FALCON",
    "urandom": "os.urandom",
    "securerandom": "SecureRandom",
    "csprng": "CSPRNG",
}

# Whole-token aliases -> canonical algorithm key (used by the precise literal/line extractor).
# Keys map to entries that exist in WEAK_ALGORITHMS or STANDARD_ALGORITHMS.
LITERAL_ALGO_ALIASES = {
    "md5": "md5", "md4": "md4", "sha1": "sha1",
    "sha224": "sha256", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512",
    "sha3": "sha3_256", "sha3256": "sha3_256", "sha3384": "sha3_384", "sha3512": "sha3_512",
    "blake2b": "blake2b", "blake2s": "blake2s",
    "aes": "aes", "aes128": "aes-128", "aes192": "aes-192", "aes256": "aes-256",
    "aesgcm": "aes-gcm", "aeswrap": "aes", "rijndael": "aes",
    "des": "des", "3des": "3des", "desede": "3des", "tripledes": "3des",
    "rc4": "rc4", "arc4": "rc4", "rc2": "rc2", "blowfish": "blowfish",
    "chacha20": "chacha20", "chacha20poly1305": "chacha20-poly1305", "poly1305": "poly1305",
    "rsa": "rsa", "rsa512": "rsa-512", "rsa1024": "rsa-1024", "rsa2048": "rsa-2048", "rsa4096": "rsa-4096",
    "ecdsa": "ecdsa", "ed25519": "ed25519", "ed448": "ed448", "x25519": "x25519",
    "ecdh": "ecdh", "diffiehellman": "dh", "dsa": "dsa",
    "hmac": "hmac", "cmac": "cmac",
    "pbkdf2": "pbkdf2", "scrypt": "scrypt", "bcrypt": "bcrypt", "argon2": "argon2", "hkdf": "hkdf",
    "securerandom": "securerandom",
    "kyber": "kyber", "mlkem": "kyber", "dilithium": "dilithium", "mldsa": "dilithium",
    "sphincs": "sphincs+", "slhdsa": "sphincs+", "falcon": "falcon",
    "tls": "tls", "ssl": "ssl", "tls10": "tls1.0", "tls11": "tls1.1", "tls12": "tls1.2", "tls13": "tls1.3",
}

# JWT "alg" header values -> component algorithm keys (very common in JWT libraries).
JWT_ALG_MAP = {
    "hs256": ["hmac", "sha256"], "hs384": ["hmac", "sha384"], "hs512": ["hmac", "sha512"],
    "rs256": ["rsa", "sha256"], "rs384": ["rsa", "sha384"], "rs512": ["rsa", "sha512"],
    "ps256": ["rsa", "sha256"], "ps384": ["rsa", "sha384"], "ps512": ["rsa", "sha512"],
    "es256": ["ecdsa", "sha256"], "es384": ["ecdsa", "sha384"], "es512": ["ecdsa", "sha512"],
    "es256k": ["ecdsa", "sha256"], "eddsa": ["ed25519"],
}

# Generic crypto API calls where the concrete algorithm is a runtime value (variable/param).
# When such a call matches a line but NO concrete algorithm is found, emit this fallback so the
# usage is still inventoried (instead of silently dropped). (regex, descriptor)
GENERIC_API_FALLBACKS = {
    "java": [
        (r"Cipher\.getInstance\s*\(", {"name": "Cipher (algorithm from config)", "key": "java_cipher_generic", "type": "symmetric_cipher", "strength": "moderate"}),
        (r"Signature\.getInstance\s*\(", {"name": "Signature (algorithm from config)", "key": "java_signature_generic", "type": "signature", "strength": "moderate"}),
        (r"Mac\.getInstance\s*\(", {"name": "MAC (algorithm from config)", "key": "java_mac_generic", "type": "mac", "strength": "strong"}),
        (r"MessageDigest\.getInstance\s*\(", {"name": "Hash (algorithm from config)", "key": "java_digest_generic", "type": "hash", "strength": "moderate"}),
        (r"KeyStore\.getInstance\s*\(", {"name": "KeyStore (type from config)", "key": "java_keystore_generic", "type": "certificate", "strength": "strong"}),
        (r"KeyPairGenerator\.getInstance\s*\(", {"name": "Asymmetric key pair (algorithm from config)", "key": "java_keypair_generic", "type": "asymmetric_cipher", "strength": "moderate"}),
        (r"KeyGenerator\.getInstance\s*\(", {"name": "Symmetric key (algorithm from config)", "key": "java_keygen_generic", "type": "symmetric_cipher", "strength": "strong"}),
        (r"SecretKeyFactory\.getInstance\s*\(", {"name": "Key derivation (algorithm from config)", "key": "java_kdf_generic", "type": "key_derivation", "strength": "strong"}),
        (r"SSLContext\.getInstance\s*\(", {"name": "TLS/SSL context (protocol from config)", "key": "java_tls_generic", "type": "protocol", "strength": "moderate"}),
        (r"(SecureRandom|TrustManagerFactory\.getInstance)\s*\(", {"name": "SecureRandom", "key": "securerandom", "type": "random_number_generator", "strength": "strong"}),
    ],
    "javascript": [
        (r"\bcreateHmac\s*\(", {"name": "HMAC (digest from config)", "key": "js_hmac_generic", "type": "mac", "strength": "strong"}),
        (r"\bcreateHash\s*\(", {"name": "Hash (algorithm from config)", "key": "js_hash_generic", "type": "hash", "strength": "moderate"}),
        (r"\bcreate(Cipheriv|Cipher|Decipheriv|Decipher)\s*\(", {"name": "Symmetric cipher (algorithm from config)", "key": "js_cipher_generic", "type": "symmetric_cipher", "strength": "moderate"}),
        (r"\bcreate(Sign|Verify)\s*\(", {"name": "Signature (algorithm from config)", "key": "js_signature_generic", "type": "signature", "strength": "moderate"}),
        (r"\b(generateKeyPairSync|generateKeyPair)\s*\(", {"name": "Asymmetric key pair (algorithm from config)", "key": "js_keypair_generic", "type": "asymmetric_cipher", "strength": "moderate"}),
        (r"\bcreateDiffieHellman\s*\(", {"name": "Diffie-Hellman", "key": "dh", "type": "asymmetric_cipher", "strength": "strong"}),
        (r"\b(pbkdf2Sync|pbkdf2|scryptSync|scrypt)\s*\(", {"name": "Key derivation (algorithm from config)", "key": "js_kdf_generic", "type": "key_derivation", "strength": "strong"}),
        (r"\b(randomBytes|randomFillSync)\s*\(", {"name": "CSPRNG", "key": "csprng", "type": "random_number_generator", "strength": "strong"}),
        (r"crypto\.subtle\.\w+\s*\(|require\s*\(\s*['\"]crypto['\"]\s*\)|from\s+['\"]crypto['\"]", {"name": "WebCrypto/Node crypto (algorithm from config)", "key": "js_crypto_generic", "type": "symmetric_cipher", "strength": "moderate"}),
    ],
    "php": [
        (r"openssl_(sign)\s*\(", {"name": "OpenSSL signature (algorithm from config)", "key": "php_sign_generic", "type": "signature", "strength": "moderate"}),
        (r"openssl_(verify)\s*\(", {"name": "OpenSSL verify (algorithm from config)", "key": "php_verify_generic", "type": "signature", "strength": "moderate"}),
        (r"openssl_(encrypt|decrypt|seal|open)\s*\(", {"name": "OpenSSL symmetric cipher (algorithm from config)", "key": "php_cipher_generic", "type": "symmetric_cipher", "strength": "moderate"}),
        (r"openssl_pkey_(new|get_public|get_private|get_details|export)\s*\(", {"name": "OpenSSL asymmetric key (algorithm from config)", "key": "php_pkey_generic", "type": "asymmetric_cipher", "strength": "moderate"}),
        (r"\bhash_hmac\s*\(", {"name": "HMAC (digest from config)", "key": "php_hmac_generic", "type": "mac", "strength": "strong"}),
        (r"\bhash\s*\(", {"name": "Hash (algorithm from config)", "key": "php_hash_generic", "type": "hash", "strength": "moderate"}),
        (r"\b(password_hash|crypt)\s*\(", {"name": "Password hashing (algorithm from config)", "key": "php_pwhash_generic", "type": "key_derivation", "strength": "strong"}),
        (r"\b(random_bytes|openssl_random_pseudo_bytes)\s*\(", {"name": "CSPRNG", "key": "csprng", "type": "random_number_generator", "strength": "strong"}),
        (r"\b(mt_rand|mt_srand|\bsrand)\s*\(", {"name": "Insecure PRNG (mt_rand)", "key": "php_weak_rng", "type": "random_number_generator", "strength": "weak"}),
    ],
    "go": [
        (r"cipher\.(NewGCM|NewCBCEncrypter|NewCBCDecrypter|NewCTR|NewCFBEncrypter|NewOFB|NewCFBDecrypter)\s*\(", {"name": "Block cipher mode (algorithm from config)", "key": "go_cipher_generic", "type": "symmetric_cipher", "strength": "moderate"}),
        (r"\bsubtle\.ConstantTimeCompare\s*\(", {"name": "Constant-time comparison", "key": "go_subtle_generic", "type": "mac", "strength": "strong"}),
    ],
    "python": [
        (r"Cipher\s*\([^)]*\)|modes\.(CBC|GCM|CTR|CFB|OFB|ECB)\s*\(", {"name": "Symmetric cipher (algorithm from config)", "key": "py_cipher_generic", "type": "symmetric_cipher", "strength": "moderate"}),
        (r"hashlib\.new\s*\(", {"name": "Hash (algorithm from config)", "key": "py_hash_generic", "type": "hash", "strength": "moderate"}),
        (r"os\.urandom\s*\(|secrets\.(token_bytes|token_hex|token_urlsafe|randbits|choice|SystemRandom)\s*[\.(]|random\.SystemRandom\s*\(", {"name": "CSPRNG", "key": "csprng", "type": "random_number_generator", "strength": "strong"}),
    ],
    "ruby": [
        (r"OpenSSL::Cipher\.new\s*\(", {"name": "Symmetric cipher (algorithm from config)", "key": "rb_cipher_generic", "type": "symmetric_cipher", "strength": "moderate"}),
        (r"OpenSSL::Digest\.new\s*\(", {"name": "Hash (algorithm from config)", "key": "rb_digest_generic", "type": "hash", "strength": "moderate"}),
    ],
}

# --------------------------------------------------------------------------
# Crypto-context signals (used to disambiguate AMBIGUOUS_TOKENS).
#
# Tokens like 'falcon' (web framework / PQC signature), 'rsa', 'aes', 'des',
# 'tls', 'ssl' are valid crypto names AND common non-crypto identifiers. They
# are only treated as crypto on an import / dotted-call line when the SAME line
# also carries an independent crypto signal. Two kinds of signal exist:
#
#   1. CRYPTO_CONTEXT_HINTS  — a recognized crypto module / package path appears
#      on the line (e.g. `from cryptography... import rsa`, `import "crypto/aes"`,
#      `from pqcrypto.sign import falcon`). Substring match, lowercase.
#   2. CRYPTO_METHOD_HINTS   — a dotted call uses a recognized crypto operation
#      name (e.g. aes.NewCipher, rsa.GenerateKey, dsa.Sign). Substring match
#      against the dotted attribute, lowercase.
#
# `import falcon`, `falcon.API()`, `falcon.add_route(...)` carry neither signal,
# so they are NOT mapped to the PQC FALCON algorithm. A genuine PQC falcon import
# routed through an actual PQC library (pqcrypto / oqs / liboqs / pqclean) DOES
# carry a context hint and is preserved.
# --------------------------------------------------------------------------
CRYPTO_CONTEXT_HINTS = {
    # PQC libraries (so real FALCON / Kyber / Dilithium usage survives)
    "pqcrypto", "liboqs", "oqs", "pqclean", "open-quantum-safe", "openquantumsafe",
    # General crypto libraries / module roots across languages
    "cryptography", "crypto.", "cryptodome", "pycrypto", "nacl", "pynacl",
    "openssl", "libsodium", "sodium", "bouncycastle", "bouncy castle",
    "crypto/", "golang.org/x/crypto", "ring", "rustls", "sodiumoxide",
    "phpseclib", "tweetnacl", "node-forge", "forge", "crypto-js", "cryptojs",
    "elliptic", "sshpk", "javax.crypto", "java.security", "javax.net.ssl",
    "hashlib", "hazmat", "mbedtls", "wolfssl", "gnutls", "secrets",
    # Subtle/web-crypto and explicit crypto namespaces
    "subtle", "webcrypto",
}

# Dotted-call attribute names that indicate a genuine crypto operation. Matched
# as substrings against the lowercase line so `aes.NewCipher` / `rsa.GenerateKey`
# / `dsa.Sign` are recognized while `falcon.API` / `falcon.add_route` are not.
# NOTE: matched as a dotted attribute (".<hint>") by the scanner, so each entry
# is the operation name as it appears after the module dot (e.g. aes.NewCipher).
CRYPTO_METHOD_HINTS = {
    "newcipher", "newgcm", "generatekey", "encryptoaep", "decryptoaep",
    "newcbcencrypter", "newcbcdecrypter", "newctr", "newcfbencrypter",
    "newofb", "newcfbdecrypter", "signpkcs1v15", "verifypkcs1v15",
    "loadx509keypair", "createcipheriv", "createdecipheriv",
    "createsign", "createverify",
}

# Per-language generic descriptor used when a LANGUAGE_PATTERNS entry matched (crypto present)
# but no concrete algorithm and no GENERIC_API_FALLBACKS entry applied.
GENERIC_LANG_FALLBACK = {
    "java": {"name": "Cryptographic primitive (unspecified)", "key": "java_crypto_unspecified", "type": "symmetric_cipher", "strength": "moderate"},
    "javascript": {"name": "Cryptographic primitive (unspecified)", "key": "js_crypto_unspecified", "type": "symmetric_cipher", "strength": "moderate"},
    "php": {"name": "Cryptographic primitive (unspecified)", "key": "php_crypto_unspecified", "type": "symmetric_cipher", "strength": "moderate"},
    "go": {"name": "Cryptographic primitive (unspecified)", "key": "go_crypto_unspecified", "type": "symmetric_cipher", "strength": "moderate"},
    "python": {"name": "Cryptographic primitive (unspecified)", "key": "py_crypto_unspecified", "type": "symmetric_cipher", "strength": "moderate"},
    "ruby": {"name": "Cryptographic primitive (unspecified)", "key": "rb_crypto_unspecified", "type": "symmetric_cipher", "strength": "moderate"},
    "rust": {"name": "Cryptographic primitive (unspecified)", "key": "rs_crypto_unspecified", "type": "symmetric_cipher", "strength": "moderate"},
    "c": {"name": "Cryptographic primitive (unspecified)", "key": "c_crypto_unspecified", "type": "symmetric_cipher", "strength": "moderate"},
}
