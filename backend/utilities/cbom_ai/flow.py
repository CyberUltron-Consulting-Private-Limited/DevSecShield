"""Rules on the common syntax tree (``syntax.N``) for the AI fix validator: the API allow-list (outside Python),
key-material data flow (taint), sinks that move, options of existing calls, TLS downgrades by value, and writes to
the process environment. Every function here is fail closed: what it cannot read is reported.
"""
from __future__ import annotations

import itertools
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from backend.utilities.cbom_ai.syntax import N, walk

# ------------------------------------------------------------------------------------------- API allow-lists
_JS_FORBIDDEN = {"constructor", "prototype", "__proto__", "__defineGetter__", "__defineSetter__", "__lookupGetter__",
                 "__lookupSetter__", "getPrototypeOf", "setPrototypeOf", "Function", "eval", "caller", "callee",
                 "arguments", "mainModule", "binding", "dlopen"}
_CAPS = re.compile(r"[A-Z][A-Z0-9_]+")


def _constant(seg: Seg) -> bool:
    """``X.SOME_CONSTANT`` read (not called): a constant of a class / package."""
    return not seg.called and bool(_CAPS.fullmatch(seg.name))


# lower-case roots of fully qualified names (packages, not locals)
_NS_ROOTS = {"java", "javax", "kotlin", "kotlinx", "jdk", "sun", "android"}
# namespaces a fully qualified class name may be written with (the class and member are still judged)
_NAMESPACES = {
    "java": {"java.util", "java.security", "java.security.spec", "javax.crypto", "javax.crypto.spec", "java.nio",
             "javax.net.ssl", "java.lang"},
    "csharp": {"System", "System.Security.Cryptography", "System.Text", "System.Security.Authentication",
               "System.Net.Security"},
}
_NAMESPACES["kotlin"] = _NAMESPACES["java"] | {"kotlin", "kotlin.random"}


class Api:
    """One language's allow-list: ``pairs`` Qualifier.member, ``ctors`` constructors / free functions, ``methods``
    on allow-listed locals and results, ``safe`` members harmless on any receiver, ``packages`` lower-case names
    that are packages / modules even without an import in the window."""

    def __init__(self, pairs: str, ctors: str, methods: str, safe: str, packages: str = "") -> None:
        self.pairs, self.ctors = set(pairs.split()), set(ctors.split())
        self.methods, self.safe, self.packages = set(methods.split()), set(safe.split()), set(packages.split())


JS_API = Api(
    pairs="""crypto.randomBytes crypto.randomFillSync crypto.randomFill crypto.randomInt crypto.randomUUID
    crypto.getRandomValues crypto.createCipheriv crypto.createDecipheriv crypto.createHash crypto.createHmac
    crypto.createSign crypto.createVerify crypto.createSecretKey crypto.createPrivateKey crypto.createPublicKey
    crypto.generateKeyPair crypto.generateKeyPairSync crypto.generateKey crypto.generateKeySync crypto.pbkdf2
    crypto.pbkdf2Sync crypto.scrypt crypto.scryptSync crypto.hkdf crypto.hkdfSync crypto.timingSafeEqual
    crypto.getCiphers crypto.getHashes crypto.getCurves crypto.publicEncrypt crypto.privateDecrypt crypto.sign
    crypto.verify crypto.subtle crypto.webcrypto crypto.constants tls.createSecureContext tls.checkServerIdentity
    tls.getCiphers tls.rootCertificates Buffer.from Buffer.alloc Buffer.concat Buffer.isBuffer Buffer.compare
    Buffer.byteLength process.env Object.freeze Object.keys JSON.parse JSON.stringify Math.floor Math.min Math.max
    Math.ceil Number.isInteger Array.isArray Array.from""",
    ctors="""require String Number Boolean Uint8Array Uint32Array ArrayBuffer DataView BigInt Error TypeError RangeError
    parseInt isNaN Promise TextEncoder TextDecoder Map Set""",
    methods="""update final digest getAuthTag setAuthTag setAAD setAutoPadding export sign verify encrypt decrypt
    importKey exportKey deriveKey deriveBits wrapKey unwrapKey generateKey then catch encode decode concat
    asymmetricKeyType symmetricKeySize""",
    safe="""length byteLength toString slice subarray equals includes indexOf startsWith endsWith split trim join map
    push padStart padEnd test match replace toLowerCase toUpperCase""",
    packages="""crypto tls net http https http2 dgram dns fs child_process cluster worker_threads vm os path process
    module Buffer Object JSON Math Number Array Reflect globalThis window global self Promise Date Symbol console
    String""")
JAVA_API = Api(
    pairs="""Cipher.getInstance KeyGenerator.getInstance KeyPairGenerator.getInstance SecretKeyFactory.getInstance
    MessageDigest.getInstance MessageDigest.isEqual Mac.getInstance Signature.getInstance KeyFactory.getInstance
    KeyAgreement.getInstance SSLContext.getInstance TrustManagerFactory.getInstance
    TrustManagerFactory.getDefaultAlgorithm KeyManagerFactory.getInstance KeyManagerFactory.getDefaultAlgorithm
    KeyStore.getInstance KeyStore.getDefaultType SecureRandom.getInstance SecureRandom.getInstanceStrong
    Base64.getDecoder Base64.getEncoder Base64.getUrlDecoder Base64.getUrlEncoder Base64.getMimeDecoder System.getenv
    System.arraycopy Arrays.copyOf Arrays.copyOfRange Arrays.fill Arrays.equals ByteBuffer.allocate ByteBuffer.wrap
    String.valueOf Objects.requireNonNull HexFormat.of""",
    ctors="""SecureRandom SecretKeySpec IvParameterSpec GCMParameterSpec PBEKeySpec ChaCha20ParameterSpec
    OAEPParameterSpec MGF1ParameterSpec PSSParameterSpec ECGenParameterSpec RSAKeyGenParameterSpec String
    SSLParameters IllegalStateException IllegalArgumentException RuntimeException GeneralSecurityException ByteArray
    CharArray""",
    methods="""init doFinal update updateAAD getIV getParameters getBlockSize getOutputSize generateKey generateSecret
    getEncoded getAlgorithm getFormat nextBytes nextInt digest reset initialize generateKeyPair getPublic getPrivate
    initSign initVerify sign verify decode encode encodeToString getTrustManagers getKeyManagers
    getDefaultSSLParameters getSupportedSSLParameters setProtocols setCipherSuites setEndpointIdentificationAlgorithm
    load put array formatHex parseHex orElseThrow""",
    safe="""length size isEmpty equals toString hashCode getBytes toCharArray toByteArray encodeToByteArray
    decodeToString copyOf copyOfRange contentEquals""")
KT_API = Api(" ".join(sorted(JAVA_API.pairs)), " ".join(sorted(JAVA_API.ctors)), " ".join(sorted(JAVA_API.methods)),
             " ".join(sorted(JAVA_API.safe)) + " to or and xor shl shr ushr inv plus minus until downTo step size"
             " also apply let run use takeIf",
             "")
CS_API = Api(
    pairs="""Aes.Create RandomNumberGenerator.Create RandomNumberGenerator.Fill RandomNumberGenerator.GetBytes
    RandomNumberGenerator.GetInt32 SHA256.Create SHA256.HashData SHA384.Create SHA384.HashData SHA512.Create
    SHA512.HashData HMACSHA256.HashData HMACSHA512.HashData Rfc2898DeriveBytes.Pbkdf2
    CryptographicOperations.FixedTimeEquals CryptographicOperations.ZeroMemory Convert.FromBase64String
    Convert.ToBase64String Convert.FromHexString Convert.ToHexString Encoding.UTF8 Encoding.ASCII
    Environment.GetEnvironmentVariable RSA.Create ECDsa.Create ECDiffieHellman.Create ECCurve.NamedCurves
    RSAEncryptionPadding.OaepSHA256 RSAEncryptionPadding.OaepSHA384 RSAEncryptionPadding.OaepSHA512
    RSASignaturePadding.Pss RSASignaturePadding.Pkcs1 SslProtocols.Tls12 SslProtocols.Tls13 Array.Copy Array.Clear
    Buffer.BlockCopy AesGcm.IsSupported AesGcm.TagByteSizes AesGcm.NonceByteSizes ChaCha20Poly1305.IsSupported""",
    ctors="""AesGcm AesCcm ChaCha20Poly1305 HMACSHA256 HMACSHA384 HMACSHA512 Rfc2898DeriveBytes ArgumentException
    InvalidOperationException CryptographicException HashAlgorithmName SslClientAuthenticationOptions
    SslServerAuthenticationOptions""",
    methods="""Encrypt Decrypt CreateEncryptor CreateDecryptor TransformFinalBlock TransformBlock GenerateKey
    GenerateIV ComputeHash GetBytes GetString EncryptCbc DecryptCbc SignData VerifyData SignHash VerifyHash
    ImportSubjectPublicKeyInfo ExportSubjectPublicKeyInfo ImportPkcs8PrivateKey ExportPkcs8PrivateKey Key IV Mode
    Padding KeySize BlockSize Dispose nistP256 nistP384 nistP521""",
    safe="Length Count ToArray AsSpan CopyTo SequenceEqual ToString Equals Slice")
GO_API = Api(
    pairs="""aes.NewCipher cipher.NewGCM cipher.NewGCMWithNonceSize cipher.NewCTR rand.Read rand.Reader rand.Int
    io.ReadFull os.Getenv os.LookupEnv hex.DecodeString hex.EncodeToString base64.StdEncoding base64.URLEncoding
    base64.RawStdEncoding base64.RawURLEncoding sha256.Sum256 sha256.New sha512.Sum512 sha512.New hmac.New
    hmac.Equal subtle.ConstantTimeCompare argon2.IDKey hkdf.New pbkdf2.Key ecdsa.GenerateKey ecdsa.SignASN1
    ecdsa.VerifyASN1 ed25519.GenerateKey ed25519.Sign ed25519.Verify rsa.GenerateKey rsa.EncryptOAEP
    rsa.DecryptOAEP rsa.SignPSS rsa.VerifyPSS rsa.SignPKCS1v15 elliptic.P256 elliptic.P384 elliptic.P521
    tls.Config tls.VersionTLS12 tls.VersionTLS13 tls.X25519 tls.CurveP256 tls.CurveP384 x509.SystemCertPool
    x509.NewCertPool x509.ParseCertificate x509.ParsePKCS8PrivateKey x509.MarshalPKCS8PrivateKey errors.New
    fmt.Errorf chacha20poly1305.New chacha20poly1305.NewX""",
    ctors="make len cap append copy panic new byte string int uint32 uint64 int64",
    methods="""Seal Open NonceSize Overhead Write Sum Reset Size BlockSize Encrypt Decrypt XORKeyStream CryptBlocks
    Public Sign DecodeString EncodeToString AppendCertsFromPEM Equal MinVersion MaxVersion CipherSuites
    CurvePreferences RootCAs Certificates""",
    safe="",
    packages="""os io ioutil exec net http syscall filepath aes cipher rand hex base64 sha256 sha512 sha1 md5 hmac
    subtle tls x509 ecdsa ed25519 rsa elliptic argon2 hkdf pbkdf2 chacha20poly1305 errors fmt bytes strings unsafe
    reflect plugin bufio log url smtp""")
APIS = {"javascript": JS_API, "typescript": JS_API, "java": JAVA_API, "kotlin": KT_API, "csharp": CS_API,
        "go": GO_API}

# ------------------------------------------------------------------------------------- data-flow name tables
# results that ARE key material (randomness, generated / derived keys, the environment)
SOURCES = set("""urandom token_bytes token_hex token_urlsafe get_random_bytes getrandom randbits randomBytes randomUUID
randomInt generateKey generateKeySync generateKeyPair generateKeyPairSync generate_key generate_private_key GenerateKey
generateSecret derive deriveKey deriveBits pbkdf2_hmac pbkdf2 pbkdf2Sync scrypt scryptSync hkdf hkdfSync IDKey Pbkdf2
DeriveKey private_bytes export exportKey ExportPkcs8PrivateKey ExportECPrivateKey ExportRSAPrivateKey getPrivate
getenv getenvb Getenv LookupEnv GetEnvironmentVariable GetBytes getEncoded GenerateIV generateKeyPair PBKDF2
derive_key Key MarshalPKCS8PrivateKey getIV""".split())
# calls that fill their arguments with random bytes (the arguments become key material)
FILLS = set("nextBytes randomFillSync randomFill getRandomValues Fill Read ReadFull".split())
# hashes, MACs, signatures and tags: KEY-DERIVED when key material goes in as DATA (a hash of the key, of one key
# byte, Go's ``h.Sum(k)`` which appends to ``k``); clean when the key is only in a key position (HMAC key, signer)
HASHES = set("""digest hexdigest Sum Sum256 Sum512 HashData ComputeHash sign Sign SignData SignHash SignASN1 SignPSS
SignPKCS1v15 getAuthTag hash""".split())
# verdicts, sizes, public keys: never key material
VERDICTS = set("""verify Verify VerifyData VerifyHash VerifyASN1 VerifyPSS timingSafeEqual compare_digest Equal
ConstantTimeCompare FixedTimeEquals isEqual public_key public_bytes getPublic Public ExportSubjectPublicKeyInfo
NonceSize Overhead BlockSize Size getBlockSize getOutputSize verify_password check_needs_rehash len cap
isinstance""".split())
DIGESTS = HASHES | VERDICTS
# signers: the receiver is the private key (a key position); the arguments are data except the positions below
SIGNERS = set("sign Sign SignData SignHash SignASN1 SignPSS SignPKCS1v15".split())
# cipher outputs: ciphertext of what goes in as DATA. Clean when the data is not key material and the cipher object
# never took key material in as data (encrypting the key under a key the author knows is not a sanitiser)
CIPHER_OUT = set("""encrypt Encrypt encrypt_and_digest Seal update final doFinal finalize finalize_with_tag
TransformFinalBlock TransformBlock EncryptCbc EncryptEcb EncryptCfb decrypt Decrypt decrypt_and_verify Open DecryptCbc
publicEncrypt EncryptOAEP XORKeyStream CryptBlocks updateAAD authenticate_additional_data""".split())
SANITIZERS = DIGESTS | CIPHER_OUT
# sources whose result is random (IV / nonce / salt material); the other sources are keys
RANDOM_SOURCES = set("""urandom token_bytes token_hex token_urlsafe get_random_bytes getrandom randbits randomBytes
randomUUID randomInt GenerateIV getIV""".split())
_ENV_PATHS = ("process.env", "os." + "environ", "environ")  # the process environment, read: key material
# taint labels: random / IV material, key material, a cipher / hash that took key material in as data, a hash /
# MAC / encoding of key material (key-derived: a check value, 256 guesses per byte), an object holding a key in its key
# position (a cipher / MAC / key spec: not key bytes, but not to be sent or logged either)
IV, KEY, ABSORBED, KEY_DERIVED, HOLDER = 1, 2, 4, 8, 16
KEYISH = KEY | ABSORBED | KEY_DERIVED  # key material or derived from it (not IV, not a key holder)
# AEAD constructions: the ciphertext of one may be framed with its public nonce (nonce || ciphertext || tag)
AEAD_RX = re.compile(r"gcm|ccm|chacha20|poly1305|(?<![a-z])siv(?![a-z])|ocb3?(?![a-z])", re.I)
_IV_WORDS = {"iv", "nonce", "salt", "seed"}
# allowed by name but the arguments end up in a message, a log or an error: a key there leaks
EXCEPTIONS = set("""Error TypeError RangeError ValueError TypeError RuntimeError KeyError Exception NotImplementedError
PermissionError OSError AttributeError IndexError LookupError OverflowError AssertionError ImportError
UnicodeDecodeError UnicodeEncodeError IllegalStateException IllegalArgumentException RuntimeException
GeneralSecurityException ArgumentException InvalidOperationException CryptographicException Errorf panic""".split())
# crypto-object methods that make sense on a receiver of unknown type (a parameter holding a key / cipher)
DISTINCTIVE = set("""private_bytes public_bytes public_key encrypt decrypt encrypt_and_digest decrypt_and_verify sign
derive finalize finalize_with_tag encryptor decryptor exchange getEncoded doFinal updateAAD getAuthTag setAuthTag
setAAD hexdigest""".split())
# value methods (str / bytes / list): the result carries the receiver's data, and a list method may take it in
VALUE_METHODS = set("""encode decode hex strip rstrip lstrip split join lower upper replace startswith endswith zfill
ljust rjust to_bytes from_bytes copy append extend insert items keys values get fromhex""".split())
# argument positions (None = all) that take key / IV material: what is passed there is key material
KEY_TAKERS: dict[str, tuple[int, ...] | None] = {
    "createCipheriv": (1, 2), "createDecipheriv": (1, 2), "createHmac": (1,), "createSecretKey": (0,),
    "createPrivateKey": (0,), "AESGCM": (0,), "AESCCM": (0,), "AESSIV": (0,), "AESOCB3": (0,), "AESGCMSIV": (0,),
    "ChaCha20Poly1305": (0,), "Fernet": (0,), "NewCipher": (0,), "SecretKeySpec": (0,), "IvParameterSpec": (0,),
    "GCMParameterSpec": (1,), "PBEKeySpec": (0, 1), "init": (1, 2), "AesGcm": (0,), "AesCcm": (0,),
    "HMACSHA256": (0,), "HMACSHA384": (0,), "HMACSHA512": (0,), "pbkdf2_hmac": (1, 2), "pbkdf2Sync": (0, 1),
    "pbkdf2": (0, 1), "scrypt": (0, 1), "scryptSync": (0, 1), "PBKDF2HMAC": None, "Scrypt": None, "HKDF": None,
    "Pbkdf2": (0, 1), "IDKey": (0, 1), "new": (0, 2), "New": (0, 1), "hkdfSync": (1, 2), "hkdf": (1, 2), "AES": (0,), "TripleDES": (0,),
    "ChaCha20": (0, 1), "Camellia": (0,), "Blowfish": (0,), "Rfc2898DeriveBytes": (0, 1)}
# positions of KEY_TAKERS that take the IV / nonce (random, public), not the key
IV_TAKERS: dict[str, tuple[int, ...]] = {
    "createCipheriv": (2,), "createDecipheriv": (2,), "IvParameterSpec": (0,), "GCMParameterSpec": (1,), "new": (2,),
    "ChaCha20": (1,),
    # KDF salts (public, stored next to the hash)
    "pbkdf2_hmac": (2,), "pbkdf2Sync": (1,), "pbkdf2": (1,), "scrypt": (1,), "scryptSync": (1,), "hkdf": (2,),
    "hkdfSync": (2,), "Pbkdf2": (1,), "IDKey": (1,), "PBEKeySpec": (1,), "Rfc2898DeriveBytes": (1,)}
_KEY_WORDS = {"key", "secret", "password", "passwd", "pwd", "passphrase", "token", "iv", "nonce", "salt", "private",
              "priv", "credential", "credentials", "cred", "creds", "apikey", "psk", "seed", "pin", "privkey", "k",
              "sk"}
# words that make a key-like name a size / label / factory, not key material (KEY_LEN, nonceSize, KeyGenerator)
_NOT_KEY_WORDS = {"len", "length", "size", "sz", "bits", "count", "name", "names", "id", "ids", "type", "alg",
                  "algorithm", "algorithms", "format", "path", "file", "mode", "usage", "version", "label", "provider",
                  "manager", "managers", "generator", "factory", "store", "selector", "header", "env", "var", "field"}
# members that are a number about the value, not the value (key.length, iv.size, k.Length)
_SIZE_MEMBERS = {"length", "Length", "size", "Count", "byteLength", "LongLength"}
# calls / constructors whose result may share memory with their receiver or arguments (a view, a wrapper, the backing
# array): Go / C# / JS slices, spans, ByteBuffer.wrap / array(), Arrays.asList, typed-array views, memoryview. A write
# into the result is a write into the buffer it views. When in doubt a name is listed (fail closed).
VIEWS = {"AsSpan", "AsMemory", "AsReadOnlySpan", "AsReadOnlyMemory", "AsBytes", "Slice", "slice", "subarray", "wrap",
         "asList", "asReadOnlyBuffer", "duplicate", "array", "memoryview", "getbuffer", "cast", "toreadonly", "Span",
         "Memory", "ReadOnlySpan", "ReadOnlyMemory", "ArraySegment", "Uint8Array", "Int8Array", "Uint8ClampedArray",
         "Uint16Array", "Int16Array", "Uint32Array", "Int32Array", "Float32Array", "Float64Array", "BigInt64Array",
         "BigUint64Array", "DataView", "from", "NewBuffer", "NewReader", "asByteBuffer", "asUByteArray",
         "asIntBuffer", "asLongBuffer", "ofArray", "order", "asReadOnly", "view", "bytearray"}
# expressions whose value is one of their operands (``a or b``, ``c ? a : b``, ``x ?: y``): may alias any of them
_CHOICE_OPS = {"or", "and", "||", "&&", "??", "?:"}
_CHOICE_NODES = {"ternary", "ternary_expression", "conditional_expression", "elvis_expression", "parenthesized_expression",
                 "if_expression", "when_expression", "when_entry", "switch_expression", "switch_expression_arm",
                 "switch_block", "switch_body", "switch_rule", "control_structure_body", "block", "statements",
                 "slice_expression", "starred", "spread_element", "variadic_argument"}
# in-place operators: they write the value INTO the target (a write-into, see ``key_writes``), they do not make the
# target the same object as the value. Every other binding operator (``=``, ``:=``, loop targets, ``instanceof`` /
# ``is`` patterns, ``??=`` / ``||=`` / ``&&=``, ref locals, ...) is treated as aliasing (fail closed)
_INPLACE_OPS = {"+=", "-=", "*=", "/=", "//=", "%=", "**=", "@=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&^=",
                "?="}
_SELF_NAMES = {"this", "self", "super", "base"}
# calls whose result is their receiver (``bb.position(0)``, ``a.fill(0)``, ``ct.apply { }``): may alias it
_RETURNS_SELF = {"position", "limit", "clear", "flip", "rewind", "mark", "reset", "compact", "order", "fill", "reverse",
                 "sort", "copyWithin", "apply", "also", "let", "run", "takeIf", "takeUnless", "requireNotNull",
                 "checkNotNull", "orEmpty", "put", "set", "putInt", "putLong", "putShort", "append", "AsSpan"}
# calls whose result holds their arguments / receiver (containers, iterators, choosers): may alias any of them
_CONTAINERS = {"arrayOf", "listOf", "mutableListOf", "arrayListOf", "setOf", "mutableSetOf", "mapOf", "mutableMapOf",
               "of", "asList", "singletonList", "singleton", "List", "ArrayList", "LinkedList", "list", "tuple", "set",
               "frozenset", "dict", "iter", "next", "reversed", "sorted", "max", "min", "first", "last", "single",
               "firstOrNull", "lastOrNull", "get", "getOrDefault", "getOrElse", "getValue", "elementAt", "ElementAt",
               "First", "Last", "Single", "pop", "popleft", "shift", "values", "items", "toList", "toTypedArray",
               "Of", "Create", "setdefault", "Iterator", "iterator", "chain", "zip", "enumerate", "requireNonNull",
               "ofNullable", "orElse", "Value", "GetValueOrDefault", "flat", "flatten", "concat", "Concat"}
# ------------------------------------------------------------------- the sink-side rule (``Flow.key_writes``)
# Key material (KEY / KEY_DERIVED / ABSORBED, environment secrets) may appear only in a KEY POSITION of an
# allow-listed crypto call. As the source of any write-into operation (a copy, put / set / fill, append / extend /
# add / push, an index or slice store, an in-place operator, a concatenation, string formatting, a container
# literal) it withholds the fix, wherever the destination points. Allow-listed calls that never write into an input
# and whose extra arguments are offsets / encodings: a key may be converted by them (``Buffer.from(env, 'base64')``,
# ``Base64.getDecoder().decode(env)``, ``key[:16]``).
_CONVERSIONS = {"encode", "decode", "decodeString", "DecodeString", "EncodeToString", "encodeToString", "hex",
                "fromhex", "unhexlify", "hexlify", "b64encode", "b64decode", "urlsafe_b64encode", "urlsafe_b64decode",
                "standard_b64encode", "standard_b64decode", "b32encode", "b32decode", "b16encode", "b16decode",
                "a85decode", "b85decode", "FromBase64String", "ToBase64String", "FromHexString", "ToHexString",
                "GetBytes", "GetString", "getBytes", "toByteArray", "toString", "ToString", "from_bytes", "to_bytes",
                "bytes", "bytearray", "from", "slice", "subarray", "Slice", "AsSpan", "AsMemory", "AsReadOnlySpan",
                "ToArray", "toArray", "copyOf", "copyOfRange", "substring", "Substring", "strip", "rstrip", "lstrip",
                "ljust", "rjust", "zfill", "lower", "upper", "trim", "Trim", "String", "str", "string", "memoryview",
                "Uint8Array", "encodeToByteArray", "decodeToString", "toUByteArray", "asUByteArray", "toCharArray",
                "ReadOnlySpan", "Span", "Memory", "ReadOnlyMemory", "Bytes", "copy", "array", "duplicate", "view"}
# copy-by-value conversions that are also names of a write (JS ``k.copy(dst)``): a conversion only without operands
_CONVERSION_IF_ALONE = {"copy", "array", "duplicate", "view", "from", "bytearray", "bytes", "Uint8Array"}
# string formatting / joining: any key material in them withholds
_FORMATS = {"format", "Format", "Sprintf", "Sprint", "Sprintln", "Fprintf", "Errorf", "formatted", "join", "Join",
            "printf", "sprintf", "format_map", "AppendFormat", "Appendf", "joinToString", "Concat", "concat", "plus",
            "repeat", "padStart", "padEnd", "PadLeft", "PadRight", "Insert", "insert", "replace", "Replace",
            "expandtabs", "translate", "center"}
# binary operators that do not build a value out of their operands (comparisons) or pick one (choices)
_NOT_BUILDING = {"==", "!=", "===", "!==", "<", ">", "<=", ">=", "in", "not in", "is", "is not", "instanceof", "!in",
                 "is!", "!is", "as", "as?", "is_not", "notin"} | {"or", "and", "||", "&&", "??", "?:"}
# write-into calls by where the destination is: the receiver (``dst.put(x)``), the first argument (``x.CopyTo(dst)``),
# or a fixed argument of a function (``copy(dst, src)``, ``System.arraycopy(src, i, dst, j, n)``)
_RECV_DEST = {"put", "set", "write", "Write", "extend", "append", "push", "unshift", "Add", "AddRange", "add", "addAll",
              "fill", "insert", "Insert", "writeBytes", "WriteByte", "write_bytes", "putInt", "putLong", "putShort",
              "update", "setdefault", "splice", "Append", "AppendLiteral", "Push", "Enqueue", "offer", "putAll",
              "writeUInt8", "writeUInt32BE", "writeUInt32LE", "writeInt32BE", "setUint8", "setUint32", "Fill",
              "Clear", "clear", "WriteString", "WriteRune"}
_RECV_SRC = {"copy", "CopyTo", "copyInto", "TryCopyTo", "copyTo"}
_FUNC_DEST = {"copy": (0, (1,)), "arraycopy": (2, (0,)), "BlockCopy": (2, (0,)), "fill": (0, (1,)),
              "assign": (0, (1, 2, 3, 4)), "Copy": (-1, (0,)), "ConstrainedCopy": (2, (0,)), "Fill": (0, (1,))}
# environment variable words that name configuration, not secrets (``CA_BUNDLE``, ``TLS_MIN_VERSION``)
_ENV_CONFIG_WORDS = {"ca", "bundle", "cafile", "capath", "cert", "certs", "certificate", "host", "hostname", "port",
                     "region", "endpoint", "dir", "directory", "timeout", "level", "debug", "min", "max", "tls", "ssl",
                     "url", "uri", "addr", "address", "server", "verify", "cipher", "ciphers", "curve", "curves"}
# fresh, empty buffers / containers a fix may build its ``nonce || ciphertext`` frame in
_FRESH_CALLS = {"make", "ByteArray", "alloc", "allocUnsafe", "allocate", "allocateDirect", "bytearray", "Buffer",
                "ByteArrayOutputStream", "MemoryStream", "ArrayList", "List", "mutableListOf", "arrayListOf",
                "bytes", "BytesIO", "StringBuilder", "zeros"}
# TLS options whose every value is checked by ``downgrades`` (a version floor / ceiling, a cipher list,
# verification on): a fix may change them inline in a call outside the allow-list (``tls.connect({.., minVersion})``)
TLS_RAISE = {"ciphers", "ciphersuites", "minversion", "maxversion", "minimumversion", "maximumversion",
             "rejectunauthorized", "checkhostname", "verifymode", "certreqs", "insecureskipverify", "secureprotocol",
             "sslprotocols", "enabledsslprotocols", "minprotocolversion", "maxprotocolversion"}
# options of a TLS call that a fix may change (their values are checked by the downgrade rules)
TLS_KEYS = {"ciphers", "ciphersuites", "minversion", "maxversion", "minimumversion", "maximumversion", "secureoptions",
            "ecdhcurve", "sigalgs", "honorcipherorder", "curvepreferences", "preferserverciphersuites", "verify",
            "checkhostname", "verifymode", "certreqs", "sslversion", "sslprotocols", "enabledsslprotocols",
            "rejectunauthorized", "timeout", "context", "sslcontext", "cafile", "capath", "cadata", "ssl", "tls",
            "insecureskipverify", "rootcas", "minprotocolversion", "maxprotocolversion", "ca"}


def norm(text: str) -> str:
    return re.sub(r"\s+", "", text)


def key_norm(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def words(ident: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", ident))
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+|\s+", spaced) if w]


def secret_name(ident: str) -> bool:
    ws = words(ident)
    if any(w in _NOT_KEY_WORDS for w in ws):
        return False
    return any(w in _KEY_WORDS or (len(w) > 3 and w.endswith("key")) for w in ws)


def path(n: N | None) -> str | None:
    """``a.b.c`` for a name / member chain (an index keeps its object's path), else None."""
    parts: list[str] = []
    cur = n
    while cur is not None:
        if cur.kind == "name":
            return ".".join([cur.name] + parts[::-1])
        if cur.kind == "member":
            parts.append(cur.name)
        elif cur.kind == "index":
            parts.clear()
        elif cur.kind != "cast":
            return None
        cur = cur.kids[0] if cur.kids else None
    return None


def names_in(n: N | None) -> Iterable[N]:
    if n is None:
        return []
    return (x for x in walk(n) if x.kind == "name")


# --------------------------------------------------------------------------------------------- chains & scope
@dataclass
class Seg:
    name: str
    called: bool
    node: N
    flag: Any = None


@dataclass
class Chain:
    head: str | None
    head_called: bool
    ctor: bool
    ctor_path: list[str]
    segs: list[Seg]
    node: N
    head_node: N | None


def unwind(n: N) -> Chain:
    segs: list[Seg] = []
    cur: N | None = n
    while cur is not None:
        if cur.kind == "call":
            callee = cur.kids[0] if cur.kids else None
            if callee is not None and callee.kind == "member":
                segs.append(Seg(callee.name, True, cur, callee.value))
                cur = callee.kids[0] if callee.kids else None
                continue
            if callee is not None and callee.kind == "name":
                return Chain(callee.name, True, False, [], segs[::-1], n, callee)
            segs.append(Seg("<call>", True, cur, cur.value))
            cur = callee
            continue
        if cur.kind == "new":
            typ = cur.kids[0] if cur.kids else None
            p = path(typ) or "<expr>"
            return Chain(p.split(".")[0], False, True, p.split("."), segs[::-1], n, cur)
        if cur.kind == "member":
            segs.append(Seg(cur.name, False, cur, cur.value))
            cur = cur.kids[0] if cur.kids else None
            continue
        if cur.kind == "index":
            segs.append(Seg("[]", False, cur, cur.value))
            cur = cur.kids[0] if cur.kids else None
            continue
        if cur.kind == "cast":
            cur = cur.kids[0] if cur.kids else None
            continue
        if cur.kind == "name":
            return Chain(cur.name, False, False, [], segs[::-1], n, cur)
        break
    return Chain(None, False, False, [], segs[::-1], n, cur)


def continues(n: N) -> bool:
    """``n`` is the object / callee of its parent (the chain goes on above it)."""
    p = n.parent
    return p is not None and p.kind in ("member", "index", "call", "cast") and bool(p.kids) and p.kids[0] is n


def binds(root: N) -> list[tuple[N, N | None, str, N]]:
    """(target, value, operator, node) for every assignment / declaration / loop target."""
    out: list[tuple[N, N | None, str, N]] = []
    for n in walk(root):
        if n.kind == "assign" and len(n.kids) >= 2:
            t, v = n.kids[0], n.kids[1]
            if t.kind == "seq" and v.kind == "seq" and len(t.kids) == len(v.kids):
                out += [(a, b, n.name, n) for a, b in zip(t.kids, v.kids)]
            else:
                out.append((t, v, n.name, n))
        elif n.kind == "for" and len(n.kids) >= 2:
            out.append((n.kids[0], n.kids[1], "for", n))
    return out


_UNWRAP_OTHER = {"ref_expression", "argument", "parenthesized_expression", "out_expression", "in_expression",
                 "declaration_expression", "non_null_expression", "postfix_expression", "checked_expression",
                 "await_expression", "satisfies_expression", "as_expression"}


def unwrap(v: N | None) -> N | None:
    """The value of ``v`` without wrappers that keep the object: a 1-tuple, a cast, ``&x`` / ``*p`` / ``await``,
    C# ``ref`` / ``out`` / ``in`` argument modifiers, ``x!`` (non-null)."""
    while v is not None and len(v.kids) == 1 and (
            v.kind in ("seq", "cast") or v.kind == "unary" and v.name in ("&", "*", "await", "+", "ref", "out", "in",
                                                                         "!!") or
            v.kind == "other" and v.name in _UNWRAP_OTHER):
        v = v.kids[0]
    return v


def target_paths(t: N | None) -> list[str]:
    if t is None:
        return []
    p = path(t)
    if p is not None:
        return [p]
    out = []
    for x in walk(t):
        if x.kind in ("name", "member"):
            q = path(x)
            if q:
                out.append(q)
    return out


class Scope:
    """What the names of one tree are: packages / modules by alias, names imported from them, declared functions,
    locals with every value they are given, and the locals that hold only allow-listed crypto objects."""

    def __init__(self, lang: str, root: N, extra: list[N] | None = None,
                 py_ok: Callable[[str], bool] | None = None, py_modules: set[str] | None = None) -> None:
        self.lang = lang
        self.api = APIS.get(lang)
        self.py_ok = py_ok
        self.aliases: dict[str, str] = {}
        self.imported: dict[str, str] = {}
        self.funcs: dict[str, list[str]] = {}
        self.func_nodes: dict[str, list[N]] = {}
        self.locals: dict[str, list[N | None]] = {}
        self.classes: set[str] = set()
        self.py_modules: set[str] = set(py_modules or ())
        for r in [root] + list(extra or []):
            for n in walk(r):
                if n.kind == "import" and lang != "python" and isinstance(n.value, list) and len(n.value) == 2:
                    mod, bnds = n.value
                    for local, what in bnds:
                        last = str(mod).split("/")[-1]
                        if what in ("*", "default"):
                            self.aliases[local] = last
                        else:
                            self.imported[local] = f"{last}.{what}"
                    if lang == "go" and not bnds:
                        self.aliases[str(mod).split("/")[-1]] = str(mod).split("/")[-1]
                elif n.kind == "func" and n.name:
                    self.funcs[n.name] = list(n.value or [])
                    self.func_nodes.setdefault(n.name, []).append(n)
                elif n.kind == "class" and n.name:
                    self.classes.add(n.name)
        for t, v, _op, _n in binds(root):
            if t is not None and t.kind == "name":
                self.locals.setdefault(t.name, []).append(v)
                self._require(t, v)
            elif t is not None and t.kind == "seq":
                for x in t.kids:  # b, err := aes.NewCipher(k): each name holds (a part of) the call's result
                    if x.kind == "name":
                        self.locals.setdefault(x.name, []).append(v)
                self._require(t, v)
        for n in walk(root):
            if n.kind == "func":
                for p in n.value or []:
                    self.locals.setdefault(p, []).append(None)
        for name in list(self.aliases):
            self.locals.pop(name, None)
        self.tracked = self._tracked()

    def _require(self, t: N, v: N | None) -> None:
        call = unwrap(v)
        if call is None or call.kind != "call" or not call.kids or call.kids[0].kind != "name" or \
                call.kids[0].name != "require" or len(call.kids) != 2 or call.kids[1].kind != "str":
            return
        mod = str(call.kids[1].value or "").split("/")[-1].removeprefix("node:")
        if t.kind == "name":
            self.aliases[t.name] = mod
        else:
            for x in t.kids:
                for nm in names_in(x):
                    self.imported[nm.name] = f"{mod}.{nm.name}"

    def _tracked(self) -> set[str]:
        """Locals every value of which is an allow-listed call / constructor (greatest fixpoint)."""
        cand = {name for name, vals in self.locals.items()
                if vals and all(unwrap(v) is not None and unwrap(v).kind in ("call", "new", "member", "obj")
                                for v in vals)}
        self.tracked = set(cand)
        for _ in range(8):
            keep = {name for name in self.tracked if all(self.made_ok(unwrap(v)) for v in self.locals[name])}
            if keep == self.tracked:
                break
            self.tracked = keep
        return self.tracked

    def made_ok(self, v: N | None) -> bool:
        if v is not None and v.kind == "obj":  # Go &tls.Config{...}: a struct of an allow-listed type
            typ = next((k for k in v.kids if k.value == "typeref"), None)
            return typ is not None and typ.kind == "member" and self.call_allowed(typ, strict=True)
        if v is None or v.kind not in ("call", "new", "member"):
            return False
        ch = unwind(v)
        if ch.head is None:
            return False
        made = ch.ctor or ch.head_called or bool(ch.segs)
        return made and self.call_allowed(v, strict=True)

    def is_package(self, name: str) -> bool:
        if self.lang == "python":
            return name in self.py_modules
        if self.lang in ("java", "kotlin", "csharp"):
            return (name[:1].isupper() or name in _NS_ROOTS) and name not in self.locals
        return name in self.aliases or (self.api is not None and name in self.api.packages and name not in self.locals)

    def is_local_path(self, p: str) -> bool:
        root = p.split(".")[0]
        return root in ("this", "self") or not self.is_package(root)

    def canon(self, name: str) -> str:
        return self.aliases.get(name, name)

    # ---------------------------------------------------------------------------------- the allow-list judge
    def judge(self, ch: Chain, strict: bool = False) -> list[tuple[str, N]]:
        """[(what, node)] of the chain's parts that the language's allow-list does not cover (outside Python)."""
        api = self.api
        if api is None:
            return [("<no allow-list>", ch.node)]
        bad: list[tuple[str, N]] = []
        ch = self._collapse(ch)
        rest = ch.segs
        if ch.ctor:
            if len(ch.ctor_path) > 1:
                bad.append((".".join(ch.ctor_path), ch.head_node or ch.node))
            elif ch.ctor_path[0] not in api.ctors:
                bad.append((f"new {ch.ctor_path[0]}", ch.head_node or ch.node))
        elif ch.head is None:
            pass
        elif ch.head_called:
            head = ch.head
            if self.lang == "kotlin" and head[:1].isupper():
                if head not in api.ctors:
                    bad.append((f"new {head}", ch.head_node.parent if ch.head_node and ch.head_node.parent else ch.node))
            elif head in self.imported:
                if self.imported[head] not in api.pairs:
                    bad.append((self.imported[head], ch.head_node.parent or ch.node))
            elif not (head in api.ctors or head in self.funcs) or head in _JS_FORBIDDEN:
                bad.append((f"{head}()", ch.head_node.parent if ch.head_node and ch.head_node.parent else ch.node))
        elif rest:
            first, rest = rest[0], rest[1:]
            head = ch.head
            if first.name == "[]":
                if first.flag == "computed" and self.lang in ("javascript", "typescript"):
                    bad.append((f"{head}[...]", first.node))
            elif self.is_package(head) or head in self.imported:
                q = self.imported.get(head, self.canon(head))
                if f"{q}.{first.name}" not in api.pairs and not _constant(first):
                    bad.append((f"{q}.{first.name}", first.node))
            elif head in self.tracked:
                if first.name in _JS_FORBIDDEN or not (first.name in api.methods or first.name in api.safe
                                                       or _constant(first)):
                    bad.append((f"{head}.{first.name}", first.node))
            elif strict or first.name in _JS_FORBIDDEN or not (first.name in api.safe or _constant(first)):
                bad.append((f"{head}.{first.name}", first.node))
        for seg in rest:
            if seg.name == "[]":
                if seg.flag == "computed" and self.lang in ("javascript", "typescript"):
                    bad.append(("[...]", seg.node))
                continue
            if seg.name == "<call>":
                bad.append(("<expression>()", seg.node))
                continue
            if seg.name in _JS_FORBIDDEN or not (seg.name in api.methods or seg.name in api.safe
                                                 or _constant(seg)):
                bad.append((f".{seg.name}", seg.node))
        return bad

    def _collapse(self, ch: Chain) -> Chain:
        """A fully qualified class (``java.util.Arrays.copyOf``, ``System.Security.Cryptography.Aes.Create``) is
        judged as ``Arrays.copyOf`` / ``Aes.Create``, when the namespace is the language's own crypto / base one."""
        if self.lang not in _NAMESPACES or ch.ctor or ch.head_called or ch.head is None or ch.head in self.locals:
            return ch
        parts = [ch.head]
        for seg in ch.segs:
            if seg.called or seg.name in ("[]", "<call>"):
                break
            parts.append(seg.name)
        for i in range(len(parts) - 1, 0, -1):
            if ".".join(parts[:i]) in _NAMESPACES[self.lang] and i < len(ch.segs) + 1 and i < len(parts):
                head_seg = ch.segs[i - 1]
                return Chain(head_seg.name, False, False, [], ch.segs[i:], ch.node, head_seg.node)
        return ch

    def call_allowed(self, n: N, strict: bool = False) -> bool:
        """The call / constructor / member chain ending at ``n`` is on the language's allow-list."""
        ch = unwind(n)
        if self.lang == "python":
            return self._py_allowed(ch)
        return not self.judge(ch, strict)

    def _py_allowed(self, ch: Chain) -> bool:
        ok = self.py_ok or (lambda _ref: False)
        if ch.ctor:
            return False
        segs = ch.segs
        if ch.head is None:  # a member of an expression's value: (AESGCM(k)).encrypt, "x".encode
            inner = ch.head_node
            base_ok = inner is not None and (inner.kind == "str" or inner.kind in ("call", "new") and
                                             self.call_allowed(inner))
            return base_ok and all(not s.called or s.name in VALUE_METHODS or s.name in SANITIZERS or
                                   s.name in DISTINCTIVE or ok(f"*.{s.name}()") for s in segs)
        if ch.head_called:
            return ok(f"{ch.head}()") and all(not s.called or ok(f"*.{s.name}()") for s in segs)
        head = ch.head
        if head in self.locals and head not in self.py_modules:
            if not segs:
                return True
            first, rest = segs[0], segs[1:]
            if first.called:
                good = (head in self.tracked and ok(f"{head}.{first.name}()")) or first.name in VALUE_METHODS or \
                    first.name in DISTINCTIVE
            else:
                good = True
            return good and all(not s.called or ok(f"*.{s.name}()") for s in rest)
        # a module / imported name: the dotted path up to the first call, then methods of the result
        dotted = [head]
        for i, s in enumerate(segs):
            if s.name == "<call>":
                return False
            if s.name == "[]" or s.flag == "computed":  # environ['K'] of os -> a value, then its methods
                return ok(".".join(dotted)) and all(not t.called or ok(f"*.{t.name}()") for t in segs[i + 1:])
            dotted.append(s.name)
            if s.called:
                return ok(".".join(dotted) + "()") and all(not t.called or ok(f"*.{t.name}()") for t in segs[i + 1:])
        return ok(".".join(dotted))


def chains(root: N) -> list[N]:
    """The outermost node of every call / constructor / member / index chain."""
    return [n for n in walk(root) if n.kind in ("call", "new", "member", "index") and not continues(n)]


def unlisted(after: N, before: N, lang: str) -> list[str]:
    """Calls / members the rewrite reaches that the allow-list does not cover, unless the window makes exactly
    the same one in the same place (counted, whitespace aside)."""
    if lang not in APIS:
        return []

    def uncovered(root: N, scope: Scope) -> tuple[Counter[tuple[str, tuple[str, ...]]], dict[Any, str]]:
        counts: Counter[tuple[str, tuple[str, ...]]] = Counter()
        what: dict[Any, str] = {}
        for top in chains(root):
            for name, node in scope.judge(unwind(top)):
                k = (_blank_tls(node, TLS_RAISE), top.ctx)
                counts[k] += 1
                what.setdefault(k, name)
        return counts, what

    a_counts, what = uncovered(after, Scope(lang, after, [before]))
    b_counts, _ = uncovered(before, Scope(lang, before, [after]))
    return sorted({what[k] for k, n in a_counts.items() if n > b_counts[k]})


# ------------------------------------------------------------------------------------------- data flow (taint)
class Flow:
    """Key material through one tree: every name the finding marks as key / IV / secret material, every value
    an allow-listed key / IV / random-generating call returns, and everything assigned or derived from them
    (assignments, concatenation, append / copy into a buffer, loop targets, object properties, arguments of local
    functions), writes through an alias or a view of a buffer (may-alias classes: the whole class takes the label),
    and what a function defined in the tree writes into its parameters (written back into every argument of its
    calls, to a fixpoint). Labels: ``IV`` (random / IV / nonce / salt), ``KEY`` (keys, passwords, the environment, derived
    keys), ``ABSORBED`` (a cipher object that took key material in as data). Any label reaching a call outside the
    allow-list, an exception message or a member of a non-local is a leak."""

    def __init__(self, root: N, scope: Scope, incoming: bool = False) -> None:
        """``incoming``: only key material that comes INTO the code (parameters, fields, key positions, what is
        derived from them by hashing / encoding / copying) - keys the code derives or generates itself (a KDF, a
        key generator, randomness) and the environment are not counted (``key_returns``)."""
        self.root, self.scope, self.incoming = root, scope, incoming
        self.calls = [n for n in walk(root) if n.kind in ("call", "new")]
        self.binds = binds(root)
        self.tainted: dict[str, int] = {}
        self._cls: dict[int, str] = {}
        self._memo: dict[int, int] = {}
        self.local_ret: dict[str, int] = {}
        # interprocedural summaries of the functions defined in the tree (rewrite and window): labels written INTO a
        # parameter (or an alias of one) by the body, by function node; a call site's arguments take them
        self.param_writes: dict[int, int] = {}
        self._fn_params: dict[int, set[str]] = {id(fn): set(fn.value or []) for fns in scope.func_nodes.values()
                                                for fn in fns}
        self._fn_params.update({id(fn): set(fn.value or []) for fn in walk(root) if fn.kind == "func"})
        self._recursive: set[int] = {id(fn) for fns in scope.func_nodes.values() for fn in fns
                                     if any(c.kind == "call" and c.kids and c.kids[0].kind == "name" and
                                            c.kids[0].name == fn.name for c in walk(fn) if c is not fn)}
        self._parent: dict[str, str] = {}
        self._aliases()
        self._seed()
        self._fixpoint()

    # ----------------------------------------------------------------------------------- call classification
    def callee(self, n: N) -> tuple[str, N | None, list[N]]:
        """(name, receiver, arguments) of a call / constructor (keyword arguments as their values)."""
        if n.kind == "new":
            typ = n.kids[0] if n.kids else None
            name = (path(typ) or "").split(".")[-1]
            return name, None, [self._arg(a) for a in n.kids[1:]]
        f = n.kids[0] if n.kids else None
        args = [self._arg(a) for a in n.kids[1:]]
        if f is not None and f.kind == "member":
            return f.name, f.kids[0] if f.kids else None, args
        if f is not None and f.kind == "name":
            return f.name, None, args
        return "", f, args

    @staticmethod
    def _arg(a: N) -> N:
        return a.kids[0] if a.kind == "kwarg" and a.kids else a

    def classify(self, n: N) -> str:
        """sink (not on the allow-list) | error (an exception / error message: on the allow-list, but what it is
        given ends up in a log) | source | fill | digest | cipher | propagate | local."""
        got = self._cls.get(id(n))
        if got is not None:
            return got
        name, _recv, _args = self.callee(n)
        f = n.kids[0] if n.kids else None
        if n.kind == "call" and f is not None and f.kind == "name" and name in self.scope.funcs \
                and name not in self.scope.locals:
            cls = "local"
        elif not self.scope.call_allowed(n):
            cls = "sink"
        elif name in EXCEPTIONS:
            cls = "error"
        elif name in SOURCES:
            cls = "source"
        elif name in FILLS:
            cls = "fill"
        elif name in DIGESTS:
            cls = "digest"
        elif name in CIPHER_OUT:
            cls = "cipher"
        else:
            cls = "propagate"
        self._cls[id(n)] = cls
        return cls

    def inputs(self, n: N) -> list[N]:
        _name, recv, args = self.callee(n)
        return ([recv] if recv is not None else []) + args

    def key_positions(self, n: N) -> tuple[set[int], bool]:
        """(indexes into ``callee()``'s arguments that take a key / IV - positional by position, keyword arguments
        by a key-like name -, whether the receiver is the key) of a call: what goes there makes the result a key
        HOLDER, not key material; everything else is data."""
        name, recv, _args = self.callee(n)
        raw = n.kids[1:]
        args = [a for a in raw if a.kind != "kwarg"]
        rp = (path(recv) or "").split(".")[-1] if recv is not None else ""
        if name == "init":  # Cipher.init(mode, key, params); Mac.init(key[, params])
            first = norm(args[0].text) if args else ""
            pos: tuple[int, ...] | None = (1, 2) if "MODE" in first.upper() else (0, 1)
        elif name == "digest" and rp == "hmac" or name == "HashData" and rp.upper().startswith("HMAC"):
            pos = (0,)  # hmac.digest(key, msg, d); HMACSHA256.HashData(key, data)
        elif name in ("SignPSS", "SignPKCS1v15", "SignASN1"):
            pos = (1,)  # (rand, priv, ...)
        elif name == "Sign" and rp == "ed25519":
            pos = (0,)
        elif rp == "subtle" and name in ("encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey", "deriveKey",
                                         "deriveBits", "exportKey"):
            pos = (1,) if name not in ("wrapKey", "exportKey") else (1, 2)  # WebCrypto (alg, key, data)
        elif name in KEY_TAKERS:
            pos = KEY_TAKERS[name]
        else:
            pos = ()
        keyed_pos = set(range(len(args))) if pos is None else set(pos)
        keyed, i_pos = set(), 0
        for i, a in enumerate(raw):  # map positional indexes to argument indexes; key-named keywords are keys
            if a.kind == "kwarg":
                if secret_name(a.name):
                    keyed.add(i)
                continue
            if i_pos in keyed_pos:
                keyed.add(i)
            i_pos += 1
        return keyed, name in SIGNERS

    def iv_positions(self, n: N) -> set[int]:
        """Argument indexes (as ``key_positions``) that take an IV / nonce, not a key."""
        name, _recv, _args = self.callee(n)
        raw = n.kids[1:]
        if name == "init":
            pos: tuple[int, ...] = (2,) if raw and "MODE" in norm(raw[0].text).upper() else (1,)
        else:
            pos = IV_TAKERS.get(name, ())
        out, i_pos = set(), 0
        for i, a in enumerate(raw):
            if a.kind == "kwarg":
                if secret_name(a.name) and self._word_label(a.name) == IV:
                    out.add(i)
                continue
            if i_pos in pos:
                out.add(i)
            i_pos += 1
        return out

    def split_inputs(self, n: N) -> tuple[list[N], list[N]]:
        """(data inputs, key-position inputs) of a call / constructor."""
        _name, recv, args = self.callee(n)
        keyed, recv_key = self.key_positions(n)
        data = [a for i, a in enumerate(args) if i not in keyed]
        key = [a for i, a in enumerate(args) if i in keyed]
        if recv is not None:
            (key if recv_key else data).insert(0, recv)
        return data, key

    # ------------------------------------------------------------------------------------------------ taint
    def _seed(self) -> None:
        for n in self.calls:
            name, _recv, args = self.callee(n)
            if name in KEY_TAKERS:
                keyed, _ = self.key_positions(n)
                ivs = self.iv_positions(n)
                for i, a in enumerate(args):
                    if i in keyed:
                        self._mark(a, IV if i in ivs else KEY)
            for a in n.kids[1:]:  # keyword arguments named like key material: AES.new(k, mode, nonce=n)
                if a.kind == "kwarg" and secret_name(a.name) and a.kids:
                    self._mark(a.kids[0], self._word_label(a.name))
        for t, v, _op, _n in self.binds:  # a.Key = k, cipher.iv = iv
            if t is not None and t.kind == "member" and secret_name(t.name):
                self._mark(v, self._word_label(t.name))

    @staticmethod
    def _word_label(name: str) -> int:
        ws = words(name)
        return IV if ws and all(w in _IV_WORDS or w not in _KEY_WORDS for w in ws) and \
            any(w in _IV_WORDS for w in ws) else KEY

    def canon(self, p: str) -> str:
        """A member of ``this`` / ``self`` / a class declared here is the field: ``this.k``, ``Z.k`` -> ``k``."""
        root, _, rest = p.partition(".")
        if rest and (root in ("this", "self", "super", "base") or root in self.scope.classes):
            return rest
        return p

    def _mark(self, n: N | None, label: int) -> bool:
        if n is None or not label:
            return False
        p = path(unwrap(n))
        if p and (self.scope.is_local_path(p) or self.canon(p) != p):
            p = self.canon(p)
            if (self.tainted.get(p, 0) | label) != self.tainted.get(p, 0):
                self.tainted[p] = self.tainted.get(p, 0) | label
                return True
        return False

    # --------------------------------------------------------------------------------- aliases and views
    def _root(self, p: str | None) -> str | None:
        """The local / parameter / field a path starts at (``this.buf.x`` -> ``buf``), None for packages."""
        if not p:
            return None
        c = self.canon(p)
        if not (self.scope.is_local_path(p) or c != p):
            return None
        r = c.split(".")[0]
        if r == "_" and self.scope.lang in ("go", "csharp", "kotlin"):  # the blank identifier / a discard
            return None
        return None if r in _SELF_NAMES or not r else r

    def _returns_param(self, fn: N) -> bool:
        params = self._fn_params.get(id(fn), set())
        for r in walk(fn):
            if r.kind == "other" and r.name in RETURNS and _owner(r) is fn and \
                    any(x in params or self._find(x) in {self._find(p) for p in params}
                        for k in r.kids for x in self.view_roots(k)):
                return True
        return False

    def view_roots(self, v: N | None, depth: int = 0) -> set[str]:
        """Locals / parameters / fields whose memory the value of ``v`` may share: the name itself, a slice / index /
        member of it, a view or wrapper of it (``VIEWS``), one operand of a choice (``a or b``), the elements of a
        container literal, the arguments of a local function that returns one of its parameters."""
        v = unwrap(v)
        if v is None or depth > 8:
            return set()
        k = v.kind
        if k == "member" and v.name in _SIZE_MEMBERS:  # ct.length is a number, not the buffer
            return set()
        if k in ("name", "member", "index", "cast"):
            p = path(v)
            if p is not None:
                r = self._root(p)
                return {r} if r else set()
            return self.view_roots(v.kids[0] if v.kids else None, depth + 1)
        if k in ("call", "new"):
            name, recv, args = self.callee(v)
            f = v.kids[0] if v.kids else None
            local = k == "call" and f is not None and f.kind == "name" and name in self.scope.funcs and \
                any(self._returns_param(fn) for fn in self.scope.func_nodes.get(name, []))
            # fail closed: a constructor that is not a key holder may keep its arguments (``new H(ct)``,
            # ``new ArrayList<>(List.of(ct))``); views, containers and calls returning their receiver alias them
            keeps = k == "new" and name not in KEY_TAKERS and not _allocation(v)
            if name in ("concat", "Concat") and recv is not None and (path(recv) or "") in ("Buffer", "bytes"):
                return set()  # Buffer.concat copies the bytes; [a].concat([b]) keeps the elements
            if name in VIEWS or name in _CONTAINERS or name in _RETURNS_SELF or local or keeps:
                out: set[str] = set()
                for x in ([recv] if recv is not None else []) + args:
                    out |= self.view_roots(x, depth + 1)
                return out
            return set()
        if k == "binary" and v.name in _CHOICE_OPS or k in ("other", "ctl") and v.name in _CHOICE_NODES or \
                k in ("seq", "obj", "pair"):
            out = set()
            for x in v.kids:
                out |= self.view_roots(x, depth + 1)
            return out
        if k == "other" and v.name not in ("params", "compare", "del", "assert"):  # fail closed: a form not classified above (array creation with
            # an initialiser ``new[] { ct }`` / ``new byte[][] { ct }``, collection expressions, ``with`` items, a
            # dict entry, a comprehension) may hold any buffer it mentions
            out = set()
            for x in v.kids:
                out |= self.view_roots(x, depth + 1)
            return out
        return set()

    def _find(self, x: str) -> str:
        while self._parent.get(x, x) != x:
            self._parent[x] = self._parent.get(self._parent[x], self._parent[x])
            x = self._parent[x]
        return x

    def _union(self, a: str, b: str) -> None:
        ra, rb = self._find(a), self._find(b)
        if ra != rb:
            self._parent[ra] = rb
            self._parent.setdefault(rb, rb)

    def _aliases(self) -> None:
        """May-alias classes (union-find) of the locals, parameters and fields: ``d2 := data``, ``var al = ct``,
        ``s = data[a:b]``, ``bb = ByteBuffer.wrap(ct)``, ``v = ct.AsSpan()``, ``for b in bufs``, ``lst = [ct]``,
        ``this.buf = ct``, ``arr[0] = ct``, and the arguments of a call to a local function that returns a parameter.
        Iterated, since a local function's 'returns a parameter' depends on the classes."""
        for _ in range(4):
            before = dict(self._parent)
            for t, v, op, _n in self.binds:
                if op in _INPLACE_OPS or t is None or v is None:  # every other binding form aliases (fail closed)
                    continue
                dst = self.view_roots(t) if unwrap(t) is not None and unwrap(t).kind != "seq" else set()
                if not dst and t.kind == "seq":
                    dst = {r for x in t.kids for r in self.view_roots(x)}
                src = self.view_roots(v)
                for a in dst:
                    for b in src:
                        self._union(a, b)
            for n in self.calls:  # C# ``out`` / ``ref`` arguments: the callee may bind any of them to any other
                if self.scope.lang == "csharp" and n.kind == "call" and re.search(r"[(,]\s*(?:out|ref)\s", n.text):
                    roots = [r for a in n.kids[1:] for r in self.view_roots(a)]
                    for a, b in itertools.pairwise(roots):
                        self._union(a, b)
            if self._parent == before:
                break

    def alias_class(self, root: str) -> set[str]:
        r = self._find(root)
        return {x for x in self._parent if self._find(x) == r} | {root}

    def _mark_into(self, x: N, label: int, at: N) -> None:
        """A call wrote ``label`` into ``x``: a name / member / index is marked; any other destination (a slice, a
        view, a wrapper, a choice) marks every buffer it may share memory with. The write is recorded against the
        functions whose parameters it reaches (``param_writes``)."""
        if not label:
            return
        p = path(unwrap(x)) if x.kind in ("name", "member", "index") else None
        if p is not None:
            self._mark(x, label)
            roots = {r for r in (self._root(p),) if r}
        elif x.kind in ("seq", "obj", "pair"):  # Buffer.concat([ct, k]) reads its elements, it does not write them
            return
        else:
            roots = self.view_roots(x)
            for r in roots:
                self.tainted[r] = self.tainted.get(r, 0) | label
        self._record_write(roots, label, at)  # type: ignore[arg-type]

    def _record_write(self, roots: set[str], label: int, at: N) -> None:
        if not roots or not label:
            return
        reach = set()
        for r in roots:
            reach |= self.alias_class(r)
        cur = at.parent
        while cur is not None:
            if cur.kind == "func" and reach & self._fn_params.get(id(cur), set()):
                self.param_writes[id(cur)] = self.param_writes.get(id(cur), 0) | label
            cur = cur.parent

    def _spread(self) -> None:
        """Taint of any member of an alias class is taint of the whole class (a write through ``d2`` is in ``data``)."""
        if not self._parent:
            return
        for t, m in list(self.tainted.items()):
            r = t.split(".")[0]
            if r in self._parent:
                for x in self.alias_class(r):
                    if (self.tainted.get(x, 0) | m) != self.tainted.get(x, 0):
                        self.tainted[x] = self.tainted.get(x, 0) | m

    def path_label(self, p: str) -> int:
        if p.startswith(_ENV_PATHS) or ".process.env" in p:
            return 0 if self.incoming else KEY
        out = 0
        for seg in p.split("."):
            if secret_name(seg):
                out |= self._word_label(seg)
        p = self.canon(p)
        for t, m in self.tainted.items():
            if p == t or p.startswith(t + ".") or t.startswith(p + "."):
                out |= m
        return out

    def label(self, n: N | None) -> int:
        if n is None:
            return 0
        got = self._memo.get(id(n))
        if got is not None:
            return got
        self._memo[id(n)] = 0  # cycles
        out = self._label(n)
        self._memo[id(n)] = out
        return out

    def is_tainted(self, n: N | None) -> bool:
        return bool(self.label(n))

    def _any(self, nodes: Iterable[N | None]) -> int:
        out = 0
        for x in nodes:
            out |= self.label(x)
        return out

    def _call_label(self, n: N) -> int:
        """What a call that is not a source / hash / cipher returns: its data inputs' labels, and HOLDER when key
        material went into a key position (``AESGCM(k)``, ``hmac.new(k, ...)``, ``SecretKeySpec(k)``)."""
        data, key = self.split_inputs(n)
        return self._any(data) | (HOLDER if self._any(key) else 0)

    def _label(self, n: N) -> int:  # noqa: C901 - one rule per node kind
        k = n.kind
        if k == "member" and n.name in _SIZE_MEMBERS:
            return 0
        if k in ("name", "member", "index"):
            p = path(n)
            out = self.path_label(p) if p is not None else 0
            if k == "member":
                if secret_name(n.name):
                    out |= self._word_label(n.name)
                if p is None:
                    out |= self.label(n.kids[0] if n.kids else None)
            elif k == "index":
                out |= self._any(n.kids)
            return out
        if k in ("call", "new"):
            cls = self.classify(n)
            name, recv, args = self.callee(n)
            if cls == "source":
                return 0 if self.incoming else IV if name in RANDOM_SOURCES else KEY
            if cls == "digest":
                if name in VERDICTS:
                    return 0
                data, _key = self.split_inputs(n)
                args_l = self._any(a for a in data if a is not recv)
                recv_l = self.label(recv) if recv is not None and any(a is recv for a in data) else 0
                # key material hashed as data (or the hash object fed it): key-derived; a MAC / signer object that
                # holds its key in the key position is not
                bad = args_l & (KEYISH | HOLDER) or recv_l & KEYISH
                return (KEY_DERIVED | ABSORBED if bad else 0) | ((args_l | recv_l) & IV)
            if cls == "cipher":
                data, _key = self.split_inputs(n)
                data_l = self._any(a for a in data if a is not recv) & KEYISH
                return KEY | ABSORBED if data_l or self.label(recv) & ABSORBED else 0
            if cls == "local":
                return self.local_ret.get(name, 0) | self._any(self.inputs(n))
            f = n.kids[0] if n.kids else None
            out = self._call_label(n) if cls == "propagate" else self._any(self.inputs(n))
            if n.kind == "call" and f is not None and f.kind == "name":
                out |= self.label(f)  # a local holding a function that returns key material: f = () => key; f()
            return out
        if k in ("num", "bool", "null", "regex", "import"):
            return 0
        if k == "other" and n.name == "params":  # parameter names are not reads (defaults are checked as calls)
            return 0
        if k == "assign":
            return self.label(n.kids[1] if len(n.kids) > 1 else None)
        return self._any(n.kids)

    def _fixpoint(self) -> None:
        for _ in range(40):
            size = (sorted(self.tainted.items()), sorted(self.local_ret.items()), sorted(self.param_writes.items()))
            self._memo.clear()
            for t, v, op, bn in self.binds:
                m = self.label(v) if v is not None else 0
                if m:
                    for p in target_paths(t):
                        if self.scope.is_local_path(p) or self.canon(p) != p:
                            p = self.canon(p)
                            self.tainted[p] = self.tainted.get(p, 0) | m
                    # a store into an element / field / through a pointer, an in-place operator (``b += k``), or any
                    # assignment to a C# parameter (``ref`` / ``out``) writes into what the caller passed
                    tt = t
                    if tt is not None and (tt.kind in ("member", "index", "unary", "other") or op in _INPLACE_OPS or
                                           self.scope.lang == "csharp"):
                        self._record_write({r for p in target_paths(tt) for r in (self._root(p),) if r}, m, bn)
            for n in self.calls:
                cls = self.classify(n)
                ins = self.inputs(n)
                if cls == "fill":
                    for x in ins:
                        self._mark_into(x, IV, n)
                elif cls == "propagate":  # copy(dst, k), System.arraycopy(k, .., out, ..), h.Write(k), buf.extend(k)
                    data, _key = self.split_inputs(n)
                    _nm, recv, _a = self.callee(n)
                    m_all = self._call_label(n)  # the receiver may now hold the key (c.init(mode, spec))
                    m_data = self._any(data) & ~HOLDER  # arguments take each other's data, not the HOLDER bit
                    for x in data:  # a destination may be a view of a buffer: copy(d[i:], k), wrap(ct).put(k)
                        self._mark_into(x, m_all if x is recv else m_data, n)
                elif cls in ("cipher", "digest"):
                    name, recv, _args = self.callee(n)
                    data, _key = self.split_inputs(n)
                    if name not in VERDICTS and self._any(a for a in data if a is not recv) & KEYISH:
                        for x in data:  # key material went in as data: the cipher / hash object took it in
                            self._mark_into(x, ABSORBED, n)
                elif cls == "local":
                    m = self._any(ins)
                    for p in self.scope.funcs.get(self.callee(n)[0], []) if m else []:
                        self.tainted[p] = self.tainted.get(p, 0) | m
                    # what the body writes into its parameters is written into this call's arguments (positions are
                    # not trusted: every argument takes it); a recursive function writes all it is given
                    w = 0
                    for fn in self.scope.func_nodes.get(self.callee(n)[0], []):
                        w |= self.param_writes.get(id(fn), 0)
                        if id(fn) in self._recursive:
                            w |= self._any(ins) | self.local_ret.get(fn.name, 0)
                    for x in ins:
                        self._mark_into(x, w, n)
                m = self._any(x for x in ins if x.kind != "func")
                for fn in (x for x in ins if x.kind == "func") if m else []:  # [key].map(k => ...), callbacks
                    for p in fn.value or []:
                        self.tainted[p] = self.tainted.get(p, 0) | m
                w = 0
                for fn in (x for x in ins if x.kind == "func"):  # ct.also { k.copyInto(it) }: the callback's writes
                    w |= self.param_writes.get(id(fn), 0)
                for x in (x for x in ins if x.kind != "func") if w else []:
                    self._mark_into(x, w, n)
            for name, nodes in self.scope.func_nodes.items():
                for fn in nodes:
                    for r in walk(fn):
                        if r.kind == "other" and r.name in RETURNS and _owner(r) is fn:
                            m = self._any(r.kids)
                            if m:
                                self.local_ret[name] = self.local_ret.get(name, 0) | m
            self._spread()
            if (sorted(self.tainted.items()), sorted(self.local_ret.items()), sorted(self.param_writes.items())) == size:
                break
        self._memo.clear()

    # ------------------------------------------------------------------------- sink-side rule: write-into
    def _flat(self, x: N | None) -> list[N]:
        """The elements of a value: a container literal / spread / keyword argument is its elements."""
        x = unwrap(x)
        if x is None:
            return []
        if x.kind in ("seq", "obj") or x.kind == "pair" or x.kind == "kwarg" or \
                x.kind == "other" and x.name in ("starred", "spread_element", "variadic_argument", "entry",
                                                 "array_creation_expression", "implicit_array_creation_expression",
                                                 "collection_expression"):
            return [e for k in x.kids if k.value != "typeref" for e in self._flat(k)]
        return [x]

    def operand(self, x: N | None) -> bool:
        """``x`` may carry data / be a buffer: anything but a literal, a size, a verdict (``len(k)``), a package /
        module member or constant (``AES.MODE_GCM``, ``StandardCharsets.UTF_8``), a lambda."""
        x = unwrap(x)
        if x is None or x.kind in ("str", "num", "bool", "null", "regex", "func", "import"):
            return x is not None and x.kind == "str" and any(self.operand(k) for k in x.kids)
        if x.kind in ("binary", "unary"):
            return any(self.operand(k) for k in x.kids)
        if x.kind == "member" and x.name in _SIZE_MEMBERS:
            return False
        if x.kind in ("name", "member", "index"):
            p = path(x)
            if p is None:
                return True
            root = p.split(".")[0]
            if root in _SELF_NAMES:
                return True
            return self.scope.is_local_path(p) or root in self.scope.imported and x.kind == "index"
        if x.kind in ("call", "new"):
            name, _recv, _args = self.callee(x)
            return not (name in VERDICTS or name in _SIZE_MEMBERS)
        if x.kind in ("seq", "obj", "pair", "kwarg"):
            return any(self.operand(k) for k in x.kids if k.value != "typeref")
        return True

    def _aead_part(self, x: N | None) -> bool:
        """``x`` is the ciphertext / tag of an allow-listed AEAD of this tree (a call, a local only ever holding
        one, a C# output buffer an AEAD writes), or a frame of nonce and such ciphertext."""
        x = unwrap(x)
        if x is None or self.label(x) & ~IV:
            return False
        if x.kind in ("call", "new") and self.classify(x) in ("cipher", "digest"):
            return self.aead(x)
        p = path(x) if x.kind == "name" else None
        if p is not None:
            vals = self.scope.locals.get(p, [])
            if vals and all(v is not None and self.out_buffer(p, v) for v in vals):
                return True
        ok, aead = self._envelope(x, frozenset())
        return ok and aead

    def _fresh(self, d: N | None, depth: int = 0) -> tuple[bool, Any]:
        """(``d`` is a buffer / container this tree freshly allocates, the key of that buffer): ``new byte[n]``,
        ``ByteBuffer.allocate(n)`` (and calls on it returning it), ``bytearray()``, ``[]``, or a local whose every
        value is one."""
        d = unwrap(d)
        if d is None or depth > 6:
            return False, None
        if _allocation(d) or d.kind in ("seq", "obj") and not d.kids:
            return True, id(d)
        if d.kind in ("call", "new"):
            name, recv, args = self.callee(d)
            if name in _RETURNS_SELF and recv is not None:
                return self._fresh(recv, depth + 1)
            if name in _FRESH_CALLS and not any(self.operand(a) for a in args if a.kind != "kwarg"):
                return True, id(d)
            return False, None
        p = path(d) if d.kind == "name" else None
        if p is None:
            return False, None
        # a local: every value it is given in the tree is fresh, and one is given before this use in the same or an
        # enclosing block (a parameter of the same name is shadowed only then)
        own = [(t, v, bn) for t, v, op, bn in self.binds if t is not None and op not in _INPLACE_OPS and
               any(x.kind == "name" and x.name == p for x in ([t] if t.kind != "seq" else t.kids))]
        if not own or not all(v is not None and self._fresh(v, depth + 1)[0] for _t, v, _bn in own):
            return False, None
        params = any(v is None for v in self.scope.locals.get(p, []))
        if params:
            order = self._order()
            here = order.get(id(d), -1)
            if not any(order.get(id(bn), 1 << 30) < here and d.ctx[:len(bn.ctx)] == bn.ctx for _t, _v, bn in own):
                return False, None
        return True, self._find(p)

    def _order(self) -> dict[int, int]:
        if not hasattr(self, "_order_memo"):
            self._order_memo = {id(n): i for i, n in enumerate(walk(self.root))}
        return self._order_memo

    def _dest(self, n: N) -> tuple[N | None, list[N]] | None:
        """(destination, sources) of a write-into call, None for a call that is not one."""
        name, recv, args = self.callee(n)
        if recv is not None and name in _RECV_SRC and args:
            return args[0], [recv]
        if recv is not None and name in _RECV_DEST:
            return recv, list(args)
        if name in _FUNC_DEST:
            d, srcs = _FUNC_DEST[name]
            if d == -1:  # Array.Copy(src, dst, n) / Array.Copy(src, si, dst, di, n)
                d = 2 if len(args) >= 5 else 1
            if d < len(args):
                return args[d], [args[i] for i in srcs if i < len(args)]
        return None

    def key_writes(self) -> list[str]:
        """The sink-side rule, independent of the alias / view machinery. KEY-class data (key material, key-derived
        values, a cipher that absorbed a key, environment secrets) appears in a write-into operation (a copy,
        put / set / fill, append / extend / add, an index or slice store, an in-place operator, a concatenation,
        string formatting, a container literal with other values): withheld, wherever the destination points.
        IV / nonce material may be written only into a buffer this tree freshly allocates whose every other input
        is ciphertext of an allow-listed AEAD of this tree (``nonce || ct || tag``), or framed so by a
        concatenation; anything else is withheld. Calls in a key position of a crypto call are not writes."""
        out: list[str] = []
        groups: dict[Any, list[tuple[N, N]]] = {}  # fresh destination -> [(source, at)] of every write into it
        iv_groups: set[Any] = set()

        def key(x: N | None) -> bool:
            return bool(x is not None and self.label(x) & KEYISH and not self._env_config(x))

        def iv(x: N | None) -> bool:
            return bool(x is not None and self.label(x) & IV)

        def note(n: N, what: str) -> None:
            out.append(f"{what}: {norm(n.text)[:70]}")

        def into(dest: N | None, sources: list[N], at: N) -> None:
            """A write of ``sources`` into ``dest``: IV sources only into a fresh frame (checked per frame below)."""
            srcs = [e for s in sources for e in self._flat(s)]
            if not any(iv(s) for s in srcs):
                fresh, gk = self._fresh(dest)
                if fresh:
                    groups.setdefault(gk, []).extend((s, at) for s in srcs)
                return
            fresh, gk = self._fresh(dest)
            if not fresh:
                note(at, "nonce / IV copied into a buffer that is not a fresh nonce || ciphertext frame")
                return
            groups.setdefault(gk, []).extend((s, at) for s in srcs)
            iv_groups.add(gk)

        for n in self.calls:
            if self.classify(n) != "propagate" or self._consumed(n):
                continue
            name, _recv, _args = self.callee(n)
            data, _key = self.split_inputs(n)
            literal_in = any(unwrap(a) is not None and unwrap(a).kind in ("seq", "obj") for a in data)
            elems = [e for a in data for e in self._flat(a) if e.kind != "func"]  # a callback is checked itself
            ks = [e for e in elems if key(e)]
            ivs = [e for e in elems if iv(e) and not key(e)]
            # every input that may be data, whatever its label (a destination the copy itself taints counts too)
            ops = [e for e in elems if key(e) or iv(e) or self.operand(e)]
            # a conversion takes one value (and offsets / encodings); one that is also the name of a copy
            # (``k.copy(dst)``, ``copy(dst, k)``) only while it is given nothing else that may be data
            conversion = name in _CONVERSIONS and not literal_in and (name not in _CONVERSION_IF_ALONE or len(ops) <= 1)
            if ks:
                if name in _FORMATS or not conversion and len(ops) > 1:
                    note(n, "key material written into another value")
                continue
            dest = self._dest(n)
            parts = _concat_parts(n)
            if dest is not None and not conversion:
                into(dest[0], dest[1], n)
            elif ivs and parts is not None and len(parts) > 1:
                if not self.envelope(n):
                    note(n, "nonce / IV concatenated with something other than AEAD ciphertext")
            elif ivs and (name in _FORMATS or not conversion and len(ops) > 1):
                note(n, "nonce / IV written into another value")
        for t, v, op, bn in self.binds:  # index / slice stores and in-place operators
            if v is None or t is None:
                continue
            tt = unwrap(t)
            store = tt is not None and tt.kind == "index"
            if not (store or op in _INPLACE_OPS):
                continue
            if key(v):
                note(bn, "key material stored into a buffer")
            elif store:
                into(tt.kids[0] if tt.kids else None, [v], bn)
            else:
                into(tt, [v], bn)
        for n in walk(self.root):
            if self._consumed(n):  # built only to be hashed / encrypted / derived from: no buffer holds it
                continue
            if n.kind == "binary" and n.name not in _NOT_BUILDING:
                if any(key(k) for k in n.kids):
                    note(n, "key material concatenated / combined with another value")
                elif any(iv(k) for k in n.kids) and not self.envelope(n):
                    p = n.parent  # judged once, as the whole ``a + b + c``
                    if not (p is not None and p.kind == "binary" and p.name == n.name and self.envelope(p)):
                        note(n, "nonce / IV concatenated with something other than AEAD ciphertext")
            elif n.kind == "str" and n.kids:
                if any(key(k) or iv(k) for k in n.kids):
                    note(n, "key material / nonce in string formatting")
            elif n.kind in ("seq", "obj") and not self._target_side(n):
                elems = self._flat(n)
                if any(key(e) for e in elems) and len([e for e in elems if key(e) or self.operand(e)]) > 1:
                    note(n, "key material put in a container with other values")
        for gk in iv_groups:  # a fresh frame with a nonce in it: every other input is AEAD ciphertext
            for s, at in groups.get(gk, []):  # (a nonce by where it comes from: a copy spreads the IV label)
                if self.operand(s) and not self._iv_origin(s) and not self._aead_part(s):
                    note(at, "nonce / IV frame also holds something other than AEAD ciphertext")
        return sorted(set(out))

    def _iv_origin(self, x: N | None, depth: int = 0) -> bool:
        """``x`` is a nonce / IV by where it comes from (not by the label a copy may have spread): a random source,
        a buffer a random fill writes, a name / member that says iv / nonce / salt, a conversion of one."""
        x = unwrap(x)
        if x is None or depth > 4 or self.label(x) & ~(IV | HOLDER) or not self.label(x) & IV:
            return False
        if x.kind in ("call", "new"):
            name, recv, args = self.callee(x)
            if name in RANDOM_SOURCES:
                return True
            if name in _CONVERSIONS:
                src = recv if recv is not None and self.operand(recv) else (args[0] if args else None)
                return self._iv_origin(src, depth + 1)
            return False
        if x.kind == "member" and secret_name(x.name) and self._word_label(x.name) == IV:
            return True
        p = path(x) if x.kind == "name" else None
        if p is None:
            return False
        if secret_name(p) and self._word_label(p) == IV:
            return True
        vals = self.scope.locals.get(p, [])
        filled = any(self.classify(n) == "fill" and any(path(unwrap(a)) == p for a in self.inputs(n))
                     for n in self.calls)
        return bool(vals) and all(v is not None and (self._iv_origin(v, depth + 1) or filled and self._fresh(v)[0])
                                  for v in vals)

    def _consumed(self, n: N) -> bool:
        """``n`` (a concatenation / join / literal) is itself a DATA argument of a hash / cipher / KDF call
        (``PasswordHasher().hash(key + msg)``, ``sha256(salt + pw)``): it exists only as that call's input, and the
        call's result carries the key-derived label."""
        if n.kind not in ("binary", "seq", "obj", "str", "call"):
            return False
        cur = n
        while cur.parent is not None and (cur.parent.kind in ("cast", "kwarg") or cur.parent.kind == "other" and
                                          cur.parent.name in _UNWRAP_OTHER or cur.parent.kind == "seq" and
                                          len(cur.parent.kids) == 1):
            cur = cur.parent
        p = cur.parent
        if p is None or p.kind not in ("call", "new") or not p.kids or p.kids[0] is cur:
            return False
        if self.classify(p) not in ("digest", "cipher", "source") or self.callee(p)[0] in VERDICTS:
            return False
        data, _key = self.split_inputs(p)
        return any(unwrap(a) is unwrap(cur) for a in data)

    def _env_config(self, x: N) -> bool:
        """``x`` reads one environment variable by a literal name that is configuration, not a secret
        (``environ['CA_BUNDLE']``, ``process.env.PORT``): the environment is key material otherwise."""
        x = unwrap(x)
        if x is None or self.label(x) & ~KEY:
            return False
        lit = None
        if x.kind == "index" and len(x.kids) > 1 and (path(x.kids[0]) or "").endswith(("environ", "env")):
            k = unwrap(x.kids[1])
            lit = k.value if k is not None and k.kind == "str" else None
        elif x.kind == "member" and any((path(x) or "").startswith(e + ".") for e in _ENV_PATHS):
            lit = x.name
        elif x.kind == "call":
            name, _recv, args = self.callee(x)
            if name in ("getenv", "getenvb", "Getenv", "LookupEnv", "GetEnvironmentVariable", "get") and args:
                a = unwrap(args[0])
                if name == "get" and not (path(self.callee(x)[1]) or "").endswith(("environ", "env")):
                    return False
                lit = a.value if a is not None and a.kind == "str" else None
            if len([a for a in args if self.operand(a)]) > 0:
                return False
        if not isinstance(lit, str) or not lit:
            return False
        ws = words(lit)
        return not any(w in _KEY_WORDS or (len(w) > 3 and w.endswith("key")) for w in ws) and \
            any(w in _ENV_CONFIG_WORDS or w in _NOT_KEY_WORDS for w in ws)

    @staticmethod
    def _target_side(n: N) -> bool:
        """``n`` is (in) the target of a binding, or the value list of a split ``a, b = x, y``."""
        cur, prev = n.parent, n
        while cur is not None and cur.kind in ("seq", "obj", "pair"):
            cur, prev = cur.parent, cur
        if cur is None or cur.kind not in ("assign", "for") or not cur.kids:
            return False
        if cur.kids[0] is prev:
            return True
        t = cur.kids[0]
        return cur.kind == "assign" and len(cur.kids) > 1 and cur.kids[1] is prev and t.kind == "seq" and \
            prev.kind == "seq" and len(t.kids) == len(prev.kids)

    # ------------------------------------------------------------------------------------- framed nonce
    def aead(self, n: N) -> bool:
        """A cipher call on an AEAD construction (GCM / CCM / ChaCha20-Poly1305 / SIV / OCB), from its own text or
        the values its receiver was built from (two hops)."""
        texts = [n.text]
        _name, recv, _args = self.callee(n)
        roots = [path(unwrap(recv)) or ""] if recv is not None else []
        for _ in range(2):
            nxt = []
            for r in roots:
                for v in self.scope.locals.get(r.split(".")[0], []):
                    if v is not None:
                        texts.append(v.text)
                        if v.kind in ("call", "new"):  # the algorithm named by a string local: alg = `aes-..-gcm`
                            for a in self.callee(v)[2][:1]:
                                vals = self.scope.locals.get(path(unwrap(a)) or "", []) if unwrap(a) is not None \
                                    and unwrap(a).kind == "name" else []
                                texts += [x.text for x in vals if x is not None and x.kind == "str"]
                        inner = unwind(v).head
                        if inner:
                            nxt.append(inner)
            roots = nxt
        return any(AEAD_RX.search(t) for t in texts)

    def envelope(self, v: N | None, seen: frozenset[int] = frozenset()) -> bool:
        """``nonce || ciphertext || tag``: a concatenation (``+``, ``Buffer.concat([...])``, ``append``) of AEAD
        cipher results / tags, IV material and locals that only ever hold such envelopes, with at least one AEAD
        ciphertext; or one crypto result."""
        return self._envelope(v, seen)[0]

    def _envelope(self, v: N | None, seen: frozenset[int]) -> tuple[bool, bool]:
        """(is an envelope, holds AEAD ciphertext)."""
        v = unwrap(v)
        if v is None or id(v) in seen or self.label(v) & ~(IV | HOLDER):  # HOLDER: ``c.nonce`` of a cipher
            return False, False
        seen = seen | {id(v)}
        parts = _concat_parts(v)
        if parts is None:
            return False, False
        aead = False
        for part in parts:
            part = unwrap(part)
            if part is None:
                return False, False
            if part.kind in ("call", "new") and self.classify(part) in ("cipher", "digest"):
                if self.label(part) & ~IV:
                    return False, False
                aead |= self.classify(part) == "cipher" and self.aead(part)
                continue
            p = path(part) if part.kind == "name" else None
            others = [x for x in self.scope.locals.get(p, []) if id(x) not in seen] if p else []
            if others and all(x is not None for x in others):  # ct = AEAD(...); ct = nonce + ct
                got = [self._envelope(x, seen) for x in others]
                if all(ok for ok, _a in got):
                    aead |= any(a for _ok, a in got)
                    continue
            if self._iv_only(part) and part.kind in ("name", "member", "call"):
                continue
            return False, False
        return aead or (len(parts) == 1 and not self.label(v)), aead

    def _iv_only(self, x: N) -> bool:
        """IV material and nothing else; a cipher's own ``.nonce`` / ``.iv`` member counts (the object holds a key,
        the member is the public nonce)."""
        lab = self.label(x)
        if lab == IV:
            return True
        return lab & ~(IV | HOLDER) == 0 and bool(lab & IV) and x.kind == "member" and \
            self._word_label(x.name) == IV and secret_name(x.name)

    def out_buffer(self, name: str, v: N | None) -> bool:
        """``var ct = new byte[d.Length]; aead.Encrypt(n, d, ct, tag)``: a fresh buffer that an AEAD call writes
        its ciphertext / tag into (C# output parameters)."""
        if not _allocation(unwrap(v)):
            return False
        for n in self.calls:
            if self.classify(n) != "cipher" or not self.aead(n):
                continue
            _nm, _recv, args = self.callee(n)
            if any(i >= 2 and path(unwrap(a)) == name for i, a in enumerate(args)):
                return True
        return False

    def framed(self, n: N, before: "Flow | None") -> bool:
        """A call of the window outside the allow-list, at the same place, given the nonce only inside an AEAD
        envelope (``sock.sendall(nonce + AESGCM.encrypt(...))``): the nonce is public."""
        if before is None:
            return False
        here = (norm(n.text), n.ctx)
        if not any(before.classify(b) == "sink" and (norm(b.text), b.ctx) == here for b in before.calls):
            return False
        for x in self.inputs(n):
            lab = self.label(x)
            if not lab:
                continue
            if lab & ~IV:
                return False
            p = path(unwrap(x))
            vals = self.scope.locals.get(p, []) if p and "." not in p else []
            if self.envelope(x):
                continue
            if not vals or not all(v is not None and (self.envelope(v) or not self.label(v)) for v in vals):
                return False
            if not any(v is not None and self.envelope(v) and self.label(v) for v in vals):
                return False
        return True

    def leaks(self, before: "Flow | None" = None) -> list[str]:
        """Calls that are not on the crypto allow-list (or build an error message) and can receive key material,
        and key material stored into a member of something that is not a local. The nonce may reach a call the
        window already makes, at the same place, only framed with AEAD ciphertext (``framed``)."""
        out = []
        for n in self.calls:
            if self.classify(n) in ("sink", "error") and self._any(self.inputs(n)):
                if self.classify(n) == "sink" and self.framed(n, before):
                    continue
                out.append(norm(n.text)[:80])
        for t, v, _op, _n in self.binds:
            p = path(t)
            if t is not None and t.kind in ("member", "index") and p and not self.scope.is_local_path(p) and \
                    self.canon(p) == p and v is not None and self.label(v):
                out.append(norm(t.text)[:80] + " = ...")
        for n in walk(self.root):  # throw key / raise / assert ..., key: the value ends up in a log
            if n.kind == "other" and (n.name in ("throw_statement", "throw_expression", "raise") or
                                      n.name == "jump_expression" and n.text.lstrip().startswith("throw")):
                if self._any(n.kids):
                    out.append(norm(n.text)[:80])
            elif n.kind == "other" and n.name in ("assert", "assert_statement") and self._any(n.kids[1:]):
                out.append(norm(n.text)[:80])
        return sorted(set(out))

    def nonce_keys(self) -> list[str]:
        """Cipher / MAC constructions whose KEY is built from a value used as an IV / nonce somewhere (the nonce
        travels in clear: a key made of it protects nothing, and what it encrypts is as good as sent)."""
        ivs: set[str] = set()
        for n in self.calls:
            _nm, _recv, args = self.callee(n)
            for i in self.iv_positions(n):
                p = path(unwrap(args[i])) if i < len(args) else None
                if p:
                    ivs.add(self.canon(p))
        out = []
        for n in self.calls:
            name, _recv, args = self.callee(n)
            if name not in KEY_TAKERS:
                continue
            keyed, _ = self.key_positions(n)
            for i in keyed - self.iv_positions(n):
                if i < len(args) and self._reads_any(args[i], ivs, 3):
                    out.append(norm(n.text)[:80])
        return sorted(set(out))

    def _reads_any(self, v: N | None, names: set[str], depth: int) -> bool:
        if v is None or depth < 0:
            return False
        for x in walk(v):
            if x.kind in ("name", "member") and (p := path(x)):
                p = self.canon(p)
                if p in names:
                    return True
                if x.kind == "name" and any(self._reads_any(val, names, depth - 1)
                                            for val in self.scope.locals.get(p, [])):
                    return True
        return False

    def key_returns(self) -> dict[str, list[str]]:
        """Functions that return / yield key material or key-derived values (not IV, not key holders), by name.
        Meant for an ``incoming`` flow: a KDF / key generator returning its own output is its job."""
        out: dict[str, list[str]] = {}
        for r in walk(self.root):
            if r.kind == "other" and r.name in RETURNS and self._any(r.kids) & KEYISH:
                fn = _owner(r)
                out.setdefault(fn.name if fn is not None else "", []).append(norm(r.text)[:80])
        return out


# return / yield forms (Python ast, tree-sitter grammars, expression bodies)
RETURNS = {"return_statement", "return", "return_expression", "jump_expression", "yield", "yieldfrom",
           "yield_expression", "arrow_return"}


def _owner(n: N) -> N | None:
    cur = n.parent
    while cur is not None and cur.kind != "func":
        cur = cur.parent
    return cur


def _concat_parts(v: N) -> list[N] | None:
    """The pieces of a byte concatenation, or [v] for a plain value; None for anything else."""
    if v.kind == "binary" and v.name == "+":
        out: list[N] = []
        for k in v.kids:
            got = _concat_parts(unwrap(k) or k)
            if got is None:
                return None
            out += got
        return out
    if v.kind == "call" and v.kids:
        f = v.kids[0]
        args = [unwrap(a) for a in v.kids[1:]]
        if f.kind == "member" and f.name == "concat" and len(args) == 1 and args[0] is not None and \
                args[0].kind == "seq":  # Buffer.concat([...])
            return [x for x in args[0].kids]
        if f.kind == "member" and f.name == "join" and len(args) == 1 and args[0] is not None and \
                args[0].kind == "seq" and f.kids and f.kids[0].kind == "str" and f.kids[0].value == "":
            return [x for x in args[0].kids]  # b"".join([nonce, ct, tag])
        if f.kind == "member" and f.name == "plus" and len(args) == 1 and f.kids:  # Kotlin iv.plus(ct)
            return [f.kids[0], args[0]] if args[0] is not None else None
        if f.kind == "name" and f.name == "append" and args:  # Go append(a, b...)
            return [_spread(a) for a in args if a is not None]
    if v.kind in ("call", "new", "name", "member"):
        return [v]
    return None


def _spread(a: N) -> N:
    return a.kids[0] if a.kind == "other" and a.name == "variadic_argument" and a.kids else a


def _allocation(v: N | None) -> bool:
    """A fresh zeroed buffer: ``new byte[n]``, ``make([]byte, n)``, ``ByteArray(n)``, ``Buffer.alloc(n)``."""
    if v is None:
        return False
    if v.kind == "other" and v.name in ("array_creation_expression", "stackalloc_expression"):
        return not any(x.kind == "seq" for x in v.kids)
    if v.kind == "call" and v.kids:
        f = v.kids[0]
        name = f.name if f.kind in ("name", "member") else ""
        return name in ("make", "ByteArray", "alloc", "bytearray") and len(v.kids) >= 2 and \
            all(x.kind not in ("seq", "str") for x in v.kids[1:])
    return False


def module_writes(root: N, scope: Scope) -> Counter[str]:
    """Assignments to a member of a module / package / class (``crypto.randomBytes = ...``, ``ssl.X = ...``,
    ``Security.x = ...``): a fix changes its own values, not the libraries'."""
    out: Counter[str] = Counter()
    for t, _v, op, _n in binds(root):
        if op == "for":
            continue
        for x in [t] if t is None or t.kind != "seq" else t.kids:
            p = path(x) if x is not None and x.kind in ("member", "index") else None
            if p and not scope.is_local_path(p):
                out[norm(x.text)[:60]] += 1
    return out


# --------------------------------------------------------------------------------------- sinks that move / change
def sink_places(flow: Flow, drop_kw: set[str]) -> Counter[tuple[str, tuple[str, ...]]]:
    """Every call that is not on the allow-list, as (its text without TLS keyword arguments and without the
    inline TLS options a fix may raise, where it is)."""
    out: Counter[tuple[str, tuple[str, ...]]] = Counter()
    for n in flow.calls:
        if flow.classify(n) != "sink":
            continue
        parts = [norm(n.kids[0].text) if n.kids else ""]
        parts += [_blank_tls(a, TLS_RAISE) for a in n.kids[1:]
                  if not (a.kind == "kwarg" and key_norm(a.name) in drop_kw)]
        out[("|".join(parts), n.ctx)] += 1
    return out


def moved_sinks(after: Flow, before: Flow) -> list[str]:
    a = sink_places(after, TLS_KEYS)
    b = sink_places(before, TLS_KEYS)
    return sorted({k[0].split("|")[0] + "(...)" for k, n in a.items() if n > b[k]})


def _blank_tls(v: N | None, keys: set[str] | None = None) -> str:
    """A value's text without its TLS options (``{ host, ciphers: '...' }`` -> ``{host}``): those may be added,
    changed or removed by a fix, and their values are checked by ``downgrades``."""
    if v is None:
        return ""
    keys = TLS_KEYS if keys is None else keys
    text = v.text
    spans = []
    for x in walk(v):
        if x.kind in ("pair", "kwarg") and key_norm(x.name) in keys:
            i = text.find(x.text)
            if i >= 0:
                spans.append((i, i + len(x.text)))
    for a, b in sorted(spans, reverse=True):
        text = text[:a] + text[b:]
    text = norm(text)
    while True:
        cleaned = re.sub(r",(?=[,}\])])|(?<=[{(\[]),", "", text)
        if cleaned == text:
            return text
        text = cleaned


def changed_sink_inputs(after: Flow, before: Flow) -> list[str]:
    """Names that a call of the window outside the allow-list reads (its receiver, its arguments, and one hop
    through what those names are set to - an options object): the rewrite may not change what they are set to,
    except to the result of a crypto operation (``ct = AES-GCM(...).encrypt(data)``), an AEAD envelope (``nonce +
    ciphertext + tag``), a fresh buffer an AEAD call writes its output into, or in a TLS option. A name read only
    through a value the rewrite replaced by such a crypto result is no longer an input."""
    kept = {norm(n.text) for n in after.calls if after.classify(n) == "sink"}
    direct: set[str] = set()
    for n in before.calls:  # the window's calls outside the allow-list that the rewrite keeps
        if before.classify(n) != "sink" or norm(n.text) not in kept:
            continue
        for x in before.inputs(n):
            for nm in _reads(before, x):
                direct.add(nm.name)

    def values(flow: Flow, names: set[str]) -> dict[str, list[N | None]]:
        out: dict[str, list[N | None]] = {}
        for t, v, op, _n in flow.binds:
            for p in target_paths(t):
                root = p.split(".")[0]
                if root in names:
                    out.setdefault(root, []).append(v if op in ("=", ":=", "for") else
                                                    N("other", f"{op}{v.text if v else ''}"))
        return out

    def judge(names: set[str]) -> tuple[list[str], set[str]]:
        names = {w for w in names if before.scope.is_local_path(w) and w not in before.scope.funcs}
        va, vb = values(after, names), values(before, names)
        bad, same = [], set()
        for name in sorted(names):
            ca = Counter(_blank_tls(v) for v in va.get(name, []))
            cb = Counter(_blank_tls(v) for v in vb.get(name, []))
            if ca == cb:
                same.add(name)
                continue
            new_texts = ca - cb
            new_nodes = [v for v in va.get(name, []) if _blank_tls(v) in new_texts]
            if cb - ca and not new_nodes:
                bad.append(name)
                continue
            if not all(_crypto_result(after, unwrap(v)) or after.envelope(v) or after.out_buffer(name, v)
                       for v in new_nodes):
                bad.append(name)
        return bad, same

    bad, same = judge(direct)
    hops: set[str] = set()
    by_name_before: dict[str, list[N | None]] = {}
    for t, v, _op, _n in before.binds:
        for p in target_paths(t):
            by_name_before.setdefault(p.split(".")[0], []).append(v)
    for name in same:  # one hop through a value the rewrite kept (an options object)
        for v in by_name_before.get(name, []):
            for nm in _reads(before, v):
                parent = nm.parent
                while parent is not None and parent is not v and parent.kind != "pair":
                    parent = parent.parent
                if parent is not None and parent.kind == "pair" and key_norm(parent.name) in TLS_KEYS:
                    continue
                hops.add(nm.name)
    more, _same = judge(hops - direct)
    return sorted(set(bad + more))


def _reads(flow: Flow, n: N | None) -> list[N]:
    """Names an expression reads, not counting those inside a crypto operation (its result is ciphertext / a
    digest; what reaches it is the data-flow rule's business)."""
    out: list[N] = []
    stack = [n] if n is not None else []
    while stack:
        cur = stack.pop()
        if cur.kind in ("call", "new") and flow.classify(cur) in ("digest", "cipher"):
            continue
        if cur.kind == "name":
            out.append(cur)
        stack.extend(cur.kids)
    return out


def _crypto_result(flow: Flow, v: N | None) -> bool:
    return v is not None and v.kind in ("call", "new") and flow.classify(v) in ("digest", "cipher") and \
        not flow.label(v)


# ------------------------------------------------------------------------------------------ constant values
class Sym(str):
    """A symbolic constant: ``ssl.TLSVersion.MINIMUM_SUPPORTED``."""


UNKNOWN = object()
NULL = object()


def const(n: N | None, scope: Scope | None = None, depth: int = 0) -> Any:
    if n is None:
        return UNKNOWN
    k = n.kind
    if k in ("num", "bool"):
        return n.value
    if k == "str":
        return n.value if n.value is not None else UNKNOWN
    if k == "null":
        return NULL
    if k == "cast":
        return const(n.kids[0] if n.kids else None, scope, depth)
    if k == "unary":
        v = const(n.kids[0] if n.kids else None, scope, depth)
        if v is UNKNOWN or isinstance(v, (Sym, frozenset)) or v is NULL:
            return UNKNOWN
        try:
            if n.name in ("!", "not"):
                return not v
            if n.name == "-":
                return -v
            if n.name in ("~", "^"):
                return ~int(v)
            if n.name == "+":
                return v
        except (TypeError, ValueError):
            return UNKNOWN
        return UNKNOWN
    if k == "binary" or (k == "call" and n.value == "infix"):
        if k == "binary":
            op, left, right = n.name, n.kids[0] if n.kids else None, n.kids[1] if len(n.kids) > 1 else None
        else:
            op = {"or": "|", "and": "&", "xor": "^", "shl": "<<", "shr": ">>"}.get(n.kids[0].name, "?")
            left = n.kids[0].kids[0] if n.kids[0].kids else None
            right = n.kids[1] if len(n.kids) > 1 else None
        a, b = const(left, scope, depth), const(right, scope, depth)
        if op == "|" and isinstance(a, (Sym, frozenset)) and isinstance(b, (Sym, frozenset)):
            return frozenset(([a] if isinstance(a, Sym) else list(a)) + ([b] if isinstance(b, Sym) else list(b)))
        if a is UNKNOWN or b is UNKNOWN or isinstance(a, (Sym, frozenset)) or isinstance(b, (Sym, frozenset)):
            return UNKNOWN
        try:
            return {"|": lambda: a | b, "&": lambda: a & b, "^": lambda: a ^ b, "+": lambda: a + b,
                    "-": lambda: a - b, "*": lambda: a * b, "<<": lambda: a << b, ">>": lambda: a >> b,
                    "or": lambda: a or b, "and": lambda: a and b, "||": lambda: a or b,
                    "&&": lambda: a and b}.get(op, lambda: UNKNOWN)()
        except (TypeError, ValueError):
            return UNKNOWN
    if k in ("name", "member"):
        p = path(n)
        if p is None:
            return UNKNOWN
        if k == "name" and scope is not None and depth < 4:
            vals = scope.locals.get(n.name, [])
            if len(vals) == 1 and vals[0] is not None:
                return const(vals[0], scope, depth + 1)
            if vals:
                return UNKNOWN
        return Sym(p)
    if k == "call" and n.kids:
        name = (path(n.kids[0]) or "").split(".")[-1]
        args = [a for a in n.kids[1:] if a.kind != "kwarg"]
        if name in ("TLSVersion", "int", "SslProtocols", "uint16", "VerifyMode", "Options") and len(args) == 1:
            return const(args[0], scope, depth)
        return UNKNOWN
    if k == "seq":
        return [const(x, scope, depth) for x in n.kids]
    if k == "obj" and not any(x.kind == "pair" for x in n.kids):  # Go []uint16{...}
        return [const(x, scope, depth) for x in n.kids if x.value != "typeref"]
    if k == "other" and n.name in ("array_creation_expression", "implicit_array_creation_expression"):
        seqs = [x for x in n.kids if x.kind == "seq"]
        return const(seqs[0], scope, depth) if len(seqs) == 1 else UNKNOWN
    if k == "func":
        return UNKNOWN
    return UNKNOWN


# ------------------------------------------------------------------------------------------- TLS downgrades
_VERSION_SYMS = {"TLSv1_2", "TLSv1_3", "VersionTLS12", "VersionTLS13", "Tls12", "Tls13", "TLS1_2_VERSION",
                 "TLS1_3_VERSION", "PROTOCOL_TLS_CLIENT", "PROTOCOL_TLS_SERVER", "PROTOCOL_TLS", "TLSv1_2_method",
                 "TLSv1_3_method"}
_VERSION_STRS = {"TLSv1.2", "TLSv1.3", "TLSv1_2_method", "TLSv1_3_method", "TLS_method", "TLS_client_method",
                 "TLS_server_method"}
_VERSION_INTS = {771, 772, 3072, 12288, 15360}
_WEAK_CIPHER_WORDS = {"ALL", "COMPLEMENTOFALL", "COMPLEMENTOFDEFAULT", "LOW", "EXPORT", "EXP", "NULL", "ENULL",
                      "ANULL", "RC4", "DES", "3DES", "MD5", "SSLV3", "SSLV2", "ADH", "AECDH", "RC2", "IDEA", "SEED",
                      "TLSV1", "EXPORT40", "EXPORT56", "KRB5"}
_WEAK_CIPHER_RX = re.compile(r"RC4|RC2|(?<![A-Z])3?DES(?![A-Z])|NULL|EXPORT|EXP-|MD5|ANON|ADH|AECDH|IDEA|SEED|"
                             r"@SECLEVEL=[01]\b", re.I)
_GOOD_SUITE_IDS = {0x1301, 0x1302, 0x1303, 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9, 0x009E, 0x009F, 0xCCAA}


def _version_ok(v: Any, key: str) -> bool:
    if isinstance(v, frozenset):
        return all(_version_ok(x, key) for x in v)
    if isinstance(v, list):
        return bool(v) and all(_version_ok(x, key) for x in v)
    if isinstance(v, Sym):
        last = v.split(".")[-1]
        return last in _VERSION_SYMS or (key.startswith("max") and last in ("MAXIMUM_SUPPORTED",)) or last == "None"
    if isinstance(v, str):
        return v in _VERSION_STRS
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return v in _VERSION_INTS
    return False


def cipher_ok(v: Any) -> bool:
    if isinstance(v, list):
        return bool(v) and all(cipher_ok(x) for x in v)
    if isinstance(v, frozenset):
        return all(cipher_ok(x) for x in v)
    if isinstance(v, Sym):
        return not _WEAK_CIPHER_RX.search(v.split(".")[-1])
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return v in _GOOD_SUITE_IDS
    if isinstance(v, str):
        if re.search(r"@SECLEVEL\s*=\s*[01]\b", v, re.I):
            return False
        for tok in re.split(r"[:,\s]+", v):
            if not tok or tok[0] in "!-":
                continue
            parts = tok.lstrip("+").upper().split("+")
            if any(p in _WEAK_CIPHER_WORDS for p in parts) or _WEAK_CIPHER_RX.search(tok):
                return False
        return True
    return False


def _must_true(v: Any, _k: str) -> bool:
    return v is True or (type(v) is int and v == 1)


def _must_false(v: Any, _k: str) -> bool:
    return v is False or (type(v) is int and v == 0)


def _not_off(v: Any, _k: str) -> bool:
    return not (v is False or v is NULL or (type(v) is int and v == 0) or v == "")


def _verify_mode(v: Any, _k: str) -> bool:
    return (isinstance(v, Sym) and v.endswith("CERT_REQUIRED")) or (type(v) is int and v == 2)


def _secure_options(v: Any, _k: str) -> bool:
    leaves = list(v) if isinstance(v, frozenset) else [v]
    return all(isinstance(x, Sym) and re.search(r"OP_NO_|CIPHER_SERVER_PREFERENCE|NO_RENEGOTIATION", x)
               for x in leaves)


def _endpoint(v: Any, _k: str) -> bool:
    return isinstance(v, str) and v.upper() in ("HTTPS", "LDAPS")


def _never(_v: Any, _k: str) -> bool:
    return False


_SETTINGS: dict[str, Callable[[Any, str], bool]] = {
    "rejectunauthorized": _must_true, "checkhostname": _must_true, "insecureskipverify": _must_false,
    "verifymode": _verify_mode, "certreqs": _verify_mode, "verify": _not_off,
    "checkcertificaterevocationlist": _not_off, "requirecertificate": _not_off,
    "minversion": _version_ok, "minimumversion": _version_ok, "maxversion": _version_ok,
    "maximumversion": _version_ok, "minprotocolversion": _version_ok, "maxprotocolversion": _version_ok,
    "sslprotocols": _version_ok, "enabledsslprotocols": _version_ok, "protocols": _version_ok,
    "enabledprotocols": _version_ok, "sslversion": _version_ok, "secureprotocol": _version_ok,
    "ciphers": lambda v, _k: cipher_ok(v), "ciphersuites": lambda v, _k: cipher_ok(v),
    "cipherlist": lambda v, _k: cipher_ok(v), "enabledciphersuites": lambda v, _k: cipher_ok(v),
    "secureoptions": _secure_options, "endpointidentificationalgorithm": _endpoint,
    "checkserveridentity": _never, "verifypeercertificate": _never, "verifyconnection": _never,
    "servercertificatecustomvalidationcallback": _never, "servercertificatevalidationcallback": _never,
    "remotecertificatevalidationcallback": _never, "hostnameverifier": _never, "defaulthostnameverifier": _never,
    "verifycallback": _never, "setverify": _never, "certificatevalidationcallback": _never,
    "localcertificateselectioncallback": _never, "trustmanager": _never, "trustmanagers": _never,
}
_SETTERS = {"setciphers": "ciphers", "setciphersuites": "ciphersuites", "setenabledciphersuites": "ciphers",
            "setprotocols": "protocols", "setenabledprotocols": "protocols",
            "setendpointidentificationalgorithm": "endpointidentificationalgorithm",
            "sethostnameverifier": "hostnameverifier", "setdefaulthostnameverifier": "hostnameverifier",
            "setverify": "setverify", "setminversion": "minversion", "setmaxversion": "maxversion",
            "setservercertificatevalidationcallback": "servercertificatevalidationcallback",
            "settrustmanager": "trustmanager", "setsslsocketfactory": "trustmanager",
            "setdefaultsslsocketfactory": "trustmanager"}


def settings(root: N, lang: str) -> list[tuple[str, N, str, N]]:
    """(normalised key, value, operator, node) of every TLS / verification setting in a tree: object keys, Go
    struct fields, keyword / named arguments, assignments to a member, setter calls."""
    out: list[tuple[str, N, str, N]] = []
    for n in walk(root):
        if n.kind in ("pair", "kwarg") and n.kids:
            out.append((key_norm(n.name), n.kids[0], "=", n))
        elif n.kind == "func" and n.name and n.parent is not None and n.parent.kind == "obj":
            out.append((key_norm(n.name), n, "=", n))
        elif n.kind == "assign" and len(n.kids) >= 2:
            t, v = n.kids[0], n.kids[1]
            pairs = list(zip(t.kids, v.kids)) if t.kind == "seq" and v.kind == "seq" and len(t.kids) == len(v.kids) \
                else [(t, v)]
            for tt, vv in pairs:
                if tt.kind == "member":
                    out.append((key_norm(tt.name), vv, n.name, n))
        elif n.kind == "call" and n.kids and n.kids[0].kind in ("member", "name"):
            name = key_norm(n.kids[0].name)
            args = [a for a in n.kids[1:] if a.kind != "kwarg"]
            if name in _SETTERS and args:
                out.append((_SETTERS[name], args[0] if len(args) == 1 or name != "setverify" else args[0], "=", n))
                if name == "setverify" and len(args) > 1:
                    out.append(("verifycallback", args[1], "=", n))
    return out


def downgrades(after: N, before: N, lang: str, scope: Scope) -> list[str]:
    """Settings the rewrite adds (not already in the window) whose VALUE weakens TLS: verification off, hostname
    check off, a minimum version below TLS 1.2, a weak cipher list / suite id, a custom verify callback, a Python
    ``options`` change other than ``|=`` of ``OP_*`` flags."""
    def entries(root: N) -> Counter[tuple[str, str, str]]:
        return Counter((k, norm(v.text), op) for k, v, op, _n in settings(root, lang))

    old = entries(before)
    seen: Counter[tuple[str, str, str]] = Counter()
    bad = []
    for key, value, op, node in settings(after, lang):
        sig = (key, norm(value.text), op)
        seen[sig] += 1
        if seen[sig] <= old[sig]:
            continue
        if key == "options" and lang == "python":
            if not _py_options_ok(node, value, op, scope):
                bad.append(f"{key} {op} {norm(value.text)[:40]}")
            continue
        check = _SETTINGS.get(key)
        if check is None:
            continue
        if key == "verify" and node.kind == "func":
            continue  # a method named verify in an object, not the verify option
        v = const(value, scope)
        if check is _never or not check(v, key):
            bad.append(f"{key} = {norm(value.text)[:40]}")
    return sorted(set(bad))


def _py_options_ok(node: N, value: N, op: str, scope: Scope) -> bool:
    if op == "|=":
        v = const(value, scope)
        leaves = list(v) if isinstance(v, frozenset) else [v]
        return all(isinstance(x, Sym) and "OP_" in x for x in leaves)
    if op == "=" and value.kind == "binary" and value.name == "|":
        target = norm(node.kids[0].text) if node.kids else ""
        leaves = _or_leaves(value)
        return any(norm(x.text) == target for x in leaves) and all(
            norm(x.text) == target or isinstance(const(x, scope), Sym) and "OP_" in const(x, scope) for x in leaves)
    return False


def _or_leaves(n: N) -> list[N]:
    if n.kind == "binary" and n.name == "|":
        return [x for k in n.kids for x in _or_leaves(k)]
    return [n]


# ----------------------------------------------------------------------------------------------- environment
def env_writes(root: N, lang: str, scope: Scope) -> Counter[str]:
    """Writes to the process environment / system properties (reads are fine): JS ``process.env`` assigned,
    deleted, passed or aliased; Go ``os.Setenv`` / ``Unsetenv`` / ``Clearenv``; Java / Kotlin
    ``System.setProperty`` / ``clearProperty`` / ``setProperties`` / ``Security.setProperty`` / anything on
    ``System.getProperties()``; C# ``Environment.SetEnvironmentVariable`` / ``AppContext.SetSwitch``."""
    out: Counter[str] = Counter()
    for n in walk(root):
        if lang in ("javascript", "typescript") and n.kind == "name" and n.name == "process" and \
                "process" not in scope.locals:
            parent = n.parent
            if not (parent is not None and parent.kind == "member" and parent.kids and parent.kids[0] is n
                    and parent.name == "env"):
                out["process (as a value)"] += 1
        if lang in ("javascript", "typescript") and n.kind == "member" and n.name == "env":
            p = path(n)
            if p is None or not (p == "process.env" or p.endswith(".process.env")):
                continue
            parent = n.parent
            if parent is not None and parent.kind in ("member", "index") and parent.kids and parent.kids[0] is n:
                gp = parent.parent
                if gp is not None and gp.kind == "assign" and gp.kids and gp.kids[0] is parent:
                    out[f"{norm(parent.text)} = ..."] += 1
                elif gp is not None and gp.kind == "unary" and gp.name == "delete":
                    out[f"delete {norm(parent.text)}"] += 1
                elif gp is not None and gp.kind in ("call",) and gp.kids and gp.kids[0] is parent:
                    out[f"{norm(parent.text)}()"] += 1  # process.env.hasOwnProperty(...) and friends: not a plain read
            else:
                out["process.env (as a value)"] += 1
        elif n.kind == "call" and n.kids:
            p = path(n.kids[0]) or ""
            parts = p.split(".")
            last = parts[-1] if parts else ""
            if lang == "go" and len(parts) == 2 and scope.canon(parts[0]) == "os" and last in (
                    "Setenv", "Unsetenv", "Clearenv"):
                out[p] += 1
            elif lang in ("java", "kotlin") and (
                    p.endswith(("System.setProperty", "System.clearProperty", "System.setProperties",
                                "Security.setProperty", "Security.insertProviderAt", "Security.addProvider"))
                    or "getProperties" in norm(n.text)):
                out[p or norm(n.text)[:40]] += 1
            elif lang == "csharp" and p.endswith(("Environment.SetEnvironmentVariable", "AppContext.SetSwitch",
                                                  "AppContext.SetData")):
                out[p] += 1
    return out
