"""AST-binding crypto fixture for C1.

Every asset here is resolvable ONLY via argument binding / cross-statement value
following — a flat line-regex sees a *name* where the AST scanner sees the bound
*value*. Nothing here is a real credential; it is a labeled detection target.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Cross-statement constants — the call lines below reference these NAMES, so only
# the AST (which follows the binding) resolves the actual values.
RSA_BITS = 3072
STATIC_IV = b"\x00" * 16          # planted static IV (related-crypto-material)
KDF_SALT = b"s" * 16              # planted KDF salt (related-crypto-material)
KDF_ROUNDS = 100000


def rsa_oaep(data: bytes) -> bytes:
    # key_size is a NAME -> RSA-3072 only resolvable by following RSA_BITS.
    priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    pub = priv.public_key()
    # OAEP padding is a nested call argument bound to the RSA asset in this scope.
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def aes_cbc(key: bytes, data: bytes) -> bytes:
    # mode + IV come from a nested call; STATIC_IV is a cross-statement literal.
    cipher = Cipher(algorithms.AES(key), modes.CBC(STATIC_IV))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def derive(password: bytes) -> bytes:
    # KDF work factor (iterations) + salt are keyword arguments the AST captures.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KDF_SALT,
        iterations=KDF_ROUNDS,
    )
    return kdf.derive(password)
