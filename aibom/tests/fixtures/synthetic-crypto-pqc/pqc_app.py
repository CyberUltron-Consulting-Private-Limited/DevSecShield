"""Synthetic PQC-readiness fixture (C7).

Hand-crafted so every asset the C7 grader must reason about is present exactly
once, with a spelling the clean-room detector matches:

* NIST-standardized PQC with a parameter set (ML-KEM-768, ML-DSA-87, SLH-DSA-256,
  FALCON-512) -> graded to a positive NIST category (3 / 5 / 5 / 1);
* stateful-hash signatures (LMS, XMSS) -> quantum-safe, category-2 anchored;
* hybrid / composite key-establishment (X25519MLKEM768, SecP384r1MLKEM1024) ->
  ONE quantum-safe hybrid asset each, NOT split into a vulnerable + a safe half;
* classical quantum-SAFE primitives (AES-256 cat 5, SHA-384 cat 4) -> positively
  graded so a report can state they are quantum-safe, not merely "not flagged";
* a quantum-VULNERABLE public key (RSA-2048) -> level 0 + a sized roadmap target.

Not real key material — identifiers/strings only, so the detector inventories the
algorithms without any live cryptography.
"""

import os


def key_encapsulation():
    kem = MLKEM768()            # ML-KEM-768  -> kem, NIST cat 3
    return kem


def signatures():
    ml_dsa = MLDSA87()         # ML-DSA-87   -> signature, NIST cat 5
    slh = load_scheme("SLH-DSA-256")   # SLH-DSA-256 -> signature, NIST cat 5
    fn = load_scheme("FALCON-512")     # FALCON-512  -> signature, NIST cat 1
    return ml_dsa, slh, fn


def stateful_hash_firmware_signing():
    lms = load_scheme("LMS")           # LMS  -> stateful-hash signature, cat 2
    xmss = load_scheme("XMSS")         # XMSS -> stateful-hash signature, cat 2
    return lms, xmss


def hybrid_kex():
    tls13 = negotiate("X25519MLKEM768")       # hybrid ML-KEM-768 -> cat 3
    nss = negotiate("SecP384r1MLKEM1024")     # hybrid ML-KEM-1024 -> cat 5
    return tls13, nss


def classical_quantum_safe():
    key = os.urandom(32)               # 32-byte key -> AES-256
    sym = algorithms.AES(key)          # AES-256 -> block-cipher, NIST cat 5
    digest = SHA384()                  # SHA-384 -> hash, NIST cat 4
    return sym, digest


def classical_quantum_vulnerable():
    rsa = build("RSA-2048")            # RSA-2048 -> pke, quantum-vulnerable, lvl 0
    return rsa
