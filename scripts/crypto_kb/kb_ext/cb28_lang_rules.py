"""CB-28: code-scan code from the .NET / C / Terraform line detectors (aibom.cbom.lang_misuse): RSA public exponent
3. The other findings these detectors raise use existing entries (WEAK_PROTOCOL, WEAK_PADDING, WEAK_CIPHER_SUITE,
WEAK_KEY_SIZE / WEAK_ALGORITHM, HARDCODED_KEY, STATIC_IV, WEAK_KDF_ITERATIONS)."""

from kb_text import entry

CODE_CODES = ["WEAK_RSA_EXPONENT"]

entry(
    "WEAK_RSA_EXPONENT",
    title="RSA key generated with public exponent 3",
    category="code",
    default_impact="High",
    description=(
        "The code generates RSA keys with public exponent e = 3 (for example BN_set_word(e, 3) or RSA_3 before "
        "RSA_generate_key_ex). FIPS 186-5 requires an exponent greater than 2^16; 65537 is the standard choice."
    ),
    attack=(
        "With e = 3, a verifier that checks PKCS#1 v1.5 signature padding loosely accepts signatures an attacker "
        "forges without the private key (Bleichenbacher, 2006), and a small message encrypted without proper padding "
        "is recovered by taking its integer cube root."
    ),
    cwe=["CWE-326"],
    owasp=["crypto"],
    cves=[],
    standards=["FIPS 186-5 (appendix A.1.1: 2^16 < e < 2^256)"],
    compliance=["algorithms"],
    remediation={
        "summary": "Generate RSA keys with e = 65537 (RSA_F4) and re-issue the keys that were generated with e = 3.",
        "steps": [
            {"platform": "OpenSSL (C)", "how": "BN_set_word(e, RSA_F4) before RSA_generate_key_ex, or "
             "EVP_PKEY_CTX_set1_rsa_keygen_pubexp with 65537"},
        ],
    },
    verify=[{"label": "Show the call", "command": "sed -n '{line}p' '{path}'"}],
    references=["https://csrc.nist.gov/pubs/fips/186-5/final"],
)
