"""CB-27: code-scan codes from Java literal flow (aibom.cbom.java_flow): a constant PBE salt and a constant PBE
iteration count below 1,000. The other constants it finds (IV, key, password, seed) use the existing STATIC_IV,
HARDCODED_KEY and WEAK_RNG entries."""

from kb_text import entry

CODE_CODES = ["STATIC_SALT", "WEAK_KDF_ITERATIONS"]

entry(
    "STATIC_SALT",
    title="Constant salt for password-based key derivation",
    category="code",
    default_impact="Medium",
    description=(
        "A salt fixed by the source code (a literal, a constant array, or a constant passed through variables, fields "
        "or method calls) reaches a password-based key derivation such as PBEKeySpec or PBEParameterSpec."
    ),
    attack=(
        "The salt exists so that each password needs its own guessing work. With one salt for everyone, an attacker "
        "who gets the derived keys or hashes builds one precomputed table, or runs one guessing pass, for all of them, "
        "and equal passwords give equal results."
    ),
    cwe=["CWE-760"],
    owasp=["crypto"],
    cves=[],
    standards=["NIST SP 800-132 (section 5.1: a random salt of at least 128 bits)"],
    compliance=["key_mgmt"],
    remediation={
        "summary": "Generate a random salt of at least 16 bytes for each password with a CSPRNG and store it next to "
                   "the derived value.",
        "steps": [
            {"platform": "Java", "how": "byte[] salt = new byte[16]; SecureRandom.getInstanceStrong().nextBytes(salt); "
             "new PBEKeySpec(password, salt, iterations, 256)"},
        ],
    },
    verify=[{"label": "Show the call", "command": "sed -n '{line}p' '{path}'"}],
    references=["https://csrc.nist.gov/pubs/sp/800/132/final", "https://cwe.mitre.org/data/definitions/760.html"],
)

entry(
    "WEAK_KDF_ITERATIONS",
    title="Too few iterations for password-based key derivation",
    category="code",
    default_impact="Medium",
    description=(
        "A constant iteration count below 1,000 reaches a password-based key derivation (PBEKeySpec, "
        "PBEParameterSpec). NIST SP 800-132 sets 1,000 as the minimum; current guidance is far higher."
    ),
    attack=(
        "Each password guess costs the attacker only as many hash computations as the iteration count, so an "
        "offline attack on the derived keys or the encrypted data tries billions of passwords quickly."
    ),
    cwe=["CWE-916"],
    owasp=["crypto"],
    cves=[],
    standards=["NIST SP 800-132 (section 5.2: at least 1,000 iterations)",
               "OWASP Password Storage Cheat Sheet (PBKDF2-HMAC-SHA256: 600,000 iterations)"],
    compliance=["key_mgmt"],
    remediation={
        "summary": "Use PBKDF2 with at least 600,000 iterations for HMAC-SHA256 (OWASP), or a memory-hard KDF such as "
                   "Argon2id or scrypt, and keep the count in configuration so it can rise.",
        "steps": [
            {"platform": "Java", "how": "SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\") with "
             "new PBEKeySpec(password, salt, 600000, 256)"},
        ],
    },
    verify=[{"label": "Show the call", "command": "sed -n '{line}p' '{path}'"}],
    references=["https://csrc.nist.gov/pubs/sp/800/132/final",
                "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
)
