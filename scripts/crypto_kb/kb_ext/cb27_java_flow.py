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
        "A constant iteration count below the minimum for the API reaches a password-based key derivation: below "
        "1,000 for Java's PBEKeySpec / PBEParameterSpec (NIST SP 800-132), below 100,000 for .NET's "
        "Rfc2898DeriveBytes, whose constructors without a count use 1,000 (Microsoft rule CA5387). For a Python "
        "KDF call the captured cost is graded against NIST SP 800-132 (below 1,000 PBKDF2 iterations: Medium) and "
        "the OWASP Password Storage minimums (PBKDF2-HMAC-SHA256 600,000, -SHA512 210,000, -SHA1 1,300,000; scrypt "
        "N 2^17 with r 8 and p 1, or an equal-strength pair: 2^16 / p 2, 2^15 / p 3, 2^14 / p 5, 2^13 / p 10; Argon2id "
        "19 MiB with 2 passes or an equivalent pair: Low). A file with several calls of one KDF is graded by its worst "
        "call, each against the minimum for its own hash."
    ),
    attack=(
        "Each password guess costs the attacker only as many hash computations as the iteration count, so an "
        "offline attack on the derived keys or the encrypted data tries billions of passwords quickly."
    ),
    cwe=["CWE-916"],
    owasp=["crypto"],
    cves=[],
    standards=["NIST SP 800-132 (section 5.2: at least 1,000 iterations)",
               "Microsoft code analysis rule CA5387 (Rfc2898DeriveBytes: at least 100,000 iterations)",
               "OWASP Password Storage Cheat Sheet (PBKDF2-HMAC-SHA256: 600,000 iterations)"],
    compliance=["key_mgmt"],
    remediation={
        "summary": "Use PBKDF2 with at least 600,000 iterations for HMAC-SHA256 (OWASP), or a memory-hard KDF such as "
                   "Argon2id or scrypt, and keep the count in configuration so it can rise.",
        "steps": [
            {"platform": "Java", "how": "SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\") with "
             "new PBEKeySpec(password, salt, 600000, 256)"},
            {"platform": ".NET", "how": "Rfc2898DeriveBytes.Pbkdf2(password, salt, 600000, "
             "HashAlgorithmName.SHA256, 32)"},
            {"platform": "Python", "how": "PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), "
             "iterations=600000) or hashlib.pbkdf2_hmac(\"sha256\", password, salt, 600_000)"},
        ],
    },
    summary_rules=[
        {"match": r"^scrypt", "summary": "Raise the scrypt cost to at least N = 2^17 with r = 8 and p = 1 (OWASP; "
         "or an equal-strength pair such as N = 2^16 with p = 2), or use Argon2id, and keep the cost in configuration "
         "so it can rise.",
         "steps": [{"platform": "Python", "how": "hashlib.scrypt(password, salt=os.urandom(16), n=2**17, r=8, p=1, "
                    "dklen=32)"}]},
        {"match": r"^argon2", "summary": "Use Argon2id with at least 19 MiB of memory and 2 passes (OWASP: m=19456, "
         "t=2, p=1, or an equivalent pair such as m=47104, t=1), and keep the cost in configuration.",
         "steps": [{"platform": "Python", "how": "argon2.PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1) "
                    "(argon2-cffi's defaults are stronger: PasswordHasher())"}]},
    ],
    verify=[{"label": "Show the call", "command": "sed -n '{line}p' '{path}'"}],
    references=["https://csrc.nist.gov/pubs/sp/800/132/final",
                "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
                "https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca5387"],
)
