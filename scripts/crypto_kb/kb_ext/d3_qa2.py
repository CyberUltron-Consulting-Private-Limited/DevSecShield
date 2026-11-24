"""Staging QA round 2 (D3): scrypt is graded by its cost parameters (N, r, p), not by an iteration count, so it has its
own code, WEAK_KDF_COST (Q2-11). WEAK_KDF_ITERATIONS keeps PBKDF2 / PBE iteration counts and Argon2's passes."""

from kb_text import entry

CODE_CODES = ["WEAK_KDF_COST"]

entry(
    "WEAK_KDF_COST",
    title="Memory-hard KDF cost below the minimum (scrypt N, r, p)",
    category="code",
    default_impact="Low",
    description=(
        "A scrypt call's cost parameters are below the OWASP Password Storage minimum: N = 2^17 (128 MiB with r = 8) "
        "and p = 1, or an equal-strength pair (N = 2^16 with p = 2, 2^15 with p 3, 2^14 with p 5, 2^13 with p 10), "
        "at a block size r of 8 (a smaller r shrinks the memory each guess needs by r / 8). scrypt has no iteration "
        "count and takes no hash argument: its cost is the memory and work N, r and p set. A file with several calls "
        "is graded by its weakest call."
    ),
    attack=(
        "scrypt's defence is that each password guess needs N x r x 128 bytes of memory and matching work; with a "
        "small N an attacker with stolen derived keys or encrypted data runs many more guesses in parallel on GPUs "
        "or dedicated hardware."
    ),
    cwe=["CWE-916"],
    owasp=["crypto"],
    cves=[],
    standards=["RFC 7914 (scrypt: N, r, p)", "OWASP Password Storage Cheat Sheet (scrypt: N = 2^17, r = 8, p = 1)"],
    compliance=["key_mgmt"],
    remediation={
        "summary": "Raise the scrypt cost to at least N = 2^17 with r = 8 and p = 1 (OWASP; or an equal-strength pair "
                   "such as N = 2^16 with p = 2), or use Argon2id, and keep the cost in configuration so it can rise.",
        "steps": [
            {"platform": "Python", "how": "hashlib.scrypt(password, salt=os.urandom(16), n=2**17, r=8, p=1, "
             "maxmem=256 * 1024 * 1024, dklen=32)"},
            {"platform": "Node.js", "how": "crypto.scryptSync(password, salt, 32, { N: 2 ** 17, r: 8, p: 1, "
             "maxmem: 256 * 1024 * 1024 })"},
            {"platform": "Java (Bouncy Castle)", "how": "SCrypt.generate(password, salt, 1 << 17, 8, 1, 32)"},
        ],
    },
    verify=[{"label": "Show the call", "command": "sed -n '{line}p' '{path}'"}],
    references=["https://www.rfc-editor.org/rfc/rfc7914",
                "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
)
