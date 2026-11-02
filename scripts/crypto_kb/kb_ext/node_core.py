"""Knowledge-base entries for the scan-node core package (WP5): PostgreSQL role password storage."""
import kb_text
from kb_text import V_PG

kb_text.entry(
    "DB_PLAINTEXT_PW", title="Passwords stored in plain text", category="database", default_impact="High",
    description="Login roles hold a stored password that is neither an MD5 nor a SCRAM-SHA-256 hash: a password kept "
                "unhashed (PostgreSQL before 10 allowed it, and an upgrade can carry it over).",
    attack="Anyone who can read pg_authid, a backup or a replica reads the password itself and can sign in as that role "
           "here and wherever the password is reused.",
    cwe=["CWE-312", "CWE-522"], owasp=["crypto", "auth"], cves=[], standards=["RFC 7677 (SCRAM-SHA-256)"],
    compliance=["auth"],
    remediation={"summary": "Set password_encryption = scram-sha-256 and set a new password for each listed role "
                            "(ALTER ROLE <role> PASSWORD '<new>'), so it is stored as a SCRAM hash.", "steps": []},
    verify=[{"label": "Hash type per login role (as a superuser; prints types, never hashes)",
             "command": "psql \"host={host} port={port} sslmode=require\" -c \"SELECT rolname, CASE WHEN rolpassword IS "
                        "NULL THEN 'none' WHEN rolpassword LIKE 'md5%' THEN 'md5' WHEN rolpassword LIKE "
                        "'SCRAM-SHA-256$%' THEN 'scram-sha-256' ELSE 'other' END FROM pg_authid WHERE rolcanlogin\""},
            *V_PG],
    references=["https://www.postgresql.org/docs/current/auth-password.html"])

NODE_CODES = ["DB_PLAINTEXT_PW"]
