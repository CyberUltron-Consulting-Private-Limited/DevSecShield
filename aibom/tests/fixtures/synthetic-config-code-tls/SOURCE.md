# synthetic-config-code-tls

Hand-derived 2026-10-27 from source files and `verification_patterns.json`
(lifted from `test_cbom_posture_verification.py`).

- `client.py` line 3: `verify=False` → one `py.requests.verify` fact,
  `TLS_VERIFICATION_DISABLED` (transport layer stays `UNKNOWN`).
- `fetch.sh` line 2: `curl -k` → one `curl.insecure` fact, same finding code.
- `safe_notes.py` is a negative control: prose comments and a safe `requests.get`
  without verification-disabling literals → **no** verification facts.

No secrets in this tree.
