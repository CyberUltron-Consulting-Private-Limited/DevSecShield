# CB-30 live proof: customer repository "rsa1024" (throwaway test branch, never merged)

A stand-in for a customer repository that uses DevSecShield's CBOM CI/CD integration (PR #95).
`.github/workflows/cbom-check.yml` is the GitHub Actions file the CI/CD page generates for a CBOM integration,
with `[cb30-proof]` steps that start a DevSecShield stack inside the runner first (see the comment in the file).

Expected: the job FAILS at "CBOM policy gate" (keys.py generates an RSA-1024 key: NIST SP 800-131A disallows RSA below 2048 bits).
