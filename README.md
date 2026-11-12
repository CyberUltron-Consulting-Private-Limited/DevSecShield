# CB-30 live proof: customer repository "clean" (throwaway test branch, never merged)

A stand-in for a customer repository that uses DevSecShield's CBOM CI/CD integration (PR #95).
`.github/workflows/cbom-check.yml` is the GitHub Actions file the CI/CD page generates for a CBOM integration,
with `[cb30-proof]` steps that start a DevSecShield stack inside the runner first (see the comment in the file).

Expected: the job PASSES (RSA-3072 and AES-GCM only).
