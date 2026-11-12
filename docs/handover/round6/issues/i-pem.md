**Found by:** the security reviews of PRs #16 and #34. Nobody has opened the file.

`cu-devsecshield-key.pem` has been tracked at the repository root since commit 2c3433a, and every branch cut from `dev` contains it. gitleaks lists it among the tracked secrets (see the debt table in `docs/ci/README.md`).

**If it is a private key** (an AWS EC2 key pair, SSH or TLS), treat it as exposed:
1. **Owner:** revoke or rotate it wherever it is trusted (EC2 key pair, `authorized_keys`, TLS endpoints).
2. **Remove it from the tree** in a PR into `dev`. Do it together with #18 (the tracked `.env` files), so the first `staging` → `main` promotion carries no key material.
3. **Optionally purge it from git history.** This is the owner's call: it rewrites history and needs every clone re-cloned.

Removing the file does not un-leak it. Rotation comes first.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01SDCVQSqoacevwbyX9VGquR
