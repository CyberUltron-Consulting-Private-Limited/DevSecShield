"""CI canary (PR #16 acceptance row 4): a FABRICATED GitHub PAT, never a real credential.

The line also carries the bypass from security review 5855812689: an inline allow comment, which the secret gate
must ignore. This branch is deleted after the run.
"""

GITHUB_TOKEN = "ghp_Bq2MDK3Gj2ad9jHh1Cjp8fM8VFkfswiJqEod"  # gitleaks:allow
# A second fabricated token, without any bypass: the plain case.
GITHUB_TOKEN_PLAIN = "ghp_NnTKvuRKKTuZudkbcTr3NIHHTSBnkMNxOSFP"
