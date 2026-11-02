"""Round 5 WP3a: code-scan posture codes for provider-managed keys and end-of-life container base images."""

import kb_text
from kb_text import entry

CODE_CODES = ["PROVIDER_MANAGED_KEY", "EOL_BASE_IMAGE"]

entry(
    "PROVIDER_MANAGED_KEY",
    title="Data encrypted only with the cloud provider's default key",
    category="cloud",
    default_impact="Low",
    description=(
        "Infrastructure code declares no encryption key for this data store, so it is encrypted at rest by the "
        "provider's default (for example SSE-S3 on an S3 bucket) with a key the provider owns and manages. The data "
        "is encrypted, but the organisation does not hold the key: it cannot set the key policy, rotate or revoke "
        "the key, or see each use of it."
    ),
    attack=(
        "Anyone the provider's own access path allows can read the data without a key decision by you, and a "
        "compromised or over-privileged role is not stopped by a key policy. Regulators and frameworks for "
        "regulated data (RBI's cyber security framework for banks, CERT-In's guidance, NIST SP 800-57 key "
        "management) expect keys whose custody, rotation and access the organisation controls."
    ),
    cwe=["CWE-320"],
    owasp=["crypto", "misconfig"],
    cves=[],
    standards=["NIST SP 800-57 Part 1 Rev. 5 (key management)"],
    compliance=["key_mgmt", "at_rest"],
    remediation={
        "summary": "Encrypt the store with a customer-managed key (a KMS / Key Vault / Cloud KMS key you own) and "
                   "restrict its key policy to the roles that need the data.",
        "steps": [
            {"platform": "Terraform (AWS S3)", "how": "aws_s3_bucket_server_side_encryption_configuration with "
             "sse_algorithm = \"aws:kms\" and kms_master_key_id = aws_kms_key.<name>.arn"},
            {"platform": "Terraform (AWS RDS / EBS / EFS)", "how": "storage_encrypted / encrypted = true and "
             "kms_key_id = aws_kms_key.<name>.arn"},
            {"platform": "Azure / GCP", "how": "a customer_managed_key block (Azure Storage) or "
             "kms_key_name / encryption.default_kms_key_name (GCP) pointing at your own key"},
        ],
    },
    verify=[{"label": "Show the resource's encryption settings", "command": "grep -n -i 'kms\\|encrypt\\|sse' '{path}'"}],
    references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html",
                "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final"],
)

entry(
    "EOL_BASE_IMAGE",
    title="Container base image past end of life",
    category="library",
    default_impact="Medium",
    description=(
        "A Dockerfile builds on a Linux distribution release whose free security updates have ended, so the "
        "OpenSSL, GnuTLS and other crypto libraries in the image no longer receive fixes (unless a paid extended "
        "support subscription is applied inside the image)."
    ),
    attack=(
        "Every TLS and crypto library vulnerability published after the end-of-life date stays exploitable in the "
        "container: an attacker uses the public advisory against the unpatched library the image ships."
    ),
    cwe=["CWE-1104"],
    owasp=["components"],
    cves=[],
    standards=[],
    compliance=["components"],
    remediation={
        "summary": "Rebuild on a supported release of the distribution (or a supported minimal base) and rebuild "
                   "regularly so security updates reach the image.",
        "steps": [
            {"platform": "Dockerfile", "how": "FROM ubuntu:24.04 (or debian:12-slim, alpine:3.22, "
             "amazonlinux:2023); then rebuild and redeploy every image built from it"},
        ],
    },
    verify=[{"label": "Show the base image", "command": "grep -n -i '^FROM' '{path}'"}],
    references=["https://endoflife.date/", "https://ubuntu.com/about/release-cycle", "https://wiki.debian.org/LTS"],
)

del kb_text
