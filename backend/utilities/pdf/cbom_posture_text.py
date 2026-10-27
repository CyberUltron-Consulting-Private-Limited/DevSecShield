"""Authored text for the three posture deliverables (WP10b).

Labels, one-line actions and reason text. Standards claims carry a ``# Source:`` comment.
This module does not read a clock and does not import a client.
"""

from __future__ import annotations

from backend.utilities.pdf.cbom_deliverable_text import CERTIN_DISCLAIMER, RBI_BOM_DISCLAIMER

FINDING_CODES = (
    "UNENCRYPTED_AT_REST",
    "UNENCRYPTED_IN_TRANSIT",
    "PLAINTEXT_LISTENER",
    "TLS_VERIFICATION_DISABLED",
    "DOWNGRADE_PROTECTION_MISSING",
    "KNOWN_TLS_VULNERABILITY",
    "KMS_KEY_ROTATION_DISABLED",
    "KMS_KEY_POLICY_PUBLIC",
    "KMS_KEY_DELETION_UNPROTECTED",
    "AT_REST_ENCRYPTION_WEAK",
)

FINDING_LABELS = {
    "UNENCRYPTED_AT_REST": "Unencrypted at rest",
    "UNENCRYPTED_IN_TRANSIT": "Unencrypted in transit",
    "PLAINTEXT_LISTENER": "Plaintext listener",
    "TLS_VERIFICATION_DISABLED": "Certificate verification disabled",
    "DOWNGRADE_PROTECTION_MISSING": "Downgrade protection missing",
    "KNOWN_TLS_VULNERABILITY": "Known TLS vulnerability",
    "KMS_KEY_ROTATION_DISABLED": "Key rotation disabled",
    "KMS_KEY_POLICY_PUBLIC": "Key policy is public",
    "KMS_KEY_DELETION_UNPROTECTED": "Key deletion is unprotected",
    "AT_REST_ENCRYPTION_WEAK": "Weak encryption at rest",
}

FINDING_IMPACT = {
    "UNENCRYPTED_AT_REST": "High",
    "UNENCRYPTED_IN_TRANSIT": "High",
    "PLAINTEXT_LISTENER": "Medium",
    "TLS_VERIFICATION_DISABLED": "High",
    "DOWNGRADE_PROTECTION_MISSING": "Medium",
    "KNOWN_TLS_VULNERABILITY": "High",
    "KMS_KEY_ROTATION_DISABLED": "Medium",
    "KMS_KEY_POLICY_PUBLIC": "High",
    "KMS_KEY_DELETION_UNPROTECTED": "Low",
    "AT_REST_ENCRYPTION_WEAK": "Medium",
}

FINDING_ANCHORS = {
    "UNENCRYPTED_AT_REST": "CWE-311, CWE-312",
    "UNENCRYPTED_IN_TRANSIT": "CWE-319",
    "PLAINTEXT_LISTENER": "CWE-319",
    "TLS_VERIFICATION_DISABLED": "CWE-295",
    "DOWNGRADE_PROTECTION_MISSING": "RFC 7507",
    "KNOWN_TLS_VULNERABILITY": "CVE of the reported entry",
    "KMS_KEY_ROTATION_DISABLED": "NIST SP 800-57 Part 1",
    "KMS_KEY_POLICY_PUBLIC": "CWE-284",
    "KMS_KEY_DELETION_UNPROTECTED": "NIST SP 800-57 Part 1",
    "AT_REST_ENCRYPTION_WEAK": "CWE-326",
}

# Source: CWE-311, missing encryption of sensitive data: https://cwe.mitre.org/data/definitions/311.html
# Source: CWE-312, cleartext storage of sensitive information: https://cwe.mitre.org/data/definitions/312.html
# Source: CWE-319, cleartext transmission: https://cwe.mitre.org/data/definitions/319.html
# Source: CWE-295, improper certificate validation: https://cwe.mitre.org/data/definitions/295.html
# Source: RFC 7507, TLS Fallback SCSV: https://www.rfc-editor.org/rfc/rfc7507
# Source: CVE-2014-0160, one scored TLS defect: https://www.cve.org/CVERecord?id=CVE-2014-0160
# Source: NIST SP 800-57 Part 1 Rev 5, cryptoperiod and key destruction: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
# Source: CWE-284, improper access control: https://cwe.mitre.org/data/definitions/284.html
# Source: CWE-295, improper certificate validation: https://cwe.mitre.org/data/definitions/295.html
# Source: CWE-311, missing encryption: https://cwe.mitre.org/data/definitions/311.html
# Source: CWE-312, cleartext storage: https://cwe.mitre.org/data/definitions/312.html
# Source: CWE-319, cleartext transmission: https://cwe.mitre.org/data/definitions/319.html
# Source: CWE-326, inadequate encryption strength: https://cwe.mitre.org/data/definitions/326.html
# Source: RFC 7507, TLS fallback SCSV: https://www.rfc-editor.org/rfc/rfc7507
FINDING_ACTIONS = {
    "UNENCRYPTED_AT_REST": "Enable encryption at rest with an approved algorithm and a managed key.",
    "UNENCRYPTED_IN_TRANSIT": "Require TLS 1.2 or later on this path and reject a plaintext listener.",
    "PLAINTEXT_LISTENER": "Disable the plaintext listener or redirect it to TLS.",
    "TLS_VERIFICATION_DISABLED": "Turn certificate verification on and trust only a known issuer.",
    "DOWNGRADE_PROTECTION_MISSING": "Enable TLS_FALLBACK_SCSV and refuse SSL and TLS below 1.2.",
    "KNOWN_TLS_VULNERABILITY": "Patch or disable the affected protocol and record the reported CVE.",
    "KMS_KEY_ROTATION_DISABLED": "Enable automatic key rotation and record the cryptoperiod.",
    "KMS_KEY_POLICY_PUBLIC": "Remove public principals from the key policy and name the roles that may use it.",
    "KMS_KEY_DELETION_UNPROTECTED": "Require a waiting period or an explicit protection before a key can be destroyed.",
    "AT_REST_ENCRYPTION_WEAK": "Replace the at-rest cipher with AES-256-GCM or another approved algorithm.",
}

VERDICT_LABELS = {
    "ENCRYPTED_DECLARED": "Encrypted (declared)",
    "ENCRYPTED_PROVIDER_DEFAULT": "Encrypted (provider default)",
    "NOT_ENCRYPTED": "Not encrypted",
    "UNKNOWN": "Not evidenceable from BOM (unknown)",
}
AT_REST_VERDICTS = (
    "ENCRYPTED_DECLARED",
    "ENCRYPTED_PROVIDER_DEFAULT",
    "NOT_ENCRYPTED",
    "UNKNOWN",
)

UNKNOWN_REASONS = (
    "variable_overridden",
    "variable_no_default",
    "unresolved_expression",
    "dynamic_block",
    "module_call",
    "template_marker",
    "unresolved_include",
    "unresolved_reference",
    "layer_not_observable",
    "attribute_not_modeled",
    "default_unknown",
    "provider_version_dependent",
    "parse_error",
    "import_not_tested",
)
UNKNOWN_LABELS = {
    "variable_overridden": "A variable is set outside this file",
    "variable_no_default": "A variable has no default",
    "unresolved_expression": "An expression could not be resolved",
    "dynamic_block": "A dynamic block hides the value",
    "module_call": "A module call hides the value",
    "template_marker": "A template marker hides the value",
    "unresolved_include": "An included file could not be read",
    "unresolved_reference": "A reference could not be resolved",
    "layer_not_observable": "This layer is not visible in the declaration",
    "attribute_not_modeled": "The attribute is not in the coverage rules",
    "default_unknown": "No documented default decides this setting",
    "provider_version_dependent": "The result depends on the provider version",
    "parse_error": "The file could not be parsed",
    "import_not_tested": "The imported result did not test this item",
}
UNKNOWN_CHECKS = {
    "variable_overridden": "Open the variable assignment and record the literal that wins.",
    "variable_no_default": "Give the variable a default or record the value used at apply time.",
    "unresolved_expression": "Replace the expression with the literal that is applied.",
    "dynamic_block": "Expand the dynamic block and record each concrete value.",
    "module_call": "Open the module source and record the concrete argument.",
    "template_marker": "Render the template and record the concrete value.",
    "unresolved_include": "Provide the included file and re-scan.",
    "unresolved_reference": "Resolve the reference to a resource in this scan.",
    "layer_not_observable": "Inspect that layer outside the repository.",
    "attribute_not_modeled": "Confirm the setting against the vendor document for this resource.",
    "default_unknown": "Record the provider default that applies to this account.",
    "provider_version_dependent": "Record the provider version and the default it documents.",
    "parse_error": "Repair the file so it parses, then re-scan.",
    "import_not_tested": "Re-run the customer's tool with this item enabled.",
}

POSTURE_SCOPE_OF_METHOD = (
    "Method: analysis of declared configuration in repositories and uploaded artefacts "
    "(infrastructure-as-code, container and cluster definitions, server and database "
    "configuration) and offline import of result files that the customer's own tools "
    "produced. The platform does not probe any endpoint, call any cloud API, inspect a "
    "KMS or HSM, or inspect stored data. A declared setting is not proof that it is in "
    "operation."
)
DISCLAIMER_PARAGRAPHS = (CERTIN_DISCLAIMER, RBI_BOM_DISCLAIMER, POSTURE_SCOPE_OF_METHOD)

FACTS_SEPARATE = "Posture facts are counted separately from crypto asset occurrences"
REFERENCE_STALE = "Reference data may be out of date"
DECLARED_LEGEND = "Declared in the repository mapping file; not verified"
ZERO_FACTS_NOTE = (
    "no in-scope infrastructure or configuration files were found in it; this is not "
    "evidence that no cloud resources or configurations exist"
)
CAPABILITY_EVIDENCE = "capability evidence, not proof that stored data is protected"
NO_CLASSIFICATION = "no classification was declared; a Business_Mapping_File supplies it"
NO_RETENTION = "no backup retention or point-in-time recovery setting was declared"
INFRA_LIMIT = "declared configuration is not proof of operation"
ENDPOINT_LIMIT = (
    "The platform did not probe any endpoint. Imported results reflect the time the "
    "customer's tool ran."
)
STORED_DATA_LIMIT = "stored data was not inspected"
STORED_DATA_STATEMENT = "The platform does not inspect stored data."

BANNER_NOT_ASSESSED_TITLE = "POSTURE NOT ASSESSED - RE-SCAN NEEDED"
BANNER_NOT_ASSESSED_TEXT = (
    "Every current source is not assessed. Re-scan to read declared configuration. "
    "No encryption verdict can be given."
)
BANNER_TRUNCATED_TITLE = "POSTURE DATA TRUNCATED"
BANNER_PARTIAL_TITLE = "POSTURE LANES FAILED"

# Entries of the named-vulnerability table that are shown and not scored.
UNSCORED_VULNERABILITIES = frozenset({"BEAST", "LUCKY13", "CRIME", "BREACH"})
PROTOCOL_KEYS = ("SSLv3", "1.0", "1.1", "1.2", "1.3")
PROTOCOL_HEADERS = ("SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")

DATA_STORE_KINDS = frozenset(
    {
        "object_store",
        "block_volume",
        "file_system",
        "relational_db",
        "nosql_db",
        "cache",
        "search_index",
        "message_queue",
        "message_topic",
        "data_stream",
        "data_warehouse",
        "log_store",
    }
)
AT_REST_KINDS = DATA_STORE_KINDS | frozenset(
    {"backup", "k8s_secrets_etcd", "k8s_storage_class", "disk_encryption"}
)
MANAGED_TLS_PROVIDERS = frozenset({"aws", "azure", "gcp", "kubernetes"})
DATABASE_KINDS = frozenset({"relational_db", "nosql_db", "cache", "search_index"})


def coverage_line(assessed: int, total: int, not_assessed: int, partial: int) -> str:
    """Basis coverage sentence. The partial clause is omitted when the count is zero."""
    text = f"Posture coverage: {assessed} of {total} current sources assessed"
    if partial:
        text += f" (of which {partial} partial)"
    return text + f"; {not_assessed} not assessed (re-scan needed)"


def finding_label(code: object) -> str:
    key = str(code or "").strip()
    return FINDING_LABELS.get(key, key.replace("_", " ").capitalize() if key else "")


def finding_action(code: object) -> str:
    key = str(code or "").strip()
    return FINDING_ACTIONS.get(key, "Review this finding against the cryptographic policy.")


def verdict_label(value: object) -> str:
    key = str(value or "").strip()
    return VERDICT_LABELS.get(key, key)


def unknown_label(reason: object) -> str:
    key = str(reason or "").strip()
    return UNKNOWN_LABELS.get(key, key.replace("_", " ") if key else "Reason not recorded")


def unknown_check(reason: object) -> str:
    key = str(reason or "").strip()
    return UNKNOWN_CHECKS.get(key, "Review the declaration by hand.")
