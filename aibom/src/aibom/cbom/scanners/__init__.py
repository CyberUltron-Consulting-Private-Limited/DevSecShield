"""CBOM scanner package. Importing it self-registers every CBOM scanner into
:data:`aibom.cbom.registry.CBOM_SCANNERS`. Adding a CBOM scanner is one module
here (mirrors :mod:`aibom.scan.scanners`).
"""

from aibom.cbom.scanners import (  # noqa: F401
    algorithm_scan,
    ast_crypto_scan,
    certificate_scan,
    crypto_advisory_scan,
    crypto_misuse_scan,
    crypto_policy_scan,
    custom_crypto_scan,
    posture_database_scan,
    posture_findings_scan,
    posture_iac_scan,
    posture_linkage_scan,
    posture_server_scan,
    posture_tls_import_scan,
    posture_verification_scan,
    pqc_scan,
    protocol_scan,
    strength_scan,
    weak_algorithm_scan,
)

__all__ = [
    "algorithm_scan",
    "ast_crypto_scan",
    "certificate_scan",
    "crypto_advisory_scan",
    "crypto_misuse_scan",
    "crypto_policy_scan",
    "custom_crypto_scan",
    "posture_database_scan",
    "posture_findings_scan",
    "posture_iac_scan",
    "posture_linkage_scan",
    "posture_server_scan",
    "posture_tls_import_scan",
    "posture_verification_scan",
    "pqc_scan",
    "protocol_scan",
    "strength_scan",
    "weak_algorithm_scan",
]
