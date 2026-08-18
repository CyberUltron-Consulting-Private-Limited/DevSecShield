"""Compliance-mapping layer (advisory). Importing this package self-registers
every framework's checks into ``_CHECK_REGISTRY`` (mirrors scan/scanners and the
emit reporter registry), so ``engine.run_all`` sees all five frameworks.

Checks read the GRAPH, never flags. Mappings are advisory only and carry the
disclaimer; they support but do not satisfy FDA / EU AI Act / HIPAA obligations.
"""

# Importing each module runs its @register_check decorators.
from aibom.compliance import (  # noqa: F401
    eu_ai_act_annexIV,
    fda_524b,
    gmlp,
    hipaa,
    nist_rmf,
    rbi_free_ai,
)
# CERT-In AIBOM Table 10 + §9.4.1 (Phase 2). Do not import CBOM/SBOM lane modules here.
from aibom.compliance.cert_in import ai as _cert_in_ai  # noqa: F401
# SEBI CSCRF AIBOM honest software-inventory reading.
# Lane isolation: do not pull CBOM or SBOM SEBI modules into this package init.
from aibom.compliance.sebi_cscrf import ai as _sebi_cscrf_ai  # noqa: F401
from aibom.compliance.base import ADVISORY_DISCLAIMER, Requirement
from aibom.compliance.engine import ALIASES, FRAMEWORKS, resolve_framework, run_all

__all__ = [
    "ADVISORY_DISCLAIMER",
    "Requirement",
    "ALIASES",
    "FRAMEWORKS",
    "resolve_framework",
    "run_all",
]
