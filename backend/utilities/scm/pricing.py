"""What one repository scan costs, before any repository is cloned (formula ``scm-size-v1``).

A bulk run over hundreds of repositories cannot clone each one to measure it the way the single-scan estimate does
(the worker clones and measures the checked-out source). The price here uses the size the SCM reports and the worker's
own rates, in hundredths of a credit:

    sast       1 credit per 0.5 MB  + 0.04 / 0.836   (helpers/tools/sast_agent: summary + vulnerability mapping)
    iac        1 credit per 0.5 MB                    (helpers/tools/iac_agent)
    sbom_sca   flat 0.01 / 0.836                      (helpers/tools/sca_sbom_agent)
    cbom       1 credit per 0.5 MB, at least 1 credit (helpers/tools/cbom_agent; decision D3)
    ai_bom     1 credit per 0.5 MB  + 0.04 / 0.836   (helpers/tools/ai_bom_agent)

Every scan costs at least 0.01. GitHub's repository size includes the git history, so for most repositories this is
an upper bound of what a clone-measured estimate of the same branch would say; GitLab reports the repository size and
Bitbucket the repository size in bytes. The customer sees this price per repository and in total before a run starts.
"""
from __future__ import annotations

FORMULA = "scm-size-v1"
PRODUCTS = ("sast", "iac", "sbom_sca", "cbom", "ai_bom")
_LLM_CONSTANT = 0.04 / 0.836
_SBOM_FLAT = 0.01 / 0.836
_MB_PER_CREDIT = 0.5
_CBOM_MIN = 1.0


def credits(product: str, size_kb: int) -> float:
    mb = max(0, int(size_kb or 0)) / 1024
    if product == "sast" or product == "ai_bom":
        value = mb / _MB_PER_CREDIT + _LLM_CONSTANT
    elif product == "iac":
        value = mb / _MB_PER_CREDIT
    elif product == "sbom_sca":
        value = _SBOM_FLAT
    elif product == "cbom":
        value = max(_CBOM_MIN, mb / _MB_PER_CREDIT)
    else:
        raise ValueError(f"{product} cannot scan a repository")
    return max(0.01, round(value, 2))


def price_c(product: str, size_kb: int) -> int:
    """The price in hundredths of a credit (integer, so totals never drift)."""
    return int(round(credits(product, size_kb) * 100))


def as_credits(cents: int) -> float:
    return round(int(cents) / 100, 2)


__all__ = ["FORMULA", "PRODUCTS", "as_credits", "credits", "price_c"]
