"""CBOM scanner package. Importing it self-registers every CBOM scanner into
:data:`aibom.cbom.registry.CBOM_SCANNERS`. Adding a CBOM scanner is one module
here (mirrors :mod:`aibom.scan.scanners`).
"""

from aibom.cbom.scanners import (  # noqa: F401
    algorithm_scan,
)

__all__ = ["algorithm_scan"]
