"""Scanner package. Importing it self-registers every scanner (import order =
registration order). Add a scanner = add one module here.
"""

from aibom.scan.scanners import model_repo, requirements  # noqa: F401

__all__ = ["requirements", "model_repo"]
