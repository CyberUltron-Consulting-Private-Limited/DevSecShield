"""Emit layer: a stateless reporter registry + the bundled-schema validators.

Importing this package self-registers every reporter (CycloneDX / SPDX / SARIF)
into the registry, so ``get_reporter(fmt)`` works after a single import.
"""

# Importing the reporter modules runs their @register_reporter decorators.
from aibom.emit import cyclonedx, sarif, spdx  # noqa: F401
from aibom.emit.registry import (
    BaseReporter,
    available_formats,
    get_reporter,
    register_reporter,
)

__all__ = [
    "BaseReporter",
    "available_formats",
    "get_reporter",
    "register_reporter",
    "cyclonedx",
    "spdx",
    "sarif",
]
