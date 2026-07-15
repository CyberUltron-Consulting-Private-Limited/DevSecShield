"""Shadow-AI discovery layer (Phase 4): allowlist diffing over the inventory."""

from aibom.shadow.diff import SHADOW_KINDS, flag_unsanctioned, load_allowlist

__all__ = ["SHADOW_KINDS", "flag_unsanctioned", "load_allowlist"]
