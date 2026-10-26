"""Numeric limits for the posture lanes. No timers."""

from __future__ import annotations

from dataclasses import dataclass

BYTES_PER_CONFIG_FILE = 5_242_880
BYTES_PER_TLS_RESULT = 20_971_520
BYTES_PER_SCAN = 268_435_456
FILES_PER_SCAN = 10_000
NESTING_DEPTH = 100
YAML_ALIASES = 1_000
YAML_NODES = 500_000
BYTES_PER_LINE = 1_048_576
INCLUDE_DEPTH = 5
FACTS_PER_SCAN = 50_000
STORED_DIAGNOSTICS = 1_000
MAPPING_ENTRIES = 10_000
POSTURE_BLOCK_BYTES = 8_388_608
POSTURE_COMPONENTS = 20_000
GLOB_STEPS = 20_000_000
NUL_PROBE_BYTES = 8_192
SNIFF_BYTES = 65_536
PATH_MAX_BYTES = 512


@dataclass(slots=True)
class GlobBudget:
    """Mutable per-scan step counter charged by the glob matcher."""

    steps_left: int = GLOB_STEPS
    skipped: int = 0
