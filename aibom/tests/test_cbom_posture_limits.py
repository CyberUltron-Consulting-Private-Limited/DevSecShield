"""Limits are the requirement table, not invented numbers."""

from aibom.cbom.posture.limits import (
    BYTES_PER_CONFIG_FILE,
    BYTES_PER_LINE,
    BYTES_PER_SCAN,
    BYTES_PER_TLS_RESULT,
    FACTS_PER_SCAN,
    FILES_PER_SCAN,
    GLOB_STEPS,
    INCLUDE_DEPTH,
    MAPPING_ENTRIES,
    NESTING_DEPTH,
    POSTURE_BLOCK_BYTES,
    POSTURE_COMPONENTS,
    STORED_DIAGNOSTICS,
    YAML_ALIASES,
    YAML_NODES,
    GlobBudget,
)


def test_table_values() -> None:
    assert BYTES_PER_CONFIG_FILE == 5_242_880
    assert BYTES_PER_TLS_RESULT == 20_971_520
    assert BYTES_PER_SCAN == 268_435_456
    assert FILES_PER_SCAN == 10_000
    assert NESTING_DEPTH == 100
    assert YAML_ALIASES == 1_000
    assert YAML_NODES == 500_000
    assert BYTES_PER_LINE == 1_048_576
    assert INCLUDE_DEPTH == 5
    assert FACTS_PER_SCAN == 50_000
    assert STORED_DIAGNOSTICS == 1_000
    assert MAPPING_ENTRIES == 10_000
    assert POSTURE_BLOCK_BYTES == 8_388_608
    assert POSTURE_COMPONENTS == 20_000
    assert GLOB_STEPS == 20_000_000
    assert GlobBudget().steps_left == GLOB_STEPS
