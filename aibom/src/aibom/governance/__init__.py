"""Runtime-governance projections of the inventory graph.

Optional, lane-clean consumers of a scored :class:`~aibom.model.result.ScanResult`
that translate *"what AI do we have?"* (the BOM) into *"what may it do at
runtime?"*. Currently: a Cedar entities + policy export (:mod:`.cedar`).
"""

from aibom.governance.cedar import (
    sample_policy,
    to_cedar_entities,
    write_entities,
    write_policy,
)

__all__ = [
    "sample_policy",
    "to_cedar_entities",
    "write_entities",
    "write_policy",
]
