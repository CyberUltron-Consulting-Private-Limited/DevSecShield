"""Limits other parts import.  This module imports nothing, so any module may import it without an import cycle
(F1.2's materialiser does, through its optional-import seam for F1.3).

``MAX_FLEET_TARGETS_PER_SOURCE``: coordinator decision of 2026-11-12 on review 5874466030.  A fleet-kind source
(``awx_hosts``, ``salt_hosts``, ``ssm_hosts``) runs as one job, and a job keeps at most
``jobs.MAX_ASSETS_PER_ATTEMPT`` (50,000) assets; past that they are dropped and the run is marked truncated.  200
hosts leave 250 assets per host (measured: 187 on a live AL2023 instance through SSM, 53 on the lab target).  Hand-made
fleet sources are refused above it, and F1.2's materialiser batches fleet-kind targets at most this many per managed
source (``min(policy batch_size, MAX_FLEET_TARGETS_PER_SOURCE)``).
"""

MAX_FLEET_TARGETS_PER_SOURCE = 200
