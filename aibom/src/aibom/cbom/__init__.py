"""CBOM (Cryptography Bill of Materials) lane.

A peer of the AIBOM scan lane: it reuses the same :class:`~aibom.model.result`
``ScanResult`` model and the same scanner contract (scanners EMIT
components/edges/flags, never score), but runs its own registry of crypto
scanners over a repo and produces ``crypto_asset`` components (CycloneDX 1.6
``cryptographic-asset``).

The crypto detection knowledge is RECONCILED from the existing worker agent at
``RabbitMQ/worker/helpers/tools/cbom_agent/`` (``crypto_rules.py`` /
``source_scanner.py``) into this lane — the real, battle-tested detection is
preserved; what this lane ADDS is per-usage parametrization (key size / mode /
curve), the hand-built CycloneDX crypto-asset emitter, PQC grading, and
tri-state compliance (later C-stories).
"""

from __future__ import annotations
