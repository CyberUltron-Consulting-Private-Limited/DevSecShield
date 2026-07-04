"""bench/cbom/emit_ours.py PATH OUT — emit OUR CycloneDX CBOM for a repo.

Runs the real CBOM pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) and renders
it through the shared, schema-validated CycloneDX 1.6 reporter — the same crypto-
asset emitter the product ships (C4). Isolated harness, NOT product code.

Usage:  uv run python bench/cbom/emit_ours.py <repo-path> <out.cdx.json>
"""

import sys

from aibom.cbom.pipeline import scan_crypto
from aibom.emit import get_reporter

path, out = sys.argv[1], sys.argv[2]
result = scan_crypto(path, level=4)
open(out, "w").write(get_reporter("cyclonedx").render(result))
crypto = sum(1 for c in result.components if c.kind == "crypto_asset")
print(f"ours: {crypto} crypto-assets / {len(result.components)} components -> {out}")
