"""bench/emit_ours.py PATH OUT — emit OUR CycloneDX at level 4 (production depth).

The `aibom emit` CLI scans at the default level 1; the product actually runs at
level 4 (`scan_to_devsecshield(level=4)`). For a fair benchmark we run ours at the
same depth so cloud-iac (L4), net-env (L3), docker (L2) scanners fire.
"""

import sys

from aibom.emit import get_reporter
from aibom.scan.pipeline import scan_repo

path, out = sys.argv[1], sys.argv[2]
result = scan_repo(path, level=4)
open(out, "w").write(get_reporter("cyclonedx").render(result))
print(f"ours L4: {len(result.components)} components -> {out}")
