"""Resource generators for later property tests. No product imports."""

from __future__ import annotations

import random


def one_resource(rng: random.Random) -> dict[str, str]:
    kind = rng.choice(("object_store", "tls_endpoint", "kms_key"))
    return {"kind": kind, "address": f"res-{rng.randrange(1000)}"}
