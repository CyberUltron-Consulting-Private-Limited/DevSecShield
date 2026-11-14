"""Import a signed zs-collect release into this deployment (operator command; deployment-wide, not a team action).

    python -m backend.utilities.cbom_sources.transports.release import --manifest zs-collect-1.0.0.manifest.json \
        [--activate]
    python -m backend.utilities.cbom_sources.transports.release show

The manifest's Ed25519 signature (``<manifest>.sig``, base64) must verify against the release public key the backend
carries (``transports/zs-release-ed25519.pub``, identical to the scan node's); otherwise nothing is stored.  Only the
manifest is imported (the binaries stay in the customer's mirror); every wrapper the transports serve embeds the sha256
per architecture from it.  ``--activate`` makes it the release every claim and artifact uses.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlmodel import Session, select


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="transports.release")
    sub = p.add_subparsers(dest="cmd", required=True)
    imp = sub.add_parser("import")
    imp.add_argument("--manifest", required=True)
    imp.add_argument("--activate", action="store_true")
    sub.add_parser("show")
    args = p.parse_args(argv)
    from backend.get_db import get_db
    from backend.utilities.cbom_sources.common import utcnow
    from backend.utilities.cbom_sources.transports.models import CbomZsCollectRelease
    from backend.utilities.cbom_sources.transports.registry import ReleaseError, active_release, import_release

    engine = get_db()
    with Session(engine) as session:
        if args.cmd == "show":
            active = active_release(session)
            for row in session.exec(select(CbomZsCollectRelease).order_by(CbomZsCollectRelease.id)).all():
                print(json.dumps({"version": row.version, "active": row.active, "verified_at": str(row.verified_at),
                                  "sha256": {"amd64": row.sha256_amd64, "arm64": row.sha256_arm64},
                                  "key": row.key_fingerprint, "usable": bool(active and active.id == row.id)}))
            return 0
        path = Path(args.manifest)
        try:
            row = import_release(session, path.read_bytes(), Path(str(path) + ".sig").read_text(),
                                 activate=args.activate, now=utcnow())
        except (ReleaseError, OSError) as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 1
        session.commit()
        print(f"imported zs-collect {row.version} (signed by {row.key_fingerprint}){' and activated' if row.active else ''}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
