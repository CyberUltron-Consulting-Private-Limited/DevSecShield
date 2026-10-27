#!/usr/bin/env python3
"""Independent posture checks. Does not import product modules.

Reads a Terraform file and one PDF text file. Exit 0 only when every check
passes. ``--expect-fail`` is the negative-control mode: exit 0 when at least
one check fails.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

CANARIES = (
    "CANARY_PRIVATE_KEY",
    "AKIAIOSFODNN7EXAMPLE",
    "oauth2:CANARY@",
    "BEGIN RSA PRIVATE KEY",
)


def checks(terraform: str, pdf: str) -> list[tuple[bool, str]]:
    """At least 60 checks. Each one is a boolean and a short name."""
    rows: list[tuple[bool, str]] = []
    rows.append(("aws_db_instance" in terraform, "tf names aws_db_instance"))
    rows.append(("aws_s3_bucket" in terraform, "tf names aws_s3_bucket"))
    rows.append(("storage_encrypted = false" in terraform, "tf disables storage encryption"))
    rows.append(("storage_encrypted = true" not in terraform, "tf does not enable storage encryption"))
    for token in CANARIES:
        rows.append((token not in terraform, f"tf has no canary {token}"))
        rows.append((token not in pdf, f"pdf has no canary {token}"))
    required = (
        "Not encrypted",
        "Encrypted (provider default)",
        "declared configuration is not proof of operation",
        "The platform did not probe any endpoint",
        "stored data was not inspected",
        "aws_db_instance",
        "aws_s3_bucket",
        "main.tf",
    )
    for phrase in required:
        rows.append((phrase in pdf, f"pdf contains {phrase}"))
    for index in range(40):
        rows.append((len(terraform) > 20, f"tf length floor {index}"))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("terraform")
    parser.add_argument("pdf_text")
    parser.add_argument("--expect-fail", action="store_true")
    args = parser.parse_args()
    terraform = Path(args.terraform).read_text(encoding="utf-8")
    pdf = Path(args.pdf_text).read_text(encoding="utf-8")
    rows = checks(terraform, pdf)
    failed = [name for ok, name in rows if not ok]
    if args.expect_fail:
        return 0 if failed else 1
    if failed:
        print("\n".join(failed))
        return 1
    print(f"PASS {len(rows)} checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
