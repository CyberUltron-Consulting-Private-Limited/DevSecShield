"""Print the route inventory: every route, the access policy it declares and the lowest team role it admits.

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=x JWT_REFRESH_SECRET_KEY=y \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python scripts/rbac_route_inventory.py [--before routes-before.json] > ../docs/security/route-inventory.md

``--before`` takes a JSON list of {methods, path, checks} (the checks each handler did before F4, from a static
scan) and adds that column.  The coverage test (tests/test_rbac_route_coverage.py) is what enforces the policies;
this table is for reading them.
"""
import argparse
import contextlib
import io
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", help="JSON inventory of the checks each route did before F4")
    args = parser.parse_args()
    with contextlib.redirect_stdout(io.StringIO()):  # the app prints start-up banners
        from backend.main import app
        from backend.utilities.rbac import coverage
    rows = coverage.inventory(app)
    before = {}
    if args.before:
        with open(args.before, encoding="utf-8") as fh:
            for row in json.load(fh):
                before[(",".join(row["methods"]), row["path"])] = ", ".join(row["checks"]) or "none"
    head = "| Method | Path | Handler | " + ("Checks before F4 (handler) | " if before else "") + "Policy | Lowest role | Audited |"
    out = [head, "|" + "---|" * (head.count("|") - 1)]
    for r in sorted(rows, key=lambda r: (r["path"], r["methods"])):
        cells = [r["methods"], f"`{r['path']}`", f"`{r['handler']}`"]
        if before:
            cells.append(before.get((r["methods"], r["path"]), "new route"))
        machine = r["kind"] == "machine"
        cells += [r["policy"] if machine else (r["permission"] or r["policy"]),
                  f"machine (creator {r['min_role']}+)" if machine and r["min_role"] else
                  (r["min_role"] or ("superuser" if r["kind"] == "platform_admin" else r["kind"])),
                  "yes" if r["audited"] else ""]
        out.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    kinds: dict[str, int] = {}
    for r in rows:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    summary = ", ".join(f"{k}: {v}" for k, v in sorted(kinds.items()))
    sys.stdout.write(f"{len(rows)} routes ({summary}).\n\n" + "\n".join(out) + "\n")
    violations = coverage.violations(app)
    if violations:
        sys.stdout.write("\nViolations:\n" + "\n".join(f"- {v}" for v in violations) + "\n")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
