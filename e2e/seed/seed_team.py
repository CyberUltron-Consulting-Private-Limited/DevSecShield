#!/usr/bin/env python3
"""Seed the dss-e2e stack with the plan's Appendix-B world (plan 7.4 step 3).

Runs inside the backend image (compose service ``seed``, profile ``seed``) on the project network, with
the same ``.env.e2e`` as the backend, and talks to postgres and mongo through the PRODUCT's own helpers:

* users, teams, memberships and scans are stored with the real SQLModel classes (``backend.new_models``)
  against the Alembic-migrated schema; passwords go through ``auth_utils.get_hashed_password`` so the
  real ``POST /login`` accepts them;
* findings go through the real ``create_findings_in_mongo_db`` for every success scan, exactly as
  ``get_status_and_update_db`` does for a finished worker task;
* ``scan_data`` is the run-object ``scan_trees.py`` produced from the real trees (or the committed
  Tier-B legacy file); nothing about it is synthesised here, except the optional perf team.

What it does, in order (any failure stops the seed with a non-zero exit code):

1. read the environment and the scan outputs; refuse a database that already holds teams / users / scans
   (the stack is built from fresh volumes for every run);
2. build the planned scans (``plan.planned_scans``) and verify Appendix B with the INDEPENDENT oracle
   (``oracle_check.verify``: plain code, no product aggregator, plus DER fingerprints of the certificate
   files) against ``fixtures/expected.json`` BEFORE storing anything;
3. insert teams, users, memberships, one-time codes and scans - with explicit ids, so the database ids ARE
   the Appendix-B scan numbers (``created_at = now - age_days``, ``task_id = None``, ``scan_metadata``
   shaped like ``backend/utilities/db/metadata.py``);
4. call ``create_findings_in_mongo_db`` for every success scan and re-count the stored documents;
5. optional (``E2E_SEED_PERF`` set): the "Perf Team" - 200 scans over 40 sources whose certificates are
   real run-object certificates renamed to be unique (about 1 000 unique certificates);
6. write ``$E2E_WORK_DIR/seed.json`` (ids, personas with their throw-away credentials, scan dates) for
   the Playwright specs, mode 600, and print a summary without any secret.

Teams: 1 "E2E Demo Team" (admin persona), 2 "Other Team" (canary certificate, other persona),
3 "Empty Team" (empty persona, no scans), 4 "Perf Team" (admin persona, optional).

Personas log in through the real ``/login``: the admin's one-time code is the backend's
``LOCAL_DEV_VERIFICATION_CODE`` (its email IS ``LOCAL_DEV_VERIFICATION_EMAIL``; the backend only accepts it with
``DSS_DEV_MODE=1``, which ``.env.e2e`` sets and no other deployment does); the other personas get a
one-time code row in ``verificationcode`` valid for 24 hours (a successful login consumes it, so the specs
cache the tokens they obtain).

Environment (set by the compose service / ``.env.e2e``):

``E2E_WORK_DIR``               work directory (``/work``): reads ``out/*.scan_data.json`` and ``trees/``
``E2E_LEGACY_SCAN_DATA``       the committed Tier-B run-object
``E2E_ADMIN_/OTHER_/EMPTY_``   ``EMAIL`` and ``PASSWORD`` of the three personas
``LOCAL_DEV_VERIFICATION_*``   the admin's one-time code
``E2E_SEED_PERF``              any non-empty value except ``0``: also seed the Perf Team
``E2E_SEED_NOW``               ISO UTC timestamp to use as "now" (dry runs only)
``E2E_EXPECTED_JSON``          override the path of ``expected.json``

Exit codes: 2 bad environment or missing input, 3 database not empty / id mismatch, 4 Appendix B not
reproduced, 5 findings could not be stored or counted.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import oracle_check  # noqa: E402
import plan  # noqa: E402

EXIT_ENV, EXIT_DB, EXIT_ORACLE, EXIT_FINDINGS = 2, 3, 4, 5
OTP_VALID_HOURS = 24
PERF_SOURCES, PERF_VERSIONS, PERF_UNIQUE_CERTS_PER_SCAN, PERF_FIRST_ID = 40, 5, 5, 101


class SeedError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Config:
    work_dir: Path
    legacy_path: Path
    expected_path: Path
    now: datetime  # timezone-aware UTC, whole seconds
    personas: dict[str, dict[str, str]]  # persona -> {email, password}
    admin_otp: str
    perf: bool = False
    seed_json: Path | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def out_dir(self) -> Path:
        return self.work_dir / "out"

    @property
    def trees_dir(self) -> Path:
        return self.work_dir / "trees"


def log(message: str) -> None:
    print(f"[seed] {message}", flush=True)


# ---------------------------------------------------------------------------------------------
# configuration and inputs
# ---------------------------------------------------------------------------------------------
def config_from_env(env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    problems: list[str] = []

    def need(key: str) -> str:
        value = (env.get(key) or "").strip()
        if not value:
            problems.append(f"{key} is not set")
        return value

    personas: dict[str, dict[str, str]] = {}
    for name, info in plan.PERSONAS.items():
        email, password = need(f"{info['env']}_EMAIL"), need(f"{info['env']}_PASSWORD")
        if password and not 8 <= len(password) <= 128:
            problems.append(
                f"{info['env']}_PASSWORD has {len(password)} characters, but new passwords are 8 to 128"
            )
        personas[name] = {"email": email, "password": password}
    admin_otp = need("LOCAL_DEV_VERIFICATION_CODE")
    otp_email = (env.get("LOCAL_DEV_VERIFICATION_EMAIL") or "").strip().lower()
    if personas["admin"]["email"] and otp_email != personas["admin"]["email"].lower():
        problems.append("LOCAL_DEV_VERIFICATION_EMAIL must equal E2E_ADMIN_EMAIL (the admin's one-time code)")
    emails = [p["email"].lower() for p in personas.values() if p["email"]]
    if len(set(emails)) != len(emails):
        problems.append("the three persona emails must be distinct")
    if problems:
        raise SeedError(EXIT_ENV, "environment: " + "; ".join(problems))

    if env.get("E2E_SEED_NOW"):
        now = oracle_check.parse_iso(env["E2E_SEED_NOW"])
    else:
        now = datetime.now(timezone.utc).replace(microsecond=0)
    work = Path(env.get("E2E_WORK_DIR", "/work"))
    expected = Path(env.get("E2E_EXPECTED_JSON") or HERE.parent / "fixtures" / "expected.json")
    legacy = Path(env.get("E2E_LEGACY_SCAN_DATA", "/e2e/backend-fixtures/cbom_export_scandata.json"))
    perf_flag = (env.get("E2E_SEED_PERF") or "").strip().lower()
    return Config(
        work_dir=work,
        legacy_path=legacy,
        expected_path=expected,
        now=now,
        personas=personas,
        admin_otp=admin_otp,
        perf=perf_flag not in ("", "0", "false", "no"),
        seed_json=work / "seed.json",
    )


def load_json(path: Path, what: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SeedError(EXIT_ENV, f"cannot read {what} ({path}): {exc}") from exc


def load_runs(cfg: Config) -> dict[str, dict[str, Any]]:
    runs = {}
    for tree in plan.TREES:
        runs[tree] = load_json(cfg.out_dir / f"{tree}.scan_data.json", f"scan output of tree {tree}")
        if not isinstance(runs[tree], dict) or "results" not in runs[tree]:
            raise SeedError(EXIT_ENV, f"scan output of tree {tree} is not a CBOM run-object")
    return runs


def tree_fingerprints(cfg: Config) -> dict[int, dict[str, str]]:
    """DER SHA-256 of every certificate FILE, per scan id (independent evidence for the oracle)."""
    fps: dict[int, dict[str, str]] = {}
    for item in plan.SEED:
        if item.payload[0] == "tree":
            tree = cfg.trees_dir / item.payload[1]
            if not tree.is_dir():
                raise SeedError(EXIT_ENV, f"tree directory missing: {tree}")
            fps[item.key] = oracle_check.tree_cert_fingerprints(tree)
    return fps


# ---------------------------------------------------------------------------------------------
# the independent oracle gate
# ---------------------------------------------------------------------------------------------
def verify_world(cfg: Config, scans: list[dict[str, Any]], file_fps: dict[int, dict[str, str]]) -> int:
    expected = load_json(cfg.expected_path, "expected.json")
    as_of = cfg.now.date()
    problems = oracle_check.verify(scans, as_of, expected, file_fps=file_fps)
    problems += oracle_check.canary_confinement(scans, expected.get("canary_owner_scan", {}))
    # The freshness guard: fixture certificates age; stop before the oracle silently goes stale.
    last_good = expected.get("freshness", {}).get("oracle_valid_through")
    if last_good and as_of.isoformat() > last_good:
        problems.append(
            f"expected.json is stale: the fixture certificates age past {last_good}, today is {as_of} "
            "(re-derive bands and order with `python3 e2e/seed/oracle_check.py --print`)"
        )
    if problems:
        raise SeedError(
            EXIT_ORACLE,
            "Appendix B is NOT reproduced by the scanned data:\n  - " + "\n  - ".join(problems),
        )
    derived = oracle_check.derive(scans, as_of, file_fps=file_fps)
    log(
        "oracle: Appendix B reproduced - "
        f"{derived['included']} of {derived['eligible']} eligible scans, {derived['sources']} sources, "
        f"{derived['cert_raw']} certificate occurrences -> {derived['cert_unique']} unique "
        f"(DER fingerprints agree: {derived['cert_unique_by_file_fingerprint']}), "
        f"{derived['occurrences']} current assets, readiness {derived['readiness']}%, "
        f"grade {derived['risk']['grade']}, bands {derived['bands']}"
    )
    return derived["cert_unique"]


# ---------------------------------------------------------------------------------------------
# perf team
# ---------------------------------------------------------------------------------------------
def build_perf_scans(base_run: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    """200 scans over 40 sources: a real certificate-heavy run-object, certificates renamed per scan.

    The first ``PERF_UNIQUE_CERTS_PER_SCAN`` certificates of each scan get a name that is unique to
    (source, version, position); the rest keep their real names, so they de-duplicate across the whole
    team.  Unique certificates: 40 x 5 x 5 + (12 - 5) = 1 007; current ones (latest scan of every
    source): 40 x 5 + 7 = 207.
    """
    certs = [
        c for c in base_run["cbom_json"]["components"]
        if (c.get("cryptoProperties") or {}).get("assetType") == "certificate"
    ]  # fmt: skip
    names = [
        next(p["value"] for p in c["properties"] if p["name"] == "crypto:subjectName") for c in certs
    ]
    base_text = json.dumps(base_run, sort_keys=True, separators=(",", ":"))
    scans: list[dict[str, Any]] = []
    scan_id = PERF_FIRST_ID
    for source in range(PERF_SOURCES):
        url = f"https://github.com/e2e-perf/repo-{source:02d}"
        for version in range(PERF_VERSIONS):
            text = base_text
            for position, old in enumerate(names[:PERF_UNIQUE_CERTS_PER_SCAN]):
                text = text.replace(old, f"perf-s{source:02d}v{version}c{position}.perf.test")
            age = (PERF_VERSIONS - version) * 15 + (source % 7)
            created = now - timedelta(days=age, minutes=source)
            scans.append(
                {
                    "id": scan_id,
                    "team_id": plan.TEAM_PERF,
                    "scan_type": "cbom",
                    "title": f"PERF-repo-{source:02d} #{version + 1}",
                    "status": "success",
                    "age_days": age,
                    "created_at": plan.iso_z(created),
                    "last_updated": plan.iso_z(created + timedelta(minutes=2)),
                    "scan_metadata": plan.repo_meta(url),
                    "scan_data": json.loads(text),
                }
            )
            scan_id += 1
    return scans


# ---------------------------------------------------------------------------------------------
# database
# ---------------------------------------------------------------------------------------------
def naive_utc(iso: str) -> datetime:
    return oracle_check.parse_iso(iso).replace(tzinfo=None)


def _scan_rows(scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(scans, key=lambda s: s["id"])


def insert_world(
    engine: Any,
    cfg: Config,
    scans: list[dict[str, Any]],
    otps: dict[str, str],
) -> None:
    from sqlmodel import Session, select

    from backend.new_models import Scan, Team, TeamMembership, User, VerificationCode
    from backend.utilities.auth.auth_utils import get_hashed_password

    now_naive = cfg.now.replace(tzinfo=None)
    with Session(engine) as session:
        busy = {
            "team": len(session.exec(select(Team.id)).all()),
            "user": len(session.exec(select(User.id)).all()),
            "scan": len(session.exec(select(Scan.id)).all()),
        }
        if any(busy.values()):
            raise SeedError(
                EXIT_DB,
                f"the database is not empty ({busy}): the E2E stack must start from fresh volumes "
                "(run e2e/scripts/teardown.sh, then start again)",
            )

        team_ids = {plan.TEAM_DEMO, plan.TEAM_OTHER, plan.TEAM_EMPTY}
        if cfg.perf:
            team_ids.add(plan.TEAM_PERF)
        for team_id in sorted(team_ids):
            session.add(
                Team(
                    id=team_id,
                    name=plan.TEAM_NAMES[team_id],
                    description=f"dss-e2e seed team {team_id}",
                    created_at=now_naive - timedelta(days=90),
                    credit_balance=1000.0,
                )
            )
        session.commit()

        for name, info in plan.PERSONAS.items():
            creds = cfg.personas[name]
            session.add(
                User(
                    id=info["id"],
                    email=creds["email"],
                    password=get_hashed_password(creds["password"]),
                    first_name=info["first"],
                    last_name=info["last"],
                    profile_photo=None,
                    session_active=True,
                    last_active=now_naive,
                    is_superuser=False,
                    default_team_id=info["default_team"],
                )
            )
        session.commit()

        for name, info in plan.PERSONAS.items():
            for team_id, role in info["teams"]:
                session.add(TeamMembership(team_id=team_id, user_id=info["id"], role=role))
            if name == "admin" and cfg.perf:
                session.add(TeamMembership(team_id=plan.TEAM_PERF, user_id=info["id"], role="admin"))
        session.commit()

        for name, code in otps.items():
            session.add(
                VerificationCode(
                    email=cfg.personas[name]["email"],
                    code=code,
                    created_at=now_naive,
                    expires_at=now_naive + timedelta(hours=OTP_VALID_HOURS),
                )
            )
        session.commit()

        owner_of = {plan.TEAM_DEMO: 1, plan.TEAM_OTHER: 2, plan.TEAM_PERF: 1}
        for scan in _scan_rows(scans):
            session.add(
                Scan(
                    id=scan["id"],
                    team_id=scan["team_id"],
                    owner_user_id=owner_of[scan["team_id"]],
                    credit_consumed=None,
                    scan_type=scan["scan_type"],
                    title=scan["title"],
                    task_id=None,
                    scan_metadata=scan["scan_metadata"],
                    scan_status=scan["status"],
                    created_at=naive_utc(scan["created_at"]),
                    last_updated=naive_utc(scan["last_updated"]),
                    scan_data=scan["scan_data"],
                    info=None,
                    integration_settings={},
                )
            )
            if len(session.new) >= 20:  # keep the transaction bounded (perf seeds hold ~19 MB of JSON)
                session.flush()
        session.commit()

        stored = [row for row in session.exec(select(Scan.id, Scan.team_id, Scan.scan_status)).all()]
    wanted = {s["id"] for s in scans}
    got = {row[0] for row in stored}
    if got != wanted:
        raise SeedError(EXIT_DB, f"stored scan ids {sorted(got)} differ from the plan {sorted(wanted)}")
    advance_sequences(engine)


def advance_sequences(engine: Any) -> None:
    """Explicit ids bypass the serial sequences: move them past the largest id (postgres only)."""
    if engine.dialect.name != "postgresql":
        return
    from sqlalchemy import text

    quote = engine.dialect.identifier_preparer.quote
    with engine.begin() as conn:
        for table in ("team", "user", "scan", "verificationcode"):
            quoted = quote(table)
            conn.execute(
                text(
                    f"SELECT setval(pg_get_serial_sequence(:t, 'id'), "
                    f"GREATEST((SELECT COALESCE(MAX(id), 1) FROM {quoted}), 1))"
                ),
                {"t": quoted},
            )


def store_findings(mongo_db: Any, scans: list[dict[str, Any]]) -> dict[int, int]:
    """The real ``create_findings_in_mongo_db`` for every success scan; returns stored counts."""
    from backend.utilities.celery.create_findings import create_findings_in_mongo_db

    counts: dict[int, int] = {}
    for scan in _scan_rows(scans):
        if str(scan["status"]).lower() != "success":
            continue
        data = scan["scan_data"]
        if not data:
            continue  # the real function returns early for an empty result, as it does in production
        try:
            create_findings_in_mongo_db(scan["id"], copy.deepcopy(data), scan["scan_type"], mongo_db)
        except Exception as exc:  # noqa: BLE001 - report which scan failed, then stop
            raise SeedError(EXIT_FINDINGS, f"findings for scan {scan['id']} could not be stored: {exc}") from exc
        stored = mongo_db["scan_findings"].count_documents({"scan_id": scan["id"]})
        rows = len(data.get("results") or []) if scan["scan_type"] in ("cbom", "ai_bom", "sbom_sca") else None
        if rows is not None and stored != rows:
            raise SeedError(
                EXIT_FINDINGS, f"scan {scan['id']}: {stored} findings stored, {rows} result rows expected"
            )
        counts[scan["id"]] = stored
    return counts


# ---------------------------------------------------------------------------------------------
# seed.json
# ---------------------------------------------------------------------------------------------
def build_seed_json(
    cfg: Config,
    scans: list[dict[str, Any]],
    otps: dict[str, str],
    findings: dict[int, int],
    unique_certs: int,
    perf_scans: list[dict[str, Any]],
) -> dict[str, Any]:
    summary_path = cfg.out_dir / "scan_summary.json"
    trees: dict[str, Any] = {}
    if summary_path.is_file():
        trees = load_json(summary_path, "scan_summary.json").get("trees", {})
    personas = {}
    for name, info in plan.PERSONAS.items():
        creds = cfg.personas[name]
        personas[name] = {
            "id": info["id"],
            "email": creds["email"],
            "password": creds["password"],
            "otp": cfg.admin_otp if name == "admin" else otps[name],
            "otp_permanent": name == "admin",
            "default_team_id": info["default_team"],
            "team_ids": [t for t, _role in info["teams"]] + ([plan.TEAM_PERF] if name == "admin" and cfg.perf else []),
        }
    demo = [s for s in scans if s["team_id"] == plan.TEAM_DEMO]
    return {
        "schema": 1,
        "seeded_at": plan.iso_z(cfg.now),
        "as_of": cfg.now.date().isoformat(),
        "teams": {
            "demo": {"id": plan.TEAM_DEMO, "name": plan.TEAM_NAMES[plan.TEAM_DEMO]},
            "other": {"id": plan.TEAM_OTHER, "name": plan.TEAM_NAMES[plan.TEAM_OTHER]},
            "empty": {"id": plan.TEAM_EMPTY, "name": plan.TEAM_NAMES[plan.TEAM_EMPTY]},
            **({"perf": {"id": plan.TEAM_PERF, "name": plan.TEAM_NAMES[plan.TEAM_PERF]}} if cfg.perf else {}),
        },
        "users": personas,
        "scans": {
            str(s["id"]): {
                "id": s["id"],
                "team_id": s["team_id"],
                "scan_type": s["scan_type"],
                "title": s["title"],
                "status": s["status"],
                "age_days": s["age_days"],
                "created_at": s["created_at"],
                "last_updated": s["last_updated"],
                "repo_url": s["scan_metadata"].get("repo_url"),
                "findings": findings.get(s["id"], 0),
            }
            for s in scans
            if s["team_id"] != plan.TEAM_PERF
        },
        "demo_scan_ids": [s["id"] for s in demo],
        "trees": trees,
        "oracle": {"checked": True, "cert_unique": unique_certs},
        "perf": (
            {
                "team_id": plan.TEAM_PERF,
                "scans": len(perf_scans),
                "sources": PERF_SOURCES,
                "versions": PERF_VERSIONS,
                "first_scan_id": perf_scans[0]["id"],
                "last_scan_id": perf_scans[-1]["id"],
                "unique_certs_total": PERF_SOURCES * PERF_VERSIONS * PERF_UNIQUE_CERTS_PER_SCAN + 7,
                "current_unique_certs": PERF_SOURCES * PERF_UNIQUE_CERTS_PER_SCAN + 7,
            }
            if perf_scans
            else None
        ),
    }


def write_private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------------------------
def run_seed(engine: Any, mongo_db: Any, cfg: Config) -> dict[str, Any]:
    """Everything after the environment is known; the engine and database may be fakes (dry runs)."""
    runs = load_runs(cfg)
    legacy = load_json(cfg.legacy_path, "the legacy Tier-B run-object")
    scans = plan.planned_scans(cfg.now, runs, legacy)
    file_fps = tree_fingerprints(cfg)
    unique_certs = verify_world(cfg, scans, file_fps)

    perf_scans = build_perf_scans(runs["identity-gateway"], cfg.now) if cfg.perf else []
    otps = {name: f"{secrets.randbelow(10**6):06d}" for name in plan.PERSONAS if name != "admin"}
    insert_world(engine, cfg, scans + perf_scans, otps)
    log(f"stored {len(scans)} planned scans" + (f" + {len(perf_scans)} perf scans" if perf_scans else ""))
    findings = store_findings(mongo_db, scans + perf_scans)
    log(f"findings stored for {len(findings)} success scans, {sum(findings.values())} documents")

    seed = build_seed_json(cfg, scans, otps, findings, unique_certs, perf_scans)
    if cfg.seed_json is not None:
        write_private_json(cfg.seed_json, seed)
    summarize(seed)
    return seed


def summarize(seed: dict[str, Any]) -> None:
    log(f"seeded at {seed['seeded_at']} (as_of {seed['as_of']})")
    for key, team in seed["teams"].items():
        count = sum(1 for s in seed["scans"].values() if s["team_id"] == team["id"])
        extra = f" (+{seed['perf']['scans']} perf scans)" if key == "perf" and seed.get("perf") else ""
        log(f"  team {team['id']} {team['name']!r}: {count} scans{extra}")
    for name, user in seed["users"].items():
        log(f"  user {user['id']} {name:<6} {user['email']} teams={user['team_ids']}")
    log("  scans (id, type, status, age, findings):")
    for scan in sorted(seed["scans"].values(), key=lambda s: s["id"]):
        log(
            f"    #{scan['id']:<3} team {scan['team_id']} {scan['scan_type']:<8} {scan['status']:<11} "
            f"{scan['age_days']:>3} d  {scan['findings']:>3} findings  {scan['title']}"
        )


def main() -> int:
    try:
        cfg = config_from_env()
        from backend.get_db import get_db, get_mongo_client_db

        run_seed(get_db(), get_mongo_client_db(), cfg)
    except SeedError as exc:
        print(f"[seed] FATAL ({exc.code}): {exc}", file=sys.stderr)
        return exc.code
    log("SEED OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
