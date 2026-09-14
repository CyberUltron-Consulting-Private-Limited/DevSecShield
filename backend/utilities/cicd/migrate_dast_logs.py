"""Move historical DAST cicd_logs off SAST integrations onto a DAST integration."""

from __future__ import annotations

from rich.console import Console
from sqlmodel import Session, select

from backend.get_db import get_db, get_mongo_client_db
from backend.new_models import CicdIntegration

console = Console()


def dast_logs_on_sast_query(sast_ids: list[int]) -> dict:
    values: list[int | str] = []
    for integration_id in sast_ids:
        values.extend([integration_id, str(integration_id)])
    return {
        "ci_cd_integration_id": {"$in": values},
        "scan_settings_metadata.scan_type": "dast",
    }


def migrate_dast_logs(collection, sast_ids: list[int], target_id: int) -> int:
    if not sast_ids or target_id is None:
        return 0
    result = collection.update_many(
        dast_logs_on_sast_query(sast_ids),
        {"$set": {"ci_cd_integration_id": target_id}},
    )
    return int(getattr(result, "modified_count", 0) or 0)


def migrate_dast_cicd_logs_for_team(session: Session, mongo_db, team_id: int) -> int:
    dast_rows = session.exec(
        select(CicdIntegration)
        .where(CicdIntegration.team_id == team_id)
        .where(CicdIntegration.scan_type == "dast")
        .order_by(CicdIntegration.id)
    ).all()
    if not dast_rows:
        return 0
    sast_ids = [
        row.id
        for row in session.exec(
            select(CicdIntegration)
            .where(CicdIntegration.team_id == team_id)
            .where(CicdIntegration.scan_type == "sast")
        ).all()
        if row.id is not None
    ]
    moved = migrate_dast_logs(mongo_db["cicd_logs"], sast_ids, dast_rows[0].id)
    if moved:
        console.print(
            f"Migrated {moved} DAST cicd_logs for team {team_id} onto integration {dast_rows[0].id}",
            style="bold green",
        )
    return moved


def migrate_all_dast_cicd_logs() -> int:
    engine = get_db()
    mongo_db = get_mongo_client_db()
    total = 0
    with Session(engine) as session:
        team_ids = {
            row.team_id
            for row in session.exec(
                select(CicdIntegration).where(CicdIntegration.scan_type == "dast")
            ).all()
            if row.team_id is not None
        }
        for team_id in sorted(team_ids):
            total += migrate_dast_cicd_logs_for_team(session, mongo_db, team_id)
    return total
