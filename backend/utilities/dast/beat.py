"""DAST profile beat sidecar: due profiles -> run_dast_from_profile."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from rich.console import Console
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import DastScanProfile
from backend.utilities.dast.dispatch import DispatchResult, run_dast_from_profile
from backend.utilities.dast.schedule import compute_next_run_at, mirror_from_config, normalize_schedule_config

console = Console()
TICK_SECONDS = 60


def _due_profile_ids(engine, now: datetime) -> list[int]:
    with Session(engine) as session:
        query = select(DastScanProfile).where(
            DastScanProfile.enabled == True,  # noqa: E712
            DastScanProfile.next_run_at != None,  # noqa: E711
            DastScanProfile.next_run_at <= now,
        )
        dialect_name = ""
        try:
            dialect_name = engine.dialect.name
        except Exception:
            pass
        if dialect_name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        rows = session.exec(query).all()
        return [int(row.id) for row in rows if row.id is not None]


def _advance_schedule(profile: DastScanProfile, now: datetime) -> None:
    cfg = normalize_schedule_config(
        profile.schedule_kind,
        profile.schedule_time,
        profile.schedule_weekday,
        profile.schedule_config,
    )
    if cfg.get("kind") == "once":
        cfg["kind"] = "off"
        kind, time_s, weekday = mirror_from_config(cfg)
        profile.schedule_config = cfg
        profile.schedule_kind = kind
        profile.schedule_time = time_s
        profile.schedule_weekday = weekday
        profile.next_run_at = None
        return
    profile.next_run_at = compute_next_run_at(
        profile.schedule_kind,
        profile.schedule_time,
        profile.schedule_weekday,
        now=now,
        config=cfg,
    )
    profile.schedule_config = cfg


def tick(*, engine=None, now: datetime | None = None) -> list[DispatchResult]:
    engine = engine or get_db()
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    results: list[DispatchResult] = []
    for profile_id in _due_profile_ids(engine, now):
        try:
            result = run_dast_from_profile(profile_id, trigger="schedule", engine=engine)
            results.append(result)
            console.print(
                f"DAST schedule tick profile={profile_id} status={result.status} scan_id={result.scan_id}",
                style="bold green",
            )
        except Exception as exc:
            console.print(f"DAST schedule tick failed profile={profile_id}: {exc}", style="bold yellow")
        with Session(engine) as session:
            profile = session.get(DastScanProfile, profile_id)
            if profile is None:
                continue
            _advance_schedule(profile, now)
            profile.last_updated = now
            session.add(profile)
            session.commit()
    return results


def main() -> None:
    console.print("DAST scheduler sidecar started (60s tick)", style="bold green")
    while True:
        try:
            tick()
        except Exception as exc:
            console.print(f"DAST scheduler tick error: {exc}", style="bold red")
        time.sleep(TICK_SECONDS)


if __name__ == "__main__":
    main()
