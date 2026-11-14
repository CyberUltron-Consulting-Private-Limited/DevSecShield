"""Scan policies per repository group: which policy a repository falls under, and when a policy's schedule fires.

* ``winning_policy`` is deterministic: a repository's pinned policy wins (when it exists and is enabled); otherwise
  the enabled policies are tried in (position, id) order and the first whose selector matches wins. The order of the
  list it is given never matters.
* ``ScheduleSpec``: off, daily, weekly (weekday 0 = Monday) or monthly (day 1-28) at HH:MM in an IANA time zone.
  ``next_run`` is the first slot strictly after a moment (naive UTC in, naive UTC out; DST handled by zoneinfo).
* ``fire_due`` claims each due slot with a compare-and-set on ``next_run_at`` (a slot fires once, whatever the number
  of schedulers) and starts a run over the policy's repositories; a run the team cannot afford is skipped and the
  policy says why.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import update
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from backend.utilities.scm import filters as F
from backend.utilities.scm.common import log
from backend.utilities.scm.models import ScmScanPolicy


@dataclass
class PolicyView:
    id: int
    position: int
    enabled: bool
    selector: dict[str, Any]
    products: list[str]
    branch: str = ""
    on_push: bool = False
    options: dict[str, Any] = field(default_factory=dict)
    name: str = ""
    owner_user_id: int | None = None

    @classmethod
    def of(cls, row: ScmScanPolicy) -> "PolicyView":
        return cls(id=row.id or 0, position=row.position, enabled=row.enabled, selector=dict(row.selector or {}),
                   products=list(row.products or []), branch=row.branch or "", on_push=row.on_push,
                   options=dict(row.options or {}), name=row.name, owner_user_id=row.owner_user_id)


def _selector(policy: PolicyView) -> F.RepoFilters:
    try:
        return F.parse(policy.selector)
    except ValueError:
        return F.RepoFilters(include_names=["\x00never"])  # an unreadable selector matches nothing


def winning_policy(repo: Mapping[str, Any], policies: Sequence[PolicyView],
                   pinned_id: int | None = None) -> tuple[PolicyView | None, str]:
    enabled = sorted((p for p in policies if p.enabled), key=lambda p: (p.position, p.id))
    if pinned_id is not None:
        for p in enabled:
            if p.id == pinned_id:
                return p, "pinned"
    for p in enabled:
        if F.evaluate(repo, _selector(p))[0]:
            return p, "selector"
    return None, "none"


def team_policies(session: Session, team_id: int) -> list[PolicyView]:
    rows = session.exec(select(ScmScanPolicy).where(ScmScanPolicy.team_id == team_id)).all()
    return [PolicyView.of(r) for r in rows]


# ---------------------------------------------------------------------------- schedules
class ScheduleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    frequency: Literal["off", "daily", "weekly", "monthly"] = "off"
    time_of_day: str = "02:00"
    weekday: int | None = Field(default=None, ge=0, le=6)
    monthday: int | None = Field(default=None, ge=1, le=28)
    timezone: str = "UTC"

    @field_validator("time_of_day")
    @classmethod
    def _hhmm(cls, value: str) -> str:
        parts = value.split(":")
        if len(parts) != 2 or not all(p.isdigit() and len(p) == 2 for p in parts) \
                or not (0 <= int(parts[0]) <= 23 and 0 <= int(parts[1]) <= 59):
            raise ValueError("time of day must be HH:MM (00:00 to 23:59)")
        return value

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("time zone must be an IANA name such as Asia/Kolkata or UTC") from None
        return value

    @model_validator(mode="after")
    def _days(self) -> "ScheduleSpec":
        if self.frequency == "weekly" and self.weekday is None:
            self.weekday = 6
        if self.frequency == "monthly" and self.monthday is None:
            self.monthday = 1
        return self


def parse_schedule(data: Mapping[str, Any] | None) -> ScheduleSpec:
    return ScheduleSpec.model_validate(dict(data or {}))


def next_run(spec: ScheduleSpec, after: dt.datetime) -> dt.datetime | None:
    """The first slot strictly after ``after`` (naive UTC), as naive UTC; None when the schedule is off."""
    if spec.frequency == "off":
        return None
    tz = ZoneInfo(spec.timezone)
    hour, minute = (int(x) for x in spec.time_of_day.split(":"))
    local = after.replace(tzinfo=dt.timezone.utc).astimezone(tz)
    day = local.date()
    for offset in range(0, 70):
        d = day + dt.timedelta(days=offset)
        if spec.frequency == "weekly" and d.weekday() != spec.weekday:
            continue
        if spec.frequency == "monthly" and d.day != spec.monthday:
            continue
        slot = dt.datetime(d.year, d.month, d.day, hour, minute, tzinfo=tz)
        utc = slot.astimezone(dt.timezone.utc).replace(tzinfo=None)
        if utc > after:
            return utc
    return None


def fire_due(engine: Engine, now: dt.datetime, *, limit: int = 50) -> list[dict[str, Any]]:
    """Fire every due policy slot once; returns what each fired slot did."""
    from backend.utilities.scm import queue as Q

    with Session(engine) as session:
        due = session.exec(select(ScmScanPolicy.id, ScmScanPolicy.next_run_at)
                           .where(ScmScanPolicy.enabled == True, ScmScanPolicy.next_run_at != None,  # noqa: E711,E712
                                  ScmScanPolicy.next_run_at <= now)
                           .order_by(ScmScanPolicy.next_run_at).limit(limit)).all()
    fired: list[dict[str, Any]] = []
    for policy_id, slot in due:
        with Session(engine) as session:
            policy = session.get(ScmScanPolicy, policy_id)
            if policy is None:
                continue
            try:
                following = next_run(parse_schedule(policy.schedule), now)
            except ValueError:
                following = None
            won = session.exec(update(ScmScanPolicy)  # type: ignore[call-overload]
                               .where(ScmScanPolicy.id == policy_id, ScmScanPolicy.next_run_at == slot)
                               .values(next_run_at=following, last_fired_at=now)
                               .execution_options(synchronize_session=False)).rowcount == 1
            session.commit()
            if not won:
                continue
            team_id, owner = policy.team_id, policy.owner_user_id
        outcome: dict[str, Any] = {"policy_id": policy_id, "team_id": team_id, "slot": slot.isoformat()}
        try:
            run = Q.create_run(engine, team_id, owner, trigger="schedule", policy_id=policy_id, expected_credits=None,
                               client_request_id=f"schedule-{policy_id}-{slot.strftime('%Y%m%dT%H%M')}", now=now)
            outcome.update(status="queued", queued=run["queued"], run_id=run["run_id"], credits=run["credits"],
                           message=f"Queued {run['queued']} scans for {run['credits']:g} credits")
        except Q.InsufficientCredits as exc:
            outcome.update(status="skipped", queued=0, run_id=None,
                           message=f"Skipped: the run needs {exc.estimate['credits']:g} credits and the team has "
                                   f"{exc.estimate['balance']:g}")
        except Q.NothingToScan:
            outcome.update(status="skipped", queued=0, run_id=None,
                           message="Skipped: no repository in scope falls under this policy (or all are queued)")
        with Session(engine) as session:
            policy = session.get(ScmScanPolicy, policy_id)
            if policy is not None:
                policy.last_status = outcome["status"]
                policy.last_message = outcome["message"][:500]
                policy.last_run_id = outcome.get("run_id") or policy.last_run_id
                session.add(policy)
                session.commit()
        log("schedule fired", policy=policy_id, team=team_id, status=outcome["status"], queued=outcome.get("queued"))
        fired.append(outcome)
    return fired


__all__ = ["PolicyView", "ScheduleSpec", "fire_due", "next_run", "parse_schedule", "team_policies", "winning_policy"]
