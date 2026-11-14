"""Request bodies and response shapes of the fleet routes (contract section 3)."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.utilities.cbom_sources.common import NAME_RE, iso_z
from backend.utilities.cbom_sources.fleet.inventory_sources import MAX_API_TARGETS
from backend.utilities.cbom_sources.fleet.models import CbomFleetPolicy, CbomInventorySource, CbomInventoryTarget
from backend.utilities.cbom_sources.fleet.policy import validate_action, validate_selector


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _name(value: str) -> str:
    if not NAME_RE.match(value):
        raise ValueError("name: letters, digits, spaces and . _ - (64 at most), starting with a letter or digit")
    return value


class ImportBody(_Strict):
    format: Literal["csv", "json"]
    content: str = Field(max_length=10 * 1024 * 1024)
    inventory_source_id: int | None = Field(default=None, ge=1, le=2_147_483_647)
    dry_run: bool = False


class ApiTargetsBody(_Strict):
    source_name: str = Field(min_length=1, max_length=64)
    targets: list[dict[str, Any]] = Field(max_length=MAX_API_TARGETS)

    @model_validator(mode="after")
    def _check(self) -> "ApiTargetsBody":
        _name(self.source_name)
        return self


class InventorySourceCreate(_Strict):
    kind: Literal["aws", "csv", "json", "api"]
    name: str = Field(min_length=1, max_length=64)
    config: dict[str, Any] = Field(default_factory=dict)
    sync_every_min: int = Field(default=60, ge=15, le=7 * 24 * 60)
    enabled: bool = True

    @model_validator(mode="after")
    def _check(self) -> "InventorySourceCreate":
        _name(self.name)
        return self


class InventorySourceUpdate(_Strict):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    config: dict[str, Any] | None = None
    sync_every_min: int | None = Field(default=None, ge=15, le=7 * 24 * 60)
    enabled: bool | None = None
    expected_version: int | None = None

    @model_validator(mode="after")
    def _check(self) -> "InventorySourceUpdate":
        if self.name is not None:
            _name(self.name)
        return self


class PolicyCreate(_Strict):
    name: str = Field(min_length=1, max_length=64)
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=1_000_000)
    selector: dict[str, Any] = Field(default_factory=dict)
    action: dict[str, Any]

    @model_validator(mode="after")
    def _check(self) -> "PolicyCreate":
        given = set(self.model_fields_set)
        _name(self.name)
        self.selector = validate_selector(self.selector)
        self.action = validate_action(self.action)
        self.__pydantic_fields_set__ = given  # normalising is not setting: an edit preview fills what the body left out
        return self


class PolicyUpdate(_Strict):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=1_000_000)
    selector: dict[str, Any] | None = None
    action: dict[str, Any] | None = None
    expected_version: int | None = None

    @model_validator(mode="after")
    def _check(self) -> "PolicyUpdate":
        if self.name is not None:
            _name(self.name)
        if self.selector is not None:
            self.selector = validate_selector(self.selector)
        if self.action is not None:
            self.action = validate_action(self.action)
        return self


class PreviewBody(_Strict):
    """``policy_id`` alone: a saved policy.  ``policy`` alone: a new draft.  Both: an edit of that saved policy (the
    draft replaces it in the preview and keeps its id, so ties break as they will once it is saved)."""
    policy: PolicyCreate | None = None
    policy_id: int | None = Field(default=None, ge=1, le=2_147_483_647)

    @model_validator(mode="after")
    def _check(self) -> "PreviewBody":
        if self.policy is None and self.policy_id is None:
            raise ValueError("send a draft policy, a policy_id, or both (an edit)")
        return self


def public_inventory_source(s: CbomInventorySource, target_count: int | None = None) -> dict[str, Any]:
    return {"id": s.id, "kind": s.kind, "name": s.name, "config": dict(s.config or {}), "enabled": s.enabled,
            "sync_every_min": s.sync_every_min, "last_sync_at": iso_z(s.last_sync_at),
            "last_sync_status": s.last_sync_status, "last_sync_summary": dict(s.last_sync_summary or {}),
            "coverage": dict(s.coverage or {}), "syncing": s.last_sync_status in ("queued", "running"),
            "target_count": target_count, "owner_user_id": s.owner_user_id, "row_version": s.row_version,
            "created_at": iso_z(s.created_at), "last_updated": iso_z(s.last_updated)}


def public_target(t: Any, decision: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"id": t.id, "inventory_source_id": t.inventory_source_id, "external_id": t.external_id, "kind": t.kind,
            "address": t.address, "addresses": list(t.addresses or []), "hostname": t.hostname,
            "tags": dict(t.tags or {}), "account_id": t.account_id, "region": t.region, "platform": t.platform,
            "handles": dict(t.handles or {}), "attributes": dict(getattr(t, "attributes", None) or {}),
            "first_seen_at": iso_z(getattr(t, "first_seen_at", None)), "last_seen_at": iso_z(getattr(t, "last_seen_at", None)),
            "missing_since": iso_z(t.missing_since), "deleted_at": iso_z(getattr(t, "deleted_at", None)),
            "managed_source_id": t.managed_source_id,
            # its managed-source change waits for a busy source (the fleet worker retries it)
            "pending": getattr(t, "pending_since", None) is not None,
            "pending_since": iso_z(getattr(t, "pending_since", None)),
            "decision": decision if decision is not None else dict(t.decision or {})}


def public_policy(p: CbomFleetPolicy, matched: int | None = None) -> dict[str, Any]:
    return {"id": p.id, "name": p.name, "enabled": p.enabled, "priority": p.priority, "selector": dict(p.selector or {}),
            "action": dict(p.action or {}), "owner_user_id": p.owner_user_id, "row_version": p.row_version,
            "matched_targets": matched, "created_at": iso_z(p.created_at), "last_updated": iso_z(p.last_updated)}


__all__ = ["ApiTargetsBody", "ImportBody", "InventorySourceCreate", "InventorySourceUpdate", "PolicyCreate",
           "PolicyUpdate", "PreviewBody", "public_inventory_source", "public_policy", "public_target",
           "CbomInventoryTarget"]
