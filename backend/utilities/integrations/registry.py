"""The integration kinds: config model, secrets, which events each can receive, and how it sends and tests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel

from backend.new_models import TeamIntegration
from backend.utilities.integrations import oscal, servicenow, siem, webhook
from backend.utilities.integrations.base import Context, Outcome
from backend.utilities.integrations.events import EVENT_KINDS

ALL_FORWARDED = tuple(k for k in EVENT_KINDS)


@dataclass(frozen=True)
class Spec:
    kind: str
    label: str
    model: type[BaseModel]
    secret_fields: Callable[[Any], set[str]]
    # changing any of these clears the stored secret unless it is re-entered: a token never follows a new address
    where_fields: tuple[str, ...]
    allowed_events: tuple[str, ...]
    default_events: tuple[str, ...]
    batch: int
    send: Callable[[Context, list[dict[str, Any]]], list[Outcome]]
    test: Callable[[Context, dict[str, Any]], Outcome]


def _syslog_test(ctx: Context, event: dict[str, Any]) -> Outcome:
    """TCP / TLS: passed when the receiver closed cleanly after the event. UDP: ``confirmed=False`` (nothing comes
    back, not even from a port with no listener), so the test reports "sent (unconfirmed)", not "passed"."""
    return siem.syslog_send(ctx, [event])[0]


def _hec_test(ctx: Context, event: dict[str, Any]) -> Outcome:
    return siem.hec_send(ctx, [event])[0]


SPECS: dict[str, Spec] = {
    "servicenow": Spec(
        "servicenow", "ServiceNow", servicenow.ServiceNowConfig,
        lambda c: {"password"} if c.auth == "basic" else {"client_secret"},
        ("instance_url", "auth", "username", "client_id", "ca_pem"),
        servicenow.OPEN_KINDS + servicenow.CLOSE_KINDS, ("opened", "resolved"), 25, servicenow.send, servicenow.test),
    "syslog": Spec(
        "syslog", "Syslog (SIEM)", siem.SyslogConfig, lambda c: set(), (), ALL_FORWARDED, ALL_FORWARDED, 200,
        siem.syslog_send, _syslog_test),
    "splunk_hec": Spec(
        "splunk_hec", "Splunk HEC", siem.SplunkHecConfig, lambda c: {"token"}, ("url", "ca_pem"), ALL_FORWARDED,
        ALL_FORWARDED, 200, siem.hec_send, _hec_test),
    "webhook": Spec(
        "webhook", "Signed webhook", webhook.WebhookConfig, lambda c: {"signing_secret"}, ("url", "ca_pem"),
        ALL_FORWARDED, ALL_FORWARDED, 50, webhook.send, webhook.test),
    "oscal": Spec(
        "oscal", "GRC (OSCAL push)", oscal.OscalPushConfig, lambda c: {"signing_secret"}, ("url", "ca_pem"),
        ("scan_finished",), ("scan_finished",), 5, oscal.send, oscal.test),
}
KINDS = tuple(SPECS)


def validate_config(kind: str, config: dict[str, Any]) -> BaseModel:
    """Raises pydantic.ValidationError / ValueError. Checks the subscribed events against the kind."""
    spec = SPECS[kind]
    cfg = spec.model.model_validate(config)
    events = getattr(cfg, "events", None)
    if events is not None:
        bad = [e for e in events if e not in spec.allowed_events]
        if bad:
            raise ValueError(f"events: {bad[0]} cannot be sent to {spec.label}")
        cfg.events = sorted(set(events), key=spec.allowed_events.index)  # type: ignore[attr-defined]
    return cfg


def subscribed_kinds(integration: TeamIntegration) -> tuple[str, ...]:
    spec = SPECS.get(integration.kind)
    if spec is None:
        return ()
    chosen = (integration.config or {}).get("events")
    if not isinstance(chosen, list):
        return spec.default_events
    return tuple(e for e in chosen if e in spec.allowed_events)
