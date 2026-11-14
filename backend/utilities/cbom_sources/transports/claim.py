"""F1.3 claim plugin (``secret_refs.PLUGINS``, contract section 3).  Loaded by F1.1's ``secret_refs`` when it exists;
nothing here imports F1.1.

For a source of kind ``awx_hosts`` / ``salt_hosts`` / ``ssm_hosts`` a job gets:
* ``config.transport``: the transport's non-secret config (or None with ``config.transport_problem`` when the transport
  is deleted, disabled, of another kind or another team, or the flag is off: the node / cloud worker then refuses the job
  with that sentence and never contacts anything);
* ``config.zs_collect``: ``{version, sha256}`` of the deployment's active, verified release (None when there is none);
* ``secrets``: the transport's secrets (AWX token, salt-api login), merged over the source's own (fleet sources store
  none).  An agent-mode node is never given these: ``secret_refs`` callers pass secrets only to agentless nodes and
  the cloud worker.
``version_input`` makes ``connection_version`` change when the transport (its row version) or the active release
changes, so queued jobs of an edited transport are not run with stale settings.
"""
from __future__ import annotations

from typing import Any

from backend.utilities.cbom_sources.crypto import decrypt_secrets
from backend.utilities.cbom_sources.transports.registry import (FLEET_KINDS, active_release, release_payload,
                                                                 usable_transport)


def _transport_for(session, source):
    kind = FLEET_KINDS.get(getattr(source, "kind", None) or "")
    if kind is None:
        return None, None, False
    row, problem = usable_transport(session, source.team_id, (source.config or {}).get("transport_id"), kind)
    return row, problem, True


def claim_extras(session, source, node, now, acc: dict) -> dict | None:
    row, problem, fleet = _transport_for(session, source)
    if not fleet:
        return None
    config = dict(acc.get("config") or {})
    secrets = dict(acc.get("secrets") or {})
    release = active_release(session)
    config["zs_collect"] = release_payload(release) if release is not None else None
    if row is None:
        config["transport"], config["transport_problem"] = None, problem
    else:
        config["transport"] = dict(row.config or {})
        config.pop("transport_problem", None)
        secrets.update(decrypt_secrets(row.secret_encrypted))
    return {"config": config, "secrets": secrets}


def version_input(session, source) -> str | None:
    row, problem, fleet = _transport_for(session, source)
    if not fleet:
        return None
    release = active_release(session)
    rel = f"{release.id}:{release.version}" if release is not None else "none"
    if row is None:
        return f"transport=unusable({problem});release={rel}"
    return f"transport={row.id}:{row.row_version};release={rel}"


def known_secrets(session, source) -> list[str]:
    row, _problem, fleet = _transport_for(session, source)
    if not fleet or row is None:
        return []
    return [v for v in decrypt_secrets(row.secret_encrypted).values() if isinstance(v, str)]


def payload_for_cloud(session, source) -> tuple[dict[str, Any], dict[str, str]]:
    """(config, secrets) for the cloud worker's SSM jobs when F1.1's ``secret_refs`` is not there to apply plugins."""
    out = claim_extras(session, source, None, None, {"config": dict(source.config or {}),
                                                      "secrets": decrypt_secrets(source.secret_encrypted)})
    return (out or {}).get("config") or {}, (out or {}).get("secrets") or {}
