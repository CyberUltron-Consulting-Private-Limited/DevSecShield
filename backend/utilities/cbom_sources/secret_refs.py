"""Where a job's config and secrets come from: the source row, then a fixed list of claim plugins (F1 contract,
section 3).  Created by F1.1; nobody else edits this file.  Every place that hands a job its secrets or scrubs node
output with them goes through here: the node claim, the cloud-worker claim, ``finish_job``, ``add_assets``, and the
secret part of ``jobs.connection_version``.

Each plugin module is optional (a module that does not exist is skipped; one that exists but fails to import is an
error, never silently skipped) and exposes:

    def claim_extras(session, source, node, now, acc: dict) -> dict | None   # acc = {"config": {...}, "secrets": {...}}
    def version_input(session, source) -> str | None   # cheap (one row read); never mints anything
    def known_secrets(session, source) -> list[str]     # for scrubbing node output

``claim_extras`` returns the new ``acc`` (or None to leave it unchanged); plugins run in the order listed.  A plugin
may mint short-lived material (an SSH certificate) in ``claim_extras`` only; ``version_input`` must stay cheap
because ``connection_version`` is computed for every job check.
"""
from __future__ import annotations

import datetime as _dt
import importlib
import threading
from types import ModuleType
from typing import Any

from sqlalchemy.orm import object_session

from backend.utilities.cbom_sources.crypto import decrypt_secrets

PLUGINS = (
    "backend.utilities.cbom_sources.fleet.claim",       # F1.2: credential_id -> secrets
    "backend.utilities.cbom_sources.transports.claim",  # F1.3: transport_id -> config.transport + secrets
    "backend.utilities.cbom_sources.sshca.claim",       # F1.4: ssh_ca -> config.ssh_ca + secrets.ssh_certificate
)

_loaded: list[ModuleType] | None = None
_lock = threading.Lock()


def _missing(exc: ModuleNotFoundError, name: str) -> bool:
    """True when the plugin module itself (or a package on its path) does not exist, not when something it imports
    is missing (that is a broken plugin and must fail loudly)."""
    missing = exc.name or ""
    return name == missing or name.startswith(missing + ".")


def plugins() -> list[ModuleType]:
    global _loaded
    if _loaded is not None:
        return _loaded
    with _lock:
        if _loaded is None:
            out = []
            for name in PLUGINS:
                try:
                    module = importlib.import_module(name)
                except ModuleNotFoundError as exc:
                    if not _missing(exc, name):
                        raise
                    continue
                check_plugin(module)
                out.append(module)
            _loaded = out
    return _loaded


def check_plugin(module: ModuleType) -> None:
    """Fail closed at load (security review S8): a plugin that hands out material (``claim_extras``) must also say
    which values to scrub from node output (``known_secrets``) and what its jobs depend on (``version_input``)."""
    if getattr(module, "claim_extras", None) is not None:
        missing = [fn for fn in ("known_secrets", "version_input") if getattr(module, fn, None) is None]
        if missing:
            raise ImportError(f"claim plugin {module.__name__} defines claim_extras but not {', '.join(missing)}")


def reset_plugins() -> None:
    """Forget the loaded plugins (tests)."""
    global _loaded
    with _lock:
        _loaded = None


def source_secrets(session, source, node, now: _dt.datetime) -> tuple[dict[str, Any], dict[str, str]]:
    """(config, secrets) a job of ``source`` runs with: the stored config and decrypted secrets, then every plugin's
    ``claim_extras`` in order.  An agent-mode node is never given a secret (callers pass the result on only for
    agentless nodes and the cloud worker)."""
    acc: dict[str, Any] = {"config": dict(source.config or {}), "secrets": decrypt_secrets(source.secret_encrypted)}
    for plugin in plugins():
        fn = getattr(plugin, "claim_extras", None)
        if fn is None:
            continue
        out = fn(session, source, node, now, acc)
        if out is not None:
            acc = out
    return acc["config"], acc["secrets"]


def known_secrets(session, source) -> list[str]:
    """Every secret value a job of ``source`` may have seen, for scrubbing what its node sends back."""
    if source is None:
        return []
    values = [v for v in decrypt_secrets(source.secret_encrypted).values() if isinstance(v, str)]
    for plugin in plugins():
        fn = getattr(plugin, "known_secrets", None)
        if fn is not None:
            values += [v for v in (fn(session, source) or []) if isinstance(v, str)]
    return values


def version_input(source, session=None) -> str | None:
    """Plugin inputs to ``connection_version`` (None when no plugin contributes, so a source's version is the same as
    before plugins existed)."""
    if not plugins():
        return None
    session = session or object_session(source)
    if session is None:
        return None
    parts = []
    for plugin in plugins():
        fn = getattr(plugin, "version_input", None)
        value = fn(session, source) if fn is not None else None
        if value is not None:
            parts.append(f"{plugin.__name__}={value}")
    return "|".join(parts) or None
