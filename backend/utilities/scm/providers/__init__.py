"""SCM provider clients. ``build_provider`` returns one with ``iter_repos()``, ``get_repo(full_name)``, ``test()``,
``clone_token()``, ``stats`` and ``close()``."""
from __future__ import annotations

from typing import Any

from backend.utilities.scm.hosts import check_api_base
from backend.utilities.scm.providers.base import DiscoveredRepo, ScmError
from backend.utilities.scm.providers.bitbucket import BitbucketProvider
from backend.utilities.scm.providers.github import GitHubProvider
from backend.utilities.scm.providers.gitlab import GitLabProvider

_CLASSES = {"github": GitHubProvider, "gitlab": GitLabProvider, "bitbucket": BitbucketProvider}


def build_provider(provider: str, auth_kind: str, api_base: str, scope_kind: str, scope_name: str,
                   config: dict[str, Any] | None, secrets: dict[str, str], **client_kw: Any):
    if provider not in _CLASSES:
        raise ScmError("Unknown provider", "refused")
    try:
        base = check_api_base(provider, api_base)
    except ValueError as exc:
        raise ScmError(str(exc), "refused") from None
    return _CLASSES[provider](base, auth_kind, scope_kind, scope_name, dict(config or {}), dict(secrets or {}),
                              **client_kw)


def provider_for_connection(connection: Any, **client_kw: Any):
    """The client for a ``ScmConnection`` row (secrets decrypted here, kept in memory only)."""
    from backend.utilities.cbom_sources.crypto import decrypt_secrets

    return build_provider(connection.provider, connection.auth_kind, connection.api_base, connection.scope_kind,
                          connection.scope_name, connection.config or {}, decrypt_secrets(connection.secret_encrypted),
                          **client_kw)


__all__ = ["DiscoveredRepo", "ScmError", "build_provider", "provider_for_connection"]
