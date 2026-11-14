"""Typed credentials that policies hand to managed sources (contract section 2, ``cbomcredential``).

The non-secret config is the subset of ``ServersConfig`` that says how to log in (``login_user``, ``port``,
``host_key_policy``, ``known_hosts``, ``vault``) plus ``ssh_ca_id`` / ``ssh_principals`` for ``ssh_ca``.  Secrets
follow the Linux servers rule (``password`` → password; ``ssh_cert`` → certificate and private key; ``node_key``,
``vault`` and ``ssh_ca`` store none), are validated like source secrets, encrypted with the deployment key and never
returned (``secrets_set`` instead).
"""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.utilities.cbom_sources.kinds import MAX_SECRET_BYTES, VaultRef, check_login
from backend.utilities.cbom_sources.fleet.models import CbomCredential
from backend.utilities.cbom_sources.common import iso_z

_PRINCIPAL = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
SECRETS_BY_TYPE = {"password": {"password"}, "ssh_cert": {"ssh_certificate", "private_key"}}


class CredentialConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    login_user: str = Field(default="zs-cbom", max_length=64)
    port: int = Field(default=22, ge=1, le=65535)
    host_key_policy: Literal["tofu", "pinned"] = "tofu"
    known_hosts: str | None = Field(default=None, max_length=MAX_SECRET_BYTES)
    vault: VaultRef | None = None
    ssh_ca_id: int | None = Field(default=None, ge=1)
    ssh_principals: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("login_user")
    @classmethod
    def _login(cls, v: str) -> str:
        return check_login(v) or "zs-cbom"

    @field_validator("ssh_principals")
    @classmethod
    def _principals(cls, v: list[str]) -> list[str]:
        for p in v:
            if not _PRINCIPAL.match(p):
                raise ValueError("principals may use letters, digits and . _ @ - (64 at most)")
        return sorted(set(v))


def check_config(credential_type: str, config: dict[str, Any]) -> dict[str, Any]:
    cfg = CredentialConfig.model_validate(config or {})
    if credential_type == "vault" and cfg.vault is None:
        raise ValueError("vault: choose a vault and enter the secret path")
    if credential_type != "vault":
        cfg.vault = None
    if credential_type == "ssh_ca":
        if cfg.ssh_ca_id is None or not cfg.ssh_principals:
            raise ValueError("ssh_ca_id: choose the SSH CA and at least one principal")
    else:
        cfg.ssh_ca_id, cfg.ssh_principals = None, []
    if cfg.host_key_policy == "pinned" and not (cfg.known_hosts or "").strip():
        raise ValueError("known_hosts: paste the known_hosts lines to pin, or choose trust on first use")
    if credential_type == "password" and cfg.host_key_policy != "pinned":
        raise ValueError("host_key_policy: password logins need pinned host keys, so the password only goes to the "
                         "real servers; paste their known_hosts lines, or use the node key")
    return cfg.model_dump()


def required_secrets(credential_type: str) -> set[str]:
    return set(SECRETS_BY_TYPE.get(credential_type, set()))


class CredentialCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=64)
    credential_type: Literal["node_key", "password", "ssh_cert", "vault", "ssh_ca"]
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] | None = None

    @model_validator(mode="after")
    def _check(self) -> "CredentialCreate":
        self.config = check_config(self.credential_type, self.config)
        return self


class CredentialUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str | None = Field(default=None, min_length=1, max_length=64)
    config: dict[str, Any] | None = None
    secrets: dict[str, str] | None = None
    expected_version: int | None = None


def public_credential(c: CbomCredential) -> dict[str, Any]:
    return {"id": c.id, "name": c.name, "credential_type": c.credential_type, "config": dict(c.config or {}),
            "secrets_set": sorted(c.secret_fields or []), "deleted": c.deleted_at is not None,
            "owner_user_id": c.owner_user_id, "row_version": c.row_version, "created_at": iso_z(c.created_at),
            "last_updated": iso_z(c.last_updated)}
