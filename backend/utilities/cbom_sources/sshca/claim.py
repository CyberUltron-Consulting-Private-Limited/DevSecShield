"""The SSH CA claim plugin (``secret_refs.PLUGINS``, F1 contract section 3).

``claim_extras`` mints a certificate for the job a node has just claimed, in the claim's transaction, and puts it in
the payload: ``source.secrets.ssh_certificate`` and ``source.config.ssh_ca`` (``serial``, ``expires_in_s``,
``refresh_before_s``).  It never raises for a CA problem: one revoked CA or a KMS outage must not stop a node from
claiming its other jobs, so the reason goes to ``config.ssh_ca.error`` and the node ends that job with it.  A Vault CA
is not called inside the claim (a slow Vault would hold the claim's row locks): the node asks the certificate route
before it connects (``config.ssh_ca.fetch``).

``version_input`` returns None: rotating or promoting a CA must not cancel open jobs (the CA is resolved when the
certificate is minted).  ``known_secrets`` returns nothing: a certificate is not a secret.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources.common import log
from backend.utilities.cbom_sources.sshca import flags
from backend.utilities.cbom_sources.sshca.ca import IssueError
from backend.utilities.cbom_sources.sshca.issue import issue_for_job, source_ca_config
from backend.utilities.cbom_sources.sshca.registry import signing_ca


def _claimed_job(session: Session, source: CbomCollectionSource, node: CbomScanNode,
                 now: _dt.datetime) -> CbomCollectionJob | None:
    """The job this claim just took: the node claims one job per request, at ``now``."""
    return session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.node_id == node.id, CbomCollectionJob.source_id == source.id,
        CbomCollectionJob.team_id == node.team_id, CbomCollectionJob.status == "claimed",
        CbomCollectionJob.claimed_at == now).order_by(CbomCollectionJob.id.desc())).first()  # type: ignore[union-attr]


def claim_extras(session: Session, source: CbomCollectionSource, node: CbomScanNode | None, now: _dt.datetime,
                 acc: dict[str, Any]) -> dict[str, Any] | None:
    if not flags.enabled() or node is None or (node.mode or "agentless") == "agent":
        return None
    if source_ca_config(source) is None:
        return None
    config = dict(acc.get("config") or {})
    secrets = {k: v for k, v in (acc.get("secrets") or {}).items() if k != "ssh_certificate"}
    job = _claimed_job(session, source, node, now)
    ca = signing_ca(session, source.team_id, (source.config or {}).get("ssh_ca_id"))
    if job is None or (ca is not None and ca.provider == "vault"):
        config["ssh_ca"] = {"fetch": True}
        return {"config": config, "secrets": secrets}
    try:
        with session.begin_nested():  # a failed mint leaves the claim itself intact
            minted = issue_for_job(session, node, job, source, now, via="claim")
    except IssueError as exc:
        log("ssh certificate not issued at claim", team=node.team_id, node=node.id, job=job.id, source=source.id)
        config["ssh_ca"] = {"error": str(exc)[:300]}
        return {"config": config, "secrets": secrets}
    payload = minted.payload(now)
    secrets["ssh_certificate"] = payload.pop("certificate")
    config["ssh_ca"] = {k: payload[k] for k in ("serial", "expires_in_s", "refresh_before_s", "valid_before", "ca_id")}
    return {"config": config, "secrets": secrets}


def version_input(session: Session, source: CbomCollectionSource) -> str | None:
    return None


def known_secrets(session: Session, source: CbomCollectionSource) -> list[str]:
    return []
