"""The SSH CA claim plugin (``secret_refs.PLUGINS``, F1 contract section 3).

``claim_extras`` mints a certificate for the job a node has just claimed, in the claim's transaction, and puts it in
the payload: ``source.secrets.ssh_certificate`` and ``source.config.ssh_ca`` (``serial``, ``expires_in_s``,
``refresh_before_s``).  It never raises for a CA problem: one revoked CA or a KMS outage must not stop a node from
claiming its other jobs, so the reason goes to ``config.ssh_ca.error`` and the node ends that job with it.

Nothing slow runs inside the claim's transaction (it holds the job, node and run rows): the plugin mints only when
signing is local, i.e. a builtin CA whose key is wrapped by the deployment key or already unwrapped in this worker.
A Vault CA, or an AWS KMS key that is not cached here, gets ``config.ssh_ca.fetch`` instead, and the node asks the
certificate route (its own short transaction) before it connects.  A passing fault (KMS throttled or unreachable, a
database error; the savepoint is rolled back) is also ``fetch``, never final; ``error`` is for configuration faults.
Every refusal is audited and logged with its reason (``denials.py``).

``version_input`` returns None: rotating or promoting a CA must not cancel open jobs (the CA is resolved when the
certificate is minted).  ``known_secrets`` returns nothing: a certificate is not a secret.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources.common import log
from backend.utilities.cbom_sources.sshca import denials as DEN
from backend.utilities.cbom_sources.sshca import flags
from backend.utilities.cbom_sources.sshca import keywrap as KW
from backend.utilities.cbom_sources.sshca.ca import IssueError
from backend.utilities.cbom_sources.sshca.models import CbomSshCa
from backend.utilities.cbom_sources.sshca.issue import issue_for_job, source_ca_config
from backend.utilities.cbom_sources.sshca.registry import signing_ca


def _claimed_job(session: Session, source: CbomCollectionSource, node: CbomScanNode,
                 now: _dt.datetime) -> CbomCollectionJob | None:
    """The job this claim just took: the node claims one job per request, at ``now``."""
    return session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.node_id == node.id, CbomCollectionJob.source_id == source.id,
        CbomCollectionJob.team_id == node.team_id, CbomCollectionJob.status == "claimed",
        CbomCollectionJob.claimed_at == now).order_by(CbomCollectionJob.id.desc())).first()  # type: ignore[union-attr]


def signs_locally(ca: CbomSshCa) -> bool:
    """Minting needs no network call: a builtin key wrapped by the deployment key, or one this worker has unwrapped."""
    if ca.provider == "vault":
        return False
    if ca.provider == "builtin" and ca.key_wrap == "aws_kms":
        return KW.is_cached(int(ca.id or 0), ca.fingerprint)
    return True  # fernet, or a provider issue.authority_for refuses (a configuration error, reported as such)


def claim_extras(session: Session, source: CbomCollectionSource, node: CbomScanNode | None, now: _dt.datetime,
                 acc: dict[str, Any]) -> dict[str, Any] | None:
    if not flags.enabled() or node is None or (node.mode or "agentless") == "agent":
        return None
    if source_ca_config(source) is None:
        return None
    config = dict(acc.get("config") or {})
    secrets = {k: v for k, v in (acc.get("secrets") or {}).items() if k != "ssh_certificate"}
    job = _claimed_job(session, source, node, now)
    ca_id = (source.config or {}).get("ssh_ca_id")
    ca = signing_ca(session, source.team_id, ca_id)
    if job is None or (ca is not None and not signs_locally(ca)):
        config["ssh_ca"] = {"fetch": True}
        return {"config": config, "secrets": secrets}
    try:
        with session.begin_nested():  # a failed mint leaves the claim itself intact
            minted = issue_for_job(session, node, job, source, now, via="claim")
    except IssueError as exc:
        DEN.record(session, team_id=node.team_id, node_id=int(node.id or 0), job_id=job.id, code=exc.code, via="claim",
                   source_id=source.id, ca_id=ca_id, status=exc.status)
        config["ssh_ca"] = {"fetch": True} if exc.transient else {"error": str(exc)[:300]}
        return {"config": config, "secrets": secrets}
    except Exception as exc:  # a database fault: the savepoint is rolled back, the claim itself goes on, and the node
        # asks the certificate route before it connects (a passing fault heals; a lasting one fails the job there)
        log("ssh certificate not issued at claim (internal error)", team=node.team_id, node=node.id, job=job.id,
            source=source.id, error=type(exc).__name__)
        config["ssh_ca"] = {"fetch": True}
        return {"config": config, "secrets": secrets}
    payload = minted.payload(now)
    secrets["ssh_certificate"] = payload.pop("certificate")
    config["ssh_ca"] = {k: payload[k] for k in ("serial", "expires_in_s", "refresh_before_s", "valid_before",
                                                "backdated_s", "ca_id")}
    return {"config": config, "secrets": secrets}


def version_input(session: Session, source: CbomCollectionSource) -> str | None:
    return None


def known_secrets(session: Session, source: CbomCollectionSource) -> list[str]:
    return []
