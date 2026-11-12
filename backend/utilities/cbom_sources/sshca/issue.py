"""Who gets a certificate, for what, and for how long (F1 contract, section 3, "Issue rules").

A certificate is issued only:
* while ``CBOM_SSH_CA`` is on;
* to an agentless scan node, for a job that node holds (the caller checked the lease), of a source in the same team
  whose ``credential_type`` is ``ssh_ca``;
* when the source was last saved by a team admin (like vault credentials: the CA is a team-wide login credential, so a
  member cannot point it at new servers or principals);
* for the principals the source names, all ``zs-<team>-<group>`` (never ``root`` or a real login name);
* for the node's own public key (its private key never leaves the node), bound with ``source-address`` to the
  addresses the source lists, else to the addresses the node reports (none known: refused, never an unbound cert);
* by the active CA of the source's lineage, for the CA's TTL (60-3600 s, default 300; ``valid_before - valid_after``
  is exactly the TTL, the clock-skew back-dating included), no extensions.
Each certificate gets one ``cbomsshcertissued`` row in the caller's transaction.  A refresh through the node route is
allowed only when the job's newest certificate has less than ``refresh_window`` left.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources.common import iso_z, log
from backend.utilities.cbom_sources.http import is_team_admin
from backend.utilities.cbom_sources.sshca import certs as C
from backend.utilities.cbom_sources.sshca import flags
from backend.utilities.cbom_sources.sshca.ca import BuiltinCA, IssueError, IssuedCert, VaultCA, clamp_ttl, usable_s
from backend.utilities.cbom_sources.sshca.models import CbomSshCa, CbomSshCertIssued
from backend.utilities.cbom_sources.sshca.registry import signing_ca

KINDS_WITH_CA = ("linux_servers",)
REFRESH_WINDOW_MAX_S = 120


def refresh_window(ttl_s: int) -> int:
    """Seconds before expiry from which a job may get its next certificate: 120 s, or half the certificate's usable
    life when shorter (so a node can never mint more often than every half life)."""
    return min(REFRESH_WINDOW_MAX_S, max(1, usable_s(ttl_s) // 2))


@dataclass(frozen=True)
class JobCert:
    cert: IssuedCert
    ca: CbomSshCa
    refresh_before_s: int

    def payload(self, now: _dt.datetime) -> dict[str, Any]:
        return {"certificate": self.cert.certificate, "serial": self.cert.serial,
                "valid_after": iso_z(self.cert.valid_after), "valid_before": iso_z(self.cert.valid_before),
                "expires_in_s": max(0, int((self.cert.valid_before - now).total_seconds())),
                "refresh_before_s": self.refresh_before_s, "principals": list(self.cert.principals),
                "ca_id": self.ca.id}


def source_ca_config(source: CbomCollectionSource) -> dict[str, Any] | None:
    """The source's validated SSH CA settings, or None when it does not use the CA."""
    if source.kind not in KINDS_WITH_CA:
        return None
    cfg = source.config or {}
    if cfg.get("credential_type") != "ssh_ca":
        return None
    return {"ssh_ca_id": cfg.get("ssh_ca_id"), "ssh_principals": list(cfg.get("ssh_principals") or []),
            "ssh_source_addresses": list(cfg.get("ssh_source_addresses") or [])}


def _check(session: Session, node: CbomScanNode, job: CbomCollectionJob,
           source: CbomCollectionSource | None) -> tuple[dict[str, Any], CbomSshCa]:
    if not flags.enabled():
        raise IssueError(flags.OFF_MESSAGE)
    if (node.mode or "agentless") == "agent":
        raise IssueError("Agent-mode scan nodes are never given certificates")
    if job.node_id != node.id or job.team_id != node.team_id:
        raise IssueError("This job is not this scan node's")
    if source is None or job.source_id != source.id or source.team_id != node.team_id:
        raise IssueError("The job's source no longer exists")
    ca_cfg = source_ca_config(source)
    if ca_cfg is None:
        raise IssueError("This source does not use SSH CA certificates")
    saved_by = source.updated_by_user_id or source.owner_user_id
    if not saved_by or not is_team_admin(session, saved_by, source.team_id):
        raise IssueError("SSH CA certificates are issued only for sources a team admin saved; ask an admin to save "
                         "this source again")
    ca = signing_ca(session, source.team_id, ca_cfg["ssh_ca_id"])
    if ca is None:
        raise IssueError("The source's SSH CA has no active key (missing, revoked or not promoted)")
    return ca_cfg, ca


def addresses_for(ca_cfg: dict[str, Any], node: CbomScanNode) -> tuple[str, ...]:
    wanted = ca_cfg.get("ssh_source_addresses") or list(node.source_ips or [])
    try:
        addresses = C.source_address_list(wanted)
    except C.CertError as exc:
        raise IssueError(f"source addresses: {exc}") from None
    if not addresses:
        raise IssueError("The scan node has not reported its addresses; enter the addresses the servers see it as "
                         "(source addresses) on the source")
    return addresses


def newest_cert(session: Session, job: CbomCollectionJob, node: CbomScanNode) -> CbomSshCertIssued | None:
    """The newest unrevoked certificate of this job's current attempt (issued to this node since its claim)."""
    query = select(CbomSshCertIssued).where(
        CbomSshCertIssued.team_id == job.team_id, CbomSshCertIssued.job_id == job.id,
        CbomSshCertIssued.node_id == node.id, CbomSshCertIssued.revoked_at.is_(None))  # type: ignore[union-attr]
    if job.claimed_at is not None:
        query = query.where(CbomSshCertIssued.issued_at >= job.claimed_at)
    return session.exec(query.order_by(CbomSshCertIssued.valid_before.desc()).limit(1)).first()  # type: ignore[union-attr]


def issue_for_job(session: Session, node: CbomScanNode, job: CbomCollectionJob, source: CbomCollectionSource | None,
                  now: _dt.datetime, *, via: str) -> JobCert:
    """Issue one certificate for this job (``IssueError`` with a safe reason otherwise)."""
    ca_cfg, ca = _check(session, node, job, source)
    ttl_s = clamp_ttl(ca.default_ttl_s)
    window = refresh_window(ttl_s)
    if via == "refresh":
        current = newest_cert(session, job, node)
        if current is not None and (current.valid_before - now).total_seconds() > window:
            raise IssueError(f"This job's certificate is valid for more than {window} s; ask again when less is left")
    addresses = addresses_for(ca_cfg, node)
    authority = VaultCA(session, ca) if ca.provider == "vault" else BuiltinCA(session, ca)
    key_id = f"zs:{node.team_id}:{node.id}:{job.id}:{{serial}}"
    cert = authority.issue(ca_cfg["ssh_principals"], ttl_s, public_key=node.ssh_public_key or "", key_id=key_id,
                           source_addresses=addresses, node_id=node.id, job_id=job.id,
                           source_id=source.id if source else None, via=via, now=now)
    log("ssh certificate issued", team=node.team_id, ca=ca.id, serial=cert.serial, node=node.id, job=job.id,
        source=job.source_id, via=via, ttl_s=ttl_s, principals=len(cert.principals))
    return JobCert(cert, ca, window)
