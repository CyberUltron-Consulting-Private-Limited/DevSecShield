"""Who gets a certificate, for what, and for how long (F1 contract, section 3, "Issue rules").

A certificate is issued only:
* while ``CBOM_SSH_CA`` is on;
* to an agentless scan node, for a job that node holds (the caller checked the lease), of a source in the same team
  whose ``credential_type`` is ``ssh_ca``;
* when the source was last saved by someone who is still a team admin (only admins save ``ssh_ca`` sources,
  ``sources.py``; an offboarded admin's sources wait for another admin's save, which the refusal says);
* while no certificate of this job attempt was revoked (an admin revoked one: the job stops, 409);
* when no other scan node with a live token (in any team) has the same SSH key (a cloned image: re-key the node);
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
from typing import Any, Callable

from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources.common import iso_z, log
from backend.utilities.cbom_sources.sshca import certs as C
from backend.utilities.cbom_sources.sshca import flags
from backend.utilities.cbom_sources.sshca import keywrap as KW
from backend.utilities.cbom_sources.sshca import sources as SRC
from backend.utilities.cbom_sources.sshca.ca import IssueError, IssuedCert, authority_for, clamp_ttl, usable_s
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


NEEDS_ADMIN_SAVE = ("SSH CA certificates are issued only for sources last saved by a team admin, and this source was "
                    "last saved by someone who is no longer a team admin. A team admin must open the source and click "
                    "Save (no change is needed)")
_fernet_warned: set[int] = set()


def _check(session: Session, node: CbomScanNode, job: CbomCollectionJob,
           source: CbomCollectionSource | None) -> tuple[dict[str, Any], CbomSshCa]:
    if not flags.enabled():
        raise IssueError(flags.OFF_MESSAGE, "flag_off")
    if (node.mode or "agentless") == "agent":
        raise IssueError("Agent-mode scan nodes are never given certificates", "agent_node")
    if job.node_id != node.id or job.team_id != node.team_id:
        raise IssueError("This job is not this scan node's", "not_this_node")
    if source is None or job.source_id != source.id or source.team_id != node.team_id:
        raise IssueError("The job's source no longer exists", "source_gone")
    ca_cfg = source_ca_config(source)
    if ca_cfg is None:
        raise IssueError("This source does not use SSH CA certificates", "not_ssh_ca")
    if SRC.needs_admin_save(session, source):
        raise IssueError(NEEDS_ADMIN_SAVE, "saved_by_non_admin")
    ca = signing_ca(session, source.team_id, ca_cfg["ssh_ca_id"])
    if ca is None:
        raise IssueError("The source's SSH CA has no active key (missing, revoked or not promoted)", "no_active_ca")
    return ca_cfg, ca


def _check_key_unique(session: Session, node: CbomScanNode) -> None:
    """Another enrolled node (any team) with the same SSH key could use this node's certificates (a cloned VM image),
    and the audit's node would no longer say who logged in.  Hash index ``ix_cbomscannode_ssh_public_key``."""
    key = (node.ssh_public_key or "").strip()
    if not key:
        return
    other = session.exec(select(CbomScanNode.id).where(
        CbomScanNode.ssh_public_key == node.ssh_public_key, CbomScanNode.id != node.id,
        CbomScanNode.node_token_hash.is_not(None)).limit(1)).first()  # type: ignore[union-attr]
    if other is not None:
        raise IssueError("Another scan node uses this node's SSH key (a cloned image?). Re-key this node: stop it, "
                         "delete its state directory's id_ed25519 and enroll it again", "key_shared")


def _check_not_revoked(session: Session, job: CbomCollectionJob, node: CbomScanNode) -> None:
    """An admin revoked a certificate of this job attempt: the attempt gets no new one (it stops)."""
    query = select(CbomSshCertIssued.serial).where(
        CbomSshCertIssued.team_id == job.team_id, CbomSshCertIssued.job_id == job.id,
        CbomSshCertIssued.node_id == node.id, CbomSshCertIssued.revoked_at.is_not(None))  # type: ignore[union-attr]
    if job.claimed_at is not None:
        query = query.where(CbomSshCertIssued.issued_at >= job.claimed_at)
    revoked = session.exec(query.limit(1)).first()
    if revoked is not None:
        from backend.utilities.cbom_sources.sshca.ca import from_db_serial

        raise IssueError(f"Stop this job: an admin revoked its SSH certificate (serial {from_db_serial(int(revoked))}); "
                         "this run gets no new certificate", "cert_revoked", status=409)


def addresses_for(ca_cfg: dict[str, Any], node: CbomScanNode) -> tuple[str, ...]:
    wanted = ca_cfg.get("ssh_source_addresses") or list(node.source_ips or [])
    try:
        addresses = C.source_address_list(wanted)
    except C.CertError as exc:
        raise IssueError(f"source addresses: {exc}", "source_addresses") from None
    if not addresses:
        raise IssueError("The scan node has not reported its addresses; enter the addresses the servers see it as "
                         "(source addresses) on the source", "source_addresses")
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
                  now: _dt.datetime, *, via: str, release: Callable[[], None] | None = None) -> JobCert:
    """Issue one certificate for this job (``IssueError`` with a safe reason otherwise).  ``release``: ends the
    caller's read transaction before a KMS or Vault call (``ca._Base``); the caller re-checks what it read before."""
    ca_cfg, ca = _check(session, node, job, source)
    ca_id, fernet = int(ca.id or 0), ca.key_wrap == "fernet"
    authority = authority_for(session, ca, release=release)
    ttl_s = clamp_ttl(ca.default_ttl_s)
    window = refresh_window(ttl_s)
    if via == "refresh":
        _check_not_revoked(session, job, node)
        current = newest_cert(session, job, node)
        if current is not None and (current.valid_before - now).total_seconds() > window:
            raise IssueError(f"This job's certificate is valid for more than {window} s; ask again when less is left",
                             "refresh_too_early")
    _check_key_unique(session, node)
    addresses = addresses_for(ca_cfg, node)
    # read before the signer may end the transaction (``release``): no reload of these rows after KMS or Vault
    team_id, node_id, job_id, source_id = node.team_id, node.id, job.id, job.source_id
    key_id = f"zs:{team_id}:{node_id}:{job_id}:{{serial}}"
    cert = authority.issue(ca_cfg["ssh_principals"], ttl_s, public_key=node.ssh_public_key or "", key_id=key_id,
                           source_addresses=addresses, node_id=node_id, job_id=job_id,
                           source_id=source.id if source else None, via=via, now=now)
    log("ssh certificate issued", team=team_id, ca=ca_id, serial=cert.serial, node=node_id, job=job_id,
        source=source_id, via=via, ttl_s=ttl_s, principals=len(cert.principals))
    if fernet and ca_id not in _fernet_warned and KW.kms_configured():
        _fernet_warned.add(ca_id)  # once per CA and worker: the operator should rotate it onto KMS
        log("ssh ca key wrapped by the deployment key while KMS is configured; rotate it", team=team_id, ca=ca_id)
    return JobCert(cert, ca, window)
