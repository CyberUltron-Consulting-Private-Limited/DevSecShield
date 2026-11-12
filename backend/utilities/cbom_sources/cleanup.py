"""Delete a team's CBOM Sources rows (children first) when the team itself is deleted."""
from __future__ import annotations

from sqlalchemy import delete
from sqlalchemy.engine import Engine
from sqlmodel import Session
from backend.utilities.cbom_sources.sshca.models import (  # F1.4
    CbomSshCa,
    CbomSshCaTrust,
    CbomSshCaTrustFetch,
    CbomSshCaTrustToken,
    CbomSshCertIssued,
)

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionAuditEvent,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSchedule,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomDriftEvent,
    CbomEvidenceArea,
    CbomEvidenceVendor,
    CbomRemediationAssignment,
    CbomNodePool,
    CbomScanNode,
    IntegrationDelivery,
    TeamIntegration,
)

_ORDER = (
    IntegrationDelivery,  # integrations (WP11): deliveries before their integration
    TeamIntegration,
    CbomDriftEvent,
    CbomRemediationAssignment,
    CbomCollectionSchedule,
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomScanNode,
    CbomNodePool,  # agent pool tokens (WP8b): after the nodes that point at them
    CbomCollectionSettings,
    CbomEvidenceVendor,
    CbomEvidenceArea,
    CbomSshCertIssued,  # F1.4: the certificate audit, the trust bundle's rows, then the CA keys
    CbomSshCaTrustFetch,
    CbomSshCaTrustToken,
    CbomSshCaTrust,
    CbomSshCa,
    CbomCollectionAuditEvent,
)


def delete_cbom_sources_for_team(engine: Engine, team_id: int) -> dict[str, int]:
    counts: dict[str, int] = {}
    with Session(engine) as session:
        for model in _ORDER:
            result = session.exec(delete(model).where(model.team_id == team_id))  # type: ignore[attr-defined]
            counts[model.__tablename__] = int(result.rowcount or 0)
        session.commit()
    return counts
