"""Delete a team's CBOM Sources rows (children first) when the team itself is deleted."""
from __future__ import annotations

from sqlalchemy import delete
from backend.utilities.cbom_sources.fleet.models import FLEET_MODELS  # F1.2 fleet (inventory, policies, credentials)
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
    CbomEstateAsset,
    CbomEstateObservation,
    CbomEstateSource,
    CbomEstateTeam,
    CbomEvidenceArea,
    CbomEvidenceVendor,
    CbomRemediationAssignment,
    CbomNodePool,
    CbomScanNode,
    IntegrationDelivery,
    TeamIntegration,
)
from backend.utilities.cbom_sources.transports.models import CbomTransport  # F1.3

_ORDER = (
    IntegrationDelivery,  # integrations (WP11): deliveries before their integration
    TeamIntegration,
    *FLEET_MODELS,  # F1.2: targets, inventory sources, policies, credentials (no foreign keys to the rows below)
    CbomDriftEvent,
    CbomEstateObservation,  # CB-20 estate store
    CbomEstateAsset,
    CbomEstateSource,
    CbomEstateTeam,
    CbomRemediationAssignment,
    CbomCollectionSchedule,
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomScanNode,
    CbomNodePool,  # agent pool tokens (WP8b): after the nodes that point at them
    CbomCollectionSettings,
    CbomTransport,  # F1.3 transports (the deployment-wide zs-collect releases are not a team's)
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
