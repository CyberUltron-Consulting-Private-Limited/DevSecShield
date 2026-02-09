from backend.new_models import Scan, CicdIntegration, GuardrailsIntegration
from sqlmodel import Session, select
from backend.get_db import get_db, get_mongo_client_db
from backend.get_db import dev_environment
from rich.console import Console
console = Console()

def delete_team_associated_data(team_id: int ):
    # get the database and mongo db
    engine = get_db(dev_environment=dev_environment)
    mongo_db = get_mongo_client_db(dev_environment=dev_environment)
    
    # STEP [ 1 ] : ======================= Delete all the scans associated with the team ==============================
    scan_ids_list = []
    with Session(engine) as session:
        scans = session.exec(select(Scan).where(Scan.team_id == team_id)).all()
        for scan in scans:
            scan_ids_list.append(scan.id)
            session.delete(scan)
        session.commit()
    console.print(f"Scans with ids: {scan_ids_list} deleted from main database" ,style="bold orange3")


    for scan_id in scan_ids_list:
        # -------------------> Delelte messages log with scan_id -----------------------------
        message_collection = mongo_db["message_log"]
        result = message_collection.delete_many({"scan_id": scan_id})
        console.print(f"{result.deleted_count} Messages with scan_id: {scan_id} deleted from mongo db" ,style="bold orange3")

        # -------------------> Delete active context log with scan_id -----------------------------
        active_context_collection = mongo_db["active_context"]
        result = active_context_collection.delete_many({"scan_id": scan_id})
        console.print(f"{result.deleted_count} Active context with scan_id: {scan_id} deleted from mongo db" ,style="bold orange3")


    # STEP [ 2 ] ======================= Delete cicd integration records associated with the team ==============================
    cicd_ids_list = []
    with Session(engine) as session:
        cicd_integrations = session.exec(select(CicdIntegration).where(CicdIntegration.team_id == team_id)).all()
        for cicd_integration in cicd_integrations:
            cicd_ids_list.append(cicd_integration.id)
            session.delete(cicd_integration)
        session.commit()
    console.print(f"Cicd integrations with ids: {cicd_ids_list} deleted from main database" ,style="bold orange3")


    for cicd_id in cicd_ids_list:
        # -------------------> Delete cicd logs with cicd_id -----------------------------
        cicd_logs_collection = mongo_db["cicd_logs"]
        cicd_logs_collection.delete_many({"ci_cd_integration_id": cicd_id})
        console.print(f"Cicd logs deleted successfully for integration {cicd_id}", style="bold green")

    

    # STEP [ 3 ] ======================= Delete guardrails associated with the team ==============================
    guardrails_ids_list = []
    with Session(engine) as session:
        guardrails = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.team_id == team_id)).all()
        for guardrails_integration in guardrails:
            guardrails_ids_list.append(guardrails_integration.id)
            session.delete(guardrails_integration)
        session.commit()
    console.print(f"Guardrails with ids: {guardrails_ids_list} deleted from main database" ,style="bold orange3")


    for guardrails_id in guardrails_ids_list:
        # -------------------> Delete guardrails logs with guardrails_id -----------------------------
        guardrails_logs_collection = mongo_db["guardrails_logs"]
        guardrails_logs_collection.delete_many({"integration_id": guardrails_id})
        console.print(f"Guardrails logs deleted successfully for integration {guardrails_id}", style="bold green")