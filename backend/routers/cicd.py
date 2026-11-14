from datetime import datetime, timezone
from io import BytesIO
from typing import Annotated

from bson import ObjectId
from celery.result import AsyncResult
from fastapi import APIRouter, Depends, File, Form, HTTPException, Header, UploadFile, status
from backend.utilities.ratelimit import RateLimiter
from backend.utilities.cicd.auth import ci_key
from rich.console import Console
from sqlmodel import Session, select
from starlette.concurrency import run_in_threadpool

from backend.get_db import get_db, get_mongo_client_db
from backend.mongo_models import CicdLogs
from backend.new_models import CicdIntegration , Scan, DastScanProfile, Team, scan_types
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.utilities.celery.celery_connection import get_celery_app, get_status_and_update_db
from backend.utilities.cicd.auth import (
    create_api_key,
    get_user_and_integration_id,
    require_dast_cicd_key,
    require_zip_cicd_key,
)
from backend.utilities.cicd import cbom_gate
from backend.utilities.cicd.api_keys import (
    can_manage_key,
    is_team_admin,
    key_record,
    key_view,
    public_settings,
    revoked_marker,
    with_key_record,
)
from backend.utilities.cicd.cbom_page import project_cbom_ci_page
from backend.utilities.cicd.migrate_dast_logs import migrate_dast_cicd_logs_for_team
from backend.utilities.cicd.poll import poll_for_results
from backend.utilities.cicd.schemas import (
    CreateCicdIntegrationData,
    UpdateCicdIntegrationData,
)
from backend.utilities.dast.dispatch import run_dast_from_profile
from backend.utilities.dast.schemas import CicdDastScanRequest
from backend.utilities.dast.severity import dast_severity_counts
from backend.utilities.dashboard.scan_metadata import get_scan_metadata
from backend.utilities.dashboard.cicd import (
    cicd_integration_id_filter,
    dast_results_for_chart,
    get_cicd_list_dashboard_data,
    get_cicd_sast_dashboard_data,
    get_cicd_vuln_chart_data,
)
from backend.utilities.team import check_if_user_is_in_team
from backend.utilities.db.s3_utils import delete_file, upload_file
from backend.utilities.cicd.start_cicd_scan import start_cicd_scan_and_update_db
from backend.utilities.cicd.estimate_cicd_scan import estimate_cicd_scan
from backend.utilities.team.credits import deduct_credits_from_team

console = Console()

router = APIRouter(tags=["CICD"])

# Per worker (backend/utilities/ratelimit.py).  CI calls are charged to the VERIFIED integration (an unknown
# key is charged to the client address); the UI routes to the verified user.  Jenkins polls DAST every 20 s.
ci_limiter = RateLimiter("cicd.ci", times=60, seconds=60, key_func=ci_key)
read_limiter = RateLimiter("cicd.read", times=120, seconds=60)
write_limiter = RateLimiter("cicd.write", times=20, seconds=60)
KEY_WARNING = "Save this API key now. It will not be shown again."
app_langs = ["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] 

# ==================================== PUBLIC API ROUTES =============================================================
# Register /cicd/dast/scan BEFORE /cicd/{type}/scan so "dast" is not swallowed by the zip poller.


@router.post("/cicd/dast/scan", summary="Start an asynchronous DAST scan from a saved profile", status_code=202, dependencies=[Depends(ci_limiter)])
async def run_cicd_dast_scan(
    body: CicdDastScanRequest,
    user_and_integration: dict = Depends(get_user_and_integration_id),
):
    """Fire-and-forget DAST. Does not poll. Same team as the CI/CD API key."""
    require_dast_cicd_key(user_and_integration)
    engine = get_db()
    team_id = user_and_integration["team_id"]
    user_id = user_and_integration["user_id"]
    integration_id = user_and_integration["integration_id"]
    with Session(engine) as session:
        profile = session.exec(
            select(DastScanProfile).where(DastScanProfile.id == body.profile_id)
        ).first()
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DAST profile not found")
        if profile.team_id != team_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="DAST profile is not on this CI/CD integration team")
        integration = session.get(CicdIntegration, integration_id)
        integ_settings = public_settings(integration.integration_settings) if integration else {}  # no key record on scans

    result = run_dast_from_profile(
        body.profile_id,
        trigger="cicd",
        engine=engine,
        target_url_override=body.target_url,
        owner_user_id=user_id,
        integration_settings=integ_settings,
    )
    if result.status == "skipped_in_flight":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=result.message)

    cicd_log_id = None
    try:
        mongo_db = get_mongo_client_db()
        insert = mongo_db["cicd_logs"].insert_one(
            CicdLogs(
                created_at=datetime.now(timezone.utc),
                ci_cd_integration_id=integration_id,
                task_id=result.task_id,
                status="pending",
                credits_consumed=result.credits,
                scan_settings_metadata={
                    "scan_type": "dast",
                    "profile_id": body.profile_id,
                    "scan_id": result.scan_id,
                    "trigger": "cicd",
                    "target_url": body.target_url,
                },
                results=None,
                error=None,
            )
        )
        cicd_log_id = str(insert.inserted_id) if insert and insert.inserted_id else None
    except Exception as exc:
        console.print(f"DAST cicd_logs insert skipped: {exc}", style="dim yellow")

    return {
        "scan_id": result.scan_id,
        "task_id": result.task_id,
        "status": result.status,
        "cicd_log_id": cicd_log_id,
        "credits": result.credits,
    }


@router.get("/cicd/dast/scan/{scan_id}", summary="DAST CI status for Jenkins wait-and-gate", dependencies=[Depends(ci_limiter)])
async def get_cicd_dast_scan(
    scan_id: int,
    user_and_integration: dict = Depends(get_user_and_integration_id),
):
    require_dast_cicd_key(user_and_integration)
    engine = get_db()
    team_id = user_and_integration["team_id"]
    with Session(engine) as session:
        scan = session.exec(
            select(Scan).where(Scan.id == scan_id, Scan.team_id == team_id, Scan.scan_type == "dast")
        ).first()
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DAST scan not found")
        task_id = scan.task_id
        scan_status = scan.scan_status
        scan_data = scan.scan_data or {}

    if scan_status in ("pending", "NOT_STARTED", "started") and task_id:
        fetched_status, fetched_data, scan = get_status_and_update_db(
            scan_id=scan_id,
            task_id=task_id,
            table=Scan,
            engine=engine,
        )
        scan_status = fetched_status or scan_status
        if fetched_data:
            scan_data = fetched_data

    meta = get_scan_metadata(scan_type="dast", scan=scan) if scan is not None else {}
    counts = dast_severity_counts(scan_data if isinstance(scan_data, dict) else {})
    results = scan_data.get("results") if isinstance(scan_data, dict) else []
    summary = {
        "finding_count": len(results) if isinstance(results, list) else 0,
        "duration_of_scan": scan_data.get("duration_of_scan") if isinstance(scan_data, dict) else None,
    }
    gate_failed = (counts.get("high") or 0) + (counts.get("critical") or 0) > 0
    return {
        "scan_id": scan_id,
        "status": (scan_status or "").lower(),
        "severity_counts": counts,
        "summary": summary,
        "scan_metadata": meta,
        "gate_failed": gate_failed,
        "info": getattr(scan, "info", None) if scan is not None else None,
    }


@router.post("/cicd/{type}/scan",summary="Run a new cicd scan", dependencies=[Depends(ci_limiter)])
async def run_cicd_scan(
    type: scan_types, 
    zip_file: UploadFile  , 
    user_and_integration: dict = Depends(get_user_and_integration_id) ):
    """
    Submit a Zip file containing the code of the project to be scanned . 
    This route will create a new cicd scan on this project and poll it with a fixed timeout . 
    The scan's results will be returned as a JSON response

    Developers notes:
    1. upload zip file to s3 bucket 
    2. get bucket name and key of file and send it to the cicd_worker 
    3. cicd_worker will download the file from s3 bucket and extract it to a temporary directory
    4. cicd_worker will scan the project using the scan type ( CI/CD )
    5. cicd_worker will return the results as a JSON response
    6. this route will poll the cicd_worker for the results and return them as a JSON response
    """
    try:
        require_zip_cicd_key(user_and_integration, type)
        if type == "dast":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="DAST CI uses POST /cicd/dast/scan with JSON {profile_id}; do not upload a zip",
            )
        # SECURITY: Early file size check before expensive operations
        MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50MB
        
        # Check content-length header first (before reading)
        if zip_file.size and zip_file.size > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE_BYTES // (1024*1024)}MB."
            )
        
        engine = get_db()
        mongo_db = get_mongo_client_db()
        cicd_log_collection = mongo_db["cicd_logs"]

        
        # STEP [ 1 ] : ================= Get the integration and check if the user has enough credits =================================
        scan_settings , credit_balance , team = None, None, None
        with Session(engine) as session:
            integration = session.exec(select(CicdIntegration).where(CicdIntegration.id == user_and_integration["integration_id"]).where(CicdIntegration.team_id == user_and_integration["team_id"])).first()
            if not integration:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd integration not found")
            scan_settings = integration.scan_settings
            scan_type = integration.scan_type
            credit_balance = integration.team.credit_balance
            team = integration.team
            team_id = team.id
            if not team:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found for specified cicd integration")
            

        
        
        # STEP [ 2 ] : ================= Estimate the credits for the scan =================================
        credits_required = await estimate_cicd_scan(
            scan_type=type,
            scan_settings=scan_settings,
            uploaded_file=zip_file)
        if credits_required > credit_balance:
            cicd_log_insert_response = cicd_log_collection.insert_one(CicdLogs(
                created_at=datetime.now(timezone.utc),
                ci_cd_integration_id=user_and_integration["integration_id"],
                task_id=None,
                status="NOT_STARTED",
                credits_consumed=None,
                scan_settings_metadata=None,
                results=None,
                error="Insufficient credits",
            ))
            CICD_LOG_ID = str(cicd_log_insert_response.inserted_id) if cicd_log_insert_response and cicd_log_insert_response.inserted_id else None
            console.print(f"Cicd log inserted successfully with id: {CICD_LOG_ID}", style="bold green")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient credits")


        # STEP [ 2.5 ] : ================= Deduct credits BEFORE dispatching scan (prevent free scans on failure) =================================
        # SECURITY FIX: Deduct credits before starting scan to prevent race condition
        deduct_credits_from_team(team_id=team_id, credits=credits_required)
        
        
        # STEP [ 3 ] : ================= Start the scan and update the main db =================================
        await zip_file.seek(0) # to resent the file pointer to the beginning of the file ( because the esitmation function reads the file and then the file pointer is at the end of the file )
        try:
            task_id, task_status = await start_cicd_scan_and_update_db(
                scan_type=type,
                scan_settings=scan_settings,
                uploaded_file=zip_file)
        except Exception as scan_dispatch_error:
            # Refund credits if scan dispatch fails
            console.print(f"CICD scan dispatch failed, refunding {credits_required} credits to team {team_id}", style="bold yellow")
            try:
                from backend.utilities.team.credits import refund_credits_to_team
                refund_credits_to_team(team_id=team_id, credits=credits_required)
            except Exception as refund_err:
                console.print(f"CRITICAL: Failed to refund credits after CICD scan dispatch failure: {refund_err}", style="bold red")
            raise scan_dispatch_error

        

        # STEP [ 4 ] : ================= Update scan log in mongo db =================================
        
        cicd_log_insert_response = cicd_log_collection.insert_one(CicdLogs(
            created_at=datetime.now(timezone.utc),
            ci_cd_integration_id=user_and_integration["integration_id"],
            task_id=task_id,
            status=task_status,
            credits_consumed=credits_required,
            scan_settings_metadata=scan_settings,
            results=None,
        ))
        CICD_LOG_ID = str(cicd_log_insert_response.inserted_id) if cicd_log_insert_response and cicd_log_insert_response.inserted_id else None
        console.print(f"Cicd log inserted successfully with id: {CICD_LOG_ID}", style="bold green")

        # STEP [ 5 ] : ============= Poll the worker for the results with a timeout =============================
        celery_app = get_celery_app()
        results : list[dict] | None = await poll_for_results(task_id, celery_app, cicd_log_collection, CICD_LOG_ID)
        console.print(f"Results obtained successfully", style="bold yellow")

        
        
        
        # STEP [ 6 ] : ================= Integrate with Jira if enabled =================================
        # Re-load Team/CicdIntegration in a live session so Jira helpers do not hit DetachedInstanceError.
        try:
            from backend.utilities.integrations.jira_ticketing import (
                auto_create_enabled,
                flatten_scan_result_rows,
                create_tickets_from_result_rows,
            )
            with Session(engine) as jira_session:
                live_integration = jira_session.get(CicdIntegration, user_and_integration["integration_id"])
                live_team = jira_session.get(Team, team_id)
                if (
                    live_integration
                    and live_team
                    and auto_create_enabled(live_integration.integration_settings)
                    and results is not None
                ):
                    jira_project_id = ((live_integration.integration_settings or {}).get("jira") or {}).get(
                        "jira_project_id"
                    )
                    if jira_project_id:
                        rows = flatten_scan_result_rows(
                            scan_type,
                            {"results": results} if isinstance(results, list) else results,
                        )
                        console.print("Creating per-finding Jira tickets from CI/CD results", style="bold yellow")
                        create_tickets_from_result_rows(
                            team=live_team,
                            project_id=str(jira_project_id),
                            scan_type=scan_type,
                            scan_id=None,
                            rows=rows,
                        )
        except Exception as e:
            console.print(f"Error Creating ticket in cicd scan: {str(e)}", style="bold red")
            
        
        
        finding_rows = []
        if isinstance(results, dict):
            finding_rows = results.get("results") or []
        elif isinstance(results, list):
            finding_rows = results
        response = {
            "results": results,
            "status": task_status,
            "cicd_log_id": CICD_LOG_ID,
            "finding_count": len(finding_rows) if isinstance(finding_rows, list) else 0,
        }

        # STEP [ 7 ] : ================= CBOM policy gate (the customer template fails the job on gate_failed) =========
        # Same codes as the code-scan CLI gate (aibom.cbom.gate.FAIL_CODES). No result in the poll window fails closed.
        # The verdict is stored on the log, so the CI/CD page shows what the pipeline was told.
        if type == "cbom":  # `type` is the path parameter (the scan type) here, not the builtin
            gate = cbom_gate.evaluate(results)
            response["gate_failed"] = cbom_gate.gate_failed(gate)
            response["gate"] = gate
            console.print(
                f"CBOM CI gate verdict={gate['verdict']} failing={gate['failing_count']} log={CICD_LOG_ID}",
                style="bold yellow",
            )
            if CICD_LOG_ID:
                try:
                    cicd_log_collection.update_one({"_id": ObjectId(CICD_LOG_ID)}, {"$set": {"gate": gate}})
                except Exception as exc:  # the pipeline still gets its verdict; the page then shows none for this log
                    console.print(f"CBOM CI gate not stored on log {CICD_LOG_ID}: {exc.__class__.__name__}", style="bold red")
        return response

    except HTTPException as e:
        console.print(f"HTTPException in running cicd scan: {str(e)}", style="bold red")
        raise e
    except Exception as e:
        console.print(f"Error running cicd scan: {str(e)}", style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")




# ==================================== INTERNAL API ROUTES =============================================================
# revamped ✅
@router.get("/{team_id}/cicd/integrations",summary="List all cicd integrations", dependencies=[Depends(read_limiter)])
async def list_cicd_integrations(
    team_id: int, 
    Authorization: Annotated[str | None, Header()] = None ):
    """
    List all cicd integrations
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)

        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)
        team_admin = is_team_admin(user.id, team_id, engine)


        
        # STEP [ 3 ] : ======================================== Get the integrations ========================================
        with Session(engine) as session:
            integrations = session.exec(select(CicdIntegration).where(CicdIntegration.team_id == team_id)).all()
        
            integrations_data = []
            integration_ids = []
            for integration in integrations:
                integration_ids.append(integration.id)
                integrations_data.append({
                    "id": integration.id,
                    "title": integration.title,
                    "created_at": integration.created_at,
                    "owner_user_email": integration.owner_user.email,
                    "owner_user_full_name": f"{integration.owner_user.first_name} {integration.owner_user.last_name}",
                    "last_updated": integration.last_updated,
                    "scan_type": integration.scan_type.upper() if integration.scan_type not in ["leakage" , "sbom_sca" , "agent_discovery"] else integration.scan_type,
                    # issue #99: never a part of the stored hash (the UI used to show and copy it)
                    **key_view(integration),
                    "can_manage_api_key": can_manage_key(integration, user.id, team_admin),
                })

            dashboard_data = get_cicd_list_dashboard_data(integration_ids=integration_ids)
            return {
                "integrations": integrations_data,
                "dashboard_data": dashboard_data,
                }
    except Exception as e:
        console.print(f"Error listing cicd integrations: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")



# revamped ✅
@router.post("/{team_id}/cicd/integration",summary="Create a new cicd integration", dependencies=[Depends(write_limiter)])
async def create_cicd_integration(
    team_id: int, 
    data: CreateCicdIntegrationData, 
    Authorization: Annotated[str | None, Header()] = None ):
    """
    Create a new cicd integration
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        if data.title is None or data.scan_type is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Title and scan type are required")
        if data.scan_type not in ("sast", "dast", "cbom"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan type must be sast, dast, or cbom")


        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)


        # STEP [ 3 ] : ======================================== Create the integration ====================================
        plaintext_api_key, hashed_api_key = create_api_key(team_id)
        with Session(engine) as session:
            existing_dast = session.exec(
                select(CicdIntegration).where(
                    CicdIntegration.team_id == team_id,
                    CicdIntegration.scan_type == "dast",
                )
            ).all()
            is_first_dast = data.scan_type == "dast" and len(existing_dast) == 0
            integration = CicdIntegration(
                team_id=team_id, 
                owner_user_id=user.id, 
                title=data.title, 
                scan_type=data.scan_type, 
                api_key=hashed_api_key,  # Store only the hash
                integration_settings=with_key_record({}, key_record(plaintext_api_key, user.email)))
            session.add(integration)
            session.commit()
            session.refresh(integration)
            created_id = integration.id
            if is_first_dast:
                try:
                    migrate_dast_cicd_logs_for_team(session, mongo_db, team_id)
                except Exception as migrate_exc:
                    console.print(f"DAST cicd_logs migrate skipped: {migrate_exc}", style="dim yellow")
            return {
                "integration_id": created_id,
                "api_key": plaintext_api_key,  # Return plaintext ONCE, user must save it
                "warning": KEY_WARNING,
                "api_key_state": "active",
                "api_key_hint": plaintext_api_key[-4:],
            }
    except Exception as e:
        console.print(f"Error creating cicd integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")



# revamped ✅
@router.delete("/{team_id}/cicd/integration/{integration_id}",summary="Delete a cicd integration", dependencies=[Depends(write_limiter)])
async def delete_cicd_integration(
    team_id: int, 
    integration_id: int, 
    Authorization: Annotated[str | None, Header()] = None ):
    """
    Delete a cicd integration
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)


        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)

        
        # STEP [ 3 ] : ======================================== Delete the integration ====================================
        with Session(engine) as session:
            integration = session.exec(select(CicdIntegration).where(CicdIntegration.id == integration_id).where(CicdIntegration.team_id == team_id)).first()
            if not integration:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd integration not found")
            if integration.owner_user_id != user.id: # only the owner of the integration can delete it ⭐⭐
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You are not the owner of this cicd integration")
            session.delete(integration)
            session.commit()
        
        # STEP [ 4 ] : ======================================== Delete the logs ====================================
        cicd_logs_collection = mongo_db["cicd_logs"]
        cicd_logs_collection.delete_many(cicd_integration_id_filter(integration_id))
        console.print(f"Cicd logs deleted successfully for integration {integration_id}", style="bold green")

        return {
            "message": "Cicd integration deleted successfully"
        }
    except Exception as e:
        console.print(f"Error deleting cicd integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")



# revamped ✅
@router.put("/{team_id}/cicd/integration/{integration_id}",summary="Update a cicd integration", dependencies=[Depends(write_limiter)])
async def update_cicd_integration(
    team_id: int, 
    integration_id: int, 
    data: UpdateCicdIntegrationData, 
    Authorization: Annotated[str | None, Header()] = None ):
    """
    Update a cicd integration
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)




        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)

        

        # STEP [ 3 ] : ======================================== Update the integration ====================================
        with Session(engine) as session:
            integration = session.exec(select(CicdIntegration).where(CicdIntegration.id == integration_id).where(CicdIntegration.team_id == team_id)).first()
            if not integration:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd integration not found")
            if integration.owner_user_id != user.id: # only the owner of the integration can update it ⭐⭐
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You are not the owner of this cicd integration")
            if data.title : 
                integration.title = data.title
            if data.integration_settings is not None:
                if data.integration_settings.jira is not None:
                    """
                    settings_dict = {
                        "jira" : {
                            "jira_project_id" : <jira_project_id>
                        }
                    }
                    """
                    specific_settings_dict = data.integration_settings.model_dump()
                    if integration.integration_settings is not None:
                        settings_dict = integration.integration_settings.copy() or {}
                    else:
                        settings_dict = {}
                    settings_dict["jira"] = specific_settings_dict["jira"]
                    console.print(settings_dict, style="bold yellow")
                    integration.integration_settings= settings_dict

            if data.scan_settings is not None:
                if data.scan_settings.sast is not None:
                    specific_scan_settings_dict = data.scan_settings.model_dump()
                    if integration.scan_settings is not None:
                        scan_settings_dict = integration.scan_settings.copy() or {}
                    else:
                        scan_settings_dict = {}
                    scan_settings_dict["sast"] = specific_scan_settings_dict["sast"]
                    console.print(scan_settings_dict, style="bold yellow")
                    integration.scan_settings= scan_settings_dict
                if data.scan_settings.cbom is not None:
                    specific_scan_settings_dict = data.scan_settings.model_dump()
                    if integration.scan_settings is not None:
                        scan_settings_dict = integration.scan_settings.copy() or {}
                    else:
                        scan_settings_dict = {}
                    scan_settings_dict["cbom"] = specific_scan_settings_dict["cbom"]
                    console.print(scan_settings_dict, style="bold yellow")
                    integration.scan_settings = scan_settings_dict
                if data.scan_settings.ai_bom is not None:
                    specific_scan_settings_dict = data.scan_settings.model_dump()
                    if integration.scan_settings is not None:
                        scan_settings_dict = integration.scan_settings.copy() or {}
                    else:
                        scan_settings_dict = {}
                    scan_settings_dict["ai_bom"] = specific_scan_settings_dict["ai_bom"]
                    console.print(scan_settings_dict, style="bold yellow")
                    integration.scan_settings = scan_settings_dict


            session.add(integration)
            session.commit()
            session.refresh(integration)
            return {
                "message": "Cicd integration updated successfully"
            }
    except Exception as e:
        console.print(f"Error updating cicd integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")



def _manageable_integration(session: Session, team_id: int, integration_id: int, user_id: int, engine) -> CicdIntegration:
    """The integration whose key the caller may rotate or revoke: 404 when it is not this team's, 403 unless the
    caller owns it or is a team admin (membership is checked by the caller first)."""
    integration = session.exec(
        select(CicdIntegration).where(CicdIntegration.id == integration_id).where(CicdIntegration.team_id == team_id)
    ).first()
    if not integration:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd integration not found")
    if not can_manage_key(integration, user_id, is_team_admin(user_id, team_id, engine)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only the integration's owner or a team admin can rotate or revoke its API key")
    return integration


@router.post("/{team_id}/cicd/integration/{integration_id}/api-key/rotate", summary="Issue a new CI/CD API key",
             dependencies=[Depends(write_limiter)])
async def rotate_cicd_api_key(
    team_id: int,
    integration_id: int,
    Authorization: Annotated[str | None, Header()] = None):
    """Issue a new key for the integration (also after a revoke). The old key stops working at once. The new key is
    in this answer only; only its hash is stored."""
    try:
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        check_if_user_is_in_team(user.id, team_id, engine)
        plaintext_api_key, hashed_api_key = create_api_key(team_id)
        with Session(engine) as session:
            integration = _manageable_integration(session, team_id, integration_id, user.id, engine)
            integration.api_key = hashed_api_key
            integration.integration_settings = with_key_record(integration.integration_settings,
                                                               key_record(plaintext_api_key, user.email))
            integration.last_updated = datetime.now(timezone.utc)
            session.add(integration)
            session.commit()
            console.print(f"CI/CD API key rotated for integration {integration_id} by user {user.id}", style="bold yellow")
        return {
            "integration_id": integration_id,
            "api_key": plaintext_api_key,  # shown ONCE
            "warning": KEY_WARNING,
            "api_key_state": "active",
            "api_key_hint": plaintext_api_key[-4:],
        }
    except Exception as e:
        console.print(f"Error rotating cicd api key: {e!s}", style="bold red")
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@router.delete("/{team_id}/cicd/integration/{integration_id}/api-key", summary="Revoke the CI/CD API key",
               dependencies=[Depends(write_limiter)])
async def revoke_cicd_api_key(
    team_id: int,
    integration_id: int,
    Authorization: Annotated[str | None, Header()] = None):
    """Revoke the integration's key: pipelines using it get 401 until a new key is issued (rotate). The integration,
    its settings and its scan history stay."""
    try:
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        check_if_user_is_in_team(user.id, team_id, engine)
        with Session(engine) as session:
            integration = _manageable_integration(session, team_id, integration_id, user.id, engine)
            integration.api_key = revoked_marker()
            integration.integration_settings = with_key_record(integration.integration_settings, None)
            integration.last_updated = datetime.now(timezone.utc)
            session.add(integration)
            session.commit()
            console.print(f"CI/CD API key revoked for integration {integration_id} by user {user.id}", style="bold yellow")
        return {"integration_id": integration_id, "api_key_state": "revoked",
                "message": "API key revoked. Pipelines using it are refused until you issue a new key."}
    except Exception as e:
        console.print(f"Error revoking cicd api key: {e!s}", style="bold red")
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")



# revamped ✅
@router.get("/{team_id}/cicd/integration/{integration_id}",summary="Get a cicd integration", dependencies=[Depends(read_limiter)])
async def get_cicd_integration(
    team_id: int, 
    integration_id: int, 
    Authorization: Annotated[str | None, Header()] = None ,
    limit : int = 100,
    offset : int = 0,
):
    """
    Get a cicd integration
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)


        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 3 ] : ================= Get the integration =================================
        with Session(engine) as session:
            integration = session.exec(select(CicdIntegration).where(CicdIntegration.id == integration_id).where(CicdIntegration.team_id == team_id)).first()
            if not integration:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd integration not found")
            scan_type = integration.scan_type
            key_fields = key_view(integration)
            key_fields["can_manage_api_key"] = can_manage_key(integration, user.id, is_team_admin(user.id, team_id, engine))
            scan_settings_snapshot = integration.scan_settings
            has_dast_profile = session.exec(
                select(DastScanProfile.id).where(DastScanProfile.team_id == team_id)
            ).first() is not None

        # STEP [ 4 ] : ==================================== Get the ci cd integration logs from the mongo db ====================================
        cicd_logs_collection = mongo_db["cicd_logs"]
        cicd_logs = cicd_logs_collection.find(
            {"$and": [cicd_integration_id_filter(integration_id), {"status": {"$in": ["pending", "started" , "success"]}}]}
        ) # including success because sometimes the scan  might have comepleted quickly and we might need to get results after status is success            
    
        

        # STEP [ 5 ] : ======================================= Cycle through the logs and see if there are any tasks that need status update =======================================
        celery_app = get_celery_app()
        result , task_status = None, None
        for log in cicd_logs:
            meta = log.get("scan_settings_metadata") or {}
            if (meta.get("scan_type") or "").lower() == "dast":
                continue

            # update status if not success
            if log["status"] != "success":
                console.print(f"Cicd log {log['_id']}", style="bold yellow")
                task_id = log["task_id"]
                task_status = AsyncResult(task_id, app=celery_app).status.lower()


            # get results if not already got and status is success
            if log["results"] == None and (task_status == "success" or log["status"] == "success"):
                console.print(f"Cicd log {log['_id']} is success, getting results", style="bold green")
                result = AsyncResult(log["task_id"], app=celery_app).result
            

            # update the log in the mongo db
            if result and task_status:
                log["results"] = result
                log["status"] = task_status
                cicd_logs_collection.update_one({"_id": log["_id"]}, {"$set": {"results": result , "status": task_status}})
                console.print(f"Cicd log {log['_id']} updated with scan status {task_status} and results successfully", style="bold green")
            if task_status : 
                log["status"] = task_status
                cicd_logs_collection.update_one({"_id": log["_id"]}, {"$set": {"status": task_status}})
                console.print(f"Cicd log {log['_id']} updated with status {task_status}", style="bold green")
            if result:
                log["results"] = result
                cicd_logs_collection.update_one({"_id": log["_id"]}, {"$set": {"results": result}})
                console.print(f"Cicd log {log['_id']} updated with results", style="bold green") 
        
        
        # STEP [ 6 ] : =============== Get ci cd mongo logs for integration ================================
        logs = mongo_db["cicd_logs"].find(cicd_integration_id_filter(integration_id)).sort("created_at", -1).limit(limit).skip(offset)
        logs_data = []
        results_list = []
        integ_is_dast = (scan_type or "").lower() == "dast"
        with Session(engine) as session:
            for log in logs:
                dashboard_data = None
                meta = log.get("scan_settings_metadata") or {}
                scan_id = meta.get("scan_id")
                is_dast = (meta.get("scan_type") or "").lower() == "dast"
                if integ_is_dast != is_dast:
                    continue
                if is_dast and scan_id:
                    scan = session.get(Scan, int(scan_id))
                    if scan is not None:
                        log["status"] = scan.scan_status
                        chart_rows = dast_results_for_chart(scan.scan_data)
                        if chart_rows:
                            log["results"] = chart_rows
                # SAST results may be list or dict with "results" key (DataSpecs.md); get_cicd_sast_dashboard_data accepts both
                if log.get("results") and scan_type == "sast" and not is_dast:
                    try:
                        dashboard_data = get_cicd_sast_dashboard_data(log["results"])
                    except Exception:
                        dashboard_data = None
                cbom_page = None
                if (scan_type or "").lower() == "cbom" and isinstance(log.get("results"), dict):
                    try:
                        cbom_page = project_cbom_ci_page(log["results"])
                    except Exception as exc:
                        console.print(f"CBOM CI page projection failed: {exc}", style="bold red")
                        cbom_page = None
                logs_data.append({
                    "id": str(log["_id"]),
                    "created_at": log["created_at"],
                    "status": log["status"],
                    "results": log["results"],
                    "dashboard": dashboard_data,
                    "cbom_page": cbom_page,
                    "credits_consumed": round(float(log["credits_consumed"]), 2) if log["credits_consumed"] else None,
                    "error": log.get("error"),
                    "scan_id": scan_id,
                    "profile_id": meta.get("profile_id"),
                    "trigger": meta.get("trigger"),
                    "scan_kind": "dast" if is_dast else scan_type,
                    # CBOM policy gate verdict as returned to the pipeline (None for logs made before the gate)
                    "gate": log.get("gate"),
                })
                if log.get("results"):
                    created = log["created_at"]
                    created_date = created.date() if hasattr(created, "date") else created
                    results_list.append((log["results"], created_date))
        
        # STEP [ 7 ] : ================= Return the integration and logs ================================
        if integ_is_dast:
            integration_active = has_dast_profile
        elif (scan_type or "").lower() in {"cbom", "ai_bom"}:
            # These scan types have no required settings. An empty object is a
            # valid, active integration.
            integration_active = True
        elif not scan_settings_snapshot or scan_settings_snapshot == {}:
            integration_active = False
        else:
            integration_active = True
        

        dashboard_data = get_cicd_vuln_chart_data(results_list=results_list)
        
        return {
            "cicd_integration_id": integration.id,
            **key_fields,  # issue #99: the key's state and last 4 characters, never the key or its hash
            "integration_active": integration_active,
            "title": integration.title,
            "created_at": integration.created_at,
            "last_updated": integration.last_updated,
            "scan_type":  integration.scan_type.upper() if integration.scan_type not in ["leakage" , "sbom_sca" , "agent_discovery"] else integration.scan_type,
            "integration_settings": public_settings(integration.integration_settings),
            "scan_settings": integration.scan_settings or {},
            "logs": logs_data,
            "dashboard_data": dashboard_data,
        }
    except Exception as e:
        console.print(f"Error getting cicd integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

