import datetime
import json
import os
import tempfile
from typing import Annotated

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Form, UploadFile
from fastapi import BackgroundTasks, Depends, HTTPException, Header, status
from fastapi.responses import FileResponse
from fastapi_throttle import RateLimiter
from pydantic import ValidationError
from sqlalchemy import update
from sqlmodel import Session, select

from backend.get_db import get_db, get_mongo_client_db
from backend.mongo_models import ActiveContextLog, MessageLog
from backend.new_models import Scan
from backend.utilities.dashboard.scan_metadata import get_scan_metadata
from backend.utilities.team.credits import deduct_credits_from_team_for_message
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
# from backend.utilities.celery.celery_connection import get_status_and_update_db
from backend.utilities.db.functions import get_messages_from_scan, return_scan_list_for_type, update_status_of_scan_in_main_db 
from backend.utilities.db.metadata import get_scan_metadata_for_type
from backend.utilities.db.findings import get_findings_for_scan_type
from backend.utilities.pdf import generate_pdf_for_type
from backend.utilities.ai.chatbot import create_response
from backend.utilities.team import (
    check_if_user_is_admin_of_team,
    check_if_user_is_in_team,
)
from backend.utilities.integrations.jira import create_issue_in_project as create_issue_in_jira
from backend.utilities.dashboard.scan import generate_scan_dashboard
from backend.utilities.scan.start_scan import start_scan_and_update_db
from backend.utilities.scan.estimate_scan import estimate_credits
from backend.utilities.team.credits import check_if_team_has_enough_credits , deduct_credits_from_team , update_scan_credit_consumed , refund_credits_to_team
from backend.utilities.db.schemas import * 
from backend.utilities.celery.celery_connection import get_status_and_update_db
from backend.utilities.db.encryption import decrypt_value, is_encrypted
from backend.new_models import scan_types
from rich.console import Console
from backend.utilities.dashboard.scan_list import generate_dashboard_data_for_scan_list
from datetime import datetime, timezone


router = APIRouter( tags=["scans"])   
console = Console()
limiter = RateLimiter(times=20, seconds=30) # 20 requests per 30 seconds
    
# revamped ✅
@router.get("/{team_id}/{type}/scans",summary="List all scans for a team")
async def list_scans(
    team_id: int, 
    type: scan_types, 
    background_tasks: BackgroundTasks, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)],
    ):
    """
    List all scans for a team.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        
        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 2 ] : =========== get the scans from the main db ======================
        with Session(engine) as session:
            scans = None
            scans = session.exec(select(Scan).where(Scan.team_id == team_id).where(Scan.scan_type == type).order_by(Scan.created_at.desc())).all()
            if scans==None :
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No scans found")
            console.print(f"{len(scans)} {type} scans found for team: {team_id}" ,style="bold green")
            scans_list_data,scans_list_to_update = return_scan_list_for_type(sequence=scans) # ✅ done for sast , iac , sbom_sca , mcp , llm 

            if len(scans_list_to_update) > 0:
                background_tasks.add_task(update_status_of_scan_in_main_db, scans = scans_list_to_update, engine = engine)
                console.print(f"Background task added to update statuses of scans: {scans_list_to_update}" ,style="bold green")
            
            
            dashboard_data = generate_dashboard_data_for_scan_list(scans=scans,scan_type=type)  # ✅ done for sast , iac , sbom_sca , mcp , llm 
            return {
                "scans_list_data": scans_list_data,
                "dashboard_data": dashboard_data, #dashboard data will look different for different scan types
            }

    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in listing {type} scans for team {team_id}: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in listing scans , please try again later")

    
# revamped ✅
@router.post("/{team_id}/{type}/scan",summary="Create a new scan")
async def create_scan( 
    team_id: int,
    data: CreateScanData, 
    type: scan_types, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)],
    ):
    """
    Create a new scan.
    return the scan id
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        
        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)
        
        # STEP [ 2 ] : =========== create a new scan in the main database ======================
        with Session(engine) as session:
            new_scan = Scan(
                team_id=team_id, 
                owner_user_id=user.id,
                scan_type=type,
                title=data.title,
            )
            session.add(new_scan)
            session.commit()
            session.refresh(new_scan)
            console.print(f"New scan id: {new_scan.id} added to main database" ,style="bold green")
            return {
                "scan_id": new_scan.id,
                }
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in creating {type} scan for team {team_id}: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in creating scan , please try again later")


# revamped ✅
@router.post("/{team_id}/{type}/scan/{scan_id}/message",summary="Send a message to a scan")
async def send_message_to_scan(
    team_id: int, 
    type: scan_types, 
    data: SendMessageToScanData,
    scan_id: int, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Send a message to a scan.
    Note : 
        Inserting any message into Messages log or Active context log must be done by associating it with : 
        1. scan_id ( scan id from main db )
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes

        # STEP [ 1 ] : =========== Check if user is in team and check if team has enough credits======================
        check_if_user_is_in_team(user.id, team_id, engine)
        if not check_if_team_has_enough_credits(team_id, 0.006):
            return { "content" : "Team does not have enough credits to send a message" }


        SCAN = None
        SCAN_DATA = {}
        SCAN_STATUS = None
        MAX_MESSAGE_LIMIT = 100


        # STEP [ 1 ] : =========== Get the conversation from the main db ======================
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if not scan:
                console.print(f"Scan with id: {scan_id} and team_id: {team_id} not found in main database" ,style="bold red")
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found ")
            
            scan.last_updated = datetime.now(timezone.utc) # updating last_updated field
            session.add(scan)
            session.commit()
            session.refresh(scan)
            
            SCAN = scan
            SCAN_STATUS = scan.scan_status
            SCAN_DATA = scan.scan_data
        

        if SCAN.owner_user_id != user.id: # only the user who created the scan can send messages to the scan 
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You do not have permission to send messages to this scan")
        if not SCAN:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        if not SCAN_DATA or SCAN_DATA == {} or "results" not in SCAN_DATA or SCAN_STATUS == "pending" or SCAN_STATUS == "NOT_STARTED" or SCAN_STATUS == "started" or SCAN_STATUS != "success":
            return { "content" : "Scan has not run or hasn't completed yet, please wait for the scan to complete if it has been initiated or start the scan" }

        
        
        # STEP [ 3 ] : =========== Add the user message to the mongo db ====================== ⭐
        message_collection = mongo_db["message_log"]
        
        # enforce max message limit
        messages_count = message_collection.count_documents({"scan_id": SCAN.id})
        if messages_count > MAX_MESSAGE_LIMIT:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Max message limit reached")
        
        message_instance = MessageLog(
            scan_id=SCAN.id,
            content=data.user_message,
            type="message",
            sender="user",
            created_at=datetime.now(timezone.utc),
        )
        result = message_collection.insert_one(message_instance)
        user_message_id = str(result.inserted_id)
        console.print(f"User message added to mongo db" ,style="dim green")
    
        
        
        
        # STEP [ 4 ] : =========== Add user message to the active context log ====================== ⭐
        active_context_collection = mongo_db["active_context"]
        active_context_instance = ActiveContextLog(
            scan_id=SCAN.id,
            content=data.user_message,
            type="message",
            sender="user",
            created_at=datetime.now(timezone.utc),
        )
        result = active_context_collection.insert_one(active_context_instance)
        active_context_message_id = str(result.inserted_id)
        console.print(f"User message added to active context log with id: {active_context_message_id}" ,style="dim green")


        
        
        
        # STEP [ 5 ] : =========== Get the response from the model ======================
        AI_RESPONSE = await create_response(
            mongo_db=mongo_db,
            scan_id=SCAN.id,
            scan_type=type,
            scan_results=json.dumps(SCAN_DATA, default=str),
            content=data.user_message,
            role="human", # doesnt get saved to any db , jsut for functional clarity 
        )


        # STEP [ 6 ] : =========== Deduct credits for message for team  ====================== ⭐
        deduct_credits_from_team_for_message(team_id)


        return AI_RESPONSE

        
    except Exception as e:
        console.print(f"Error in send_message_to_{type}_scan_conversation: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending message , please try again later")


# revamped ✅
@router.get("/{team_id}/{type}/scan/{scan_id}",summary="Get the scan status of a scan conversation")
async def get_scan(
    type: scan_types, 
    scan_id: int, 
    team_id: int,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Get the scan status of a scan conversation.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes



        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)

        
        
        # STEP [ 2 ] : =========== Get task id ( for celery ) from the main db , after getting the scan from the main db ======================

        SCAN_STATUS = None
        MESSAGES = None
        SCAN_DATA = None
        TASK_ID = None

        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
            TASK_ID = scan.task_id
            SCAN_STATUS = scan.scan_status
            SCAN_DATA = scan.scan_data
            SCAN_INFO = scan.info


        # STEP [ 2 ] : =================== Get the scan status from the celery worker if scan is not completed yet ======================
        console.print(f"SCAN_STATUS: {SCAN_STATUS} TASK_ID: {TASK_ID}",style="dim yellow")
        if (SCAN_STATUS == "pending" or SCAN_STATUS == "NOT_STARTED" or SCAN_DATA == {} or SCAN_STATUS == "started") and (TASK_ID != None) and (TASK_ID != ""):
            FETCHED_SCAN_STATUS , FETCHED_SCAN_DATA , scan = get_status_and_update_db(
                scan_id=scan_id,
                task_id=TASK_ID,
                table=Scan,
                engine=engine
            )
            SCAN_STATUS = FETCHED_SCAN_STATUS if FETCHED_SCAN_STATUS else SCAN_STATUS
            SCAN_DATA = FETCHED_SCAN_DATA if FETCHED_SCAN_DATA else SCAN_DATA
            # I-13: get_status_and_update_db may have just written scan.info={"error":...} on a
            # failure transition; re-read it from the updated scan so the error surfaces on THIS
            # poll instead of one poll later.
            if scan is not None:
                SCAN_INFO = scan.info

        # STEP [ 3 ] : =================== Fetching messages if scan is completed ======================
        MESSAGES = get_messages_from_scan(
            scan_id=scan_id,
            team_id=team_id,
            engine=engine,
            mongo_db=mongo_db
        )


        if not SCAN_STATUS :
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan status or scan data or messages not found")
        
        # STEP [ 4 ] : =================== Get the dashboard data ======================
        if SCAN_DATA : 
            dashboard_data = generate_scan_dashboard(scan_type=type, scan_results=SCAN_DATA ,scan_id=scan_id) # ✅ done for mcp , sbom_sca , llm , sast , iac
        else:
            dashboard_data = None

        scan_metadata = get_scan_metadata(scan_type=type, scan=scan) # ✅ done for mcp , sbom_sca , llm , sast , iac 

        findings_list = get_findings_for_scan_type(scan_type=type, scan_id=scan_id) # ✅ done for iac , sbom_sca , mcp , llm , sast 

        

        # STEP [ 4 ] : =================== Return the scan data ======================
        # Expose raw scan result as "data" so frontend can show agent view (e.g. MCP tools/prompts/resources)
        scan_result = None
        if SCAN_DATA and isinstance(SCAN_DATA, dict):
            scan_result = SCAN_DATA.get("results", SCAN_DATA)
        data = {
                "title": scan.title,
                "scan_metadata": scan_metadata,
                "scan_status": SCAN_STATUS.lower(),
                "findings": findings_list,
                "dashboard": dashboard_data,
                "messages": MESSAGES,
                "integration_settings": scan.integration_settings or {},
                "info": SCAN_INFO,
                "data": scan_result,
            }

        
        return data
        
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in get_scan: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting scan , please try again later")






def _release_scan_claim(engine, scan_id: int, team_id: int) -> None:
    """
    Release an atomic start-claim made by the /start handler.

    The /start handler atomically flips NOT_STARTED -> pending BEFORE deducting credits
    and dispatching the scan (I-1). If deduction or dispatch then fails, the scan would be
    stranded in "pending" with no task_id and could never be started again. This resets the
    claim back to NOT_STARTED, but ONLY while task_id is still None (i.e. dispatch never
    actually happened) so we never clobber a scan that did get dispatched.
    """
    try:
        with Session(engine) as session:
            session.exec(
                update(Scan)
                .where(
                    Scan.id == scan_id,
                    Scan.team_id == team_id,
                    Scan.scan_status == "pending",
                    Scan.task_id == None,
                )
                .values(scan_status="NOT_STARTED")
            )
            session.commit()
    except Exception as e:
        console.print(f"Failed to release scan claim for scan {scan_id}: {e}", style="bold red")


# revamped ✅
@router.post("/{team_id}/{type}/scan/{scan_id}/start",summary="Start a scan")
async def start_scan(
    type: scan_types,
    scan_id: int,
    team_id: int,
    start_scan_payload_string: str = Form(...),
    uploaded_file: UploadFile | None = None,
    Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Start a scan.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes

        # -----------------> get start scan payload from the json formatted string in start_scan_payload_string -----------------
        try:
            start_scan_payload = StartScanPayload.model_validate_json(start_scan_payload_string)
        except ValidationError as ve:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid start scan payload: {ve.errors()}")
        


        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)
        
        
        
        
        
        # STEP [ 2 ] : =========== Validate getting the conversation from the main db ======================
        with Session(engine) as session:
            scan = None
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if scan==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or User not allowed to start this scan")
            if scan.credit_consumed == None :
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has not been estimated yet , please estimate the credits for the scan first")
            if scan.credit_consumed == -1:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Error in estimating credits for scan , please try again later")
            if scan.owner_user_id != user.id: # only the user who created the scan can start the scan ⭐
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You do not have permission to start this scan")
            if not check_if_team_has_enough_credits(team_id, scan.credit_consumed):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Team does not have enough credits to start this scan")
            if scan.scan_status == "success" or scan.scan_status == "started" or scan.scan_data != {} or  scan.scan_status == "started" or scan.scan_status == "failure":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has already started or completed , cannot start again")
            if (scan.scan_status == "pending" or scan.scan_status == "NOT_STARTED" or scan.scan_status == "started") and (scan.task_id != None) and (scan.task_id != "") :
                FETCHED_STATUS , FETCHED_DATA , _  = get_status_and_update_db(
                    scan_id=scan_id,
                    task_id=scan.task_id,
                    table=Scan,
                    engine=engine
                )
                if FETCHED_STATUS == "success" or FETCHED_STATUS == "started" or FETCHED_STATUS == "failure" or FETCHED_STATUS == "pending" or FETCHED_DATA != {} :
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has already started or completed , cannot start again")

            scan_metadata = get_scan_metadata_for_type(type, start_scan_payload)
            if scan_metadata == None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Error in getting scan metadata")

            # STEP [ 2.5 ] : =========== ATOMIC CLAIM (I-1) ====================== ⭐
            # TOCTOU fix: the read-based "already started" checks above can let two concurrent
            # /start requests both pass and both deduct + dispatch (double-charge / duplicate scan).
            # Atomically compare-and-set NOT_STARTED -> pending BEFORE any deduct/dispatch.
            # Only the single request that flips the row (rowcount == 1) wins the right to charge
            # and dispatch; all losers get a 400. task_id == None ensures we never re-claim a scan
            # that was already dispatched. A failed scan stays at "failure" (never reset to
            # NOT_STARTED), so this preserves the existing "cannot re-run after failure" behavior.
            claim_result = session.exec(
                update(Scan)
                .where(
                    Scan.id == scan_id,
                    Scan.team_id == team_id,
                    Scan.scan_status == "NOT_STARTED",
                    Scan.task_id == None,
                )
                .values(scan_status="pending")
            )
            session.commit()
            if claim_result.rowcount == 0:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has already started or is not ready")

            # Winner of the claim: persist metadata and proceed to deduct + dispatch.
            session.refresh(scan)
            scan.scan_metadata = scan_metadata
            scan.last_updated = datetime.now(timezone.utc) # updating last_updated field
            session.add(scan)
            session.commit()
            # Capture credits while session is open; scan is detached after the block exits
            credits_to_deduct = scan.credit_consumed
        


        # STEP [ 3 ] : =========== Deduct credits BEFORE dispatching scan (atomic with check) ====================== ⭐
        # SECURITY FIX: Deduct credits first to prevent race condition where scan runs without payment.
        # If deduction fails (e.g. a concurrent spend drained the balance after our pre-check),
        # release the atomic claim so the scan can be started again later.
        try:
            deduct_credits_from_team(team_id=team_id, credits=credits_to_deduct)
        except Exception as deduct_error:
            console.print(f"Credit deduction failed after claim, releasing claim for scan {scan_id}", style="bold yellow")
            _release_scan_claim(engine=engine, scan_id=scan_id, team_id=team_id)
            raise deduct_error



        # STEP [ 4 ] : =========== Start the scan and update the main db ======================
        try:
            await start_scan_and_update_db(
                scan_id=scan_id,
                start_scan_payload=start_scan_payload,
                team_id=team_id,
                engine=engine,
                scan_type=type,
                uploaded_file=uploaded_file,
            )
        except Exception as scan_dispatch_error:
            # Refund credits if scan dispatch fails
            console.print(f"Scan dispatch failed, refunding {credits_to_deduct} credits to team {team_id}", style="bold yellow")
            try:
                refund_credits_to_team(team_id=team_id, credits=credits_to_deduct)
            except Exception as refund_err:
                console.print(f"CRITICAL: Failed to refund credits after scan dispatch failure: {refund_err}", style="bold red")
            # Release the atomic claim so the scan is not stranded in "pending" and can be retried.
            _release_scan_claim(engine=engine, scan_id=scan_id, team_id=team_id)
            raise scan_dispatch_error

        return {
            "message": "Scan started successfully",
        }
    except Exception as e:
        console.print(f"Error in starting {type} scan: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in starting scan , please try again later")







# revamped ✅
@router.delete("/{team_id}/{type}/scan/{scan_id}",summary="Delete a scan conversation")
async def delete_scan(
    type: scan_types, 
    scan_id: int, 
    team_id: int, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Delete a scan.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        

        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 2 ] : =========== Delete the scan from the main db ======================
        # D-1 (IDOR fix): authorize the scan (team + type + owner) BEFORE deleting any of its
        # data. Previously the mongo scan_findings delete_many ran before this check, so an
        # attacker in any team could wipe another team's findings by enumerating global scan ids
        # and still receive a 404 that masked the destruction.
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if scan==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for specified team and scan id")
            if scan.owner_user_id != user.id: # only the user who created the scan can delete the scan ⭐
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You do not have permission to delete this scan")
            session.delete(scan)
            session.commit()
        console.print(f"Scan id: {scan.id} deleted from main database" ,style="bold orange3")

        # deleting scan findings for this scan (only AFTER ownership is confirmed above)
        scan_findings_collection = mongo_db["scan_findings"]
        result = scan_findings_collection.delete_many({"scan_id": scan_id})
        console.print(f"{result.deleted_count} Scan findings with scan_id: {scan_id} deleted from mongo db" ,style="bold orange3")

        
        # STEP [ 3 ] ------------------ Delelte messages with scan_id -----------------------------
        message_collection = mongo_db["message_log"]
        result = message_collection.delete_many({"scan_id": scan_id})
        console.print(f"{result.deleted_count} Messages with scan_id: {scan_id} deleted from mongo db" ,style="bold orange3")


        # STEP [ 4 ] ------------------ Delete active context with scan_id -----------------------------
        active_context_collection = mongo_db["active_context"]
        result = active_context_collection.delete_many({"scan_id": scan_id})
        console.print(f"{result.deleted_count} Active context with scan_id: {scan_id} deleted from mongo db" ,style="bold orange3")



        console.print(f"Scan id: {scan.id} deleted from main database and scan id: {scan_id} deleted along with messages from mongo db" ,style="bold green")
        return {
            "message": "Scan deleted successfully",
        }
            
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in deleting scan with id: {scan_id} for team: {team_id}: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in deleting scan , please try again later")

    




# revamped ✅
@router.put("/{team_id}/{type}/scan/{scan_id}",summary="Update a scan . Use this for renaming the scan")
async def update_scan(
    type: scan_types, 
    scan_id: int, 
    team_id: int,
    data: UpdateScanData, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)],
):
    """
    Update a scan. ( rename the scan )
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        
        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 2 ] : =========== Update the main db scan the title ======================
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for specified team and scan id")
            if scan.owner_user_id != user.id: # only the user who created the scan can update the scan ⭐
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You do not have permission to update this scan")
            
            
            if data.title is not None:
                scan.title = data.title

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
                    if scan.integration_settings is not None:
                        settings_dict = scan.integration_settings.copy() or {}
                    else:
                        settings_dict = {}
                    settings_dict["jira"] = specific_settings_dict["jira"]
                    console.print(settings_dict, style="bold yellow")
                    scan.integration_settings= settings_dict
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return {
                "message": "Scan title updated successfully",
            }
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in updating scan with id: {scan_id} for team: {team_id}: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in updating scan , please try again later")






# revamped ✅
@router.get("/{team_id}/{type}/scan/{scan_id}/export",summary="Export the results of a scan")
async def export_scan(
    type: scan_types, 
    scan_id: int, 
    team_id: int,
    background_tasks: BackgroundTasks,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)] ,
    ):
    """
    Export the results of a scan.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        
        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)
        
        
        # STEP [ 2 ] : ======================= Get the conversation from main db and check if export_results is already populated ========================================
        scan = None
        scan_data = None
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for specified team and scan id")
            if scan.scan_status not in ["success"]:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has not completed yet or failed, cannot export results")
            if scan.scan_data and "results" in scan.scan_data:
                scan_data = scan.scan_data["results"]
            else :
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan data not found for specified team and scan id")

        
        
        # STEP [ 3 ] : =========================== create a temp pdf file to create the exported scan data pdf ========================================
        temp_pdf_file = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
        temp_pdf_path = temp_pdf_file.name
        temp_pdf_file.close()
        generate_pdf_for_type(type, scan_data, temp_pdf_path)


        # STEP [ 4 ] : =========================== return the pdf file as a response and schedule cleanup ========================================
        background_tasks.add_task(os.unlink, temp_pdf_path)
        return FileResponse(temp_pdf_path, media_type="application/pdf")
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in exporting scan with id: {scan_id} for team: {team_id}: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in exporting scan , please try again later")





# revamped ✅
@router.post("/{team_id}/{type}/scan/{scan_id}/reinitialize",summary="Reinitialize a scan")
async def reinitialize_scan(
    type: scan_types,
    scan_id: int, 
    team_id: int,
    start_scan_payload_string: str = Form(...),
    uploaded_file: UploadFile | None = None,
    Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Reinitialize a scan.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes

        # -----------------> get start scan payload from the json formatted string in start_scan_payload_string -----------------
        try:
            start_scan_payload = StartScanPayload.model_validate_json(start_scan_payload_string)
        except ValidationError as ve:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid start scan payload: {ve.errors()}")

        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)
        

        
        
        # STEP [ 2 ] : =========== Validate getting the conversation from the main db ======================
        with Session(engine) as session:
            scan = None
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if scan==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or User not allowed to start this scan")
            if scan.scan_status != "pending" : 
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan is not pending, cannot reinitialize")
            if scan.owner_user_id != user.id: # only the user who created the scan can reinitialize the scan ⭐
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You do not have permission to reinitialize this scan")
            
        
        # STEP [ 3 ] : =========== Reinitialize the scan and update the main db ======================
        await start_scan_and_update_db(
            scan_id=scan_id,
            start_scan_payload=start_scan_payload,
            team_id=team_id,
            engine=engine,
            scan_type=type,
            uploaded_file=uploaded_file,
        )

        return {
            "message": "Scan reinitialized successfully",
        }
    except Exception as e:
        console.print(f"Error in reinitializing {type} scan: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in reinitializing scan , please try again later")





# new route ✅
@router.post("/{team_id}/{type}/scan/{scan_id}/estimate_credits",summary="Estimate the credits for a scan")
async def estimate_credits_for_scan(
    type: scan_types,
    scan_id: int, 
    team_id: int,
    start_scan_payload_string: str = Form(...),
    uploaded_file: UploadFile | None = None,
    Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Estimate the credits for a scan.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes

        # -----------------> get start scan payload from the json formatted string in start_scan_payload_string -----------------
        try:
            start_scan_payload = StartScanPayload.model_validate_json(start_scan_payload_string)
        except ValidationError as ve:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid start scan payload: {ve.errors()}")

        console.print(f"Start scan payload: {start_scan_payload}",style="bold yellow")


        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)
        
        
        
        # STEP [ 2 ] : =========== Validate getting the scan from the main db ======================
        with Session(engine) as session:
            scan = None
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if scan==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or User not allowed to start this scan")
            if scan.owner_user_id != user.id: # only the user who created the scan can estimate the credits for the scan ⭐
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You do not have permission to estimate the credits for this scan")
            if scan.scan_status != "NOT_STARTED":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User cannot estimate credits")
        
        
        
        # STEP [ 3 ] : =========== Estimate the credits for the scan and update the main db ======================
        console.print(f"Estimating credits for {type} scan. start scan payload: {start_scan_payload}" ,style="bold yellow")
        credits_required = await estimate_credits(
            scan_type=type,
            engine=engine,
            start_scan_payload=start_scan_payload,
            uploaded_file=uploaded_file,
        )

        # STEP [ 4 ] : =========== Update the main db scan the credit_consumed ======================
        update_scan_credit_consumed(scan_id=scan_id, credits_consumed=credits_required)
        console.print(f"Credits required for {type} scan: {credits_required} updated in main database" ,style="dim cyan")

        return {
            "credits_required": credits_required,
        }
    except Exception as e:
        console.print(f"Error in estimating credits for {type} scan: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in estimating credits for scan , please try again later")


# revamped ✅
@router.post("/{team_id}/{type}/scan/{scan_id}/create_ticket",summary="Create a ticket for a scan")
async def create_ticket(
    type: scan_types, 
    scan_id: int, 
    team_id: int,
    data: CreateTicketData,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)] ,
    ):
    """
    Create a ticket for a scan.
    """
    try:
         # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)


        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 2 ] : ============= get Team and Scan from the main db ======================
        scan , team = None, None
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for specified team and scan id")
            if scan.scan_status not in ["success"]:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has not completed yet or failed, cannot create ticket")
            if scan.integration_settings is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan does not have any integration settings, cannot create ticket")
            
            team = scan.team
            if not team:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found for specified scan")
            if not team.integration_settings or team.integration_settings == {}:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Team does not have any integration settings, cannot create ticket")
            
        
        # STEP [ 3 ] : ============= create the ticket ======================
        if data.ticket_type == "jira":
            if "jira" not in team.integration_settings or "jira" not in scan.integration_settings:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira integration settings are not found, cannot create ticket")
            
            jira_project_id = scan.integration_settings["jira"]["jira_project_id"]
            jira_api_token_raw = team.integration_settings["jira"]["api_token"]
            # SECURITY: Decrypt api_token if encrypted (supports both encrypted and legacy plaintext)
            jira_api_token = decrypt_value(jira_api_token_raw) if is_encrypted(jira_api_token_raw) else jira_api_token_raw
            jira_api_url = team.integration_settings["jira"]["url"]
            jira_api_email = team.integration_settings["jira"]["email"]

            if not jira_project_id or not jira_api_token or not jira_api_url or not jira_api_email:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Jira project id, api token, url or email is missing, cannot create ticket")

            create_issue_in_jira(
                project_id=jira_project_id,
                jira_token=jira_api_token,
                jira_url=jira_api_url,
                jira_email=jira_api_email,
                summary=data.summary,
                description=data.description,
            )

            return {
                "message": "Ticket created successfully",
            }

    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in creating ticket for {type} scan: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in creating ticket for scan , please try again later")


@router.post("/{team_id}/{type}/scan/{scan_id}/finding",summary="Toggle finding state between fixed | ignored | in_progress | not_started ") 
async def toggle_finding_state(
    type: scan_types,
    scan_id: int,
    team_id: int,
    data: ToggleFindingStateData,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)] ,
    ):
    """
    Toggle finding state between fixed | ignored | in_progress | not_started 
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        mongo_db = get_mongo_client_db()

        # STEP [ 1 ] : =========== Check if user is admin of team ======================
        check_if_user_is_admin_of_team(user.id, team_id, engine)

        # STEP [ 1.5 ] : === Authorize: scan must belong to this team (prevent cross-tenant IDOR) ===
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for this team")

        # STEP [ 2 ] : ================= update scan finding in mongo db ======================
        if data.state not in ["fixed" , "ignored" , "in_progress" , "not_started"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid finding state")

        try:
            finding_oid = ObjectId(data.finding_id)
        except (InvalidId, TypeError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid finding id")

        scan_findings_collection = mongo_db["scan_findings"]
        # The finding must belong to the (team-owned) scan referenced in the path.
        target_finding = scan_findings_collection.find_one({"_id": finding_oid})
        if not target_finding or target_finding.get("scan_id") != scan_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found for this scan")

        if data.state == "fixed":
            scan_findings_collection.update_one({"_id": finding_oid}, {"$set": {"finding_status": data.state, "fixed_at": datetime.now(timezone.utc)}})
        elif data.state == "ignored":
            scan_findings_collection.update_one({"_id": finding_oid}, {"$set": {"finding_status": data.state, "ignored_at": datetime.now(timezone.utc)}})
        else:
            scan_findings_collection.update_one({"_id": finding_oid}, {"$set": {"finding_status": data.state}})
        console.print(f"Finding state updated for {data.finding_id} to {data.state}",style="bold green")

        return {
            "message": f"Finding state updated successfully for finding id: {data.finding_id} to {data.state}",
        }


    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in toggling finding state for {type} scan: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in toggling finding state for scan , please try again later")


@router.post("/{team_id}/{type}/scan/{scan_id}/finding/{finding_id}/remediate",
             summary="Generate AI remediation (fix code + exploit payload) for a finding")
async def generate_finding_remediation(
    team_id: int,
    type: scan_types,
    scan_id: int,
    finding_id: str,
    Authorization: Annotated[str | None, Header()] = None,
    dependencies=[Depends(limiter)],
    ):
    """
    Generate AI remediation for a specific finding.
    Returns fix code + educational exploit payload.
    Results are cached in MongoDB — subsequent calls return the stored result.
    """
    from backend.utilities.ai.remediation import generate_remediation

    try:
        # STEP [ 0 ] : =========== Auth + team check ======================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        check_if_user_is_in_team(user.id, team_id, engine)

        # === Authorize: scan must belong to this team (prevent cross-tenant IDOR) ===
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id).where(Scan.scan_type == type)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for this team")

        try:
            finding_oid = ObjectId(finding_id)
        except (InvalidId, TypeError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid finding id")

        # STEP [ 1 ] : =========== Fetch finding from MongoDB ======================
        scan_findings_collection = mongo_db["scan_findings"]
        finding = scan_findings_collection.find_one({"_id": finding_oid})
        if not finding:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
        if finding.get("scan_id") != scan_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Finding does not belong to this scan")

        # STEP [ 2 ] : =========== Check if remediation already exists (cache hit) ======================
        existing_remediation = finding.get("remediation")
        if existing_remediation and existing_remediation.get("status") == "completed":
            console.print(f"Remediation cache hit for finding {finding_id}", style="dim green")
            return existing_remediation

        # STEP [ 3 ] : =========== Credit check (0.05 per remediation) ======================
        REMEDIATION_CREDIT_COST = 0.05
        if not check_if_team_has_enough_credits(team_id, REMEDIATION_CREDIT_COST):
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="Team does not have enough credits for remediation generation",
            )

        # STEP [ 4 ] : =========== Generate remediation ======================
        finding_data = finding.get("finding_data", {})
        remediation_result = generate_remediation(finding_data, type)

        # STEP [ 5 ] : =========== Atomic store + deduct (prevent double-deduction) ======================
        if remediation_result.get("status") == "completed":
            # Use MongoDB findOneAndUpdate to atomically set remediation only if not already set
            update_result = scan_findings_collection.update_one(
                {"_id": ObjectId(finding_id), "remediation.status": {"$ne": "completed"}},
                {"$set": {"remediation": remediation_result}},
            )
            if update_result.modified_count > 0:
                # Only deduct credits if we were the one to write the remediation
                deduct_credits_from_team(team_id, REMEDIATION_CREDIT_COST)
                console.print(f"Remediation stored and credits deducted for finding {finding_id}", style="bold green")
            else:
                console.print(f"Remediation already stored by concurrent request for finding {finding_id}", style="dim yellow")
                # Return the already-stored remediation
                updated_finding = scan_findings_collection.find_one({"_id": ObjectId(finding_id)})
                if updated_finding and updated_finding.get("remediation"):
                    return updated_finding["remediation"]
        else:
            # Non-completed remediation, just store without deducting
            scan_findings_collection.update_one(
                {"_id": ObjectId(finding_id)},
                {"$set": {"remediation": remediation_result}},
            )
            console.print(f"Remediation (non-completed) stored for finding {finding_id}", style="bold yellow")

        return remediation_result

    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error generating remediation for finding {finding_id}: {e}", style="bold red")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error generating remediation, please try again later",
        )