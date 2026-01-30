import datetime
import tempfile
from typing import Annotated

from bson import ObjectId
from fastapi import APIRouter
from fastapi import BackgroundTasks, Depends, HTTPException, Header, status
from fastapi.responses import FileResponse
from fastapi_throttle import RateLimiter
from sqlmodel import Session, select

from backend.get_db import get_db, get_mongo_client_db
from backend.mongo_models import ActiveContextLog, MessageLog
from backend.new_models import Scan
from backend.utilities.team.credits import deduct_credits_from_team_for_message
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
# from backend.utilities.celery.celery_connection import get_status_and_update_db
from backend.utilities.db.functions import *
from backend.utilities.db.metadata import get_scan_metadata_for_type
from backend.utilities.pdf import generate_pdf_for_type
from backend.utilities.ai.chatbot import create_response
from backend.utilities.team import (
    check_if_user_is_admin_of_team,
    check_if_user_is_in_team,
)
from backend.utilities.scan.start_scan import start_scan_and_update_db
from backend.utilities.scan.estimate_scan import estimate_credits
from backend.utilities.team.credits import check_if_team_has_enough_credits , deduct_credits_from_team , update_scan_credit_consumed



dev_environment = True # for local development ⚠️⚠️⚠️⚠️

router = APIRouter(
    tags=["scans"]
)   


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
        engine = get_db(dev_environment=dev_environment)
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
            scans_list_data,scans_list_to_update = return_scan_list_for_type(scans=scans)

            if len(scans_list_to_update) > 0:
                background_tasks.add_task(update_status_of_scan_in_main_db, scans = scans_list_to_update, engine = engine)
                console.print(f"Background task added to update statuses of scans: {scans_list_to_update}" ,style="bold green")
            
            return scans_list_data

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
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
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
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes

        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)


        SCAN = None
        SCAN_DATA = {}
        SCAN_STATUS = None


        # STEP [ 1 ] : =========== Get the conversation from the main db ======================
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if not scan:
                console.print(f"Scan with id: {scan_id} and team_id: {team_id} not found in main database" ,style="bold red")
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found ")
            
            scan.last_updated = datetime.datetime.now(datetime.timezone.utc) # updating last_updated field
            session.commit()
            session.refresh(scan)
            
            SCAN = scan
            SCAN_STATUS = scan.scan_status
            SCAN_DATA = scan.scan_data
        

        if SCAN.owner_user_id != user.id: # only the user who created the scan can send messages to the scan 
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to send messages to this scan")
        if not SCAN:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        if not SCAN_DATA or SCAN_DATA == {} or SCAN_STATUS == "pending" or SCAN_STATUS == "NOT_STARTED" or SCAN_STATUS == "started" or SCAN_STATUS != "success":
            return { "content" : "Scan has not run or hasn't completed yet, please wait for the scan to complete if it has been initiated or start the scan" }

        
        
        # STEP [ 3 ] : =========== Add the user message to the mongo db ====================== ⭐
        message_collection = mongo_db["message_log"]
        message_instance = MessageLog(
            scan_id=SCAN.id,
            content=data.user_message,
            type="message",
            sender="user",
            created_at=datetime.datetime.now(datetime.timezone.utc),
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
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        result = active_context_collection.insert_one(active_context_instance)
        active_context_message_id = str(result.inserted_id)
        console.print(f"User message added to active context log with id: {active_context_message_id}" ,style="dim green")


        
        
        
        # STEP [ 5 ] : =========== Get the response from the model ======================
        AI_RESPONSE = await create_response(
            scan_id=SCAN.id,
            scan_type=type,
            scan_results=SCAN_DATA,
            history=[],
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
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
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
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
            TASK_ID = scan.task_id
            SCAN_STATUS = scan.scan_status
            SCAN_DATA = scan.scan_data


        # STEP [ 2 ] : =================== Get the scan status from the celery worker if scan is not completed yet ======================
        console.print(f"SCAN_STATUS: {SCAN_STATUS} TASK_ID: {TASK_ID}",style="bold yellow",style="dim yellow")
        if (SCAN_STATUS == "pending" or SCAN_STATUS == "NOT_STARTED" or SCAN_DATA == {} or SCAN_STATUS == "started") and (TASK_ID != None) and (TASK_ID != ""):
            FETCHED_SCAN_STATUS , FETCHED_SCAN_DATA , scan = get_status_and_update_db(
                scan_id=scan_id,
                task_id=TASK_ID,
                table=Scan,
                engine=engine
            )
            SCAN_STATUS = FETCHED_SCAN_STATUS if FETCHED_SCAN_STATUS else SCAN_STATUS
            SCAN_DATA = FETCHED_SCAN_DATA if FETCHED_SCAN_DATA else SCAN_DATA
        
        # STEP [ 3 ] : =================== Fetching messages if scan is completed ======================
        MESSAGES = get_messages_from_scan(
            scan_id=scan_id,
            team_id=team_id,
            engine=engine,
            mongo_db=mongo_db
        )


        if not SCAN_STATUS :
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan status or scan data or messages not found")
        

        
        # STEP [ 4 ] : =================== Return the scan data ======================
        return {
                "title": scan.title,
                "scan_metadata": scan.scan_metadata,
                "scan_status": SCAN_STATUS.lower(),
                "data": SCAN_DATA,
                "messages": MESSAGES,
            }
        
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in get_scan: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting scan , please try again later")






# revamped ✅
@router.post("/{team_id}/{type}/scan/{scan_id}/start",summary="Start a scan")
async def start_scan(
    type: scan_types,
    scan_id: int, 
    team_id: int,
    start_scan_payload: StartScanPayload,
    Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Start a scan.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        


        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)
        
        
        
        
        # STEP [ 2 ] : =========== Validate getting the conversation from the main db ======================
        with Session(engine) as session:
            scan = None
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if scan==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or User not allowed to start this scan")
            if scan.credit_consumed == None or scan.credit_consumed == 0 :
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has not been estimated yet , please estimate the credits for the scan first")
            if scan.owner_user_id != user.id: # only the user who created the scan can start the scan ⭐
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to start this scan")
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
        
        


        # STEP [ 3 ] : =========== Start the scan and update the main db ======================
        start_scan_and_update_db(
            scan_id=scan_id,
            start_scan_payload=start_scan_payload,
            team_id=team_id,
            engine=engine,
            scan_type=type,
        )



        # STEP [ 4 ] : =========== Deduct credits for scan for team  ====================== ⭐
        deduct_credits_from_team(team_id=team_id, credits=scan.credit_consumed)

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
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        

        # STEP [ 1 ] : =========== Check if user is admin of team ======================
        check_if_user_is_admin_of_team(user.id, team_id, engine)

        # STEP [ 2 ] : =========== Delete the scan from the main db ======================
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if scan==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for specified team and scan id")
            if scan.owner_user_id != user.id: # only the user who created the scan can delete the scan ⭐
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to delete this scan")
            session.delete(scan)
            session.commit()
        console.print(f"Scan id: {scan.id} deleted from main database" ,style="bold orange3")

        
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
        engine = get_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        
        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 2 ] : =========== Update the main db scan the title ======================
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for specified team and scan id")
            if scan.owner_user_id != user.id: # only the user who created the scan can update the scan ⭐
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to update this scan")
            scan.title = data.title
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
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)] ,
    ):
    """
    Export the results of a scan.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        
        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)
        
        
        # STEP [ 2 ] : ======================= Get the conversation from main db and check if export_results is already populated ========================================
        scan = None
        scan_data = None
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for specified team and scan id")
            if scan.scan_status not in ["success"]:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has not completed yet or failed, cannot export results")
            if scan.scan_data:
                scan_data = scan.scan_data

        
        
        # STEP [ 3 ] : =========================== create a temp pdf file to create the exported scan data pdf ========================================
        temp_pdf_file = tempfile.NamedTemporaryFile(suffix=".pdf",mode="w+",delete=False)
        temp_pdf_file.close()
        generate_pdf_for_type(type, scan_data, temp_pdf_file.name)


        # STEP [ 4 ] : =========================== return the pdf file as a response ========================================
        return FileResponse(temp_pdf_file.name, media_type="application/pdf")
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in exporting scan with id: {scan_id} for team: {team_id}: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in exporting scan , please try again later")
    finally:
        temp_pdf_file.close()





# revamped ✅
@router.post("/{team_id}/{type}/scan/{scan_id}/reinitialize",summary="Reinitialize a scan")
async def reinitialize_scan(
    type: scan_types,
    scan_id: int, 
    team_id: int,
    start_scan_payload: StartScanPayload,
    Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Reinitialize a scan.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        


        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)
        

        
        
        # STEP [ 2 ] : =========== Validate getting the conversation from the main db ======================
        with Session(engine) as session:
            scan = None
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if scan==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or User not allowed to start this scan")
            if scan.scan_status != "pending" : 
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan is not pending, cannot reinitialize")
            if scan.owner_user_id != user.id: # only the user who created the scan can start the scan ⭐
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to start this scan")
            
        
        # STEP [ 3 ] : =========== Start the scan and update the main db ======================
        start_scan_and_update_db(
            scan_id=scan_id,
            start_scan_payload=start_scan_payload,
            team_id=team_id,
            engine=engine,
            scan_type=type,
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
    start_scan_payload: StartScanPayload,
    Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Estimate the credits for a scan.
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        


        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)
        


        # STEP [ 2 ] : =========== Check if team has enough credits ======================
        check_if_team_has_enough_credits(team_id=team_id, credits_required=credits_required)
        
        
        # STEP [ 3 ] : =========== Validate getting the conversation from the main db ======================
        with Session(engine) as session:
            scan = None
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if scan==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or User not allowed to start this scan")
            if scan.owner_user_id != user.id: # only the user who created the scan can start the scan ⭐
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to start this scan")
            if scan.scan_status != "NOT_STARTED":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User cannot estimate credits")
        
        
        
        # STEP [ 3 ] : =========== Estimate the credits for the scan ======================
        credits_required = estimate_credits(
            scan_type=type,
            engine=engine,
            start_scan_payload=start_scan_payload,
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

