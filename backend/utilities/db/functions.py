import datetime
from typing import Annotated, Literal
from bson import ObjectId
from celery.result import AsyncResult
from fastapi import FastAPI, HTTPException, Header, status
from sqlalchemy.engine import Engine
from sqlmodel import Sequence, Session, select
from pydantic import BaseModel, model_validator
from backend.utilities.celery.celery_connection import get_celery_app, get_status_and_update_db
from rich.console import Console
from pymongo.database import Database
import json
import time
import uuid
from backend.new_models import Scan


console = Console()

# ============================================================ Request body models ===========================================================


def stream_text(text: str):
    text_array = text.split(" ")
    id = str(uuid.uuid4())
    for word in text_array:
        data = {
                "message_id": "Not_allowed_" + id,
                "content": word + " ",
                "reasoning": "",
            }
        yield json.dumps(data)
        time.sleep(0.1)

# ====================================================== functions for fetching data ===========================================================


# revamped ✅
def get_messages_from_scan(
    scan_id: int,
    team_id: int, 
    engine: Engine, 
    mongo_db: Database):
    """
    Returns the messages from the scan.
    If messages not found , raise an exception.
    """
    try:

        # STEP [ 1 ] : =========== get the scan from the main db to get the scan id ======================
        scan = None
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        console.print(f"Scan id: {scan.id} found in main database" ,style="bold green")
        

        # STEP [ 2 ] : =========== return the messages from the mongo db ======================
        with mongo_db["message_log"].find({"scan_id": scan.id}).sort("created_at", 1) as messages:
            messages_data = []
            i = 0
            for message in messages:
                messages_data.append({
                    "id": i,
                    "content": message["content"],
                    "role": message["sender"],
                    "timestamp": message["created_at"] ,
                    "is_streaming": False,
                })
                i += 1
            console.print(f"{len(messages_data)} messages found for scan: {scan.id}" ,style="bold green")
            return messages_data

        
    except Exception as e:
        console.print(f"Error in get_messages_from_scan: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in fetching messages from scan , please try again later")





# revamped ✅
# ======================================= functions for assembling output data for different types of conversations ======================
def return_scan_list_for_type(
    sequence : Sequence[Scan]
    )->tuple[list[dict],list[tuple[int,str]]]:
    """
    Returns a tuple of two lists.
    - The first list contains the data for each scan.
    - The second list contains the ids and task ids of the scans that need to be updated.
    scans list to update example  : [(scan_id,task_id)]
    """

    try:
        scans_list_data = []
        scans_to_update = []
        
        for scan in sequence:
            if (scan.scan_status == "pending" or scan.scan_status == "started") and scan.task_id:
                scans_to_update.append((scan.id,scan.task_id))
            scans_list_data.append({
                "id": scan.id,
                "scan_metadata": scan.scan_metadata,
                "title": scan.title,
                "created_at": scan.created_at,
                "last_updated": scan.last_updated,
                "scan_status": scan.scan_status.lower(),
                "owner_user_email": scan.owner_user.email,
                "owner_user_full_name": f"{scan.owner_user.first_name} {scan.owner_user.last_name}",
            })

        return (scans_list_data,scans_to_update)
    
    except Exception as e:
        console.print(f"Error in return_scan_list_for_type: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in returning scan list , please try again later")




# ======================================================= background task for updating statuses of conversations in main db ======================================================
# revamped ✅
def update_status_of_scan_in_main_db(
    scans: list[(int,str)], 
    engine: Engine):
    try:
        console.print(f"Updating statuses of scans " ,style="bold bright_cyan")
        


        # cycle through the conversations and update the status of the conversation in main db
        for scan_id,task_id in scans:
            get_status_and_update_db(
                scan_id=scan_id, 
                task_id=task_id,
                table=Scan, 
                engine=engine)
            console.print(f"Status of scan: {scan_id} updated in main db" ,style="bold green")
    except Exception as e:
        console.print(f"Error in update_status_of_conversation_in_main_db: {e}",style="bold red")