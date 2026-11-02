"""DEPRECATED: Guardrails public API router.

The Guardrails product UI has been removed from the user-facing frontend.
Public scan endpoints remain for legacy API-key integrations. Prefer not to
expand this surface; mark any new callers as transitional.
"""

from datetime import datetime , timezone
from bson import ObjectId
from celery.result import AsyncResult
from backend.utilities.celery.celery_connection import get_celery_app
from fastapi import FastAPI, Depends, APIRouter, HTTPException, status
from sqlalchemy.engine import Engine
from pymongo.database import Database
from pydantic import BaseModel
from backend.utilities.guardrails.auth import get_user_and_integration_id
from backend.new_models import GuardrailsIntegration
from backend.mongo_models import GuardrailLogs
from sqlmodel import Session, select
from rich.console import Console
from backend.utilities.ratelimit import RateLimiter, ip_key
from backend.get_db import get_db , get_mongo_client_db
from backend.utilities.db.encryption import decrypt_if_encrypted

class StartScanData(BaseModel):
    input_prompt: str

console = Console()

router = APIRouter(tags=["Guardrails Public API (deprecated)"])


# Deprecated public API: 2 requests per 10 seconds per client address, per worker.
limiter = RateLimiter("guardrails_public", times=2, seconds=10, key_func=ip_key)


@router.post("/public/guardrails/start_scan", summary="Start a new guardrails scan", dependencies=[Depends(limiter)])
async def start_scan(data: StartScanData, user_and_integration: dict = Depends(get_user_and_integration_id)):
    """
    developer notes : 
    1. start guardrails scan and get task id 
    2. get the status of the scan task
    3. create mongo db log for this scan 
    4. update the scan task status in the database
    5. return the mongo db log id as string 
    
    """
    try:
        engine = get_db()
        mongo_db = get_mongo_client_db()

        # STEP [ 1 ] : ======================================== Get the integration from the main database ====================================
        user_id = user_and_integration["user_id"]
        integration_id = user_and_integration["integration_id"]
        console.print(f"User ID: {user_id}, Integration ID: {integration_id} has started the scan", style="bold yellow")
        if not user_id or not integration_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Guardrails API key")
        
        with Session(engine) as session:
            integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id)).first()
            if integration == None or not integration.id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            
            # getting team instance of the integration 
            team = integration.team
            if not team:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
            try:
                if "jira" in team.integration_settings and "jira" in integration.integration_settings and integration.integration_settings["jira"]["jira_project_id"] and team.integration_settings["jira"]["api_token"] and team.integration_settings["jira"]["url"] and team.integration_settings["jira"]["email"]:
                    # SECURITY: Decrypt api_token if encrypted (supports both encrypted and legacy plaintext)
                    jira_api_token_raw = team.integration_settings["jira"]["api_token"]
                    jira_api_token = decrypt_if_encrypted(jira_api_token_raw)
                    integration_kwargs = { "jira" : {
                        "jira_project_id": integration.integration_settings["jira"]["jira_project_id"],
                        "jira_api_token": jira_api_token,
                        "jira_url": team.integration_settings["jira"]["url"],
                        "jira_email": team.integration_settings["jira"]["email"],
                    }}
                else:
                    integration_kwargs = None
            except Exception as e:
                console.print(f"Error in getting integration kwargs: {str(e)}", style="bold red")
                integration_kwargs = None
            
        
        # STEP [ 2 ] : ======================================== Start the guardrails scan and get status  ====================================
        task_id , status = None , None 
        celery_app = get_celery_app()
        if not integration_kwargs:
            console.print(f"Integration kwargs not found", style="bold orange1")
        input_guardrail_kwargs = {
            "input_prompt": data.input_prompt,
            "context": integration.settings,
            "ticketing_integration_context": integration_kwargs
        }
        task = celery_app.send_task(name="guardrail_worker.input_guardrail", kwargs=input_guardrail_kwargs , queue="guardrail_worker_queue")
        task_id = task.id
        status = AsyncResult(task_id, app=celery_app).status.lower()
        if not status or not task_id:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error starting guardrails scan")

        # STEP [ 3 ] : ======================================== Create a new mongo db log ====================================
        guardrails_logs_collection = mongo_db["guardrails_logs"]
        result = guardrails_logs_collection.insert_one(GuardrailLogs(
            integration_id=integration.id,
            task_id=task.id,
            status=status,
            input_prompt=data.input_prompt,
            created_at=datetime.now(timezone.utc),
            settings=integration.settings,
            results=None,
        ))
        inserted_id = None
        if result and result.inserted_id:
            inserted_id = str(result.inserted_id)
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error creating mongo db log")
        
        # STEP [ 4 ] : ======================================== Return the inserted id ====================================
        if not inserted_id:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error creating mongo db log")
        
        
        return {
            "result_id": inserted_id,
            "status": status,
        }


    except Exception as e:
        console.print(f"Error starting guardrails scan: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Error starting guardrails scan")




@router.get("/public/guardrails/{scan_id}", summary="Get the status of a guardrails scan", dependencies=[Depends(limiter)])
async def get_scan_status(scan_id: str, user_and_integration: dict = Depends(get_user_and_integration_id)):
    """
    developer notes : 
    1. validate the scan_id , check if it is a valid mongo db object id 
    2. get the scan status from celery worker 
    3. check if scan is "success" , if yes then get the results from the celery worker
    4. update the mongo db log with the new scan status ( and results if the scan is successful )
    5. return scan status and results . ( results will be None if scan status is anything but "success")
    """
    try:
        engine = get_db()
        mongo_db = get_mongo_client_db()

        user_id = user_and_integration["user_id"]
        integration_id = user_and_integration["integration_id"]
        if not user_id or not integration_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Guardrails API key")

        # STEP [ 1 ] : ======================================== Validate the scan_id ====================================
        if not scan_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan ID is required")
        if not ObjectId.is_valid(scan_id):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan ID")
        guardrails_logs_collection = mongo_db["guardrails_logs"]
        # SECURITY FIX: Add integration_id to query to prevent IDOR (accessing other users' scans)
        log = guardrails_logs_collection.find_one({
            "_id": ObjectId(scan_id),
            "integration_id": integration_id  # Ownership check - only return if caller owns this scan
        })

        if not log:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails log not found")
    
        # STEP [ 2 ] : ======================================== Get the scan status from celery worker ====================================
        results = log["results"] if log["results"] else None

        celery_app = get_celery_app()
        status = AsyncResult(log["task_id"], app=celery_app).status.lower()

        if not status:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error getting scan status")
        console.print(f"Scan status is {status}", style="bold yellow")
        if status == "success" and log["results"] is None:
            console.print(f"Scan status is success, getting results", style="bold green")
            results = AsyncResult(log["task_id"], app=celery_app).result
            if not results:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error getting scan results")
            guardrails_logs_collection.update_one({"_id": ObjectId(scan_id)}, {"$set": {"results": results , "status": status}})
        else:
            guardrails_logs_collection.update_one({"_id": ObjectId(scan_id)}, {"$set": {"status": status}})
        
        # STEP [ 3 ] : ======================================== Return the scan status and results  ====================================
        return {
            "status": status,
            "results": results
        }

    except Exception as e:
        console.print(f"Error getting guardrails scan status: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Error getting guardrails scan status")