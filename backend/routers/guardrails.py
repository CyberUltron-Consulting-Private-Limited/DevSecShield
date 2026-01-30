import datetime
from typing import Annotated
from fastapi import  APIRouter, HTTPException, Header, status, BackgroundTasks, Depends
from sqlmodel import Session, select
from rich.console import Console
from backend.utilities.db.functions import * 
from backend.utilities.guardrails.auth import create_api_key
from backend.utilities.guardrails.schemas import CreateGuardrailsIntegrationData, UpdateGuardrailsIntegrationData
from backend.utilities.auth.auth_utils import *
from fastapi_throttle import RateLimiter
from backend.get_db import get_db , get_mongo_client_db

console = Console()
dev_environment = True # for local development

router = APIRouter(prefix="/guardrails",tags=["Guardrails"])


limiter = RateLimiter(times=20, seconds=30) # 20 requests per 30 seconds
@router.get("/integrations",summary="List all guardrails conversations")
async def list_guardrails_integrations( background_tasks: BackgroundTasks, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    List all guardrails integrations.
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        
        with Session(engine) as session:
            statement = select(GuardrailsIntegration).where(GuardrailsIntegration.user_id == user.id)
            integrations = session.exec(statement).all()
        
        response_data = []
        
        for integration in integrations:
            response_data.append({
                "id": integration.id,
                "title": integration.title,
                "scanners_enabled": list(integration.settings.keys()),
                "api_key": integration.api_key,
                "created_at": integration.created_at,
                "last_updated": integration.last_updated
            })
        return response_data
    except Exception as e:
        console.print(f"Error fetching guardrails integrations: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Error fetching guardrails integrations")

@router.post("/integration",summary="Create a new guardrails integration")
async def create_guardrails_integration(data: CreateGuardrailsIntegrationData, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Create a new guardrails integration.
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        with Session(engine) as session:
            api_key = create_api_key(user.id)
            new_integration = GuardrailsIntegration(
                user_id=user.id,
                title=data.title,
                api_key=api_key,
            )
            session.add(new_integration)
            session.commit()
            session.refresh(new_integration)
            return {
                "message": "Guardrails integration created successfully",
                "integration_id": new_integration.id
            }
    except Exception as e:
        console.print(f"Error creating guardrails integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Error creating guardrails integration")

@router.get("/integration/{integration_id}",summary="Get a guardrails integration")
async def get_guardrails_integration(integration_id: int, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Get a guardrails integration dashboard data
    Run a scan status update for all the scans in this integration 
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine , Authorization)

        # STEP [ 1 ] : ==================================== Get the integration from the main database ====================================
        with Session(engine) as session:
            integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.user_id == user.id)).first()
            if integration == None or not integration.id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            integration.last_updated = datetime.datetime.now(datetime.timezone.utc)
            session.add(integration)
            session.commit()
            session.refresh(integration)
        
        # STEP [ 2 ] : ==================================== Get the integration logs from the mongo db ====================================
        guardrails_logs_collection = mongo_db["guardrails_logs"]
        guardrails_logs = guardrails_logs_collection.find(
            {"$and": [{"integration_id": integration_id}, {"status": {"$in": ["pending", "started", "NOT_STARTED" , "success"]}}]}
        ) # including success because sometimes the scan  might have comepleted quickly and we might need to get results after status is success            
    
        

        # STEP [ 3 ] : ======================================= Cycle through the logs and see if there are any tasks that need status update =======================================
        celery_app = get_celery_app()
        result , status = None, None
        for log in guardrails_logs:
            console.print(f"Guardrails log {log['_id']} , status: {log['status']} , results is None: {log['results']==None}", style="bold yellow")

            # if status is not success , get new status and update ( if new status is success , get results also and update )
            if log["status"] != "success":
                console.print(f"Guardrails log {log['_id']}", style="bold yellow")
                task_id = log["task_id"]
                status = AsyncResult(task_id, app=celery_app).status.lower()
                if status == "success":
                    result = AsyncResult(task_id, app=celery_app).result
                    guardrails_logs_collection.update_one({"_id": log["_id"]}, {"$set": {"results": result , "status": status}})
                    console.print(f"Guardrails log {log['_id']} updated with scan status {status} and results successfully", style="bold green")
                else:
                    guardrails_logs_collection.update_one({"_id": log["_id"]}, {"$set": {"status": status}})
                    console.print(f"Guardrails log {log['_id']} updated with scan status {status}", style="bold green")



        # STEP [ 4 ] : =========================================Fetch and Calculate Metrics =======================================================================
        total_logs , successful_logs , failed_logs , pending_logs , started_logs , not_started_logs = 0 , 0 , 0 , 0 , 0 , 0 
        log_data = []
        with guardrails_logs_collection.find({"integration_id": integration_id}).sort("created_at", -1) as cursor:
            for log in cursor:
                total_logs += 1
                log_data.append({
                    "id": str(log["_id"]),
                    "status": log["status"],
                    "created_at": log["created_at"],
                    "input_prompt": log["input_prompt"],
                    "results": log["results"],
                })
                if log["status"] == "success":
                    successful_logs += 1
                elif log["status"] == "failed":
                    failed_logs += 1
                elif log["status"] == "pending":
                    pending_logs += 1
                elif log["status"] == "started":
                    started_logs += 1
                elif log["status"] == "NOT_STARTED":
                    not_started_logs += 1
                    

        return {
            "total_logs": total_logs,
            "successful_logs": successful_logs,
            "failed_logs": failed_logs,
            "pending_logs": pending_logs,
            "started_logs": started_logs,
            "not_started_logs": not_started_logs,
            "api_key": integration.api_key,
            "log_data": log_data,
            "settings": integration.settings
        }
    
    except Exception as e:
        console.print(f"Error getting guardrails integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Error getting guardrails integration")

@router.put("/integration/{integration_id}",summary="Update a guardrails integration")
async def update_guardrails_integration(integration_id: int, data: UpdateGuardrailsIntegrationData, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Update a guardrails integration.
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        

        with Session(engine) as session:
            integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.user_id == user.id)).first()
            if integration == None or not integration.id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            if data.title is not None:
                integration.title = data.title
            if data.settings is not None:
                integration.settings = data.settings.model_dump()
            session.add(integration)
            session.commit()
            return {
                "message": f"Guardrails integration {integration_id} updated successfully"
            }
    except Exception as e:
        console.print(f"Error updating guardrails integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Error updating guardrails integration")

@router.delete("/integration/{integration_id}",summary="Delete a guardrails integration")
async def delete_guardrails_integration(integration_id: int, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Delete a guardrails integration.
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine , Authorization)

        # deleting the integration from the main database
        with Session(engine) as session:
            integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.user_id == user.id)).first()
            if integration == None or not integration.id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            session.delete(integration)
            session.commit()
        console.print(f"Guardrails integration {integration_id} deleted from main database", style="bold green")

        # deleting the integration logs from the mongo db
        guardrails_logs_collection = mongo_db["guardrails_logs"]
        response = guardrails_logs_collection.delete_many({"integration_id": integration_id})
        console.print(f"Guardrails integration logs {integration_id} deleted from mongo db {response.deleted_count} logs deleted", style="bold green")

        return {
            "message": f"Guardrails integration {integration_id} deleted successfully"
        }

    except Exception as e:
        console.print(f"Error deleting guardrails integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Error deleting guardrails integration")

@router.get("/integration/{integration_id}/settings",summary="Get the integration settings of all the scanners in the integration")
async def get_guardrails_integration_settings(integration_id: int, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)] ):
    """
    Get the integration settings of all the scanners in the integration.
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await  get_user_from_header_or_raise_exception(engine , Authorization)
        with Session(engine) as session:
            integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.user_id == user.id)).first()
            if integration == None or not integration.id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            return {
                "settings": integration.settings
            }
    except Exception as e:
        console.print(f"Error getting guardrails integration settings: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Error getting guardrails integration settings")