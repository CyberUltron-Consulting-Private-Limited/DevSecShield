"""DEPRECATED: Guardrails authenticated API router.

The Guardrails product UI has been removed from the user-facing frontend.
This router remains mounted for legacy/internal API callers. Do not add new
user-facing product surfaces that depend on these endpoints.
"""

from datetime import datetime
from datetime import timezone
from typing import Annotated
from fastapi import  APIRouter, HTTPException, Header, status, BackgroundTasks, Depends
from sqlmodel import Session, select
from rich.console import Console
from backend.utilities.celery.celery_connection import get_celery_app
from celery.result import AsyncResult
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.new_models import GuardrailsIntegration
from backend.utilities.dashboard.guardrail_integration import get_guardrails_integration_dashboard_data
from backend.utilities.dashboard.guardrails_list import create_dashboard_data_for_guardrails_list
from backend.utilities.guardrails.auth import create_api_key
from backend.utilities.guardrails.schemas import CreateGuardrailsIntegrationData, UpdateGuardrailsIntegrationData
from backend.utilities.auth.auth_utils import *
from backend.utilities.ratelimit import RateLimiter
from backend.get_db import get_db , get_mongo_client_db
from backend.utilities.team.credits import deduct_credits_from_team
from backend.utilities.team.validation import check_if_user_is_in_team
console = Console()

router = APIRouter(prefix="/guardrails", tags=["Guardrails (deprecated)"])

# revamped ✅
# Per verified user, per worker (backend/utilities/ratelimit.py).
read_limiter = RateLimiter("guardrails.read", times=120, seconds=60)
write_limiter = RateLimiter("guardrails.write", times=20, seconds=60)
@router.get("/{team_id}/integrations",summary="List all guardrails integrations for a team", deprecated=True, dependencies=[Depends(read_limiter)])
async def list_guardrails_integrations( 
    team_id: int,
    background_tasks: BackgroundTasks, 
    Authorization: Annotated[str | None, Header()] = None ):
    """
    List all guardrails integrations.
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        
        
        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)
        
        
        
        # STEP [ 3 ] : ======================================== Get the guardrails integrations for the team ====================================
        with Session(engine) as session:
            statement = select(GuardrailsIntegration).where(GuardrailsIntegration.team_id == team_id)
            integrations = session.exec(statement).all()
        
            response_data = []
            
            for integration in integrations:
                # owner_user = session.exec(select(User).where(User.id == integration.owner_user_id)).first()
                owner_user = integration.owner_user
                response_data.append({
                    "id": integration.id,
                    "title": integration.title,
                    "scanners_enabled": list(integration.settings.keys()),
                    "owner_user_email": owner_user.email,
                    "owner_user_full_name": f"{owner_user.first_name} {owner_user.last_name}",
                    "api_key": integration.api_key[:8] + "..." + integration.api_key[-4:] if len(integration.api_key) > 12 else "****",
                    "created_at": integration.created_at,
                    "last_updated": integration.last_updated
                })
            return {
                "integrations": response_data,
                "dashboard_data": create_dashboard_data_for_guardrails_list(team_id=team_id),
            }
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error fetching guardrails integrations: {str(e)}", style="bold red")
        raise HTTPException(status_code=500, detail="Error fetching guardrails integrations")



# revamped ✅
@router.post("/{team_id}/integration",summary="Create a new guardrails integration for a team", deprecated=True, dependencies=[Depends(write_limiter)])
async def create_guardrails_integration(
    team_id: int, 
    data: CreateGuardrailsIntegrationData, 
    Authorization: Annotated[str | None, Header()] = None ):
    """
    Create a new guardrails integration.
    credits required : 0.5 
    """
    try:
        # STEP [ 1 ] : ======================================== Get the database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        
        
        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)
        
        
        # STEP [ 3 ] : ======================================== Create the guardrails integration ====================================
        with Session(engine) as session:
            plaintext_api_key, hashed_api_key = create_api_key(team_id)
            new_integration = GuardrailsIntegration(
                owner_user_id=user.id,
                team_id=team_id,
                title=data.title,
                api_key=hashed_api_key,  # Store only the hash
            )
            session.add(new_integration)
            session.commit()
            session.refresh(new_integration)


        deduct_credits_from_team(team_id=team_id, credits=0.5)
        return {
            "message": "Guardrails integration created successfully",
            "integration_id": new_integration.id,
            "api_key": plaintext_api_key,  # Return plaintext ONCE, user must save it
            "warning": "Save this API key now. It will not be shown again."
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error creating guardrails integration: {str(e)}", style="bold red")
        raise HTTPException(status_code=500, detail="Error creating guardrails integration")


# revamped ✅
@router.get("/{team_id}/integration/{integration_id}",summary="Get a guardrails integration", deprecated=True, dependencies=[Depends(read_limiter)])
async def get_guardrails_integration(
    team_id: int, 
    integration_id: int, 
    Authorization: Annotated[str | None, Header()] = None ,
    limit : int = 10,
    offset : int = 0,
    ):
    """
    Get a guardrails integration dashboard data
    Run a scan status update for all the scans in this integration 
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)

        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 3 ] : ==================================== Get the integration from the main database ====================================
        with Session(engine) as session:
            integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.team_id == team_id)).first()
            if integration == None or not integration.id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            integration.last_updated = datetime.now(timezone.utc)
            session.add(integration)
            session.commit()
            session.refresh(integration)


        
        # STEP [ 4 ] : ======================================== Get the integration logs from the mongo db ====================================
        guardrails_logs_collection = mongo_db["guardrails_logs"]
        guardrails_logs = guardrails_logs_collection.find(
            {"$and": [{"integration_id": integration_id}, {"status": {"$in": ["pending", "started", "NOT_STARTED" , "success"]}}]}
        ) # including success because sometimes the scan  might have comepleted quickly and we might need to get results after status is success            

        


        # STEP [ 5 ] : ======================================== Cycle through the logs and see if there are any tasks that need status update ========================================
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





        # STEP [ 6 ] : ======================================== Fetch and Calculate Metrics =======================================
        log_data = []
        with guardrails_logs_collection.find({"integration_id": integration_id}).sort("created_at", -1).limit(limit).skip(offset) as cursor:
            for log in cursor:
                log_data.append({
                    "id": str(log["_id"]),
                    "status": log["status"],
                    "created_at": log["created_at"],
                    "input_prompt": log["input_prompt"],
                    "results": log["results"],
                })
                    

        # STEP [ 7 ] : ======================================== Fetch and Calculate Metrics ========================================
        dashboard_data = get_guardrails_integration_dashboard_data(
            team_id=team_id,
            integration_id=integration_id,
        )
        
        return {
            "dashboard_data" : dashboard_data,
            "api_key": integration.api_key[:8] + "..." + integration.api_key[-4:] if len(integration.api_key) > 12 else "****",
            "log_data": log_data,
            "settings": integration.settings,
            "integration_settings": integration.integration_settings or {},
        }
    
    except Exception as e:
        console.print(f"Error getting guardrails integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Error getting guardrails integration")





# revamped ✅
@router.put("/{team_id}/integration/{integration_id}",summary="Update a guardrails integration", deprecated=True, dependencies=[Depends(write_limiter)])
async def update_guardrails_integration(
    team_id: int, 
    integration_id: int, 
    data: UpdateGuardrailsIntegrationData, 
    Authorization: Annotated[str | None, Header()] = None ):
    """
    Update a guardrails integration.
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)


        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)

        
        
        # STEP [ 3 ] : ======================================== Update the guardrails integration ========================================
        with Session(engine) as session:
            integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.team_id == team_id)).first()
            if integration == None or not integration.id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            if integration.owner_user_id != user.id: # only the owner of the integration can update it ⭐⭐
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You are not the owner of this guardrails integration")
            if data.title is not None:
                integration.title = data.title
            if data.settings is not None:
                integration.settings = data.settings.model_dump()
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
                    settings_dict = integration.integration_settings.copy() or {}
                    settings_dict["jira"] = specific_settings_dict["jira"]
                    console.print(settings_dict, style="bold yellow")
                    integration.integration_settings= settings_dict
            session.add(integration)
            session.commit()
            return {
                "message": f"Guardrails integration {integration_id} updated successfully"
            }
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error updating guardrails integration: {str(e)}", style="bold red")
        raise HTTPException(status_code=500, detail="Error updating guardrails integration")




# revamped ✅
@router.delete("/{team_id}/integration/{integration_id}",summary="Delete a guardrails integration", deprecated=True, dependencies=[Depends(write_limiter)])
async def delete_guardrails_integration(
    team_id: int, 
    integration_id: int, 
    Authorization: Annotated[str | None, Header()] = None ):
    """
    Delete a guardrails integration.
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine , Authorization)

        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)


        # STEP [ 3 ] : ======================================== Delete the guardrails integration ========================================

        # deleting the integration from the main database
        with Session(engine) as session:
            integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.team_id == team_id)).first()
            if integration == None or not integration.id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            if integration.owner_user_id != user.id: # only the owner of the integration can delete it ⭐⭐
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You are not the owner of this guardrails integration")
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
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error deleting guardrails integration: {str(e)}", style="bold red")
        raise HTTPException(status_code=500, detail="Error deleting guardrails integration")



# revamped ✅
@router.get("/{team_id}/integration/{integration_id}/settings",summary="Get the integration settings of all the scanners in the integration", deprecated=True, dependencies=[Depends(read_limiter)])
async def get_guardrails_integration_settings(
    team_id: int, 
    integration_id: int, 
    Authorization: Annotated[str | None, Header()] = None ):
    """
    Get the integration settings of all the scanners in the integration.
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await  get_user_from_header_or_raise_exception(engine , Authorization)

        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)


        # STEP [ 3 ] : ======================================== Get the integration settings ========================================
        with Session(engine) as session:
            integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.team_id == team_id)).first()
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


# new ✅
@router.post("/{team_id}/integration/{integration_id}/rotate-key", summary="Rotate API key for a guardrails integration", deprecated=True, dependencies=[Depends(write_limiter)])
async def rotate_guardrails_api_key(
    team_id: int,
    integration_id: int,
    Authorization: Annotated[str | None, Header()] = None):
    """
    Rotate the API key for a guardrails integration.
    The old key is immediately invalidated and a new key is generated.
    Only the integration owner can rotate the key.
    
    Returns the new API key ONCE - user must save it immediately.
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)

        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 3 ] : ======================================== Rotate the API key ========================================
        with Session(engine) as session:
            integration: GuardrailsIntegration | None = session.exec(
                select(GuardrailsIntegration).where(
                    GuardrailsIntegration.id == integration_id,
                    GuardrailsIntegration.team_id == team_id
                )
            ).first()
            
            if integration is None or not integration.id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            
            # Only the owner can rotate the key
            if integration.owner_user_id != user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only the integration owner can rotate the API key"
                )
            
            # Generate new API key
            plaintext_api_key, hashed_api_key = create_api_key(team_id)
            
            # Update the integration with new hashed key
            integration.api_key = hashed_api_key
            integration.last_updated = datetime.now(timezone.utc)
            session.add(integration)
            session.commit()
            
            console.print(f"API key rotated for guardrails integration {integration_id}", style="bold green")
            
            return {
                "message": "API key rotated successfully",
                "integration_id": integration_id,
                "api_key": plaintext_api_key,  # Return plaintext ONCE, user must save it
                "warning": "Save this API key now. It will not be shown again. The old key has been invalidated."
            }

    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error rotating API key: {str(e)}", style="bold red")
        raise HTTPException(status_code=500, detail="Error rotating API key")
