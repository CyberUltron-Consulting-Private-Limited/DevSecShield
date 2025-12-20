import datetime
from typing import Annotated, Literal
from bson import ObjectId
from fastapi import FastAPI, HTTPException, Header, status, BackgroundTasks
from sqlalchemy.engine import Engine
from sqlmodel import Sequence, Session, select
from backend.auth_utils.plans import plans
from rich.console import Console
from pymongo.database import Database
import uuid
from backend.api_routes.functions import * 
from backend.guardrails_api_utils.schemas import CreateGuardrailsIntegrationData, UpdateGuardrailsIntegrationData
from backend.guardrails_api_utils.auth import *

console = Console()


def guardrails_routes(app: FastAPI, engine: Engine , mongo_db: Database):
    
    @app.get("/guardrails/integrations",summary="List all guardrails conversations")
    async def list_guardrails_integrations( background_tasks: BackgroundTasks, Authorization: Annotated[str | None, Header()] = None):
        """
        List all guardrails integrations.
        """
        try:
            user = get_user_from_header_or_raise_exception(Authorization)
            
            with Session(engine) as session:
                statement = select(GuardrailsIntegration).where(GuardrailsIntegration.user_id == user.id)
                integrations = session.exec(statement).all()
            
            response_data = []
            for integration in integrations:
                response_data.append({
                    "id": integration.id,
                    "title": integration.title,
                    "scanners_enabled": integration.settings.keys(),
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

    @app.post("/guardrails/integration",summary="Create a new guardrails integration")
    async def create_guardrails_integration(data: CreateGuardrailsIntegrationData, Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new guardrails integration.
        """
        try:
            user = get_user_from_header_or_raise_exception(Authorization)
            with Session(engine) as session:
                api_key = create_api_key()
                new_integration = GuardrailsIntegration(
                    user_id=user.id,
                    title=data.title,
                    api_key=api_key,
                    settings=data.settings.model_dump()
                )
                session.add(new_integration)
        except Exception as e:
            console.print(f"Error creating guardrails integration: {str(e)}", style="bold red")
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=500, detail="Error creating guardrails integration")

    @app.get("/guardrails/integration/{integration_id}",summary="Get a guardrails integration")
    async def get_guardrails_integration(integration_id: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Get a guardrails integration dashboard data
        Run a scan status update for all the scans in this integration 
        """
        try:
            user = get_user_from_header_or_raise_exception(Authorization)

            # STEP [ 1 ] : ==================================== Get the integration from the main database ====================================
            with Session(engine) as session:
                integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.user_id == user.id)).first()
                if integration == None or not integration.id:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
            
            # STEP [ 2 ] : ==================================== Get the integration logs from the mongo db ====================================
            guardrails_logs_collection = mongo_db["guardrails_logs"]
            guardrails_logs = guardrails_logs_collection.find({"integration_id": integration_id})
            

            # STEP [ 3 ] : ======================================= Cycle through the logs and see if there are any tasks that need status update =======================================
            celery_app = get_celery_app()
            result , status = None, None
            for log in guardrails_logs:
                if log["status"] == "pending" or log["status"] == "started" or log["status"] == "NOT_STARTED":
                    task_id = log["task_id"]
                    status = AsyncResult(task_id, app=celery_app).status.lower()
                    if status == "success":
                        result = AsyncResult(task_id, app=celery_app).result
                
                if result and status:
                    log["results"] = result
                    log["status"] = status
                    guardrails_logs_collection.update_one({"_id": log["_id"]}, {"$set": {"results": result , "status": status}})
                    console.print(f"Guardrails log {log['_id']} updated with scan status {status} and results successfully", style="bold green")
                if status : 
                    log["status"] = status
                    guardrails_logs_collection.update_one({"_id": log["_id"]}, {"$set": {"status": status}})
                    console.print(f"Guardrails log {log['_id']} updated with status {status}", style="bold green")
            
            # STEP [ 4 ] : ======================================== Fetch all integration logs again ==========================================================
            guardrails_logs = guardrails_logs_collection.find({"integration_id": integration_id})

            # STEP [ 5 ] : ========================================= Calculate Metrics =======================================================================
            total_logs = len(guardrails_logs)
            successful_logs = len([log for log in guardrails_logs if log["status"] == "success"])
            failed_logs = len([log for log in guardrails_logs if log["status"] == "failed"])
            pending_logs = len([log for log in guardrails_logs if log["status"] == "pending"])
            started_logs = len([log for log in guardrails_logs if log["status"] == "started"])
            not_started_logs = len([log for log in guardrails_logs if log["status"] == "NOT_STARTED"])

            return {
                "total_logs": total_logs,
                "successful_logs": successful_logs,
                "failed_logs": failed_logs,
                "pending_logs": pending_logs,
                "started_logs": started_logs,
                "not_started_logs": not_started_logs
            }
        
        except Exception as e:
            console.print(f"Error getting guardrails integration: {str(e)}", style="bold red")
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=500, detail="Error getting guardrails integration")

    @app.put("/guardrails/integration/{integration_id}",summary="Update a guardrails integration")
    async def update_guardrails_integration(integration_id: str, data: UpdateGuardrailsIntegrationData, Authorization: Annotated[str | None, Header()] = None):
        """
        Update a guardrails integration.
        """
        try:
            user = get_user_from_header_or_raise_exception(Authorization)
            

            with Session(engine) as session:
                integration : GuardrailsIntegration | None = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id, GuardrailsIntegration.user_id == user.id)).first()
                if integration == None or not integration.id:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardrails integration not found")
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

    @app.delete("/guardrails/integration/{integration_id}",summary="Delete a guardrails integration")
    async def delete_guardrails_integration(integration_id: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a guardrails integration.
        """
        try:
            user = get_user_from_header_or_raise_exception(Authorization)

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
            guardrails_logs_collection.delete_many({"integration_id": integration_id})
            console.print(f"Guardrails integration logs {integration_id} deleted from mongo db", style="bold green")

            return {
                "message": f"Guardrails integration {integration_id} deleted successfully"
            }

        except Exception as e:
            console.print(f"Error deleting guardrails integration: {str(e)}", style="bold red")
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=500, detail="Error deleting guardrails integration")

    @app.get("/guardrails/integration/{integration_id}/settings",summary="Get the integration settings of all the scanners in the integration")
    async def get_guardrails_integration_settings(integration_id: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Get the integration settings of all the scanners in the integration.
        """
        try:
            user = get_user_from_header_or_raise_exception(Authorization)
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