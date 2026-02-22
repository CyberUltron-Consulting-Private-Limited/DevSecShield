from datetime import datetime, timezone
from io import BytesIO
from typing import Annotated

from bson import ObjectId
from celery.result import AsyncResult
from fastapi import APIRouter, Depends, File, Form, HTTPException, Header, UploadFile, status
from fastapi_throttle import RateLimiter
from rich.console import Console
from sqlmodel import Session, select
from starlette.concurrency import run_in_threadpool

from backend.get_db import get_db, get_mongo_client_db
from backend.mongo_models import CicdLogs
from backend.new_models import CicdIntegration , scan_types
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.utilities.celery.celery_connection import get_celery_app
from backend.utilities.cicd.auth import create_api_key, get_user_and_integration_id
from backend.utilities.cicd.parser import get_vulns
from backend.utilities.cicd.poll import poll_for_results
from backend.utilities.cicd.schemas import (
    CreateCicdIntegrationData,
    UpdateCicdIntegrationData,
)
from backend.utilities.dashboard.cicd import get_cicd_list_dashboard_data, get_cicd_sast_dashboard_data, get_cicd_vuln_chart_data
from backend.utilities.team import check_if_user_is_in_team
from backend.utilities.db.s3_utils import delete_file, upload_file
from backend.utilities.cicd.start_cicd_scan import start_cicd_scan_and_update_db
from backend.utilities.cicd.estimate_cicd_scan import estimate_cicd_scan
from backend.utilities.integrations.jira import create_issue_in_project as create_issue_in_jira
from backend.utilities.cicd.sast_output import create_output_string_for_results
from backend.utilities.team.credits import deduct_credits_from_team
from backend.get_db import dev_environment

console = Console()

router = APIRouter(tags=["CICD"])

limiter = RateLimiter(times=20, seconds=30)
app_langs = ["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] 

# ==================================== PUBLIC API ROUTES =============================================================

@router.post("/cicd/{type}/scan",summary="Run a new cicd scan")
async def run_cicd_scan(
    type: scan_types, 
    zip_file: UploadFile  , 
    user_and_integration: dict = Depends(get_user_and_integration_id) , 
    dependencies=[Depends(limiter)]):
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
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
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

        
        
        # STEP [ 3 ] : ================= Start the scan and update the main db =================================
        await zip_file.seek(0) # to resent the file pointer to the beginning of the file ( because the esitmation function reads the file and then the file pointer is at the end of the file )
        task_id, task_status = await start_cicd_scan_and_update_db(
            scan_type=type,
            scan_settings=scan_settings,
            uploaded_file=zip_file)

        

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
        deduct_credits_from_team(team_id=team_id, credits=credits_required) # deduct credits from team 
        CICD_LOG_ID = str(cicd_log_insert_response.inserted_id) if cicd_log_insert_response and cicd_log_insert_response.inserted_id else None
        console.print(f"Cicd log inserted successfully with id: {CICD_LOG_ID}", style="bold green")

        # STEP [ 5 ] : ============= Poll the worker for the results with a timeout =============================
        celery_app = get_celery_app()
        results : list[dict] | None = await run_in_threadpool(poll_for_results, task_id, celery_app, cicd_log_collection, CICD_LOG_ID)
        console.print(f"Results obtained successfully", style="bold yellow")

        
        
        
        # STEP [ 6 ] : ================= Integrate with Jira if enabled =================================
        try:
            if integration.integration_settings  and "jira" in integration.integration_settings and results is not None :
                jira_project_id = integration.integration_settings["jira"].get("jira_project_id")
                jira_email = team.integration_settings["jira"].get("email")
                jira_api_token = team.integration_settings["jira"].get("api_token")
                jira_api_url = team.integration_settings["jira"].get("url")
                if not jira_project_id or not jira_email or not jira_api_token or not jira_api_url:
                    raise Exception("Jira project id, email, api token or url is missing, cannot create ticket")
                
                description = create_output_string_for_results(scan_type = scan_type, results = results)
                console.print("Creating ticket in jira 🎫", style="bold yellow")
                create_issue_in_jira(
                    project_id=jira_project_id,
                    jira_token=jira_api_token,
                    jira_url=jira_api_url,
                    jira_email=jira_email,
                    summary=f"CICD Scan Results Scan that ran on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
                    description=description,
                )
        except Exception as e:
            console.print(f"Error Creating ticket in cicd scan: {str(e)}", style="bold red")
            
        
        
        return {
            "results": results,
            "status": task_status,
            "cicd_log_id": CICD_LOG_ID,
        }

    except HTTPException as e:
        console.print(f"HTTPException in running cicd scan: {str(e)}", style="bold red")
        raise e
    except Exception as e:
        console.print(f"Error running cicd scan: {str(e)}", style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")




# ==================================== INTERNAL API ROUTES =============================================================
# revamped ✅
@router.get("/{team_id}/cicd/integrations",summary="List all cicd integrations")
async def list_cicd_integrations(
    team_id: int, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    List all cicd integrations
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine , Authorization)

        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)


        
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
                    "api_key": integration.api_key,
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
@router.post("/{team_id}/cicd/integration",summary="Create a new cicd integration")
async def create_cicd_integration(
    team_id: int, 
    data: CreateCicdIntegrationData, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Create a new cicd integration
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        if data.title is None or data.scan_type is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Title and scan type are required")


        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)


        # STEP [ 3 ] : ======================================== Create the integration ====================================
        api_key = create_api_key(team_id)
        with Session(engine) as session:
            integration = CicdIntegration(
                team_id=team_id, 
                owner_user_id=user.id, 
                title=data.title, 
                scan_type=data.scan_type, 
                api_key=api_key)
            session.add(integration)
            session.commit()
            session.refresh(integration)
            return {
                "integration_id": integration.id
            }
    except Exception as e:
        console.print(f"Error creating cicd integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")



# revamped ✅
@router.delete("/{team_id}/cicd/integration/{integration_id}",summary="Delete a cicd integration")
async def delete_cicd_integration(
    team_id: int, 
    integration_id: int, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Delete a cicd integration
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
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
        cicd_logs_collection.delete_many({"ci_cd_integration_id": integration_id})
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
@router.put("/{team_id}/cicd/integration/{integration_id}",summary="Update a cicd integration")
async def update_cicd_integration(
    team_id: int, 
    integration_id: int, 
    data: UpdateCicdIntegrationData, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Update a cicd integration
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
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



# revamped ✅
@router.get("/{team_id}/cicd/integration/{integration_id}",summary="Get a cicd integration")
async def get_cicd_integration(
    team_id: int, 
    integration_id: int, 
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)],
    limit : int = 100,
    offset : int = 0,
):
    """
    Get a cicd integration
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        user = await get_user_from_header_or_raise_exception(engine , Authorization)


        # STEP [ 2 ] : ======================================== Check if user is in team ====================================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 3 ] : ================= Get the integration =================================
        with Session(engine) as session:
            integration = session.exec(select(CicdIntegration).where(CicdIntegration.id == integration_id).where(CicdIntegration.team_id == team_id)).first()
            if not integration:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd integration not found")
            scan_type = integration.scan_type

        # STEP [ 4 ] : ==================================== Get the ci cd integration logs from the mongo db ====================================
        cicd_logs_collection = mongo_db["cicd_logs"]
        cicd_logs = cicd_logs_collection.find(
            {"$and": [{"ci_cd_integration_id": integration_id}, {"status": {"$in": ["pending", "started" , "success"]}}]}
        ) # including success because sometimes the scan  might have comepleted quickly and we might need to get results after status is success            
    
        

        # STEP [ 5 ] : ======================================= Cycle through the logs and see if there are any tasks that need status update =======================================
        celery_app = get_celery_app()
        result , task_status = None, None
        for log in cicd_logs:

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
        logs = mongo_db["cicd_logs"].find({"ci_cd_integration_id": integration_id}).sort("created_at", -1).limit(limit).skip(offset)
        logs_data = []
        results_list = []
        for log in logs:
            dashboard_data = None
            if log.get("results") and isinstance(log["results"], list) and scan_type == "sast":
                try:
                    dashboard_data = get_cicd_sast_dashboard_data(log["results"])
                except Exception:
                    dashboard_data = None
            logs_data.append({
                "id": str(log["_id"]),
                "created_at": log["created_at"],
                "status": log["status"],
                "results": log["results"],
                "dashboard": dashboard_data,
                "credits_consumed": round(float(log["credits_consumed"]), 2) if log["credits_consumed"] else None,
                "error": log.get("error"),
            })
            if log["results"]:
                results_list.append((log["results"],log["created_at"].date()))
        
        # STEP [ 7 ] : ================= Return the integration and logs ================================
        if not integration.scan_settings  or integration.scan_settings == {} : 
            integration_active = False
        else:
            integration_active = True
        

        dashboard_data = get_cicd_vuln_chart_data(results_list=results_list)
        
        return {
            "cicd_integration_id": integration.id,
            "api_key": integration.api_key,
            "integration_active": integration_active,
            "title": integration.title,
            "created_at": integration.created_at,
            "last_updated": integration.last_updated,
            "scan_type":  integration.scan_type.upper() if integration.scan_type not in ["leakage" , "sbom_sca" , "agent_discovery"] else integration.scan_type,
            "integration_settings": integration.integration_settings or {},
            "scan_settings": integration.scan_settings or {},
            "logs": logs_data,
            "dashboard_data": dashboard_data,
        }
    except Exception as e:
        console.print(f"Error getting cicd integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
