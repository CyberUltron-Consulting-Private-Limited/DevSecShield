import datetime
from io import BytesIO
from typing import Annotated

from bson import ObjectId
from celery.result import AsyncResult
from fastapi import APIRouter, Depends, Form, HTTPException, Header, UploadFile, status
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

from backend.utilities.db.s3_utils import delete_file, upload_file

console = Console()

router = APIRouter(tags=["CICD"])

dev_environment = True # for local development
limiter = RateLimiter(times=20, seconds=30)
app_langs = ["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] 

# ==================================== PUBLIC API ROUTES =============================================================

@router.post("/cicd/{type}/scan",summary="Run a new cicd scan")
async def run_cicd_scan(
    type: scan_types, 
    zip_file: UploadFile , 
    user_and_integration: dict = Depends(get_user_and_integration_id) , 
    app_lang: str = Form(...) , 
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


        console.print(f"Data: {app_lang}", style="bold yellow")
        if app_lang not in app_langs:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid app language")
        # STEP [ 1 ] : ================= Get the user and integration id from the api key  =================================
        user_id = user_and_integration["user_id"]
        cicd_integration_id = user_and_integration["integration_id"]
        console.print(f"User ID: {user_id}, Integration ID: {cicd_integration_id} has started the scan", style="bold yellow")
        if not user_id or not cicd_integration_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Guardrails API key")
        
        # STEP [ 1 ] : ================= Upload zip file to s3 bucket ================================
        bytes_io_zip_file_object = BytesIO(await zip_file.read())
        response = upload_file(bytes_io_zip_file_object, "devsecshield-storage")
        bucket_name = response["bucket"] if response and "bucket" in response else None
        object_name = response["object_name"] if response and "object_name" in response else None
        if not bucket_name or not object_name:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload zip file to s3 bucket")
        console.print(f"Zip file uploaded to s3 bucket successfully", style="bold green")

        # STEP [ 3 ] : ================== Send task to ci cd worker ==================================
        celery_app = get_celery_app()
        cicd_kwargs = {
            "bucket_name": bucket_name,
            "object_name": object_name,
            "app_lang": app_lang
        }
        task = celery_app.send_task(name="cicd_worker.sast", kwargs=cicd_kwargs , queue="cicd_worker_queue")
        task_id = task.id if task and task.id else None
        task_status = AsyncResult(task_id, app=celery_app).status.lower() if task_id else None
        if not task_id or not task_status:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send task to ci cd worker")
        console.print(f"Task sent to ci cd worker successfully with id: {task_id} and status: {task_status}", style="bold green")

        # STEP [ 2 ] : ================= Update scan log in mongo db =================================
        cicd_log_collection = mongo_db["cicd_logs"]
        cicd_log_insert_response = cicd_log_collection.insert_one(CicdLogs(
            created_at=datetime.datetime.now(),
            ci_cd_integration_id=cicd_integration_id,
            user_id=user_id,
            task_id=task_id,
            status=task_status,
            zip_file_bucket=bucket_name,
            zip_file_key=object_name,
            results=None,
        ))
        CICD_LOG_ID = str(cicd_log_insert_response.inserted_id) if cicd_log_insert_response and cicd_log_insert_response.inserted_id else None
        console.print(f"Cicd log inserted successfully with id: {CICD_LOG_ID}", style="bold green")

        # STEP [ 4 ] : ============= Poll the worker for the results with a timeout =============================
        results = await run_in_threadpool(poll_for_results, task_id, celery_app, cicd_log_collection, CICD_LOG_ID)
        console.print(f"Results obtained successfully", style="bold yellow")

        # STEP [ 6 ] : =================== return the results to the user ===================================
        vulnerabilities = get_vulns(results) if results else None

        # STEP [ 7 ] : ================ delete the zip file from s3 bucket ===================================
        delete_file("devsecshield-storage", object_name)

        return {
            "vulnerabilities": vulnerabilities,
            "status": task_status,
            "cicd_log_id": CICD_LOG_ID,
        }

        
    except Exception as e:
        console.print(f"Error running cicd scan: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.get("/cicd/log/{log_id}",summary="Get a cicd log")
async def get_cicd_log(log_id: str, user_and_integration: dict = Depends(get_user_and_integration_id) , dependencies=[Depends(limiter)]):
    """
    Get a cicd log
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)


        user_id = user_and_integration["user_id"]
        cicd_integration_id = user_and_integration["integration_id"]
        console.print(f"User ID: {user_id}, Integration ID: {cicd_integration_id} has requested the log", style="bold yellow")
        if not user_id or not cicd_integration_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid CICD API key")


        # STEP [ 1 ] : ================= Get the log from the mongo db =================================
        cicd_log_collection = mongo_db["cicd_logs"]
        cicd_log = cicd_log_collection.find_one({"_id": ObjectId(log_id)})
        if not cicd_log:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd log not found")

        #STEP [ 2 ] : ============ check if status needs update =================================
        celery_app = get_celery_app()
        if cicd_log["status"] in [ "pending", "started", "NOT_STARTED" ]:
            task_id = cicd_log["task_id"]
            task_status = AsyncResult(task_id, app=celery_app).status.lower()
            if task_status:
                cicd_log["status"] = task_status
                cicd_log_collection.update_one({"_id": ObjectId(log_id)}, {"$set": {"status": task_status}})
                console.print(f"Cicd log {log_id} updated with status {task_status}", style="bold green")

        if cicd_log["results"] == None and (task_status == "success" or cicd_log["status"] == "success"):
            result = AsyncResult(cicd_log["task_id"], app=celery_app).result if (cicd_log["task_id"] and AsyncResult(cicd_log["task_id"], app=celery_app).result )else None
            if result:
                cicd_log["results"] = result
                cicd_log_collection.update_one({"_id": ObjectId(log_id)}, {"$set": {"results": result}})
                console.print(f"Cicd log {log_id} updated with results {result}", style="bold green")
        
        #STEP [ 3 ] : ============ return the log =================================
        return {
            "results": cicd_log["results"],
            "status": task_status,
            "cicd_log_id": str(cicd_log["_id"]),

        }
    except Exception as e:
        console.print(f"Error getting cicd log: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")



# ==================================== INTERNAL API ROUTES =============================================================

@router.get("/cicd/integrations",summary="List all cicd integrations")
async def list_cicd_integrations(Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    List all cicd integrations
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)


        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        with Session(engine) as session:
            integrations = session.exec(select(CicdIntegration).where(CicdIntegration.user_id == user.id)).all()
        
        integrations_data = []
        for integration in integrations:
            integrations_data.append({
                "id": integration.id,
                "title": integration.title,
                "created_at": integration.created_at,
                "last_updated": integration.last_updated,
                "scan_type": integration.scan_type.upper() if integration.scan_type not in ["leakage" , "sbom_sca" , "agent_discovery"] else integration.scan_type,
                "api_key": integration.api_key,
            })
        return integrations_data
    except Exception as e:
        console.print(f"Error listing cicd integrations: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@router.post("/cicd/integration",summary="Create a new cicd integration")
async def create_cicd_integration(data: CreateCicdIntegrationData, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Create a new cicd integration
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)

        # STEP [ 1 ] : ================= Validate the data =================================
        if data.title is None or data.scan_type is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Title and scan type are required")
        # STEP [ 2 ] : ================= Get the user from the header =================================
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        # STEP [ 3 ] : ================= Create the api key =================================
        api_key = create_api_key(user.id)
        # STEP [ 4 ] : ================= Create the integration =================================
        with Session(engine) as session:
            integration = CicdIntegration(
                user_id=user.id, 
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


@router.delete("/cicd/integration/{integration_id}",summary="Delete a cicd integration")
async def delete_cicd_integration(integration_id: int, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Delete a cicd integration
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        
        # STEP [ 1 ] : ================= Get the user from the header =================================
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        # STEP [ 2 ] : ================= Delete the integration =================================
        with Session(engine) as session:
            integration = session.exec(select(CicdIntegration).where(CicdIntegration.id == integration_id, CicdIntegration.user_id == user.id)).first()
            if not integration:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd integration not found")
            session.delete(integration)
            session.commit()
        
        # STEP [ 3 ] : ================= Delete the logs =================================
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

@router.put("/cicd/integration/{integration_id}",summary="Update a cicd integration")
async def update_cicd_integration(integration_id: int, data: UpdateCicdIntegrationData, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Update a cicd integration
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        
        # STEP [ 1 ] : ================= Validate the data =================================
        if data.title is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Title is required")
        # STEP [ 2 ] : ================= Get the user from the header =================================
        user = await get_user_from_header_or_raise_exception(engine , Authorization)
        # STEP [ 3 ] : ================= Update the integration =================================
        with Session(engine) as session:
            integration = session.exec(select(CicdIntegration).where(CicdIntegration.id == integration_id, CicdIntegration.user_id == user.id)).first()
            if not integration:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd integration not found")
            integration.title = data.title
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

@router.get("/cicd/integration/{integration_id}",summary="Get a cicd integration")
async def get_cicd_integration(integration_id: int, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
    """
    Get a cicd integration
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        
        # STEP [ 1 ] : ================= Get the user from the header =================================
        user = await get_user_from_header_or_raise_exception(engine , Authorization)

        # STEP [ 2 ] : ================= Get the integration =================================
        with Session(engine) as session:
            integration = session.exec(select(CicdIntegration).where(CicdIntegration.id == integration_id, CicdIntegration.user_id == user.id)).first()
            if not integration:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cicd integration not found")
            

        # STEP [ 3 ] : ==================================== Get the ci cd integration logs from the mongo db ====================================
        cicd_logs_collection = mongo_db["cicd_logs"]
        cicd_logs = cicd_logs_collection.find(
            {"$and": [{"ci_cd_integration_id": integration_id}, {"status": {"$in": ["pending", "started", "NOT_STARTED" , "success"]}}]}
        ) # including success because sometimes the scan  might have comepleted quickly and we might need to get results after status is success            
    
        

        # STEP [ 4 ] : ======================================= Cycle through the logs and see if there are any tasks that need status update =======================================
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
        
        
        # STEP [ 5 ] : =============== Get ci cd mongo logs for integration ================================
        logs = mongo_db["cicd_logs"].find({"ci_cd_integration_id": integration_id}).sort("created_at", -1)
        logs_data = []
        for log in logs:
            logs_data.append({
                "id": str(log["_id"]),
                "created_at": log["created_at"],
                "status": log["status"],
                "results": log["results"],
            })
        
        # STEP [ 6 ] : ================= Return the integration and logs ================================
        return {
            "cicd_integration_id": integration.id,
            "api_key": integration.api_key,
            "title": integration.title,
            "created_at": integration.created_at,
            "last_updated": integration.last_updated,
            "scan_type":  integration.scan_type.upper() if integration.scan_type not in ["leakage" , "sbom_sca" , "agent_discovery"] else integration.scan_type,
            "logs": logs_data,
        }
    except Exception as e:
        console.print(f"Error getting cicd integration: {str(e)}", style="bold red")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
