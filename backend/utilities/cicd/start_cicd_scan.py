
from celery.result import AsyncResult
from fastapi import HTTPException, status, UploadFile
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from backend.utilities.celery.celery_connection import get_celery_app
from rich.console import Console
from pymongo.database import Database
import time
from backend.new_models import CicdIntegration, Scan , scan_types
from backend.utilities.cicd.format_input import format_cicd_input
console = Console()


async def start_cicd_scan_and_update_db(
    scan_type: scan_types,
    scan_settings: dict,
    uploaded_file: UploadFile | None = None,
    ) -> tuple[str, str] :
    """
    Returns task_id of celery task and status of task as a tuple ( task_id, task_status )

    """
    try:
        
        # STEP [ 1 ] : =========== Send the task to the celery worker ======================
        simple_app = get_celery_app()
        if simple_app==None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
        task_result = None
        
        
        
        cicd_kwargs = await format_cicd_input(
            scan_settings=scan_settings,
            scan_type=scan_type,
            uploaded_file=uploaded_file)
        

        # start scan 
        if scan_type == "sast":
            task_result = simple_app.send_task(name="scan_worker.sast", kwargs=cicd_kwargs, queue="cicd_worker_queue")
        elif scan_type == "iac": # not enabled 
            task_result = simple_app.send_task(name="scan_worker.iac", kwargs=cicd_kwargs, queue="cicd_worker_queue")
        elif scan_type == "sbom_sca": # not enabled 
            task_result = simple_app.send_task(name="scan_worker.sbom_sca", kwargs=cicd_kwargs, queue="cicd_worker_queue")
        elif scan_type == "cbom":
            task_result = simple_app.send_task(name="scan_worker.cbom", kwargs=cicd_kwargs, queue="cicd_worker_queue")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")


        
        
        
        # STEP [ 3 ] : =========== Update the main db conversation the task id and status of task======================
        time.sleep(2) 
        celery_app = get_celery_app()
        task_id = task_result.id if task_result and task_result.id else None
        task_status = AsyncResult(task_id, app=celery_app).status.lower() if task_id else None
        if not task_id or not task_status:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send task to ci cd worker")
        console.print(f"Task sent to ci cd worker successfully with id: {task_id} and status: {task_status}", style="bold green")

        return (task_id, task_status)
    
    
    except HTTPException as e:
        console.print(f"HTTPException in start_scan_and_update_db: {e}",style="bold red")
        raise e
    except Exception as e:
        console.print(f"Error in start_scan_and_update_db: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in starting scan , please try again later")
