
from celery.result import AsyncResult
from fastapi import HTTPException, status, UploadFile
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from backend.utilities.celery.celery_connection import get_celery_app
from rich.console import Console
from pymongo.database import Database
import time
from backend.new_models import Scan , scan_types
from backend.utilities.db.schemas import StartScanPayload
from backend.utilities.scan.format_input import format_input_for_scan
from backend.utilities.db.metadata import get_scan_metadata_for_type
console = Console()


async def start_scan_and_update_db(
    scan_type: scan_types,
    engine: Engine, 
    scan_id: int,
    team_id: int,   
    start_scan_payload: StartScanPayload,
    uploaded_file: UploadFile | None = None,
    ) -> None :
    try:
        
        # STEP [ 1 ] : =========== Send the task to the celery worker ======================
        simple_app = get_celery_app()
        if simple_app==None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
        task_result = None
        scan_kwargs = await format_input_for_scan(
                scan_type=scan_type, 
                start_scan_payload=start_scan_payload,
                uploaded_file=uploaded_file)
        if scan_type == "sast":
            task_result = simple_app.send_task(name="scan_worker.sast", kwargs=scan_kwargs, queue="scan_worker_queue")
        elif scan_type == "iac":
            task_result = simple_app.send_task(name="scan_worker.iac", kwargs=scan_kwargs, queue="scan_worker_queue")
        elif scan_type == "sbom_sca":
            task_result = simple_app.send_task(name="scan_worker.sbom_sca", kwargs=scan_kwargs, queue="scan_worker_queue")
        elif scan_type == "mcp":
            task_result = simple_app.send_task(name="scan_worker.mcp_scan", kwargs=scan_kwargs, queue="scan_worker_queue")
        elif scan_type == "llm":
            task_result = simple_app.send_task(name="scan_worker.llm_benchmark_scan", kwargs=scan_kwargs, queue="scan_worker_queue")
        elif scan_type == "dast":
            task_result = simple_app.send_task(name="dast_worker.dast", kwargs=scan_kwargs, queue="dast_worker_queue")
        elif scan_type == "cbom":
            task_result = simple_app.send_task(name="scan_worker.cbom", kwargs=scan_kwargs, queue="scan_worker_queue")
        elif scan_type == "ai_bom":
            task_result = simple_app.send_task(name="scan_worker.ai_bom", kwargs=scan_kwargs, queue="scan_worker_queue")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")


        
        
        
        # STEP [ 3 ] : =========== Update the main db conversation the task id and status of task======================
        # I-17: removed time.sleep(2). Persist scan.task_id from the send_task() return synchronously
        # so the duplicate-start guard window (task_id == None) closes immediately after dispatch.
        with Session(engine) as session:
            scan = None
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if scan==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or User not allowed to start this scan")
            scan.task_id = task_result.id

            # getting the status of the task and adding it to the conversation in main db
            async_result : AsyncResult = simple_app.AsyncResult(task_result.id)
            SCAN_STATUS = str(async_result.state).lower()
            scan.scan_status = SCAN_STATUS
            
            # get scan metadata for type 
            scan_metadata = get_scan_metadata_for_type(scan_type=scan_type,start_scan_payload=start_scan_payload)
            scan.scan_metadata = scan_metadata
            session.commit()
    
    
    except HTTPException as e:
        console.print(f"HTTPException in start_scan_and_update_db: {e}",style="bold red")
        raise e
    except Exception as e:
        console.print(f"Error in start_scan_and_update_db: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in starting scan , please try again later")
