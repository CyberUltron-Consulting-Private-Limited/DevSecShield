
from celery.result import AsyncResult
from fastapi import HTTPException, status, UploadFile
from sqlalchemy import or_, update
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

# The worker task and queue of each scan type's run. Every task here must honour the withdrawal mark the backend
# writes (utilities/scan/cancel_scan.py tell_workers): a reinitialize withdraws the run it replaces, and a revoke alone
# is lost when no worker is up, on a worker restart and after 3 h (tests/test_reinitialize_withdraws_every_type.py).
SCAN_TASKS: dict[str, tuple[str, str]] = {
    "sast": ("scan_worker.sast", "scan_worker_queue"),
    "iac": ("scan_worker.iac", "scan_worker_queue"),
    "sbom_sca": ("scan_worker.sbom_sca", "scan_worker_queue"),
    "mcp": ("scan_worker.mcp_scan", "scan_worker_queue"),
    "llm": ("scan_worker.llm_benchmark_scan", "scan_worker_queue"),
    "dast": ("dast_worker.dast", "dast_worker_queue"),
    "cbom": ("scan_worker.cbom", "scan_worker_queue"),
    "ai_bom": ("scan_worker.ai_bom", "scan_worker_queue"),
}


async def start_scan_and_update_db(
    scan_type: scan_types,
    engine: Engine, 
    scan_id: int,
    team_id: int,   
    start_scan_payload: StartScanPayload,
    uploaded_file: UploadFile | None = None,
    *,
    scan_kwargs: dict | None = None,
    expected_task_id: str | None = None,
    task_id: str | None = None,
    ) -> str :
    """Send the scan's run to its worker and record the task on the scan; returns the task id.

    ``scan_kwargs``: the worker input already formatted (and its file uploaded) by the caller, which then ran the
    target checks before charging (reinitialize); otherwise it is formatted here.
    ``expected_task_id``: record the task only while the scan is still ``pending`` with this task id (the claim a
    reinitialize holds); a scan cancelled, finished or claimed by another request meanwhile keeps its state.
    ``task_id``: the Celery task id to send the run with (a reinitialize chooses it before its claim, so the run can be
    withdrawn even if this process dies after sending it).
    A run that was sent but could not be recorded is withdrawn (it would otherwise run unpaid and unseen)."""
    try:
        
        # STEP [ 1 ] : =========== Send the task to the celery worker ======================
        simple_app = get_celery_app()
        if simple_app==None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
        task_result = None
        if scan_kwargs is None:
            scan_kwargs = await format_input_for_scan(
                    scan_type=scan_type, 
                    start_scan_payload=start_scan_payload,
                    uploaded_file=uploaded_file)
        if scan_type not in SCAN_TASKS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")
        task_name, queue = SCAN_TASKS[scan_type]
        send_options = {"task_id": task_id} if task_id else {}
        task_result = simple_app.send_task(name=task_name, kwargs=scan_kwargs, queue=queue, **send_options)


        
        
        
        # STEP [ 3 ] : =========== Update the main db conversation the task id and status of task======================
        # I-17: removed time.sleep(2). Persist scan.task_id from the send_task() return synchronously
        # so the duplicate-start guard window (task_id == None) closes immediately after dispatch.
        from backend.utilities.scan.cancel_scan import tell_workers
        try:
            with Session(engine) as session:
                scan = None
                scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
                if scan==None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found or User not allowed to start this scan")

                # getting the status of the task and adding it to the conversation in main db
                async_result : AsyncResult = simple_app.AsyncResult(task_result.id)
                SCAN_STATUS = str(async_result.state).lower()

                # get scan metadata for type
                scan_metadata = get_scan_metadata_for_type(scan_type=scan_type,start_scan_payload=start_scan_payload)
                # conditional: a scan cancelled meanwhile (a reinitialize racing a cancel) stays cancelled, and the
                # task just sent is withdrawn (utilities/scan/cancel_scan.py)
                conditions = [Scan.id == scan_id, Scan.team_id == team_id,
                              or_(Scan.scan_status.is_(None), Scan.scan_status != "cancelled")]
                if expected_task_id is not None:
                    conditions += [Scan.task_id == expected_task_id, Scan.scan_status == "pending"]
                stored = session.exec(
                    update(Scan)
                    .where(*conditions)
                    .values(task_id=task_result.id, scan_status=SCAN_STATUS, scan_metadata=scan_metadata)
                ).rowcount == 1
                session.commit()
        except BaseException:
            tell_workers(task_result.id)  # sent but not recorded: nobody would ever see or pay for this run
            raise
        if not stored:
            tell_workers(task_result.id)
            if expected_task_id is not None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                    detail="This scan was cancelled, finished or reinitialized by another request "
                                           "while it was being reinitialized. Reload the scan.")
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This scan was cancelled.")
        return task_result.id
    
    
    except HTTPException as e:
        console.print(f"HTTPException in start_scan_and_update_db: {e}",style="bold red")
        raise e
    except Exception as e:
        console.print(f"Error in start_scan_and_update_db: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in starting scan , please try again later")
