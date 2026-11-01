import datetime
import asyncio
from typing import Annotated, Literal
from bson import ObjectId
from celery.result import AsyncResult
from fastapi import FastAPI, HTTPException, Header, status, UploadFile
from sqlalchemy.engine import Engine
from sqlmodel import Sequence, Session, select
from pydantic import BaseModel, model_validator
from backend.utilities.celery.celery_connection import get_celery_app, get_status_and_update_db
from rich.console import Console
from pymongo.database import Database
import json
import time
import uuid
from backend.new_models import Scan , scan_types
from backend.utilities.db.schemas import StartScanPayload
from backend.utilities.scan.format_input import format_input_for_scan
from backend.utilities.db.metadata import get_scan_metadata_for_type
from celery import Celery
console = Console()

_DEBUG_LOG_PATH = "/Users/anshsinghal/Desktop/DevSecShield/.cursor/debug-dd4a33.log"
# SAST estimation clones repos and builds embeddings; 60s was too tight (prod task ~59.6s).
ESTIMATION_POLL_INTERVAL_SEC = 2
ESTIMATION_POLL_MAX_ATTEMPTS = 300  # up to ~600s (multi-engine SBOM / large clones)


def _agent_debug_log(location: str, message: str, data: dict, hypothesis_id: str, run_id: str = "pre-fix") -> None:
    # #region agent log
    try:
        payload = {
            "sessionId": "dd4a33",
            "runId": run_id,
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data,
            "timestamp": int(time.time() * 1000),
        }
        with open(_DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception:
        pass
    # #endregion


def _estimation_failure(task_result) -> HTTPException:
    """Zip-safety rejects are bad input. Everything else stays a credit-estimation failure."""
    err = task_result.result
    text = str(err or "")
    lowered = text.lower()
    if any(
        token in lowered
        for token in (
            "zip bomb",
            "suspicious compression",
            "path traversal",
            "too many files",
            "uncompressed size exceeds",
        )
    ):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=text)
    # A corrupt, truncated, encrypted or mislabelled archive is bad input too, not an outage (found by the lab's
    # hostile-input suite: a truncated zip and a tar.gz renamed .zip both came back as "try again later").
    if any(token in lowered for token in ("not a zip file", "bad magic number", "truncated file header", "bad crc-32",
                                          "password required", "is encrypted", "span multiple disks")):
        reason = text.rsplit(":", 1)[-1].strip() or "unreadable archive"
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail=f"The uploaded file is not a readable zip archive ({reason[:120]})")
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Credit estimation failed, please try again later",
    )


async def poll_for_estimated_credits ( 
    task_id: str,
    simple_app: Celery,
) -> float :
    try:
        poll_started = time.monotonic()
        for i in range(ESTIMATION_POLL_MAX_ATTEMPTS):
            task_result = simple_app.AsyncResult(task_id)
            if task_result.state == "FAILURE":
                raise _estimation_failure(task_result)
            if task_result.state == "SUCCESS":
                result = task_result.result
                if result is None or result < 0:
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Credit estimation failed, please try again later")
                # #region agent log
                _agent_debug_log(
                    "estimate_scan.py:poll_for_estimated_credits",
                    "Credit estimation poll succeeded",
                    {
                        "task_id": task_id,
                        "poll_attempt": i + 1,
                        "elapsed_sec": round(time.monotonic() - poll_started, 2),
                        "credits": result,
                    },
                    hypothesis_id="A",
                )
                # #endregion
                return result # here the result is a float number that represents the estimated credits consumed for the scan
            await asyncio.sleep(ESTIMATION_POLL_INTERVAL_SEC)
        # Final check: worker may finish between last sleep and timeout raise.
        task_result = simple_app.AsyncResult(task_id)
        if task_result.state == "SUCCESS":
            result = task_result.result
            if result is not None and result >= 0:
                # #region agent log
                _agent_debug_log(
                    "estimate_scan.py:poll_for_estimated_credits",
                    "Credit estimation succeeded on final poll check",
                    {
                        "task_id": task_id,
                        "elapsed_sec": round(time.monotonic() - poll_started, 2),
                        "credits": result,
                    },
                    hypothesis_id="A",
                )
                # #endregion
                return result
        if task_result.state == "FAILURE":
            raise _estimation_failure(task_result)
        # #region agent log
        _agent_debug_log(
            "estimate_scan.py:poll_for_estimated_credits",
            "Credit estimation poll timed out",
            {
                "task_id": task_id,
                "poll_attempts": ESTIMATION_POLL_MAX_ATTEMPTS,
                "elapsed_sec": round(time.monotonic() - poll_started, 2),
                "final_state": task_result.state,
            },
            hypothesis_id="A",
        )
        # #endregion
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Credit estimation timed out, please try again later")
    except HTTPException:
        raise
    except Exception as e:
        console.print(f"Error in polling for result of task: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in polling for result of task, please try again later")


async def estimate_credits(
    scan_type: scan_types,
    engine: Engine, 
    start_scan_payload: StartScanPayload,
    uploaded_file: UploadFile | None = None,
    ) -> float  :
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
            task_result = simple_app.send_task(name="scan_worker.sast_estimation", kwargs=scan_kwargs, queue="scan_worker_queue")
            console.print(f"Sent sast estimation task to celery worker. task id: {task_result.id}" ,style="bold yellow")
        elif scan_type == "iac":
            task_result = simple_app.send_task(name="scan_worker.iac_estimation", kwargs=scan_kwargs, queue="scan_worker_queue")
            console.print(f"Sent iac estimation task to celery worker. task id: {task_result.id}" ,style="bold yellow")
        elif scan_type == "sbom_sca":
            task_result = simple_app.send_task(name="scan_worker.sbom_sca_estimation", kwargs=scan_kwargs, queue="scan_worker_queue")
            console.print(f"Sent sbom sca estimation task to celery worker. task id: {task_result.id}" ,style="bold yellow")
        elif scan_type == "mcp":
            task_result = simple_app.send_task(name="scan_worker.mcp_estimation", kwargs=scan_kwargs, queue="scan_worker_queue")
            console.print(f"Sent mcp estimation task to celery worker. task id: {task_result.id}" ,style="bold yellow")
        elif scan_type == "llm":
            task_result = simple_app.send_task(name="scan_worker.llm_benchmark_estimation", kwargs=scan_kwargs, queue="scan_worker_queue")
            console.print(f"Sent llm benchmark estimation task to celery worker. task id: {task_result.id}" ,style="bold yellow")
        elif scan_type == "dast":
            task_result = simple_app.send_task(name="dast_worker.dast_estimation", kwargs=scan_kwargs, queue="dast_worker_queue")
            console.print(f"Sent dast estimation task to celery worker. task id: {task_result.id}" ,style="bold yellow")
        elif scan_type == "cbom":
            task_result = simple_app.send_task(name="scan_worker.cbom_estimation", kwargs=scan_kwargs, queue="scan_worker_queue")
            console.print(f"Sent cbom estimation task to celery worker. task id: {task_result.id}" ,style="bold yellow")
        elif scan_type == "ai_bom":
            task_result = simple_app.send_task(name="scan_worker.ai_bom_estimation", kwargs=scan_kwargs, queue="scan_worker_queue")
            console.print(f"Sent ai_bom estimation task to celery worker. task id: {task_result.id}" ,style="bold yellow")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")


        
        
        
        # STEP [ 3 ] : =========== poll for results and return esitmated credit consumption for the scan ======================
        credits_consumed : float = await poll_for_estimated_credits(task_id=task_result.id, simple_app=simple_app)
        credits_consumed = round(credits_consumed, 2)
        return credits_consumed
    except Exception as e:
        console.print(f"Error in estimating credits for {scan_type} scan: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in estimating credits for scan , please try again later")
