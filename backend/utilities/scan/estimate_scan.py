import datetime
from typing import Annotated, Literal
from bson import ObjectId
from celery.result import AsyncResult
from fastapi import FastAPI, HTTPException, Header, status
from sqlalchemy.engine import Engine
from sqlmodel import Sequence, Session, select
from pydantic import BaseModel, model_validator
from backend.utilities.celery.celery_connection import get_celery_app, get_status_and_update_db
from backend.models import * 
from rich.console import Console
from pymongo.database import Database
import json
import time
import uuid
from backend.new_models import Scan , scan_types
from backend.utilities.db.functions import StartScanPayload
from backend.utilities.db.metadata import get_scan_metadata_for_type
from celery import Celery
console = Console()


def poll_for_estimated_credits ( 
    task_id: str,
    simple_app: Celery,
) -> None :
    try:
        for i in range(30):
            task_result = simple_app.AsyncResult(task_id)
            if task_result.state == "SUCCESS":
                return task_result.result # here the result is a float number that represents the estimated credits consumed for the scan
            time.sleep(2)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in polling for result of task , please try again later")
    except Exception as e:
        console.print(f"Error in polling for result of task: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in polling for result of task , please try again later")


def estimate_credits(
    scan_type: scan_types,
    engine: Engine, 
    start_scan_payload: StartScanPayload,
    ) -> float  :
    try:
        
        # STEP [ 1 ] : =========== Send the task to the celery worker ======================
        simple_app = get_celery_app()
        if simple_app==None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
        task_result = None
        if scan_type == "sast":
            sast_kwargs ={ } #TODO: Add sast kwargs
            task_result = simple_app.send_task(name="scan_worker.sast", kwargs=sast_kwargs, queue="scan_worker_queue")
        elif scan_type == "llm":
            llm_kwargs={ } #TODO: Add llm kwargs
            task_result = simple_app.send_task(name="scan_worker.llm_benchmark", kwargs=llm_kwargs, queue="scan_worker_queue")
        elif scan_type == "mcp":
            mcp_kwargs={ } #TODO: Add mcp kwargs
            task_result = simple_app.send_task(name="scan_worker.mcp", kwargs=mcp_kwargs, queue="scan_worker_queue")
        elif scan_type == "iac":
            iac_kwargs={ } #TODO: Add iac kwargs
            task_result = simple_app.send_task(name="scan_worker.iac", kwargs=iac_kwargs, queue="scan_worker_queue")
        elif scan_type == "leakage":
            leakage_kwargs={ } #TODO: Add leakage kwargs
            task_result = simple_app.send_task(name="scan_worker.gitleaks", kwargs=leakage_kwargs, queue="scan_worker_queue")
        elif scan_type == "sbom_sca":
            sbom_sca_kwargs={ } #TODO: Add sbom_sca kwargs
            task_result = simple_app.send_task(name="scan_worker.sbom_sca", kwargs=sbom_sca_kwargs, queue="scan_worker_queue")
        elif scan_type == "agent_discovery":
            agent_discovery_kwargs={ } #TODO: Add agent_discovery kwargs
            task_result = simple_app.send_task(name="scan_worker.discovery", kwargs=agent_discovery_kwargs, queue="scan_worker_queue")
        elif scan_type == "dast":
            if start_scan_payload.dast.auth_mode == "header_cookie_based":
                dast_kwargs={ } #TODO: Add dast kwargs
                task_result = simple_app.send_task(name="dast_worker.wapiti_dast", kwargs=dast_kwargs, queue="dast_worker_queue")
            elif start_scan_payload.dast.auth_mode == "form_based":
                dast_kwargs={ } #TODO: Add dast kwargs
                task_result = simple_app.send_task(name="dast_worker.zap_dast", kwargs=dast_kwargs, queue="dast_worker_queue")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")


        
        
        
        # STEP [ 3 ] : =========== poll for results and return esitmated credit consumption for the scan ======================
        credits_consumed = poll_for_estimated_credits(task_id=task_result.id, simple_app=simple_app)
        return credits_consumed
    except Exception as e:
        console.print(f"Error in estimating credits for {scan_type} scan: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in estimating credits for scan , please try again later")
