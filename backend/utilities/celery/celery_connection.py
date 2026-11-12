from celery import Celery
from dotenv import load_dotenv
import psycopg2
from rich.console import Console
import os
from fastapi import HTTPException, status
from celery.result import AsyncResult
from sqlmodel import Session, select
from sqlalchemy import or_, true, update
from sqlalchemy.engine import Engine
import datetime
from datetime import timezone

from backend.new_models import Scan
from backend.utilities.celery.create_findings import create_findings_in_mongo_db
from backend.get_db import get_mongo_client_db
from backend.utilities.team.credits import refund_credits_to_team
console = Console()

def get_celery_app():
    try:

        load_dotenv()

        is_docker_container = os.getenv("IS_DOCKER_CONTAINER", "False") == "True"
        
        RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "devsecshield-rabbitmq" if is_docker_container else "localhost")
        RABBITMQ_PORT = os.getenv("RABBITMQ_PORT", "5672" if is_docker_container else "4672")
        MONGO_HOST = os.getenv("MONGO_HOST", "devsecshield-mongodb" if is_docker_container else "localhost")
        MONGO_PORT = os.getenv("MONGO_PORT", "27017")

        env_label = "Docker" if is_docker_container else "Local"
        console.print(f"Getting celery app in {env_label} environment", style="bold green")

        # broker url
        username = os.getenv("RABBIT_ADMIN_USERNAME")
        password = os.getenv("RABBIT_ADMIN_PASSWORD")
        if not username or not password:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="RABBIT_ADMIN_USERNAME or RABBIT_ADMIN_PASSWORD not set")
        broker_url = f"amqp://{username}:{password}@{RABBITMQ_HOST}:{RABBITMQ_PORT}"

        # mongo
        mongo_username = os.getenv("MONGO_INITDB_ROOT_USERNAME")
        mongo_password = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
        if mongo_username and mongo_password:
            mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{MONGO_HOST}:{MONGO_PORT}/"
        else:
            mongo_url = f"mongodb://{MONGO_HOST}:{MONGO_PORT}/"

        simple_app = Celery('task_sender',
                        broker=broker_url,
                        backend=mongo_url)
        simple_app.conf.update(
            CELERY_RESULT_PERSISTENT=True,
            CELERY_TRACK_STARTED=True,
        )
        console.print("Celery app instantiated",style="bold green")
        return simple_app
    

    except Exception as e:
        console.print(f"Error in getting celery app: {e}" ,style="dim red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app, please try again later")

# revamped ✅
def get_status_and_update_db(
    scan_id: int,
    task_id: str,
    table: Scan, 
    engine: Engine,
     ):
    """
    ### Args : 
    - scan_id (Required) : int ( id of the scan in the main db )
    - task_id (Required) : str ( id of the task in celery )
    - table (Required) : Scan ( Scan object from the main db )
    - engine (Required) : Engine ( SQLAlchemy Engine object )


    ### This function hanldes :
    1. getting current status of the task from celery 
    2. updating that status to the Table and id provided 
    3. updating the scan's data to the Table if scan is successful 

    It returns 
    1. scan status 
    2. scan_data 
    3. Updated Scan Object ( SQLModel Object )
    """
    try:
        SCAN_STATUS = None
        SCAN_DATA = {}
        SCAN_OBJECT = None
        console.print(f"Getting status and updating db for scan id: {scan_id} and task id: {task_id}" ,style="bold magenta2")
        
        # STEP [ 1 ] : =================== Get celery app and status of task  =======================
        simple_app = get_celery_app()
        if task_id:
            if simple_app==None:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
            async_result : AsyncResult = simple_app.AsyncResult(task_id)
            SCAN_STATUS = str(async_result.state).lower()
            if not SCAN_STATUS:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Scan status not found in celery worker")
        

        # STEP [ 2 ] : =================== Update the status in the main db ( if it has changed )=======================
        # The transitions into success and failure are COMPARE-AND-SET updates: several polls (list, get, start,
        # background tasks) can see the same finished task at once, and only the one whose UPDATE flips the row may
        # insert the findings, create Jira tickets or refund the credits. The others read what the winner stored.
        ingested = False
        # Every transition below is also conditional on the scan still running THIS task: a reinitialize replaces the
        # task (utilities/scan/reinitialize.py), and a poll of the replaced one (the scan list polls in a background
        # task with the task ids it read) must never store its result, refund it, or write its state.
        this_task = (table.task_id == task_id) if task_id else true()
        with Session(engine) as session:
            scan : Scan | None = session.exec(select(table).where(table.id == scan_id)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
            previous_status = scan.scan_status  # capture BEFORE mutation, to detect the transition
            now = datetime.datetime.now(timezone.utc)
            if previous_status == "cancelled":
                # cancelled is final (utilities/scan/cancel_scan.py): the charge was refunded, so whatever the worker
                # reports afterwards (a result that raced the cancel, a failure, "revoked") is never stored
                return ("cancelled", {}, scan)
            if task_id and scan.task_id != task_id:
                return (scan.scan_status, scan.scan_data or {}, scan)  # a replaced task: report the scan as stored

            if SCAN_STATUS == "success" and previous_status != "success":
                results = simple_app.AsyncResult(task_id).result
                if not results:
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Scan data not found in celery worker")
                won = session.exec(
                    update(table)
                    .where(table.id == scan_id, this_task, or_(table.scan_status.is_(None),
                                                               table.scan_status.not_in(("success", "cancelled"))))
                    .values(scan_status="success", scan_data=results, info=None, last_updated=now)
                ).rowcount == 1
                session.commit()
                if won:
                    try:
                        mongo_db = get_mongo_client_db()
                        # Idempotency: clear any pre-existing findings for this scan before (re)inserting.
                        mongo_db["scan_findings"].delete_many({"scan_id": scan_id})
                        create_findings_in_mongo_db(scan_id=scan_id, scan_results=results, scan_type=scan.scan_type, mongo_db=mongo_db)
                    except Exception:
                        # give the transition back so the next poll ingests again (findings never half-stored)
                        session.exec(update(table).where(table.id == scan_id, table.scan_status == "success")
                                     .values(scan_status=previous_status, scan_data={}))
                        session.commit()
                        raise
                    ingested = True
                    console.print(f"Scan with id: {task_id} scan data updated successfully in main database" ,style="bold green")
                else:
                    console.print(f"Scan {scan_id}: another poll already stored the results", style="dim")
                session.refresh(scan)
                SCAN_DATA = scan.scan_data
            elif SCAN_STATUS == "failure" and previous_status not in ("failure", "success"):
                # Capture a SANITIZED, concise error summary so the cause is not lost.
                # Prefer the task's exception (async_result.result); fall back to the traceback.
                # We deliberately avoid persisting the full traceback (file paths / internals).
                raw_error = None
                try:
                    raw_error = async_result.result
                except Exception:
                    raw_error = None
                if raw_error is None:
                    try:
                        raw_error = async_result.traceback
                    except Exception:
                        raw_error = None

                error_message = str(raw_error) if raw_error is not None else "Scan failed"
                # Collapse to the first non-empty line to drop multi-line traceback noise,
                # then truncate to keep the field small.
                first_line = next(
                    (line.strip() for line in error_message.splitlines() if line.strip()),
                    error_message.strip(),
                )
                if not first_line:
                    first_line = "Scan failed"
                won = session.exec(
                    update(table)
                    .where(table.id == scan_id, this_task,
                           or_(table.scan_status.is_(None),
                               table.scan_status.not_in(("failure", "success", "cancelled"))))
                    .values(scan_status="failure", info={"error": first_line[:500]}, last_updated=now)
                ).rowcount == 1
                session.commit()
                session.refresh(scan)
                console.print(f"Scan with id: {task_id} failed. Captured sanitized error summary in scan.info." ,style="bold red")
                # Refund the credits charged at dispatch, ONCE: only the poll that made the transition refunds
                # (prevents the customer being billed for a scan that crashed in the worker).
                refund = scan.credit_charged if scan.credit_charged is not None else scan.credit_consumed
                if won and refund and refund > 0:
                    try:
                        refund_credits_to_team(scan.team_id, refund)
                        console.print(f"Refunded {refund} credits to team {scan.team_id} for failed scan {scan_id}", style="bold yellow")
                    except Exception as refund_err:
                        console.print(f"Refund failed for scan {scan_id}: {refund_err}", style="bold red")
            else:
                # a conditional UPDATE, not an ORM write of the row read above: a final state committed in between
                # (a cancel, or another poll's success / failure) is never moved back to "started" -- that would let a
                # cancel refund a scan that completed, or refund a failed scan a second time
                values = {"last_updated": now}
                if previous_status != SCAN_STATUS and SCAN_STATUS not in ("success", "failure"):
                    values["scan_status"] = SCAN_STATUS
                    console.print(f"Scan with id: {task_id} status updated to {SCAN_STATUS} in main database" ,style="bold green")
                if SCAN_STATUS == "started":
                    info = async_result.info
                    # info is None until the task emits its first progress meta (race at scan start) — guard the type.
                    if isinstance(info, dict) and "current" in info:
                        values["info"] = {"current": info["current"]}  # for progress bar updates
                        console.print(f"Scan with id: {task_id} progress updated to {info['current']} in main database" ,style="bold green")
                elif SCAN_STATUS == "success":
                    SCAN_DATA = scan.scan_data  # already ingested on a prior poll
                    values["info"] = None
                elif SCAN_STATUS != "failure":
                    values["info"] = None # reset the info field
                session.exec(
                    update(table)
                    .where(table.id == scan_id, this_task,
                           or_(table.scan_status.is_(None),
                               table.scan_status.not_in(("success", "failure", "cancelled"))))
                    .values(**values)
                )
                session.commit()

            if SCAN_STATUS in ("success", "failure"):
                try:
                    from backend.utilities.dast.dispatch import clear_inflight_for_scan
                    clear_inflight_for_scan(session, scan_id)
                except Exception as inflight_err:
                    console.print(f"DAST inflight clear skipped for scan {scan_id}: {inflight_err}", style="dim yellow")

            session.refresh(scan)
            SCAN_OBJECT = scan
            if scan.scan_status == "cancelled":
                # a cancel won the row while this poll ran: report the stored state, not the worker's
                return ("cancelled", {}, scan)
            if task_id and scan.task_id != task_id:
                # a reinitialize replaced the task while this poll ran: nothing above was stored for it
                return (scan.scan_status, scan.scan_data or {}, scan)

        if ingested:
            try:
                from backend.utilities.integrations.jira_ticketing import auto_create_tickets_for_successful_scan
                auto_create_tickets_for_successful_scan(scan_id, engine)
            except Exception as jira_err:
                console.print(f"Auto-Jira skipped for scan {scan_id}: {jira_err}", style="yellow")
            if SCAN_OBJECT is not None and SCAN_OBJECT.scan_type == "cbom":
                # drift against the previous scan of the same repository and branch; findings it no longer has are
                # marked fixed and their Jira tickets closed (runs once: only the poll that ingested gets here)
                try:
                    from backend.utilities.cbom_sources.drift import on_code_scan_success
                    on_code_scan_success(scan_id, engine)
                except Exception as drift_err:
                    console.print(f"CBOM drift skipped for scan {scan_id}: {type(drift_err).__name__}", style="yellow")


        return (SCAN_STATUS , SCAN_DATA , SCAN_OBJECT)

    except Exception as e:
        console.print(f"{e}" ,style="dim red")
        if isinstance(e,HTTPException):
            raise e
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Server is busy, please try again later")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting status and updating db, please try again later")


