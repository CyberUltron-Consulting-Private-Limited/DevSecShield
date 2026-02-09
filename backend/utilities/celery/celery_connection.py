from celery import Celery
from dotenv import load_dotenv
import psycopg2
from rich.console import Console
import os
from fastapi import HTTPException, status
from celery.result import AsyncResult
from sqlmodel import Session, select
from sqlalchemy.engine import Engine
import datetime
from datetime import timezone

from backend.new_models import Scan
console = Console()

def get_celery_app():
    try:

        load_dotenv()

        is_docker_container = os.getenv("IS_DOCKER_CONTAINER")

        if is_docker_container and is_docker_container == "True":
            console.print("Getting celery app in docker container",style="bold green")
            # broker url
            username = os.getenv("RABBIT_ADMIN_USERNAME")
            password = os.getenv("RABBIT_ADMIN_PASSWORD")
            if not username or not password:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Username or password not set")
            broker_url = f"amqp://{username}:{password}@13.203.233.15:4672"

            # mongo 
            mongo_username = os.getenv("MONGO_INITDB_ROOT_USERNAME")
            mongo_password = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
            if not mongo_username or not mongo_password:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Mongo username or password not set")
            mongo_host = "13.203.233.15"
            mongo_port = "27017"
            mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"
        
        
        else:
            console.print("Getting celery app in local environment",style="bold green")
            # broker url
            username = os.getenv("RABBIT_ADMIN_USERNAME")
            password = os.getenv("RABBIT_ADMIN_PASSWORD")
            if not username or not password:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Username or password not set")
            broker_url = f"amqp://{username}:{password}@localhost:4672"

            # mongo 
            mongo_url = f"mongodb://localhost:27017/"

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
        with Session(engine) as session:
            scan : Scan | None = session.exec(select(table).where(table.id == scan_id)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
            
            #updating last_updated field
            scan.last_updated = datetime.datetime.now(timezone.utc)


            if scan.scan_status != SCAN_STATUS:  # update the scan status only if it has changed
                scan.scan_status = SCAN_STATUS
                console.print(f"Scan with id: {task_id} status updated to {SCAN_STATUS} in main database" ,style="bold green")
            if SCAN_STATUS == "success":
                results = simple_app.AsyncResult(task_id).result 
                if not results:
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Scan data not found in celery worker")
                SCAN_DATA = results
                scan.scan_data = SCAN_DATA
                console.print(f"Scan with id: {task_id} scan data updated successfully in main database" ,style="bold green")
            else:  
                console.print(f"Scan with id: {task_id} status is already {SCAN_STATUS}, and has not changed . No update needed." ,style="bold green")
            
            session.add(scan)
            session.commit()
            session.refresh(scan)
            SCAN_OBJECT = scan
        
            
        return (SCAN_STATUS , SCAN_DATA , SCAN_OBJECT)

    except Exception as e:
        console.print(f"{e}" ,style="dim red")
        if isinstance(e,HTTPException):
            raise e
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Server is busy, please try again later")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting status and updating db, please try again later")


