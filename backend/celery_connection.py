from celery import Celery
from dotenv import load_dotenv
import psycopg2
from rich.console import Console
import os
from backend.models import SASTConversation
from fastapi import HTTPException, status
from celery.result import AsyncResult
from sqlmodel import Session, select
from sqlalchemy.engine import Engine

console = Console()

def get_celery_app():
    load_dotenv()
    username = os.getenv("RABBIT_ADMIN_USERNAME")
    password = os.getenv("RABBIT_ADMIN_PASSWORD")
    mongo_url = os.getenv("RABBIT_MONGO_CONNECTION_URL")
    if not username or not password or not mongo_url:
        console.print(f"Username, password or mongo url not set",style="bold red")
        return None
    simple_app = Celery('task_sender',
                    broker=f"amqp://{username}:{password}@localhost:5672",
                    backend=mongo_url)
    simple_app.conf.update(
        CELERY_RESULT_PERSISTENT=True,
        CELERY_TRACK_STARTED=True,
    )
    return simple_app

def get_status_and_update_db(
    conversation_id: int,
    task_id: str,
    table: SASTConversation , 
    engine: Engine,
     ):
    """
    ### Args : 
    - conversation_id (Required) : int ( id of the conversation in the main db )
    - task_id (Required) : str ( id of the task in celery )
    - table (Required) : SQLModel Object ( SQLModel Object of the table to update )
    - engine (Required) : Engine ( SQLAlchemy Engine object )


    ### This function hanldes :
    1. getting current status of the task from celery 
    2. updating that status to the Table and id provided 
    3. updating the scan's data to the Table if scan is successful 

    It returns 
    1. scan status 
    2. scan_data 
    3. Updated Table Conversation Object ( SQLModel Object )
    """
    try:
        SCAN_STATUS = None
        SCAN_DATA = {}
        CONVERSATION = None
        
        
        # STEP [ 1 ] : =================== Get celery app and status of task  =======================
        if task_id:
            simple_app = get_celery_app()
            if simple_app==None:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
            async_result : AsyncResult = simple_app.AsyncResult(task_id)
            SCAN_STATUS = str(async_result.state).lower()
            if not SCAN_STATUS:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Scan status not found in celery worker")
        

        # STEP [ 2 ] : =================== Update the status in the main db ( if it has changed )=======================
        with Session(engine) as session:
            conversation = session.exec(select(table).where(table.id == conversation_id)).first()
            if not conversation:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
            
            if conversation.scan_status != SCAN_STATUS:  # update the scan status only if it has changed
                conversation.scan_status = SCAN_STATUS
                console.print(f"Scan with id: {task_id} status updated to {SCAN_STATUS} in main database" ,style="bold green")
            if SCAN_STATUS == "success" and conversation.scan_data == {} or not conversation.scan_data:
                results = simple_app.AsyncResult(task_id).result 
                if not results:
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Scan data not found in celery worker")
                SCAN_DATA = results
                conversation.scan_data = SCAN_DATA
                console.print(f"Scan with id: {task_id} scan data updated to {SCAN_DATA} in main database" ,style="bold green")
            else:
                console.print(f"Scan with id: {task_id} status is already {SCAN_STATUS}, and has not changed . No update needed." ,style="bold green")
            
            session.commit()
            session.refresh(conversation)
            CONVERSATION = conversation
        
            
        return (SCAN_STATUS , SCAN_DATA , CONVERSATION)

    except Exception as e:
        console.print(f"Error in getting status and updating db: {e}" ,style="bold red")
        if isinstance(e,HTTPException):
            raise e
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Server is busy, please try again later")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting status and updating db, please try again later")


