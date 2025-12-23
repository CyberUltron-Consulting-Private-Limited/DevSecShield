import datetime
from typing import Annotated, Literal
from bson import ObjectId
from fastapi import FastAPI, HTTPException, Header, status, BackgroundTasks
from sqlalchemy.engine import Engine
from sqlmodel import Sequence, Session, select
from pydantic import BaseModel
from backend.ai_utils.chatbot import create_response
from backend.ai_utils.export_generation import create_export_results
from backend.auth_utils.auth_utils import get_user_from_header_or_raise_exception
from backend.celery_connection import get_celery_app, get_status_and_update_db
from backend.cicd_utils.schemas import CreateCicdConversationData
from backend.models import SASTConversation, User , LLMBenchmarkingConversation
from backend.auth_utils.plans import plans
from rich.console import Console
from sse_starlette.sse import EventSourceResponse
from pymongo.database import Database
import json
import time
from backend.mongo_models import ActiveContextLog, Conversation, MessageLog
import uuid
from backend.api_routes.functions import * 


console = Console()




def cicd_routes(app: FastAPI, engine: Engine , mongo_db: Database):


    @app.post("/cicd/{type}/scan",summary="Run a new cicd scan")
    async def run_cicd_scan(type: scan_types, data: CreateCicdConversationData,):
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
            pass
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))