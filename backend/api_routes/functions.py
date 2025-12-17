import datetime
from typing import Annotated, Literal
from bson import ObjectId
from fastapi import FastAPI, HTTPException, Header, status
from sqlalchemy.engine import Engine
from sqlmodel import Sequence, Session, select
from pydantic import BaseModel, model_validator
from backend.ai_utils.chatbot import create_response
from backend.ai_utils.export_generation import create_export_results
from backend.auth_utils.auth_utils import get_user_from_header_or_raise_exception
from backend.celery_connection import get_celery_app, get_status_and_update_db
from backend.models import SASTConversation, User , LLMBenchmarkingConversation, MCPConversation
from backend.auth_utils.plans import plans
from rich.console import Console
from sse_starlette.sse import EventSourceResponse
from pymongo.database import Database
import json
import time
from backend.mongo_models import ActiveContextLog, Conversation, MessageLog
import uuid


console = Console()


# ============================================================ Request body models ===========================================================
class CreateScanConversationData(BaseModel):
    title: str

class SendMessageToScanConversationData(BaseModel):
    user_message: str

class StartSastScanData(BaseModel):
    mode: Literal["github", "gitlab", "bitbucket"]
    repo_url: str
    PAT: str
    app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]

    @model_validator(mode="after")
    def validate_data(self):
        if not self.repo_url or not self.PAT or not self.app_lang:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid sast scan input")

        if self.app_lang not in ["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid app language")
        return self

class StartLLMBenchmarkingData(BaseModel):
    model_type: Literal["openai", "anthropic", "gemini", "custom"]
    model_name: str
    generations: int | None = 1
    probes: list[str] = ["all"]
    api_key: str | None = None
    headers: dict | None = None
    request_template: dict | None = None
    response_json_field: str | None = None
    model_uri: str | None = None
    method: Literal["get", "post"] = "post"

class StartMCPScanData(BaseModel):
    server_config: str

class StartScanData(BaseModel):
    sast : StartSastScanData | None = None
    llm : StartLLMBenchmarkingData | None = None
    mcp : StartMCPScanData | None = None

class UpdateScanConversationData(BaseModel):
    title: str


def stream_text(text: str):
    text_array = text.split(" ")
    id = str(uuid.uuid4())
    for word in text_array:
        data = {
                "message_id": "Not_allowed_" + id,
                "content": word + " ",
                "reasoning": "",
            }
        yield json.dumps(data)
        time.sleep(0.1)

# ====================================================== functions for fetching data ===========================================================
def get_Table_from_type(type: Literal["sast", "llm", "mcp"]) -> SASTConversation | LLMBenchmarkingConversation | MCPConversation:
    """
    Returns the table corresponding to the type. 
    If table not found , raise an exception.
    """
    if type == "sast":
        return SASTConversation
    elif type == "llm":
        return LLMBenchmarkingConversation
    elif type == "mcp":
        return MCPConversation
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid type of conversation")


def get_messages_from_conversation(conversation_id: int,user_id: int, Table: SASTConversation | LLMBenchmarkingConversation | MCPConversation, engine: Engine, mongo_db: Database):
    try:

        # STEP [ 1 ] : =========== get the conversation from the main db to get the conversation id ======================
        conversation = None
        with Session(engine) as session:
            conversation = session.exec(select(Table).where(Table.id == conversation_id).where(Table.user_id == user_id)).first()
            if not conversation:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
        console.print(f"Conversation id: {conversation.id} found in main database" ,style="bold green")
        

        # STEP [ 2 ] : =========== get the conversation from the mongo db to get the conversation id ( for validation )======================
        conversation_collection = mongo_db["conversations"]
        mongo_conversation = None
        mongo_conversation = conversation_collection.find_one({"_id": ObjectId(conversation.conversation_id)})
        if not mongo_conversation:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
        console.print(f"Conversation id: {mongo_conversation['_id']} found in mongo db" ,style="bold green")

        # STEP [ 3 ] : =========== return the messages from the mongo db ======================
        with mongo_db["message_log"].find({"conversation_id": str(mongo_conversation['_id'])}).sort("created_at", 1) as messages:
            messages_data = []
            i = 0
            for message in messages:
                messages_data.append({
                    "id": i,
                    "content": message["content"],
                    "role": message["sender"],
                    "timestamp": message["created_at"] ,
                    "is_streaming": False,
                })
                i += 1
            console.print(f"{len(messages_data)} messages found for conversation: {mongo_conversation['_id']}" ,style="bold green")
            return messages_data

        
    except Exception as e:
        console.print(f"Error in get_sast_scan_conversation: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in fetching conversation , please try again later")


def start_scan_and_update_db(
    type: Literal["sast", "llm", "mcp"],
    table: SASTConversation | LLMBenchmarkingConversation | MCPConversation, 
    engine: Engine, 
    mongo_db: Database,
    conversation_id: int,
    user_id: int,   
    sast_data: StartSastScanData | None = None,
    llm_data: StartLLMBenchmarkingData | None = None,
    mcp_data: StartMCPScanData | None = None,
    ) -> None :
    try:
        
        # STEP [ 1 ] : =========== Send the task to the celery worker ======================
        simple_app = get_celery_app()
        if simple_app==None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
        task_result = None
        if type == "sast":
            sast_kwargs ={
                "dict_context":{
                    "mode":sast_data.mode,
                    "repo_url":sast_data.repo_url,
                    "PAT":sast_data.PAT,
                },
                "app_lang":sast_data.app_lang,
            }
            task_result = simple_app.send_task(name="scan_worker.sast", kwargs=sast_kwargs)
        elif type == "llm":
            llm_kwargs={
                "model_type":llm_data.model_type,
                "model_name":llm_data.model_name,
                "api_key":llm_data.api_key,
                "headers": llm_data.headers,
                "request_template":llm_data.request_template,
                "response_json_field":llm_data.response_json_field,
                "probes":",".join(llm_data.probes),
                "model_uri":llm_data.model_uri,
                "method":llm_data.method,
            }
            task_result = simple_app.send_task(name="scan_worker.llm_benchmark", kwargs=llm_kwargs)
        elif type == "mcp":
            mcp_kwargs={
                "server_config_json":mcp_data.server_config,
            }
            task_result = simple_app.send_task(name="scan_worker.mcp", kwargs=mcp_kwargs)
        if not task_result:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending task to Scan worker , please try again later")


        # STEP [ 3 ] : =========== Update the main db conversation the task id ======================
        with Session(engine) as session:
            conversation = None
            conversation = session.exec(select(table).where(table.id == conversation_id).where(table.user_id == user_id)).first()
            if conversation==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found or User not allowed to start this conversation")
            conversation.task_id = task_result.id
            
    
            if type == "sast" and table == SASTConversation:
                console.print(f"Updating conversation data for sast scan with metadata" ,style="bold green")
                conversation.mode = sast_data.mode
                conversation.repo_url = sast_data.repo_url
                conversation.app_lang = sast_data.app_lang
            elif type == "llm" and table == LLMBenchmarkingConversation:
                console.print(f"Updating conversation data for llm scan with metadata" ,style="bold green")
                conversation.model_type = llm_data.model_type
                conversation.model_name = llm_data.model_name
                conversation.probes = llm_data.probes
            elif type == "mcp" and table == MCPConversation:
                console.print(f"Updating conversation data for mcp scan with metadata" ,style="bold green")
                # nothing to update here , because the server config is not stored in the database
            
            
            session.commit()
    except Exception as e:
        console.print(f"Error in start_scan: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in starting scan , please try again later")





# ======================================= functions for assembling output data for different types of conversations ======================
def return_conversations_list_for_type(type: Literal["sast", "llm", "mcp"], sequence : Sequence[SASTConversation] | Sequence[LLMBenchmarkingConversation] | Sequence[MCPConversation]):
    conversations_data = []
    match type:
        case "sast":
            for conversation in sequence:
                conversations_data.append({
                    "id": conversation.id,
                    "repo_url": conversation.repo_url,
                    "mode": conversation.mode,
                    "title": conversation.title,
                    "created_at": conversation.created_at,
                    "last_updated": conversation.last_updated,
                    "scan_status": conversation.scan_status.lower(),
                })
        case "llm":
            for conversation in sequence:

                conversations_data.append({
                    "id": conversation.id,
                    "model_type": conversation.model_type,
                    "model_name": conversation.model_name,
                    "title": conversation.title,
                    "created_at": conversation.created_at,
                    "last_updated": conversation.last_updated,
                    "scan_status": conversation.scan_status.lower(),
                })
        case "mcp":
            for conversation in sequence:
                conversations_data.append({
                    "id": conversation.id,
                    "title": conversation.title,
                    "created_at": conversation.created_at,
                    "last_updated": conversation.last_updated,
                    "scan_status": conversation.scan_status.lower(),
                })
        case _:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid type of conversation")
    return conversations_data


def return_conversation_data(
    conversation: SASTConversation | LLMBenchmarkingConversation , 
    type: Literal["sast", "llm", "mcp"],
    SCAN_STATUS: Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"],
    SCAN_DATA: dict,
    MESSAGES: list[dict],
):
    match type:
        case "sast":
            return {
                "title": conversation.title,
                "repo_url": conversation.repo_url,
                "scan_status": SCAN_STATUS.lower(),
                "data": SCAN_DATA,
                "messages": MESSAGES,
            }
        case "llm":
            return {
                "title": conversation.title,
                "model_type": conversation.model_type,
                "model_name": conversation.model_name,
                "scan_status": SCAN_STATUS.lower(),
                "data": SCAN_DATA,
                "messages": MESSAGES,
            }
        case "mcp":
            return {
                "title": conversation.title,
                "scan_status": SCAN_STATUS.lower(),
                "data": SCAN_DATA,
                "messages": MESSAGES,
            }
        case _:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid type of conversation")