import datetime
from typing import Annotated, Literal
from bson import ObjectId
from celery.result import AsyncResult
from fastapi import FastAPI, HTTPException, Header, status
from sqlalchemy.engine import Engine
from sqlmodel import Sequence, Session, select
from pydantic import BaseModel, model_validator
from backend.ai_utils.chatbot import create_response
from backend.ai_utils.export_generation import create_export_results
from backend.auth_utils.auth_utils import get_user_from_header_or_raise_exception
from backend.celery_connection import get_celery_app, get_status_and_update_db
from backend.models import * 
from backend.auth_utils.plans import plans
from rich.console import Console
from sse_starlette.sse import EventSourceResponse
from pymongo.database import Database
import json
import time
import uuid


console = Console()
scan_types = Literal["sast", "llm", "mcp" , "iac" , "leakage" , "sbom_sca" , "agent_discovery" , "dast"]

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

class StartGeneralScanData(BaseModel):
    mode: Literal["github", "gitlab", "bitbucket"]
    repo_url: str
    PAT: str

    @model_validator(mode="after")
    def validate_data(self):
        if not self.repo_url or not self.PAT:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid sast scan input")
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


class HeaderCookieSchema(BaseModel):
    name: str
    value: str

class HeaderCookieDASTSchema(BaseModel):
    target_url: str
    attack_modules: list[Literal["common", "all", "backup", "brute_login_form", "buster", "cms", "crlf", "csrf", "exec", "file", "htaccess", "htp", "ldap", "log4shell", "methods", "network_device", "nikto", "permanentxss", "redirect", "shellshock", "spring4shell", "sql", "ssl", "ssrf", "takeover", "timesql", "upload", "wapp", "wp_enum", "xss", "xxe"]] = ["common"]
    max_scan_time: int = 60
    user_agent: str | None = None
    headers: list[HeaderCookieSchema] | None = None
    cookies: list[HeaderCookieSchema] | None = None
    scan_force: Literal["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"] = "normal"
    exclude_url_patterns: list[str] | None = None
    additional_urls: list[str] | None = None

class FormBasedDASTSchema(BaseModel):
    target_url: str
    login_url: str
    include_urls: list[str] | None = None
    exclude_urls: list[str] | None = None
    timeout_durations_mins: int = 20
    poll_durations_seconds: int = 5
    username_value: str | None = None
    password_value: str | None = None
    username_key: str | None = None
    password_key: str | None = None
    logged_in_regex: str | None = None
    logged_out_regex: str | None = None
    
    @model_validator(mode="after")
    def validate_data(self):
        if not self.target_url or not self.login_url:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target URL and Login URL are required")
        if not self.include_urls:
            self.include_urls = []
        if not self.exclude_urls:
            self.exclude_urls = []
        if not self.username_value or not self.password_value:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and Password are required")
        if not self.username_key or not self.password_key:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and Password key are required")
        if not self.logged_in_regex or not self.logged_out_regex:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Logged in and Logged out regex are required")
        return self

class StartDASTScanData(BaseModel):
    auth_mode: Literal["header_cookie_based" , "form_based"]
    header_cookie_based: HeaderCookieDASTSchema | None = None
    form_based: FormBasedDASTSchema | None = None

    @model_validator(mode="after")
    def validate_data(self):
        if self.auth_mode == "header_cookie_based":
            if not self.header_cookie_based:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Header cookie based data is required")
        elif self.auth_mode == "form_based":
            if not self.form_based:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Form based data is required")
        return self

class StartScanData(BaseModel):
    sast : StartSastScanData | None = None
    llm : StartLLMBenchmarkingData | None = None
    mcp : StartMCPScanData | None = None

    # these scans use the same context pattern 
    iac : StartGeneralScanData | None = None
    leakage : StartGeneralScanData | None = None
    sbom_sca : StartGeneralScanData | None = None
    agent_discovery : StartGeneralScanData | None = None
    dast : StartDASTScanData | None = None

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
def get_Table_from_type(type: scan_types) -> SASTConversation | LLMBenchmarkingConversation | MCPConversation:
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
    elif type == "iac":
        return IACConversation
    elif type == "leakage":
        return GitleaksConversation
    elif type == "sbom_sca":
        return SBOM_SCAConversation
    elif type == "agent_discovery":
        return Agent_DiscoveryConversation
    elif type == "dast":
        return DASTConversation
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid type of conversation")


def get_messages_from_conversation(
    conversation_id: int,
    user_id: int, 
    Table: SASTConversation | LLMBenchmarkingConversation | MCPConversation | IACConversation | GitleaksConversation | SBOM_SCAConversation | Agent_DiscoveryConversation | DASTConversation, 
    engine: Engine, 
    mongo_db: Database):
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
    type: scan_types,
    table: SASTConversation | LLMBenchmarkingConversation | MCPConversation | IACConversation | GitleaksConversation | SBOM_SCAConversation | Agent_DiscoveryConversation | DASTConversation, 
    engine: Engine, 
    mongo_db: Database,
    conversation_id: int,
    user_id: int,   
    sast_data: StartSastScanData | None = None,
    llm_data: StartLLMBenchmarkingData | None = None,
    mcp_data: StartMCPScanData | None = None,
    iac_data: StartGeneralScanData | None = None,
    leakage_data: StartGeneralScanData | None = None,
    sbom_sca_data: StartGeneralScanData | None = None,
    agent_discovery_data: StartGeneralScanData | None = None,
    dast_data: StartDASTScanData | None = None,
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
            task_result = simple_app.send_task(name="scan_worker.sast", kwargs=sast_kwargs, queue="scan_worker_queue")
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
            task_result = simple_app.send_task(name="scan_worker.llm_benchmark", kwargs=llm_kwargs, queue="scan_worker_queue")
        elif type == "mcp":
            mcp_kwargs={
                "server_config_json":mcp_data.server_config,
            }
            task_result = simple_app.send_task(name="scan_worker.mcp", kwargs=mcp_kwargs, queue="scan_worker_queue")
        elif type == "iac":
            iac_kwargs={
                "dict_context":{
                    "mode":iac_data.mode,
                    "repo_url":iac_data.repo_url,
                    "PAT":iac_data.PAT,
                },
            }
            task_result = simple_app.send_task(name="scan_worker.iac", kwargs=iac_kwargs, queue="scan_worker_queue")
        elif type == "leakage":
            leakage_kwargs={
                "dict_context":{
                    "mode":leakage_data.mode,
                    "repo_url":leakage_data.repo_url,
                    "PAT":leakage_data.PAT,
                },
            }
            task_result = simple_app.send_task(name="scan_worker.gitleaks", kwargs=leakage_kwargs, queue="scan_worker_queue")
        elif type == "sbom_sca":
            sbom_sca_kwargs={
                "dict_context":{
                    "mode":sbom_sca_data.mode,
                    "repo_url":sbom_sca_data.repo_url,
                    "PAT":sbom_sca_data.PAT,
                },
            }
            task_result = simple_app.send_task(name="scan_worker.sbom_sca", kwargs=sbom_sca_kwargs, queue="scan_worker_queue")
        elif type == "agent_discovery":
            agent_discovery_kwargs={
                "dict_context":{
                    "mode":agent_discovery_data.mode,
                    "repo_url":agent_discovery_data.repo_url,
                    "PAT":agent_discovery_data.PAT,
                },
            }
            task_result = simple_app.send_task(name="scan_worker.discovery", kwargs=agent_discovery_kwargs, queue="scan_worker_queue")
        elif type == "dast":
            if dast_data.auth_mode == "header_cookie_based":
                dast_kwargs={
                    "target_url":dast_data.header_cookie_based.target_url,
                    "attack_modules":dast_data.header_cookie_based.attack_modules,
                    "max_scan_time":dast_data.header_cookie_based.max_scan_time,
                    "user_agent":dast_data.header_cookie_based.user_agent,
                    "headers":[{"name": header.name, "value": header.value} for header in dast_data.header_cookie_based.headers] if dast_data.header_cookie_based.headers else [],
                    "cookies":[{"name": cookie.name, "value": cookie.value} for cookie in dast_data.header_cookie_based.cookies] if dast_data.header_cookie_based.cookies else [],
                    "scan_force":dast_data.header_cookie_based.scan_force,
                    "exclude_url_patterns":dast_data.header_cookie_based.exclude_url_patterns,
                    "additional_urls":dast_data.header_cookie_based.additional_urls,
                }
                console.print(f"Sending task to wapiti dast worker with kwargs: {dast_kwargs}",style="bold green")
                task_result = simple_app.send_task(name="dast_worker.wapiti_dast", kwargs=dast_kwargs, queue="dast_worker_queue")
            elif dast_data.auth_mode == "form_based":
                dast_kwargs={
                    "target_url":dast_data.form_based.target_url,
                    "login_url":dast_data.form_based.login_url,
                    "include_urls":dast_data.form_based.include_urls,
                    "exclude_urls":dast_data.form_based.exclude_urls,
                    "timeout_durations_mins":dast_data.form_based.timeout_durations_mins,
                    "poll_durations_seconds":dast_data.form_based.poll_durations_seconds,
                    "username_value":dast_data.form_based.username_value,
                    "password_value":dast_data.form_based.password_value,
                    "username_key":dast_data.form_based.username_key,
                    "password_key":dast_data.form_based.password_key,
                    "logged_in_regex":dast_data.form_based.logged_in_regex,
                    "logged_out_regex":dast_data.form_based.logged_out_regex,
                }
                console.print(f"Sending task to zap dast worker with kwargs: {dast_kwargs}",style="bold green")
                task_result = simple_app.send_task(name="dast_worker.zap_dast", kwargs=dast_kwargs, queue="dast_worker_queue")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid type of scan")

        
        try: 
            if not task_result:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending task to Scan worker , please try again later")
            if not task_result.id:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending task to Scan worker , please try again later")
        except Exception as e:
            console.print(f"Error in checking task result: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending task to Scan worker , please try again later")


        # STEP [ 3 ] : =========== Update the main db conversation the task id and status of task======================
        time.sleep(2) 
        with Session(engine) as session:
            conversation = None
            conversation = session.exec(select(table).where(table.id == conversation_id).where(table.user_id == user_id)).first()
            if conversation==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found or User not allowed to start this conversation")
            conversation.task_id = task_result.id

            # getting the status of the task and adding it to the conversation in main db
            async_result : AsyncResult = simple_app.AsyncResult(task_result.id)
            SCAN_STATUS = str(async_result.state).lower()
            conversation.scan_status = SCAN_STATUS
            
    
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
            
            elif type == "iac" and table == IACConversation:
                console.print(f"Updating conversation data for iac scan with metadata" ,style="bold green")
                conversation.mode = iac_data.mode
                conversation.repo_url = iac_data.repo_url
            elif type == "leakage" and table == GitleaksConversation:
                console.print(f"Updating conversation data for leakage scan with metadata" ,style="bold green")
                conversation.mode = leakage_data.mode
                conversation.repo_url = leakage_data.repo_url
            elif type == "sbom_sca" and table == SBOM_SCAConversation:
                console.print(f"Updating conversation data for sbom_sca scan with metadata" ,style="bold green")
                conversation.mode = sbom_sca_data.mode
                conversation.repo_url = sbom_sca_data.repo_url
            elif type == "agent_discovery" and table == Agent_DiscoveryConversation:
                console.print(f"Updating conversation data for agent discovery scan with metadata" ,style="bold green")
                conversation.mode = agent_discovery_data.mode
                conversation.repo_url = agent_discovery_data.repo_url
            elif type == "dast" and table == DASTConversation:
                console.print(f"Updating conversation data for dast scan with metadata" ,style="bold green")
                conversation.auth_mode = dast_data.auth_mode
                if dast_data.auth_mode == "header_cookie_based":
                    conversation.target_url = dast_data.header_cookie_based.target_url
                elif dast_data.auth_mode == "form_based":
                    conversation.target_url = dast_data.form_based.target_url
            session.commit()
    except Exception as e:
        console.print(f"Error in start_scan: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in starting scan , please try again later")





# ======================================= functions for assembling output data for different types of conversations ======================
def return_conversations_list_for_type(
    type: scan_types, 
    sequence : Sequence[SASTConversation] | Sequence[LLMBenchmarkingConversation] | Sequence[MCPConversation] | Sequence[IACConversation] | Sequence[GitleaksConversation] | Sequence[SBOM_SCAConversation] | Sequence[Agent_DiscoveryConversation] | Sequence[DASTConversation]):
    conversations_data = []
    conversations_to_update = []
    match type:
        case "sast":
            for conversation in sequence:
                if (conversation.scan_status == "pending" or conversation.scan_status == "started") and conversation.task_id:
                    conversations_to_update.append((conversation.id,conversation.task_id))
                conversations_data.append({
                    "id": conversation.id,
                    "repo_url": conversation.repo_url,
                    "mode": conversation.mode,
                    "app_lang": conversation.app_lang,
                    "title": conversation.title,
                    "created_at": conversation.created_at,
                    "last_updated": conversation.last_updated,
                    "scan_status": conversation.scan_status.lower(),
                })
        case "llm":
            for conversation in sequence:
                if (conversation.scan_status == "pending" or conversation.scan_status == "started") and conversation.task_id:
                    conversations_to_update.append((conversation.id,conversation.task_id))
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
                if (conversation.scan_status == "pending" or conversation.scan_status == "started") and conversation.task_id:
                    conversations_to_update.append((conversation.id,conversation.task_id))
                conversations_data.append({
                    "id": conversation.id,
                    "title": conversation.title,
                    "created_at": conversation.created_at,
                    "last_updated": conversation.last_updated,
                    "scan_status": conversation.scan_status.lower(),
                })
        case "iac" | "leakage" | "sbom_sca" | "agent_discovery":
            for conversation in sequence:
                if (conversation.scan_status == "pending" or conversation.scan_status == "started") and conversation.task_id:
                    conversations_to_update.append((conversation.id,conversation.task_id))
                conversations_data.append({
                    "id": conversation.id,
                    "repo_url": conversation.repo_url,
                    "mode": conversation.mode,
                    "title": conversation.title,
                    "created_at": conversation.created_at,
                    "last_updated": conversation.last_updated,
                    "scan_status": conversation.scan_status.lower(),
                })
        case "dast":
            for conversation in sequence:
                if (conversation.scan_status == "pending" or conversation.scan_status == "started") and conversation.task_id:
                    conversations_to_update.append((conversation.id,conversation.task_id))
                conversations_data.append({
                    "id": conversation.id,
                    "target_url": conversation.target_url,
                    "auth_mode": conversation.auth_mode,
                    "title": conversation.title,
                    "created_at": conversation.created_at,
                    "last_updated": conversation.last_updated,
                    "scan_status": conversation.scan_status.lower(),
                })
        case _:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid type of conversation")

    return (conversations_data,conversations_to_update)


def return_conversation_data(
    conversation: SASTConversation | LLMBenchmarkingConversation | MCPConversation | IACConversation | GitleaksConversation | SBOM_SCAConversation | Agent_DiscoveryConversation | DASTConversation, 
    type: scan_types,
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
        case "iac" | "leakage" | "sbom_sca" | "agent_discovery":
            return {
                "title": conversation.title,
                "repo_url": conversation.repo_url,
                "scan_status": SCAN_STATUS.lower(),
                "data": SCAN_DATA,
                "messages": MESSAGES,
            }
        case "dast":
            return {
                "title": conversation.title,
                "target_url": conversation.target_url,
                "auth_mode": conversation.auth_mode,
                "scan_status": SCAN_STATUS.lower(),
                "data": SCAN_DATA,
                "messages": MESSAGES,
            }
        case _:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid type of conversation")

# ======================================================= background task for updating statuses of conversations in main db ======================================================
def update_status_of_conversation_in_main_db(
    conversations: list[(int,str)], 
    user_id: int, 
    type: scan_types, 
    engine: Engine):
    try:
        console.print(f"Updating statuses of conversations " ,style="bold bright_cyan")
        
        
        # get the table from the type
        table = get_Table_from_type(type)


        # cycle through the conversations and update the status of the conversation in main db
        for conversation_id,task_id in conversations:
            get_status_and_update_db(
                conversation_id=conversation_id, 
                task_id=task_id,
                table=table, 
                engine=engine)
            console.print(f"Status of conversation: {conversation_id} updated in main db" ,style="bold green")
    except Exception as e:
        console.print(f"Error in update_status_of_conversation_in_main_db: {e}",style="bold red")