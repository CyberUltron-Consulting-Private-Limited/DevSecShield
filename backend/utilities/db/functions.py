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


console = Console()

# ============================================================ Request body models ===========================================================
class CreateScanData(BaseModel):
    title: str

class SendMessageToScanData(BaseModel):
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


class StartScanPayload(BaseModel):
    sast : StartSastScanData | None = None
    llm : StartLLMBenchmarkingData | None = None
    mcp : StartMCPScanData | None = None
    iac : StartGeneralScanData | None = None
    sbom_sca : StartGeneralScanData | None = None
    agent_discovery : StartGeneralScanData | None = None
    dast : StartDASTScanData | None = None


class UpdateScanData(BaseModel):
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


# revamped ✅
def get_messages_from_scan(
    scan_id: int,
    team_id: int, 
    engine: Engine, 
    mongo_db: Database):
    """
    Returns the messages from the scan.
    If messages not found , raise an exception.
    """
    try:

        # STEP [ 1 ] : =========== get the scan from the main db to get the scan id ======================
        scan = None
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id).where(Scan.team_id == team_id)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        console.print(f"Scan id: {scan.id} found in main database" ,style="bold green")
        

        # STEP [ 2 ] : =========== return the messages from the mongo db ======================
        with mongo_db["message_log"].find({"scan_id": scan.id}).sort("created_at", 1) as messages:
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
            console.print(f"{len(messages_data)} messages found for scan: {scan.id}" ,style="bold green")
            return messages_data

        
    except Exception as e:
        console.print(f"Error in get_messages_from_scan: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in fetching messages from scan , please try again later")





# revamped ✅
# ======================================= functions for assembling output data for different types of conversations ======================
def return_scan_list_for_type(
    sequence : Sequence[Scan]
    )->tuple[list[dict],list[tuple[int,str]]]:
    """
    Returns a tuple of two lists.
    - The first list contains the data for each scan.
    - The second list contains the ids and task ids of the scans that need to be updated.
    scans list to update example  : [(scan_id,task_id)]
    """

    try:
        scans_list_data = []
        scans_to_update = []
        
        for scan in sequence:
            if (scan.scan_status == "pending" or scan.scan_status == "started") and scan.task_id:
                scans_to_update.append((scan.id,scan.task_id))
            scans_list_data.append({
                "id": scan.id,
                "scan_metadata": scan.scan_metadata,
                "title": scan.title,
                "created_at": scan.created_at,
                "last_updated": scan.last_updated,
                "scan_status": scan.scan_status.lower(),
            })

        return (scans_list_data,scans_to_update)
    
    except Exception as e:
        console.print(f"Error in return_scan_list_for_type: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in returning scan list , please try again later")




# ======================================================= background task for updating statuses of conversations in main db ======================================================
def update_status_of_scan_in_main_db(
    scans: list[(int,str)], 
    engine: Engine):
    try:
        console.print(f"Updating statuses of scans " ,style="bold bright_cyan")
        


        # cycle through the conversations and update the status of the conversation in main db
        for scan_id,task_id in scans:
            get_status_and_update_db(
                scan_id=scan_id, 
                task_id=task_id,
                table=Scan, 
                engine=engine)
            console.print(f"Status of scan: {scan_id} updated in main db" ,style="bold green")
    except Exception as e:
        console.print(f"Error in update_status_of_conversation_in_main_db: {e}",style="bold red")