from typing import TypedDict, Literal, List, Optional
from datetime import datetime

# Conversation types
ConversationType = Literal[
    "sast",
    "sbom_sca",
    "iac",
    "gitleaks",
    "discovery",
    "llm",
    "mcp",
    "dast",
    "cbom",
    "ai_bom"
]

# Message/Active context types
MessageType = Literal["message", "tool"]
SenderType = Literal["user", "assistant"]


class ScanFindings(TypedDict, total=False):

    scan_id: int # int of scan collection document 
    created_at: datetime

    finding_data : dict | None = None
    finding_status : Literal["fixed" , "ignored" , "in_progress" , "not_started"] = "not_started"
    fixed_at : datetime | None = None
    ignored_at : datetime | None = None
    info : dict | None = None

class MessageLog(TypedDict, total=False):

    _id: str  # MongoDB ObjectId  (auto-generated, always present when reading)
    scan_id: int # int of scan collection document 
    # user_id: int
    content: str
    created_at: datetime
    type: MessageType
    sender: SenderType


class ActiveContextLog(TypedDict, total=False):

    _id: str  # MongoDB ObjectId  (auto-generated, always present when reading)
    scan_id: int # int of scan collection document 
    # user_id: int
    content: str
    created_at: datetime
    type: MessageType
    sender: SenderType

class GuardrailLogs(TypedDict, total=False):

    _id: str  # MongoDB ObjectId as string (auto-generated, always present when reading)
    integration_id: str  
    task_id: str # celery task id ( has to be created when the task is initiated or log created )
    status: Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = "NOT_STARTED"
    # user_id: int
    input_prompt: str
    created_at: datetime

    # scanner settings
    settings : dict | None = None 

    # results
    results: dict | None = None

    # calculated fields
    # check_passed: bool | None = None  # not in use ( maybe remove this )


class CicdLogs(TypedDict, total=False):

    _id: str  # MongoDB ObjectId as string (auto-generated, always present when reading)
    ci_cd_integration_id: str # ObjectId as string of guardrails integration collection document 
    # user_id: int
    task_id: str # celery task id ( has to be created when the task is initiated or log created )
    status: Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = "NOT_STARTED"
    created_at: datetime

    credits_consumed: float | None = None
    scan_settings_metadata: dict | None = None

    # results
    results: dict | None = None

    # error
    error: str | None = None
