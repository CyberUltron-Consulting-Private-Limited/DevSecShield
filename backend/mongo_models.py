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
    "dast"
]

# Message/Active context types
MessageType = Literal["message", "tool"]
SenderType = Literal["user", "assistant"]


# class Conversation(TypedDict, total=False): # removed from use ⚠️

#     _id: str  # MongoDB ObjectId  (auto-generated, always present when reading)
#     # user_id: int 
#     messages: List[str]  # Array of ObjectIds ( as string ) of message collection documents in order (earliest to latest)
#     created_at: datetime
#     conv_type: ConversationType
#     title: str


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
