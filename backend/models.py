import datetime
from typing import Dict, List, Literal, Optional
from sqlmodel import JSON, Column, DateTime, Field, Integer, Session, SQLModel, String, create_engine, select
from pydantic import BaseModel
from backend.auth_utils.plans import plans

class User(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    email : str
    password : str
    first_name : str | None
    last_name : str | None
    profile_photo : str | None

    
    session_active : bool | None = Field(default=False)
    last_active : datetime.datetime | None = Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)

    # superuser
    is_superuser : bool | None = Field(default=False)

    # plan related fields
    plan : str = Field(default="free")
    total_scans : int = Field(default=0)

class VerificationCode(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    email : str
    code : str
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    expires_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10),sa_type=DateTime)
    
    class Config:
        arbitrary_types_allowed = True



class SASTConversation(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    user_id : int = Field(foreign_key="user.id")
    task_id : str | None = Field(default=None)
    mode : Literal["github", "gitlab", "bitbucket","not_initiated"] = Field(default="not_initiated",sa_type=String)
    repo_url : str | None = Field(default=None)
    app_lang : Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] | None = Field(default=None,sa_type=String)
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)
    title : str = Field(default="New SAST Conversation")
    conversation_id : str #mongo db conversation id
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    message_limit : int

    class Config:
        arbitrary_types_allowed = True
    
class LLMBenchmarkingConversation(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    user_id : int = Field(foreign_key="user.id")
    task_id : str | None = Field(default=None)
    model_type : Literal["openai", "anthropic", "gemini", "custom"] | None = Field(default=None,sa_type=String)
    model_name : str | None
    probes : List[str] | None = Field(default_factory=list,sa_column=Column(JSON))
    generations : int | None = Field(default=1,sa_type=Integer)
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)
    title : str = Field(default="New SAST Conversation")
    conversation_id : str #mongo db conversation id
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    message_limit : int

    class Config:
        arbitrary_types_allowed = True


class MCPConversation(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    user_id : int = Field(foreign_key="user.id")
    task_id : str | None = Field(default=None)
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)
    title : str = Field(default="New SAST Conversation")
    conversation_id : str #mongo db conversation id
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    message_limit : int

    class Config:
        arbitrary_types_allowed = True

class IACConversation(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    user_id : int = Field(foreign_key="user.id")
    task_id : str | None = Field(default=None)
    mode : Literal["github", "gitlab", "bitbucket","not_initiated"] = Field(default="not_initiated",sa_type=String)
    repo_url : str | None = Field(default=None)
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)
    title : str = Field(default="New SAST Conversation")
    conversation_id : str #mongo db conversation id
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    message_limit : int

    class Config:
        arbitrary_types_allowed = True



class SBOM_SCAConversation(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    user_id : int = Field(foreign_key="user.id")
    task_id : str | None = Field(default=None)
    mode : Literal["github", "gitlab", "bitbucket","not_initiated"] = Field(default="not_initiated",sa_type=String)
    repo_url : str | None = Field(default=None)
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)
    title : str = Field(default="New SAST Conversation")
    conversation_id : str #mongo db conversation id
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    message_limit : int

    class Config:
        arbitrary_types_allowed = True

class Agent_DiscoveryConversation(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    user_id : int = Field(foreign_key="user.id")
    task_id : str | None = Field(default=None)
    mode : Literal["github", "gitlab", "bitbucket","not_initiated"] = Field(default="not_initiated",sa_type=String)
    repo_url : str | None = Field(default=None)
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)

    title : str = Field(default="New SAST Conversation")
    conversation_id : str #mongo db conversation id
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    message_limit : int

    class Config:
        arbitrary_types_allowed = True


class DASTConversation(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    user_id : int = Field(foreign_key="user.id")
    task_id : str | None = Field(default=None)

    auth_mode : Literal["form_based" , "header_cookie_based"] | None = Field(default=None,sa_type=String)
    target_url : str | None = Field(default=None)
    
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)  
    title : str = Field(default="New DAST Conversation")
    conversation_id : str #mongo db conversation id
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    message_limit : int

    class Config:
        arbitrary_types_allowed = True


# ========================================= Guardrails Integration =========================================
"""
threshold should not be 0 or it will fail the scan ( add validation for this )
"""
default_settings = {
    "anonymize": None,
    "toxicity": None,
    "tokenlimit": None,
    "promptinjection": None,
    "regex": None,
    "code": None,
    "secrets": None
}

class GuardrailsIntegration(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    user_id : int = Field(foreign_key="user.id")
    api_key : str
    title : str = Field(default="New Guardrails Integration")
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)

    # scanner settings 
    settings : Dict | None = Field(default=default_settings,sa_column=Column(JSON))



    class Config:
        arbitrary_types_allowed = True


# ========================================= CI/CD Integration =========================================
scan_types = Literal["sast", "llm", "mcp" , "iac" , "leakage" , "sbom_sca" , "agent_discovery"]

class CicdIntegration(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    user_id : int = Field(foreign_key="user.id")
    api_key : str
    title : str = Field(default="New CI/CD Integration")
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)

    # settings
    scan_type : scan_types | None= Field(default=None,sa_type=String)


    # results
    results : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))

    class Config:
        arbitrary_types_allowed = True