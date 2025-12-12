import datetime
from typing import Dict, Literal, Optional
from sqlmodel import JSON, Column, DateTime, Field, Session, SQLModel, String, create_engine, select
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
    user_id : int
    task_id : str | None = Field(default=None)
    mode : Literal["github", "gitlab", "bitbucket","not_initiated"] = Field(default="not_initiated",sa_type=String)
    repo_url : str | None = Field(default=None)
    app_lang : Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] | None = Field(default=None,sa_type=String)
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)
    export_results : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    title : str = Field(default="New SAST Conversation")
    conversation_id : str
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    message_limit : int

    class Config:
        arbitrary_types_allowed = True
    