import datetime
from typing import Dict, Literal
from sqlmodel import JSON, Column, DateTime, Field, SQLModel, String
scan_types = Literal["sast", "llm", "mcp" , "iac" , "leakage" , "sbom_sca" , "agent_discovery", "dast"]

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


class VerificationCode(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    email : str
    code : str
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    expires_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10),sa_type=DateTime)
    
    class Config:
        arbitrary_types_allowed = True


class Team(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    name : str = Field(default="New Team")
    description : str | None = Field(default=None)
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    credit_balance : int = Field(default=0)
    integration_settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON)) 
    settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))


# every user is a member of the "default-team" by default when a user is created ⭐
class TeamMember(SQLModel,table=True): # many-to-many relationship between team and user
    id : int | None = Field(default=None,primary_key=True)
    team_id : int = Field(foreign_key="team.id",index=True)
    user_id : int = Field(foreign_key="user.id",index=True)
    role : Literal["admin" , "member"] = Field(default="member",sa_type=String)

# only the user who created the scan can run the scan or update the scan  or send messages to the scan 
class Scan(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    team_id : int = Field(foreign_key="team.id")
    owner_user_id : int = Field(foreign_key="user.id") 
    credit_consumed : float | None = Field(default=None)
    scan_type : Literal["sast" , "llm" , "mcp" , "iac" , "leakage" , "sbom_sca" , "agent_discovery" , "dast"] = Field(default="sast",sa_type=String , index=True)
    title : str = Field(default="New Scan")
    task_id : str | None = Field(default=None)
    scan_metadata : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))

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
    team_id : int = Field(foreign_key="team.id")
    api_key : str
    title : str = Field(default="New Guardrails Integration")
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    settings : Dict | None = Field(default=default_settings,sa_column=Column(JSON))  # scanner settings 
    class Config:
        arbitrary_types_allowed = True


# ========================================= CI/CD Integration =========================================

class CicdIntegration(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    team_id : int = Field(foreign_key="team.id")
    api_key : str
    title : str = Field(default="New CI/CD Integration")
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_type : scan_types | None= Field(default=None,sa_type=String)
    results : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))

    class Config:
        arbitrary_types_allowed = True