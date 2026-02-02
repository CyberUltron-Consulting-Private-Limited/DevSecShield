import datetime
from typing import Dict, Literal
from sqlmodel import JSON, Column, DateTime, Field, SQLModel, String, Relationship
scan_types = Literal["sast", "llm", "mcp" , "iac" , "leakage" , "sbom_sca" , "agent_discovery", "dast"]



class VerificationCode(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    email : str
    code : str
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    expires_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10),sa_type=DateTime)
    
    class Config:
        arbitrary_types_allowed = True



# every user is a member of the "default-team" by default when a user is created ⭐
class TeamMembership(SQLModel,table=True): # many-to-many relationship between team and user
    team_id : int | None = Field(default=None,foreign_key="team.id",primary_key=True)
    user_id : int | None = Field(default=None,foreign_key="user.id",primary_key=True)
    role : Literal["admin" , "member"] = Field(default="member",sa_type=String)

    team : "Team" = Relationship(back_populates="team_memberships")
    user : "User" = Relationship(back_populates="team_memberships")



class Team(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    name : str = Field(default="New Team")
    description : str | None = Field(default=None)
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    credit_balance : int = Field(default=0)
    integration_settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON)) 
    settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))

    # many-to-many relationship between team and user
    team_memberships : list[TeamMembership] = Relationship(back_populates="team")

class User(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    email : str
    password : str
    first_name : str | None
    last_name : str | None
    profile_photo : str | None
    session_active : bool | None = Field(default=False)
    last_active : datetime.datetime | None = Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    is_superuser : bool | None = Field(default=False)
    default_team_id : int | None = Field(default=None,foreign_key="team.id")

    # many-to-many relationship between user and team
    team_memberships : list[TeamMembership] = Relationship(back_populates="user")

    # guardrails integrations that this user owns 
    guardrails_integrations : list["GuardrailsIntegration"] = Relationship(back_populates="owner_user")

    # cicd integrations that this user owns 
    cicd_integrations : list["CicdIntegration"] = Relationship(back_populates="owner_user")

    # scans that this user owns 
    scans : list["Scan"] = Relationship(back_populates="owner_user")
    

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

    # owner user relationship
    owner_user : "User" = Relationship(back_populates="scans")

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
    owner_user_id : int = Field(foreign_key="user.id")
    api_key : str
    title : str = Field(default="New Guardrails Integration")
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    settings : Dict | None = Field(default=default_settings,sa_column=Column(JSON))  # scanner settings 
    integration_settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))  # integration settings 
    
    # owner user relationship
    owner_user : "User" = Relationship(back_populates="guardrails_integrations")
    
    
    class Config:
        arbitrary_types_allowed = True


# ========================================= CI/CD Integration =========================================

class CicdIntegration(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    team_id : int = Field(foreign_key="team.id")
    owner_user_id : int = Field(foreign_key="user.id")
    api_key : str
    title : str = Field(default="New CI/CD Integration")
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    scan_type : scan_types | None= Field(default=None,sa_type=String)
    results : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    integration_settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))  # integration settings 
    
    # owner user relationship
    owner_user : "User" = Relationship(back_populates="cicd_integrations")
    
    class Config:
        arbitrary_types_allowed = True