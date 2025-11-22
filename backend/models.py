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

class NormalSystemTM(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    status : Literal["started" , "not_started" , "completed" , "running" , "failed"] | None = Field(default="not_started",sa_type=String)
    user_id : int | None = Field(default=None,foreign_key="user.id")
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    dfd_path : str | None
    sys_diagram_path : str | None
    system_name : str | None
    repo_url : str | None
    PASTA_code : str | None
    MAESTRO_code : str | None
    heat_map_data : Dict | None= Field(default_factory=dict, sa_column=Column(JSON))
    compliance_tracker_data : Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    OWASP_tracker_data : Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    
    
    # Needed for Column(JSON)
    class Config:
        arbitrary_types_allowed = True

class ThreatTracker(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    tm_id : int | None = Field(default=None,foreign_key="normalsystemtm.id")
    data : Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    resolved : bool | None = Field(default=False)
    
    # Needed for Column(JSON)
    class Config:
        arbitrary_types_allowed = True

class LLMScan(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    model_type : Literal["openai", "anthropic", "gemini", "custom"] | None = Field(default=None,sa_type=String)
    model_name : str | None
    probes : str | None
    generations : int | None
    raw_scan_data : Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    user_id : int | None = Field(default=None,foreign_key="user.id")
    status : Literal["started" , "not_started" , "completed" , "running" , "failed"] | None = Field(default="not_started",sa_type=String)
    
    # Needed for Column(JSON)
    class Config:
        arbitrary_types_allowed = True

class Probe(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    llm_scan_id : int | None = Field(default=None,foreign_key="llmscan.id")
    probe_name : str | None
    detector_name : str | None
    passed : int | None
    total : int | None
    hit_rate : float | None
    fix: str | None = Field(default=None,sa_type=String)
    compliance_data : Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    OWASP_data : Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Needed for Column(JSON)
    class Config:
        arbitrary_types_allowed = True

class MCPScan(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    created_at : datetime.datetime | None= Field(default=datetime.datetime.now(datetime.timezone.utc),sa_type=DateTime)
    user_id : int | None = Field(default=None,foreign_key="user.id")
    repo : str | None = Field(default=None)

    # results
    status : Literal["started" , "not_started" , "completed" , "running" , "failed"] | None = Field(default="not_started",sa_type=String)
    total_findings : int | None = Field(default=None)
    total_results : int | None = Field(default=None)
    language : str | None = Field(default=None)
    raw_scan_data : Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Needed for Column(JSON)
    class Config:
        arbitrary_types_allowed = True

class MCPScanResults(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    mcpscan_id : int | None = Field(default=None,foreign_key="mcpscan.id")
    
    #results
    file : str | None = Field(default=None)
    rule_id : str | None = Field(default=None)
    severity : str | None = Field(default=None)
    risk : str | None = Field(default=None)
    result_class : str | None = Field(default=None) #corresponds to the "class" in the scan results
    explanation : str | None = Field(default=None)
    code : str | None = Field(default=None)
    compliance_tracker_data : Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    owasp_tracker_data : Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    fix : str | None = Field(default=None)

    resolved : bool | None = Field(default=False)
    
    # Needed for Column(JSON)
    class Config:
        arbitrary_types_allowed = True



