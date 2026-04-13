from pydantic import BaseModel
from typing import Literal
from fastapi import HTTPException, status
from pydantic import model_validator

class CreateScanData(BaseModel):
    title: str

class SendMessageToScanData(BaseModel):
    user_message: str


class ToggleFindingStateData(BaseModel):
    finding_id: str
    state: Literal["fixed" , "ignored" , "in_progress" , "not_started"]


class CreateTeamData(BaseModel):
    name: str
    description: str | None = None

class JiraTeamSettingsData(BaseModel):
    email: str | None = None
    api_token: str | None = None
    url: str | None = None

class TicketingIntegrationSettingsData(BaseModel):
    jira: JiraTeamSettingsData | None = None



class UpdateTeamData(BaseModel):
    name: str | None = None
    description: str | None = None
    integration_settings: TicketingIntegrationSettingsData | None = None

class JiraScanSettingsData(BaseModel):
    jira_project_id: str | None = None

class ScanTicketingIntegrationSettingsData(BaseModel):
    jira: JiraScanSettingsData | None = None

class UpdateScanData(BaseModel):
    title: str | None = None
    integration_settings: ScanTicketingIntegrationSettingsData | None = None

class RemoveOrAddMembersToTeamData(BaseModel):
    intent : Literal["remove" , "add"]
    email_ids: list[str]

class CreateTicketData(BaseModel):
    ticket_type: Literal["jira"]
    summary: str
    description: str
# ----------------------------------------------------- Start scan related schemas --------------------------------------------

class GithubContextSchema(BaseModel):
    mode: Literal["github"] = "github"
    repo_url: str
    PAT: str
    branch: str = "main"

class GitlabContextSchema(BaseModel):
    mode: Literal["gitlab"] = "gitlab"
    repo_url: str
    PAT: str
    branch: str = "main"

class BitbucketContextSchema(BaseModel):
    mode: Literal["bitbucket"] = "bitbucket"
    repo_url: str
    PAT: str
    branch: str = "main"

class BaseStartRepositoryScanData(BaseModel):
    repo_context: GithubContextSchema | GitlabContextSchema | BitbucketContextSchema | None = None
    zip_file_used : bool = False # if true , then the zip file was used to start the scan 


class StartSastScanData(BaseStartRepositoryScanData):
    exclude_path_arrays: list[list[str]] | None = None
    app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]

    @model_validator(mode="after")
    def validate_data(self):
        if not self.app_lang:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="App language is required")

        if self.app_lang not in ["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid app language")
        
        if not self.repo_context and not self.zip_file_used:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Repository context or zip file is required")

        return self

class IACContextSchema(BaseModel):
    mode : Literal["terraform","k8s","pulumi","ansible","helm","aws_cloudformation","aws_cdk"] 
    include_path_arrays: list[list[str]] = []

class StartIACScanData(BaseStartRepositoryScanData):
    iac_contexts: list[IACContextSchema]
    environment: Literal["production", "staging", "development"] = "development"


    @model_validator(mode="after")
    def validate_data(self):
        if not self.iac_contexts:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IAC contexts are required")
        if not self.repo_context and not self.zip_file_used:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Repository context or zip file is required")
        return self


class StartSBOMScanData(BaseStartRepositoryScanData):
    zip_file_used : bool = False # if true , then the zip file was used to start the scan 
    sbom_file_used : bool = False # if true , then the sbom file was used to start the scan 

    @model_validator(mode="after")
    def validate_data(self):
        if not self.sbom_file_used and not self.zip_file_used and not self.repo_context:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SBOM file or zip file or repository context is required")
        return self


class StartMCPScanData(BaseModel):
    server_url: str
    server_mode: Literal["httpstreamable", "sse"]
    headers: dict | None = None
    environment: Literal["production", "staging", "development"] = "development"

    @model_validator(mode="after")
    def validate_data(self):
        if not self.server_url or not self.server_url.strip():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MCP server URL is required")
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


class AuthRequirements(BaseModel):
    login_url: str 
    xpath_of_username_field: str 
    xpath_of_password_field: str    
    username: str 
    password: str 
    xpath_of_submit_button: str 

class StartDASTScanData(BaseModel):
    """
    Both include and exclude url patterns are not going to be used together 
    """
    target_url: str
    auth : AuthRequirements 
    scan_speed : Literal["fast" , "medium" , "slow"] = "medium"
    max_urls: int = 100
    additional_urls_to_scan: list[str] | None = None # these urls will be scanned definitely 
    exclude_url_patterns: list[str] | None = None # either exclude urls that match these patterns or include urls that match these patterns
    include_url_patterns: list[str] | None = None # either exclude urls that match these patterns or include urls that match these patterns


class StartCBOMScanData(BaseStartRepositoryScanData):
    zip_file_used : bool = False
    cbom_file_used : bool = False  # if true, a pre-existing CBOM JSON file was uploaded
    scan_binaries : bool = False   # if true, enable cbomkit-theia binary/config scanning

    @model_validator(mode="after")
    def validate_data(self):
        if not self.cbom_file_used and not self.zip_file_used and not self.repo_context:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CBOM file or zip file or repository context is required")
        return self


class StartScanPayload(BaseModel):
    sast : StartSastScanData | None = None
    iac : StartIACScanData | None = None
    sbom_sca : StartSBOMScanData | None = None
    mcp : StartMCPScanData | None = None
    llm : StartLLMBenchmarkingData | None = None
    dast : StartDASTScanData | None = None
    cbom : StartCBOMScanData | None = None