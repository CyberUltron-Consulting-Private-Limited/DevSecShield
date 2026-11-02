from pydantic import BaseModel, Field
from typing import Literal
from fastapi import HTTPException, status
from pydantic import model_validator

from backend.utilities.git_hosts import check_repo_url

class CreateScanData(BaseModel):
    title: str = Field(min_length=1, max_length=256)

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
    auto_create_tickets: bool | None = None

class ScanTicketingIntegrationSettingsData(BaseModel):
    jira: JiraScanSettingsData | None = None

class UpdateScanData(BaseModel):
    title: str | None = Field(default=None, max_length=256)
    integration_settings: ScanTicketingIntegrationSettingsData | None = None

class RemoveOrAddMembersToTeamData(BaseModel):
    intent : Literal["remove" , "add"]
    email_ids: list[str]

class CreateTicketData(BaseModel):
    ticket_type: Literal["jira"]
    summary: str
    description: str
    finding_ids: list[str] | None = None
# ----------------------------------------------------- Start scan related schemas --------------------------------------------

def _validate_repo_url(repo_url: str, provider_host: str, provider_label: str) -> None:
    """
    Validate that `repo_url` is an https URL of the provider host (e.g. 'github.com') or a subdomain of it, or of a
    self-hosted Git server the operator listed in GIT_ALLOWED_HOSTS (plain http only for hosts listed as http://).
    Exact host / suffix matching rejects look-alike hosts such as 'github.com.evil.tld'. The scan worker applies the
    same rules (backend/utilities/git_hosts.py is shared byte for byte with it).

    Raises ValueError on failure. Pydantic converts the ValueError raised
    inside a `mode="after"` validator into a ValidationError, which the
    scan handlers map to a 422 response.
    """
    check_repo_url(repo_url, provider_host, provider_label)


class GithubContextSchema(BaseModel):
    mode: Literal["github"] = "github"
    repo_url: str
    PAT: str
    branch: str = "main"

    @model_validator(mode="after")
    def validate_repo_url(self):
        _validate_repo_url(self.repo_url, "github.com", "GitHub")
        return self

class GitlabContextSchema(BaseModel):
    mode: Literal["gitlab"] = "gitlab"
    repo_url: str
    PAT: str
    branch: str = "main"

    @model_validator(mode="after")
    def validate_repo_url(self):
        _validate_repo_url(self.repo_url, "gitlab.com", "GitLab")
        return self

class BitbucketContextSchema(BaseModel):
    mode: Literal["bitbucket"] = "bitbucket"
    repo_url: str
    PAT: str
    branch: str = "main"

    @model_validator(mode="after")
    def validate_repo_url(self):
        _validate_repo_url(self.repo_url, "bitbucket.org", "Bitbucket")
        return self

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
    include_vendored : bool = False  # code scans: also read vendor/, dist/, build/, node_modules/ (opt-in)

    @model_validator(mode="after")
    def validate_data(self):
        if not self.cbom_file_used and not self.zip_file_used and not self.repo_context:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CBOM file or zip file or repository context is required")
        return self


class StartAIBOMScanData(BaseStartRepositoryScanData):
    zip_file_used : bool = False
    ai_bom_file_used : bool = False  # if true, a pre-existing AI-BOM JSON file was uploaded
    scan_binaries : bool = False   # if true, enable binary/config scanning

    @model_validator(mode="after")
    def validate_data(self):
        if not self.ai_bom_file_used and not self.zip_file_used and not self.repo_context:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="AI-BOM file or zip file or repository context is required")
        return self


class StartScanPayload(BaseModel):
    sast : StartSastScanData | None = None
    iac : StartIACScanData | None = None
    sbom_sca : StartSBOMScanData | None = None
    mcp : StartMCPScanData | None = None
    llm : StartLLMBenchmarkingData | None = None
    dast : StartDASTScanData | None = None
    cbom : StartCBOMScanData | None = None
    ai_bom : StartAIBOMScanData | None = None