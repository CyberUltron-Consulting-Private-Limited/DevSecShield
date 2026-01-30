from pydantic import BaseModel
from typing import Literal
from fastapi import HTTPException, status
from pydantic import model_validator

class CreateScanData(BaseModel):
    title: str

class SendMessageToScanData(BaseModel):
    user_message: str

class UpdateScanData(BaseModel):
    title: str


# ----------------------------------------------------- Start scan related schemas --------------------------------------------

class GithubContextSchema(BaseModel):
    mode: Literal["github"] = "github"
    repo_url: str
    PAT: str

class GitlabContextSchema(BaseModel):
    mode: Literal["gitlab"] = "gitlab"
    repo_url: str
    PAT: str

class BitbucketContextSchema(BaseModel):
    mode: Literal["bitbucket"] = "bitbucket"
    repo_url: str
    PAT: str

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


class StartScanPayload(BaseModel):
    sast : StartSastScanData | None = None
    iac : StartIACScanData | None = None
    sbom_sca : StartSBOMScanData | None = None



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




# ----------------- for later if need be --------------------
# class StartMCPScanData(BaseModel):
#     server_config: str


# class HeaderCookieSchema(BaseModel):
#     name: str
#     value: str

# class HeaderCookieDASTSchema(BaseModel):
#     target_url: str
#     attack_modules: list[Literal["common", "all", "backup", "brute_login_form", "buster", "cms", "crlf", "csrf", "exec", "file", "htaccess", "htp", "ldap", "log4shell", "methods", "network_device", "nikto", "permanentxss", "redirect", "shellshock", "spring4shell", "sql", "ssl", "ssrf", "takeover", "timesql", "upload", "wapp", "wp_enum", "xss", "xxe"]] = ["common"]
#     max_scan_time: int = 60
#     user_agent: str | None = None
#     headers: list[HeaderCookieSchema] | None = None
#     cookies: list[HeaderCookieSchema] | None = None
#     scan_force: Literal["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"] = "normal"
#     exclude_url_patterns: list[str] | None = None
#     additional_urls: list[str] | None = None

# class FormBasedDASTSchema(BaseModel):
#     target_url: str
#     login_url: str
#     include_urls: list[str] | None = None
#     exclude_urls: list[str] | None = None
#     timeout_durations_mins: int = 20
#     poll_durations_seconds: int = 5
#     username_value: str | None = None
#     password_value: str | None = None
#     username_key: str | None = None
#     password_key: str | None = None
#     logged_in_regex: str | None = None
#     logged_out_regex: str | None = None
    
#     @model_validator(mode="after")
#     def validate_data(self):
#         if not self.target_url or not self.login_url:
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target URL and Login URL are required")
#         if not self.include_urls:
#             self.include_urls = []
#         if not self.exclude_urls:
#             self.exclude_urls = []
#         if not self.username_value or not self.password_value:
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and Password are required")
#         if not self.username_key or not self.password_key:
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and Password key are required")
#         if not self.logged_in_regex or not self.logged_out_regex:
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Logged in and Logged out regex are required")
#         return self

# class StartDASTScanData(BaseModel):
#     auth_mode: Literal["header_cookie_based" , "form_based"]
#     header_cookie_based: HeaderCookieDASTSchema | None = None
#     form_based: FormBasedDASTSchema | None = None

#     @model_validator(mode="after")
#     def validate_data(self):
#         if self.auth_mode == "header_cookie_based":
#             if not self.header_cookie_based:
#                 raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Header cookie based data is required")
#         elif self.auth_mode == "form_based":
#             if not self.form_based:
#                 raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Form based data is required")
#         return self