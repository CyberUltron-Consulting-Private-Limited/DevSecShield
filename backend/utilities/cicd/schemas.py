from pydantic import BaseModel, Field
from backend.new_models import scan_types
from typing import Literal

class CreateCicdIntegrationData(BaseModel):
    title: str | None = None
    scan_type: scan_types | None = None

class JiraCICDSettingsData(BaseModel):
    jira_project_id: str | None = None

class CicdIntegrationSettingsData(BaseModel):
    jira: JiraCICDSettingsData | None = None

class SastScanSettingsData(BaseModel):
    app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] 
    exclude_path_arrays: list[list[str]] | None = None

class CbomScanSettingsData(BaseModel):
    scan_binaries: bool = False

class CicdScanSettingsData(BaseModel):
    sast: SastScanSettingsData | None = None
    cbom: CbomScanSettingsData | None = None


class UpdateCicdIntegrationData(BaseModel):
    title: str | None = None
    integration_settings: CicdIntegrationSettingsData | None = None
    scan_settings: CicdScanSettingsData | None = None

class RunCicdScanData(BaseModel):
    app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] | None = None

