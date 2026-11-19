from pydantic import BaseModel, Field, model_validator
from backend.new_models import scan_types
from backend.utilities.scan.path_patterns import PATH_PATTERN_VERSION, check_excludes
from typing import Literal

class CreateCicdIntegrationData(BaseModel):
    title: str | None = None
    scan_type: Literal["sast", "dast", "cbom"] | None = None

class JiraCICDSettingsData(BaseModel):
    jira_project_id: str | None = None
    auto_create_tickets: bool | None = None

class CicdIntegrationSettingsData(BaseModel):
    jira: JiraCICDSettingsData | None = None

class SastScanSettingsData(BaseModel):
    app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] 
    exclude_path_arrays: list[list[str]] | None = None
    # saved with the settings: excludes saved before #443 (no version) are translated when a run starts (format_input)
    path_pattern_v: int = PATH_PATTERN_VERSION

    @model_validator(mode="after")
    def validate_exclude_path_arrays(self):
        check_excludes(self.exclude_path_arrays)  # an exclude matching every file leaves nothing to scan
        return self

class CbomScanSettingsData(BaseModel):
    scan_binaries: bool = False
    include_vendored: bool = False  # also read vendor/, dist/, build/, node_modules/ (opt-in, as code scans)

class AiBomScanSettingsData(BaseModel):
    scan_binaries: bool = False

class CicdScanSettingsData(BaseModel):
    sast: SastScanSettingsData | None = None
    cbom: CbomScanSettingsData | None = None
    ai_bom: AiBomScanSettingsData | None = None


class UpdateCicdIntegrationData(BaseModel):
    title: str | None = None
    integration_settings: CicdIntegrationSettingsData | None = None
    scan_settings: CicdScanSettingsData | None = None

class RunCicdScanData(BaseModel):
    app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] | None = None

