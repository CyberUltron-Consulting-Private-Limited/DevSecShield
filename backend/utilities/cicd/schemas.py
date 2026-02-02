from pydantic import BaseModel, Field
from backend.new_models import scan_types
from typing import Literal

class CreateCicdIntegrationData(BaseModel):
    title: str | None = None
    scan_type: scan_types | None = None

class IntegrationSettingsData(BaseModel):
    jira_enabled: bool = Field(description="Whether to enable Jira integration or not.",default=False)

class UpdateCicdIntegrationData(BaseModel):
    title: str | None = None
    integration_settings: IntegrationSettingsData | None = None

class RunCicdScanData(BaseModel):
    app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] | None = None

