from pydantic import BaseModel
from backend.api_routes.functions import scan_types
from typing import Literal

class CreateCicdIntegrationData(BaseModel):
    title: str | None = None
    scan_type: scan_types | None = None

class UpdateCicdIntegrationData(BaseModel):
    title: str | None = None

class RunCicdScanData(BaseModel):
    app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"] | None = None

