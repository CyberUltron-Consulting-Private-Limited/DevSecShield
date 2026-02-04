from typing import Literal
from pydantic import BaseModel, Field


input_scanners = Literal["anonymize", "toxicity", "tokenlimit", "promptinjection", "regex", "code", "secrets"]


class AnonymizeContext(BaseModel):
    preamble: str = Field(description="Directs the LLM to bypass specific content." , default="")
    threshold: float = Field(description="Sets the acceptance threshold (Default: 0).",default=0)
    allowed_names: list[str] = Field(description="List of names to be allowed to be present in the output.",default=[])

class ToxicityContext(BaseModel):
    threshold: float = Field(description="Sets the acceptance threshold (Default: 0).",default=0)

class TokenLimitContext(BaseModel):
    max_tokens: int = Field(description="Maximum number of tokens to be allowed in the output.",default=2000)

class PromptInjectionContext(BaseModel):
    threshold: float = Field(description="Sets the acceptance threshold (Default: 0).",default=0)

class RegexContext(BaseModel):
    regex_patterns: list[str] = Field(description="List of regex patterns to be used for detection.",default=[])
    redact: bool = Field(description="Whether to redact the matched content or not.",default=False)

default_langs = ["ARM Assembly", "AppleScript", "C", "C#", "C++", "COBOL", "Erlang", "Fortran", "Go", "Java", "JavaScript", "Kotlin", "Lua", "Mathematica/Wolfram Language", "PHP", "Pascal", "Perl", "PowerShell", "Python", "R", "Ruby", "Rust", "Scala", "Swift", "Visual Basic .NET", "jq"]
class CodeContext(BaseModel):
    languages: list[Literal["ARM Assembly", "AppleScript", "C", "C#", "C++", "COBOL", "Erlang", "Fortran", "Go", "Java", "JavaScript", "Kotlin", "Lua", "Mathematica/Wolfram Language", "PHP", "Pascal", "Perl", "PowerShell", "Python", "R", "Ruby", "Rust", "Scala", "Swift", "Visual Basic .NET", "jq"]] = Field(description="List of languages to be allowed to be present in the output.",default=default_langs)
    is_blocked: bool = Field(description="Whether to block the code or not.",default=True)
    
class SecretsContext(BaseModel):
    redact_mode: Literal["REDACT_PARTIAL", "REDACT_ALL", "REDACT_HASH"] = Field(description="Mode of redactiion to be used for the secrets.",default="REDACT_PARTIAL")




class SettingsData(BaseModel):
    anonymize_context: AnonymizeContext | None = None
    toxicity_context: ToxicityContext | None = None
    tokenlimit_context: TokenLimitContext | None = None
    promptinjection_context: PromptInjectionContext | None = None
    regex_context: RegexContext | None = None
    code_context: CodeContext | None = None
    secrets_context: SecretsContext | None = None



class JiraTeamSettingsData(BaseModel):
    jira_project_id: str | None = None

class IntegrationSettingsData(BaseModel):
    jira: JiraTeamSettingsData | None = None

class CreateGuardrailsIntegrationData(BaseModel):
    title: str

class UpdateGuardrailsIntegrationData(BaseModel):
    title: str | None = None
    settings: SettingsData | None = None
    integration_settings: IntegrationSettingsData | None = None