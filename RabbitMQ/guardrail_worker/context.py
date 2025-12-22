from pydantic import BaseModel , Field, model_validator
from typing import Literal




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




class GuardrailContext(BaseModel):
    anonymize_context: AnonymizeContext | None = Field(description="The context for the anonymize scanner",default=None)
    toxicity_context: ToxicityContext | None = Field(description="The context for the toxicity scanner",default=None)
    tokenlimit_context: TokenLimitContext | None = Field(description="The context for the tokenlimit scanner",default=None)
    promptinjection_context: PromptInjectionContext | None = Field(description="The context for the promptinjection scanner",default=None)
    regex_context: RegexContext | None = Field(description="The context for the regex scanner",default=None)
    code_context: CodeContext | None = Field(description="The context for the code scanner",default=None)
    secrets_context: SecretsContext | None = Field(description="The context for the secrets scanner",default=None)

    @model_validator(mode="after")
    def validate_context(self):
        """
        Validate the context for the guardrail scanner.

        fallback for threshold is 0.1 
        fallback for absense of tokenlimit is None for the entire scanner ( scanner will not be run )
        fallback for absense of regex patterns is None for the entire scanner ( scanner will not be run )
        fallback for absense of code languages is default_langs
        fallback for absense of secrets redact mode is REDACT_PARTIAL
        fallback for absense of allowed names is None
        fallback for absense of hidden names is None
        fallback for absense of preamble is ""
        """
        if self.anonymize_context:
            if self.anonymize_context.threshold == 0 or self.anonymize_context.threshold == None:
                self.anonymize_context.threshold = 0.1
            if self.anonymize_context.allowed_names == []:
                self.anonymize_context.allowed_names = None
            if self.anonymize_context.preamble == None :
                self.anonymize_context.preamble = ""
        if self.toxicity_context:
            if self.toxicity_context.threshold == 0 or self.toxicity_context.threshold == None:
                self.toxicity_context.threshold = 0.1
        if self.tokenlimit_context:
            if self.tokenlimit_context.max_tokens == 0 or self.tokenlimit_context.max_tokens == None:
                self.tokenlimit_context = None  # removing scanner ⚠️⚠️
        if self.promptinjection_context:
            if self.promptinjection_context.threshold == 0 or self.promptinjection_context.threshold == None:
                self.promptinjection_context.threshold = 0.1
        if self.regex_context:
            if self.regex_context.redact == None:
                self.regex_context.redact = False
            if self.regex_context.regex_patterns == []:
                self.regex_context = None # removing scanner ⚠️⚠️
        if self.code_context:
            if self.code_context.languages == []:
                self.code_context.languages = default_langs
            if self.code_context.is_blocked == None:
                self.code_context.is_blocked = True
        if self.secrets_context:
            if self.secrets_context.redact_mode == None:
                self.secrets_context.redact_mode = "REDACT_PARTIAL"
        return self