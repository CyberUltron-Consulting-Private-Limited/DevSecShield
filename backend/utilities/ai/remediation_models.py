from pydantic import BaseModel, Field
from typing import Literal


class RemediationFixCode(BaseModel):
    description: str = Field(description="A clear explanation of what the fix does and why it resolves the vulnerability")
    original_code: str = Field(description="The original vulnerable code snippet that needs to be changed")
    fixed_code: str = Field(description="The corrected/safe code snippet that replaces the vulnerable code")
    language: str = Field(description="The programming language of the code (e.g., python, javascript, yaml, dockerfile)")
    confidence: int = Field(ge=0, le=100, description="Confidence score 0-100 that this fix correctly addresses the vulnerability")
    validation_notes: str = Field(default="", description="Notes about completeness, edge cases, or limitations of this fix")
    references: list[str] = Field(default_factory=list, description="URLs to relevant documentation, CWE entries, or OWASP guides")


class ExploitPayload(BaseModel):
    description: str = Field(description="Educational explanation of how this vulnerability can be exploited")
    payload: str = Field(description="A demonstrative exploit payload or proof-of-concept code/command")
    impact_demonstration: str = Field(description="What happens when the exploit succeeds - the observable impact")
    prerequisites: str = Field(description="Conditions or access required to exploit this vulnerability")
    difficulty: Literal["trivial", "easy", "moderate", "hard", "expert"] = Field(description="How difficult it is to exploit this vulnerability")
    attack_vector: str = Field(description="The attack vector (e.g., network, local, adjacent, physical)")


class RemediationResponse(BaseModel):
    fix: RemediationFixCode
    exploit_payload: ExploitPayload
