from pydantic import BaseModel
from typing import Literal, Optional
from helpers.tools.llm_agent.probes_type import ProbesLiteral

class LLMBenchmarkingContext(BaseModel):
    """
    Context for LLM Benchmarking
    """
    model_type: Literal["openai", "anthropic", "gemini","custom"]
    model_name: str 
    probes: list[ProbesLiteral] = ["malwaregen.TopLevel","malwaregen.Evasion"]
    api_key: Optional[str] = None
    headers: Optional[dict] = None
    request_template: Optional[dict] = None
    response_json_field: Optional[str] = None
    generations: Optional[int] = 1
    method: Literal["get", "post"] = "post"
    model_uri: Optional[str] = None

