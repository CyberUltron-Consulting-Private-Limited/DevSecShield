from pydantic import BaseModel
from typing import Literal, Optional

ProbesLiteral = Literal["all", "ansiescape", "atkgen", "audio", "av_spam_scanning", "continuation", "dan", "divergence", "doctor", "donotanswer", "encoding", "exploitation", "fileformats", "glitch", "goodside", "grandma", "latentinjection", "leakreplay", "lmrc", "malwaregen", "misleading", "packagehallucination", "phrasing", "promptinject", "realtoxicityprompts", "sata", "snowball", "suffix", "tap", "test", "topic", "visual_jailbreak", "xss"]

class LLMBenchmarkingContext(BaseModel):
    """
    Context for LLM Benchmarking
    """
    model_type: Literal["openai", "anthropic", "gemini","custom"]
    model_name: str 
    probes: ProbesLiteral = "all"
    api_key: Optional[str] = None
    headers: Optional[dict] = None
    request_template: Optional[dict] = None
    response_json_field: Optional[str] = None
    generations: Optional[int] = 1
    method: Literal["get", "post"] = "post"
    model_uri: Optional[str] = None

