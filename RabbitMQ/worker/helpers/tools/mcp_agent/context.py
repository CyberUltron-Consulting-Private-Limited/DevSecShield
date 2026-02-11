from pydantic import BaseModel, Field
from typing import Literal, Optional


class MCPContext(BaseModel):
    server_url: str
    server_mode: Literal["httpstreamable","sse"]
    headers: Optional[dict] = None

class MCPTool(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    input_schema: Optional[dict] = None
    output_schema: Optional[dict] = None

class MCPPrompt(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None   
    name: Optional[str] = None
    arguments: dict | str | None = None

class MCPResource(BaseModel):
    title: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    uri: Optional[str] = None
    size: int | float | None = None

class MCPReconContext(BaseModel):
    tools: Optional[list[MCPTool]] = Field(default=None, description="A list of tools that can be used to scan the codebase")
    prompts: Optional[list[MCPPrompt]] = Field(default=None, description="A list of prompts that can be used to scan the codebase")
    resources: Optional[list[MCPResource]] = Field(default=None, description="A list of resources that can be used to scan the codebase")