from pydantic import BaseModel, Field
from typing import Literal

class IACTypeContext(BaseModel):
    mode : Literal["terraform","k8s","pulumi","ansible","helm","aws_cloudformation","aws_cdk"] | None= Field(default=None)
    include_path_arrays: list[list[str]] = Field(default=[])