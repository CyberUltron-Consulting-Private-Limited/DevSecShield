from pydantic import BaseModel, Field
from typing import Literal
import json

class IACTypeContext(BaseModel):
    mode : Literal["terraform","k8s","pulumi","ansible","helm","aws_cloudformation","aws_cdk"] | None= Field(default=None)
    include_path_arrays: list[list[str]] = Field(default=[])


def validate_dict_with_iac_context(dict_context: dict) -> IACTypeContext:
    try:
        json_context = json.dumps(dict_context)
        context = IACTypeContext.model_validate_json(json_context)
        return context
    except Exception as e:
        raise ValueError(f"Invalid iac context JSON: {e}")