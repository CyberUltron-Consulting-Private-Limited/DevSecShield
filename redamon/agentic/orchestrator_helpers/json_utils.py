"""JSON utilities for the orchestrator."""

import json
from datetime import datetime
from typing import Optional


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""

    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def json_dumps_safe(obj, **kwargs) -> str:
    """JSON dumps with datetime support."""
    return json.dumps(obj, cls=DateTimeEncoder, **kwargs)


def normalize_content(content) -> str:
    """Extract text from LLM response content.

    ChatBedrockConverse (and some Anthropic wrappers) return content as a list
    of content blocks, e.g. [{"type": "text", "text": "..."}], instead of a
    plain string.  This normalizes both forms to a single string.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block["text"])
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return str(content)


def extract_json(response_text: str) -> Optional[str]:
    """Extract JSON from LLM response (may be wrapped in markdown)."""
    json_start = response_text.find("{")
    json_end = response_text.rfind("}") + 1

    if json_start >= 0 and json_end > json_start:
        return response_text[json_start:json_end]
    return None
