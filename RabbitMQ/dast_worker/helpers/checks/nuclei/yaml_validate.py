import re

import yaml

_FENCE_OPEN = re.compile(r"^```(?:ya?ml)?\s*", re.I)
_FENCE_CLOSE = re.compile(r"\s*```$")


def strip_markdown_fences(text: str) -> str:
    if not text:
        return ""
    stripped = text.strip()
    stripped = _FENCE_OPEN.sub("", stripped, count=1)
    stripped = _FENCE_CLOSE.sub("", stripped, count=1)
    return stripped.strip()


def validate_nuclei_yaml(text: str) -> tuple[bool, str | None]:
    cleaned = strip_markdown_fences(text or "")
    if not cleaned:
        return False, "empty template"
    try:
        parsed = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        return False, str(exc)
    if not isinstance(parsed, dict):
        return False, "template is not a YAML mapping"
    if not parsed.get("id"):
        return False, "missing id"
    if "headless" not in parsed and "http" not in parsed:
        return False, "missing headless or http section"
    return True, None
