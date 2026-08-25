import re

_HTML_RE = re.compile(r"<\s*(html|body|div|form|input|textarea|script|span|a)\b", re.I)
_INJECTION_RE = re.compile(
    r"<\s*(form|input|textarea|select)\b|contenteditable\s*=",
    re.I,
)


def documents_to_text(documents) -> str:
    if not documents:
        return ""
    parts = []
    for document in documents:
        parts.append(getattr(document, "page_content", None) or "")
    return "".join(parts)


def looks_like_html(text: str | None) -> bool:
    if not text:
        return False
    sample = text[:8000].lstrip()
    if sample[:1] in "{[" and "<" not in sample[:200]:
        return False
    return bool(_HTML_RE.search(sample))


def has_injection_surface(text: str | None) -> bool:
    if not text or not looks_like_html(text):
        return False
    return bool(_INJECTION_RE.search(text[:200000]))


def should_run_injection_agents(text: str | None, skip_if_no_surface: bool) -> bool:
    if not text:
        return False
    if skip_if_no_surface:
        return has_injection_surface(text)
    return True
