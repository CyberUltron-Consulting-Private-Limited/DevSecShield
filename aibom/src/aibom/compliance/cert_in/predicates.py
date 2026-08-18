"""Pure CERT-In graph helpers — no cbom / scanner imports."""

from __future__ import annotations

from typing import Any

__all__ = ["prop", "has_nonempty", "has_purl_like"]


def prop(component: Any, key: str, default: str | None = None) -> str | None:
    """Read a namespaced property off a component (dict or object with `.properties`)."""
    props = getattr(component, "properties", None)
    if props is None and isinstance(component, dict):
        props = component.get("properties")
    if not isinstance(props, dict):
        return default
    val = props.get(key)
    if val is None:
        return default
    text = str(val).strip()
    return text if text else default


def has_nonempty(value: Any) -> bool:
    """True when ``value`` is a non-empty string / collection after strip."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def has_purl_like(value: Any) -> bool:
    """Loose PURL / bom-ref presence check (pkg:… or non-empty identifier)."""
    if not has_nonempty(value):
        return False
    text = str(value).strip()
    return text.startswith("pkg:") or ("/" in text) or (":" in text) or len(text) >= 3
