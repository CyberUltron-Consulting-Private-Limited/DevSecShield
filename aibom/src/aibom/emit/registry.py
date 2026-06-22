"""Stateless reporter registry.

A reporter turns a :class:`~aibom.model.result.ScanResult` into a serialized
string for one format. Reporters are stateless and self-registering: subclass
:class:`BaseReporter`, set ``format``, decorate with ``@register_reporter``.

The registry is populated when :mod:`aibom.emit` is imported (its ``__init__``
imports each reporter module). Adding a format = adding one module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from aibom.model.result import ScanResult


class BaseReporter(ABC):
    """Render a :class:`ScanResult` to a serialized document string."""

    #: format key used on the CLI (``--format``) and in the registry.
    format: str = ""

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Return the serialized, schema-validated document as a string."""


_REPORTERS: dict[str, BaseReporter] = {}


def register_reporter(cls: type[BaseReporter]) -> type[BaseReporter]:
    """Class decorator: instantiate ``cls`` and register it under ``cls.format``."""
    if not cls.format:
        raise ValueError(f"{cls.__name__} must set a non-empty `format`")
    _REPORTERS[cls.format] = cls()
    return cls


def get_reporter(fmt: str) -> BaseReporter:
    """Return the reporter for ``fmt`` or raise ``KeyError`` listing the choices."""
    try:
        return _REPORTERS[fmt]
    except KeyError as exc:
        choices = ", ".join(available_formats()) or "(none registered)"
        raise KeyError(f"unknown format {fmt!r}; available: {choices}") from exc


def available_formats() -> list[str]:
    return sorted(_REPORTERS)


__all__ = [
    "BaseReporter",
    "register_reporter",
    "get_reporter",
    "available_formats",
]
