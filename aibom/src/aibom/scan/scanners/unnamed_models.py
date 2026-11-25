"""Finalize scanner: the library behind model calls that name no model.

``net_env_scan`` records LangChain model wrappers built with no model argument
(``ChatOpenAI()``) as ``aibom:model_unnamed_calls`` / ``aibom:model_unnamed_detail``.
Such a call runs the library's default model, which changes between releases, so
the BOM names the call and the library version that decides it, and never guesses
a model (#498 round 3: alejandro-ao/ask-multiple-pdfs pins langchain 0.0.184 and
read "0 models" with no explanation). One property:

* ``aibom:model_unnamed_library`` — ``"langchain 0.0.184"``, or ``"langchain
  (version not pinned)"``.

Lanes: properties only, never flags or scores.
"""

from __future__ import annotations

from pathlib import Path

from aibom.scan.registry import ScanContext, Scanner, register


@register
class UnnamedModels(Scanner):
    name = "unnamed-models"
    order = 97  # after every component-producing scanner
    level = 1

    def matches(self, root: Path) -> bool:
        return True

    def scan(self, ctx: ScanContext) -> None:
        if not ctx.properties.get("aibom:model_unnamed_calls"):
            return
        libs = sorted(
            (c.name, c.version)
            for c in ctx.components
            if c.kind == "framework" and (c.name or "").lower().startswith("langchain")
        )
        library = (
            ", ".join(
                f"{name} {version}" if version else f"{name} (version not pinned)"
                for name, version in libs
            )
            if libs
            else "langchain (not declared)"
        )
        ctx.properties["aibom:model_unnamed_library"] = library
        # the unidentified model entries carry the library that decides the default
        for comp in ctx.components:
            props = comp.properties or {}
            if comp.kind == "model" and props.get("model:identified") == "false":
                comp.properties = {**props, "model:default_from_library": library}


__all__ = ["UnnamedModels"]
