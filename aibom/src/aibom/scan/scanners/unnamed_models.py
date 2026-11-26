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
        frameworks = [c for c in ctx.components if c.kind == "framework"]

        def library_of(cls: str) -> str:
            """The library whose client the call uses (review 6063080163 of #498,
            m5): the SDK for a direct call, LangChain for a LangChain wrapper."""
            prefix = _SDK_LIBRARY.get(cls)
            libs = sorted(
                (c.name, c.version) for c in frameworks
                if (prefix and (c.name or "").lower() == prefix)
                or (not prefix and (c.name or "").lower().startswith("langchain"))
            )
            label = prefix or "langchain"
            if not libs:
                return f"{label} (not declared)"
            return ", ".join(
                f"{name} {version}" if version else f"{name} (version not pinned)"
                for name, version in libs
            )

        classes = (ctx.properties.get("aibom:model_unnamed_classes") or "").split(",")
        by_class = {cls: library_of(cls) for cls in classes if cls}
        ctx.properties["aibom:model_unnamed_library"] = "; ".join(
            dict.fromkeys(by_class.values())
        ) or "langchain (not declared)"
        # each unidentified model entry carries the library that decides its default
        for comp in ctx.components:
            props = comp.properties or {}
            if comp.kind == "model" and props.get("model:identified") == "false":
                cls = (comp.name or "").removeprefix("unidentified model (").rstrip(")")
                if cls in by_class:
                    comp.properties = {
                        **props, "model:default_from_library": by_class[cls]
                    }


# direct SDK calls (net-env ``_SDK_MODEL_CALLS``): the SDK package
_SDK_LIBRARY = {"OpenAI": "openai", "Anthropic": "anthropic", "Ollama": "ollama",
                "LiteLLM": "litellm"}


__all__ = ["UnnamedModels"]
