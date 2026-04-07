from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage


@dataclass
class _CompatAgent:
    model: Any
    system_prompt: str | None = None

    def _normalize_messages(self, payload: dict[str, Any]) -> list[BaseMessage]:
        raw_messages = payload.get("messages", [])
        messages: list[BaseMessage] = []

        if self.system_prompt:
            messages.append(SystemMessage(content=self.system_prompt))

        for item in raw_messages:
            if isinstance(item, BaseMessage):
                messages.append(item)
            elif isinstance(item, str):
                messages.append(HumanMessage(content=item))
            else:
                raise TypeError(f"Unsupported message type: {type(item)!r}")

        return messages

    def invoke(self, payload: dict[str, Any]) -> dict[str, list[BaseMessage]]:
        messages = self._normalize_messages(payload)
        response = self.model.invoke(messages)
        return {"messages": [*messages, response]}

    async def ainvoke(self, payload: dict[str, Any]) -> dict[str, list[BaseMessage]]:
        messages = self._normalize_messages(payload)
        response = await self.model.ainvoke(messages)
        return {"messages": [*messages, response]}


def create_agent(model: Any, system_prompt: str | None = None) -> _CompatAgent:
    """Compatibility wrapper for environments missing langchain.agents.create_agent."""
    return _CompatAgent(model=model, system_prompt=system_prompt)
