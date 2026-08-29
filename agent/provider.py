from __future__ import annotations

from typing import Protocol, Sequence

from .models import AgentTurn, Message


class ModelProvider(Protocol):
    @property
    def model_name(self) -> str:
        ...

    def generate(
        self,
        *,
        system_prompt: str,
        messages: Sequence[Message],
        tools: Sequence[dict],
    ) -> AgentTurn:
        ...

