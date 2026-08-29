from __future__ import annotations

import json
import os
from typing import Any, Sequence

from .models import (
    AgentTurn,
    Message,
    TextBlock,
    TokenUsage,
    ToolCallBlock,
    ToolResultBlock,
)


class AnthropicProvider:
    """Anthropic Messages API adapter. SDK import is deferred for testability."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "claude-sonnet-5",
        max_tokens: int = 16384,
        client: Any | None = None,
    ) -> None:
        self._model = model
        self._max_tokens = max_tokens
        if client is not None:
            self._client = client
            return

        resolved_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise ValueError("ANTHROPIC_API_KEY 환경 변수가 필요합니다.")
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError("anthropic 패키지가 없습니다. pip install -r requirements.txt") from exc
        self._client = anthropic.Anthropic(api_key=resolved_key)

    @property
    def model_name(self) -> str:
        return self._model

    def generate(
        self,
        *,
        system_prompt: str,
        messages: Sequence[Message],
        tools: Sequence[dict],
    ) -> AgentTurn:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system_prompt,
            tools=list(tools),
            tool_choice={"type": "auto", "disable_parallel_tool_use": True},
            messages=[self._serialize_message(message) for message in messages],
        )

        blocks: list[TextBlock | ToolCallBlock] = []
        for block in response.content:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                blocks.append(TextBlock(text=block.text))
            elif block_type == "tool_use":
                arguments = block.input if isinstance(block.input, dict) else dict(block.input)
                blocks.append(
                    ToolCallBlock(
                        id=block.id,
                        name=block.name,
                        arguments=arguments,
                    )
                )

        usage = getattr(response, "usage", None)
        return AgentTurn(
            blocks=tuple(blocks),
            stop_reason=str(response.stop_reason),
            usage=TokenUsage(
                input_tokens=int(getattr(usage, "input_tokens", 0)),
                output_tokens=int(getattr(usage, "output_tokens", 0)),
            ),
        )

    @staticmethod
    def _serialize_message(message: Message) -> dict[str, Any]:
        if isinstance(message.content, str):
            return {"role": message.role, "content": message.content}

        content: list[dict[str, Any]] = []
        for block in message.content:
            if isinstance(block, TextBlock):
                content.append({"type": "text", "text": block.text})
            elif isinstance(block, ToolCallBlock):
                content.append(
                    {
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": dict(block.arguments),
                    }
                )
            elif isinstance(block, ToolResultBlock):
                content.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.tool_call_id,
                        "content": json.dumps(block.result, ensure_ascii=False),
                        "is_error": block.is_error,
                    }
                )
            else:  # pragma: no cover - closed union protection
                raise TypeError(f"지원하지 않는 메시지 블록: {type(block).__name__}")
        return {"role": message.role, "content": content}

