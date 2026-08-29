from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping


JsonObject = dict[str, Any]


@dataclass(frozen=True)
class TextBlock:
    text: str


@dataclass(frozen=True)
class ToolCallBlock:
    id: str
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class ToolResultBlock:
    tool_call_id: str
    name: str
    result: Mapping[str, Any]
    is_error: bool = False


MessageBlock = TextBlock | ToolCallBlock | ToolResultBlock


@dataclass(frozen=True)
class Message:
    role: Literal["user", "assistant"]
    content: str | tuple[MessageBlock, ...]


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )

    def to_dict(self) -> JsonObject:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


@dataclass(frozen=True)
class AgentTurn:
    blocks: tuple[TextBlock | ToolCallBlock, ...]
    stop_reason: str
    usage: TokenUsage = field(default_factory=TokenUsage)

    @property
    def tool_calls(self) -> tuple[ToolCallBlock, ...]:
        return tuple(block for block in self.blocks if isinstance(block, ToolCallBlock))

    @property
    def text(self) -> str:
        return "\n".join(
            block.text for block in self.blocks if isinstance(block, TextBlock)
        ).strip()


@dataclass(frozen=True)
class AnalysisWindow:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("분석 시간은 시간대 정보가 포함되어야 합니다.")
        if self.start >= self.end:
            raise ValueError("분석 시작 시간은 종료 시간보다 빨라야 합니다.")

    def to_dict(self) -> JsonObject:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
        }


@dataclass(frozen=True)
class DetectionRun:
    run_id: str
    source_agent: str
    created_at: str
    window: AnalysisWindow
    status: str
    summary: str
    observed_ip_count: int
    assessments: tuple[JsonObject, ...]

    def to_dict(self) -> JsonObject:
        return {
            "run_id": self.run_id,
            "source_agent": self.source_agent,
            "created_at": self.created_at,
            "window": self.window.to_dict(),
            "status": self.status,
            "summary": self.summary,
            "observed_ip_count": self.observed_ip_count,
            "assessments": list(self.assessments),
        }


@dataclass(frozen=True)
class InvestigationRequest:
    request_id: str
    detection_run_id: str
    source_agent: str
    created_at: str
    window: AnalysisWindow
    target: JsonObject
    assessment: JsonObject
    evidence: tuple[JsonObject, ...]
    enrichment: JsonObject
    requested_checks: tuple[str, ...]

    def to_dict(self) -> JsonObject:
        return {
            "request_id": self.request_id,
            "detection_run_id": self.detection_run_id,
            "source_agent": self.source_agent,
            "created_at": self.created_at,
            "window": self.window.to_dict(),
            "target": self.target,
            "assessment": self.assessment,
            "evidence": list(self.evidence),
            "enrichment": self.enrichment,
            "requested_checks": list(self.requested_checks),
        }

