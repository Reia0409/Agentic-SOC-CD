from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class TraceEvent:
    sequence: int
    timestamp: str
    event: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event": self.event,
            "details": self.details,
        }


class TraceRecorder:
    def __init__(self) -> None:
        self._events: list[TraceEvent] = []

    def add(self, event: str, **details: Any) -> None:
        self._events.append(
            TraceEvent(
                sequence=len(self._events) + 1,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event=event,
                details=details,
            )
        )

    def to_list(self) -> list[dict[str, Any]]:
        return [event.to_dict() for event in self._events]

