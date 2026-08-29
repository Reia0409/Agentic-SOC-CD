from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from .models import (
    AnalysisWindow,
    DetectionRun,
    InvestigationRequest,
    Message,
    TokenUsage,
    ToolResultBlock,
)
from .prompts import SYSTEM_PROMPT, build_run_request
from .provider import ModelProvider
from .schemas import SUBMIT_TOOL_NAME, SubmissionValidationError, terminal_tool_schema, validate_submission
from .tooling import ToolCatalog
from .trace import TraceRecorder


class AgentRunError(RuntimeError):
    pass


@dataclass(frozen=True)
class RunOutcome:
    detection: DetectionRun
    investigations: tuple[InvestigationRequest, ...]
    trace: tuple[dict[str, Any], ...]
    usage: TokenUsage
    model: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection": self.detection.to_dict(),
            "investigation_requests": [item.to_dict() for item in self.investigations],
            "agent_trace": list(self.trace),
            "usage": self.usage.to_dict(),
            "model": self.model,
        }


class DetectionAgentRunner:
    def __init__(
        self,
        *,
        provider: ModelProvider,
        tools: ToolCatalog,
        max_steps: int = 12,
        max_submission_retries: int = 3,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps는 1 이상이어야 합니다.")
        if max_submission_retries < 0:
            raise ValueError("max_submission_retries는 0 이상이어야 합니다.")
        self._provider = provider
        self._tools = tools
        self._max_steps = max_steps
        self._max_submission_retries = max_submission_retries

    def run(self, window: AnalysisWindow) -> RunOutcome:
        trace = TraceRecorder()
        trace.add(
            "agent_started",
            model=self._provider.model_name,
            window=window.to_dict(),
        )

        tool_schemas = self._tools.get_schemas()
        names = {schema["name"] for schema in tool_schemas}
        if SUBMIT_TOOL_NAME in names:
            # 이건 배포 설정 오류다. 실행 전에 드러나야 하므로 예외로 둔다.
            raise AgentRunError(f"도구 이름 충돌: {SUBMIT_TOOL_NAME}")
        all_schemas = [*tool_schemas, terminal_tool_schema()]
        # 도구 모듈 import 에 실패한 것이 있으면 함께 남긴다.
        # 조용히 사라진 도구 때문에 판정이 비는 것을 나중에 추적할 수 있어야 한다.
        import_errors = getattr(self._tools, "import_errors", None)
        trace.add(
            "tools_available",
            names=[schema["name"] for schema in all_schemas],
            import_errors=dict(import_errors) if import_errors else {},
        )

        messages: list[Message] = [Message(role="user", content=build_run_request(window))]
        usage = TokenUsage()
        protocol_recovery_used = False
        # 집계 도구가 실제로 돌려준 IP. 최종 제출을 이 집합과 대조해 환각을 막는다.
        observed_ips: set[str] = set()
        aggregate_seen = False
        # 제출 재시도는 탐색과 성격이 다르다. 반복 실패는 한도를 넘기기 전에 끊는다.
        submission_retries = 0

        for step in range(1, self._max_steps + 1):
            turn = self._provider.generate(
                system_prompt=SYSTEM_PROMPT,
                messages=messages,
                tools=all_schemas,
            )
            usage = usage + turn.usage
            trace.add(
                "model_turn",
                step=step,
                stop_reason=turn.stop_reason,
                tool_calls=[call.name for call in turn.tool_calls],
                text=turn.text[:2000],
                usage=turn.usage.to_dict(),
            )

            if turn.tool_calls:
                messages.append(Message(role="assistant", content=turn.blocks))
                terminal_calls = [
                    call for call in turn.tool_calls if call.name == SUBMIT_TOOL_NAME
                ]
                if terminal_calls:
                    if len(turn.tool_calls) != 1:
                        return _partial(
                            window, trace, usage, self._provider.model_name,
                            "최종 제출과 데이터 조회 도구를 동시에 호출했습니다.",
                        )
                    try:
                        submission = validate_submission(
                            terminal_calls[0].arguments,
                            observed_ips=observed_ips if aggregate_seen else None,
                        )
                    except SubmissionValidationError as exc:
                        # 우리는 정답을 알고 있다. 거부만 하지 말고 알려준다.
                        hint = ""
                        if aggregate_seen:
                            hint = (
                                f" 집계 도구가 돌려준 IP는 {len(observed_ips)}개다: "
                                f"{sorted(observed_ips)}. observed_ip_count 에 이 수를 넣고 "
                                f"이 IP 전부를 assessments 에 담아 다시 호출하라."
                            )
                        result = {
                            "success": False,
                            "data": None,
                            "error": f"최종 결과 검증 실패: {exc}.{hint}",
                        }
                        messages.append(
                            Message(
                                role="user",
                                content=(
                                    ToolResultBlock(
                                        tool_call_id=terminal_calls[0].id,
                                        name=SUBMIT_TOOL_NAME,
                                        result=result,
                                        is_error=True,
                                    ),
                                ),
                            )
                        )
                        trace.add(
                            "submission_rejected",
                            step=step,
                            error=str(exc),
                            submitted_keys=sorted(terminal_calls[0].arguments.keys()),
                            arguments=dict(terminal_calls[0].arguments),
                        )
                        submission_retries += 1
                        if submission_retries > self._max_submission_retries:
                            return _partial(
                                window, trace, usage, self._provider.model_name,
                                f"최종 제출 검증에 {submission_retries}회 연속 실패했습니다: {exc}",
                            )
                        continue

                    detection, investigations = _build_outputs(window, submission)
                    trace.add(
                        "agent_completed",
                        run_id=detection.run_id,
                        assessment_count=len(detection.assessments),
                        investigation_count=len(investigations),
                    )
                    return RunOutcome(
                        detection=detection,
                        investigations=investigations,
                        trace=tuple(trace.to_list()),
                        usage=usage,
                        model=self._provider.model_name,
                    )

                tool_results: list[ToolResultBlock] = []
                for call in turn.tool_calls:
                    result = self._tools.execute(call.name, call.arguments)
                    is_error = not bool(result.get("success"))
                    if not is_error and call.name == AGGREGATE_TOOL_NAME:
                        found = _extract_ips(result.get("data"))
                        if found:
                            aggregate_seen = True
                            observed_ips |= found
                    trace.add(
                        "tool_executed",
                        step=step,
                        tool_call_id=call.id,
                        tool_name=call.name,
                        arguments=dict(call.arguments),
                        result=result,
                    )
                    tool_results.append(
                        ToolResultBlock(
                            tool_call_id=call.id,
                            name=call.name,
                            result=result,
                            is_error=is_error,
                        )
                    )
                messages.append(Message(role="user", content=tuple(tool_results)))
                continue

            if turn.blocks:
                messages.append(Message(role="assistant", content=turn.blocks))
            if turn.stop_reason in {"end_turn", "stop_sequence"} and not protocol_recovery_used:
                protocol_recovery_used = True
                messages.append(
                    Message(
                        role="user",
                        content=(
                            "일반 텍스트로 종료하지 말고, 지금까지 확인한 근거를 사용해 "
                            "submit_detection_result 도구를 호출하라."
                        ),
                    )
                )
                trace.add("protocol_recovery", step=step, reason="missing_terminal_tool")
                continue

            return _partial(
                window, trace, usage, self._provider.model_name,
                _stop_reason_message(turn.stop_reason),
            )

        return _partial(
            window, trace, usage, self._provider.model_name,
            f"최대 에이전트 단계({self._max_steps})를 초과했습니다.",
        )


AGGREGATE_TOOL_NAME = "aggregate_logs"


def _extract_ips(data: Any) -> set[str]:
    """도구 결과에서 IP 를 모은다.

    도구 팀 aggregate_logs 는 {"window":…, "ip_count":N, "stats":[…]} 를 돌려준다.
    IP 목록이 stats 안에 중첩돼 있으므로 그것을 먼저 본다.
    이 처리가 없으면 observed_ips 가 비고, 도구 결과 대조(환각 차단)가 조용히 꺼진다.
    """
    if isinstance(data, Mapping):
        rows = data.get("stats")
        if isinstance(rows, list):
            return {
                row["ip"] for row in rows
                if isinstance(row, Mapping) and isinstance(row.get("ip"), str)
            }
        # resolve_ip_geo 는 {"ip":…, "country":…} 형태의 단일 객체를 돌려준다.
        ip = data.get("ip")
        return {ip} if isinstance(ip, str) else set()
    if isinstance(data, list):
        found: set[str] = set()
        for row in data:
            if isinstance(row, Mapping) and isinstance(row.get("ip"), str):
                found.add(row["ip"])
        return found
    return set()


def _stop_reason_message(stop_reason: str) -> str:
    if stop_reason == "max_tokens":
        return (
            "모델 응답이 max_tokens 한도에서 잘렸습니다. "
            "--max-tokens 를 늘리거나 관찰 IP 수를 줄이세요."
        )
    return f"모델이 최종 결과 없이 중단됐습니다: stop_reason={stop_reason}"


def _partial(
    window: AnalysisWindow,
    trace: TraceRecorder,
    usage: TokenUsage,
    model: str,
    reason: str,
) -> RunOutcome:
    """판정을 못 받았어도 **실행 기록은 남긴다.**

    cron 으로 돌리면 실패한 회차가 파일조차 남기지 않을 때 그 시각에 에이전트가
    돌았는지조차 알 수 없다. 토큰은 이미 썼고 trace 에는 무슨 일이 있었는지가 담겨 있다.
    """
    trace.add("agent_failed", reason=reason)
    now = datetime.now(timezone.utc)
    detection = DetectionRun(
        run_id=f"DET-{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}",
        source_agent="detection-agent",
        created_at=now.isoformat(),
        window=window,
        status="partial",
        summary=f"감지를 완료하지 못했습니다: {reason}",
        observed_ip_count=0,
        assessments=(),
    )
    return RunOutcome(
        detection=detection,
        investigations=(),
        trace=tuple(trace.to_list()),
        usage=usage,
        model=model,
    )


def _build_outputs(
    window: AnalysisWindow,
    submission: dict[str, Any],
) -> tuple[DetectionRun, tuple[InvestigationRequest, ...]]:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    run_id = f"DET-{timestamp}-{uuid4().hex[:8]}"
    created_at = now.isoformat()
    assessments = tuple(submission["assessments"])
    detection = DetectionRun(
        run_id=run_id,
        source_agent="detection-agent",
        created_at=created_at,
        window=window,
        status=submission["status"],
        summary=submission["summary"],
        observed_ip_count=submission["observed_ip_count"],
        assessments=assessments,
    )

    investigations: list[InvestigationRequest] = []
    for assessment in assessments:
        if not assessment["investigation_required"]:
            continue
        investigations.append(
            InvestigationRequest(
                request_id=f"INV-{timestamp}-{uuid4().hex[:8]}",
                detection_run_id=run_id,
                source_agent="detection-agent",
                created_at=created_at,
                window=window,
                target={"type": "ip", "value": assessment["ip"]},
                assessment={
                    "classification": assessment["classification"],
                    "threat_type": assessment["threat_type"],
                    "severity": assessment["severity"],
                    "confidence": assessment["confidence"],
                    "rationale": assessment["rationale"],
                },
                evidence=tuple(assessment["evidence"]),
                enrichment=dict(assessment["enrichment"]),
                requested_checks=tuple(assessment["requested_checks"]),
            )
        )
    return detection, tuple(investigations)

