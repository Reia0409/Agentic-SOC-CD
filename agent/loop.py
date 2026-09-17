"""Agent Loop 총괄 + Agent 제어 담당 모듈.

Seed -> LLM 판단 -> Tool 선택/실행 -> 결과 관찰 -> 재판단 -> 종료 흐름을
구현하고, 그 안에서 아래 제어 로직을 함께 수행한다.
  - 중복 호출 방지 (동일 tool+args 재호출 차단)
  - max_call 도달 시 강제 종료
  - 도구 호출 실패 시에도 조사 전체를 중단하지 않고 계속 진행
  - 3가지 종료 조건(confidence_sufficient / no_more_evidence / max_call) 판단

*** 2026-09-17 업데이트 (멘토링 2.2 조사 규율 강화 반영) ***
1. 종료 관문 도입: termination_reason이 "confidence_sufficient"인 경우에 한해,
   실제 current_confidence가 threshold 미만이거나 서로 다른 tool_name이 1종류
   이하면 종료를 거부하고 추가 조사를 강제한다. ("no_more_evidence" 종료는
   계층 수와 무관하게 LLM 판단을 존중. unknowns가 남아있는 것 자체도 차단
   사유 아님 — remaining_unknowns로 후속 과제를 보고서에 남긴 채 정상 종료하는
   것은 허용되는 정상 흐름.)
2. confidence_threshold를 prompts.py/gemini_client.py를 통해 매 턴 LLM에게
   노출한다.
3. max_call 도달 시, 도구 호출 없이 판정만 요청하는 마무리 턴(force_terminate=True)을
   1회 추가로 호출한다. 그래도 final_verdict가 없으면 _derive_fallback_verdict()로
   자체 계산한 verdict를 최후 안전망으로 사용한다.
4. 도구 호출 실패 시에도 성공 케이스와 동일하게 pending_observations에 error를
   담아 다음 턴 프롬프트(raw_observations_since_last_turn)에 실리도록 한다.

*** 2026-09-17 추가 업데이트 (종료 관문 무한 거부 루프 버그 수정) ***
실제 실행(main.py)에서 종료 관문이 같은 사유로 8번 연속 거부되며 max_cycles를
거의 다 소진하는 현상을 발견했다. 원인: 게이트가 종료를 거부하면 state.notes에만
기록되는데, build_user_prompt()의 payload엔 notes 필드가 없어서 LLM이 자신이
거부당했다는 사실 자체를 알 방법이 없었다 — 그래서 매 턴 동일한 상태를 보고
동일하게 "confidence 충분, 종료"를 반복 요청했다. 수정 내용:
  a. 게이트 거부 시 그 사유(gate_rejection_reason)를 다음 llm_client.reason() 호출에
     실어 보내서, prompts.py가 "직전 종료 시도가 거부됐다"는 사실과 이유를 명시적으로
     알리도록 했다.
  b. 그래도 동일 사유로 연속 2회 거부되면(LLM이 새 도구를 못 찾거나 confidence
     재평가도 안 하는 경우), 사이클을 낭비하지 않고 즉시 강제 종료 턴(force_terminate)으로
     전환해 지금까지의 증거로 판정을 확정짓는다.

*** 2026-09-17 추가 업데이트 (조사 고도화: src_ip 계층 강제 + 판단 근거 명시) ***
1. seed에 src_ip가 있는(외부 IP 관련 의심) 사건인데 fetch_network_log를 한 번도
   호출하지 않은 채 confidence_sufficient로 종료하려 하면 게이트가 거부한다.
   실제 실행에서 이 계층을 빼먹고도(네트워크 통신 유무는 지지/반박 모두에 중요한
   신호) confidence만으로 종료가 승인되는 사례가 관찰되어 추가했다.
2. _derive_fallback_verdict()에 reasoning 필드를 추가해, 자체 폴백 판정임을
   명시하고 어떤 근거로 verdict_type을 계산했는지 남긴다. (LLM이 직접 낸
   final_verdict의 reasoning은 prompts.py의 출력 스키마에서 요구한다.)
"""

from __future__ import annotations

from typing import Any, Dict

from .models import AgentState, Evidence, Hypothesis, TerminationReason, ToolCallRecord, VerdictType
from .report import build_investigation_result
from .tools import ToolRegistry, ToolValidationError

# [17] seed 하나당 이 루프가 "충분하다" 판단이 나올 때까지 반복됨
class InvestigationAgent:
    def __init__(
        self,
        llm_client: Any,
        tool_registry: ToolRegistry,
        max_calls: int = 8,
        confidence_threshold: float = 0.85,
    ) -> None:
        self.llm_client = llm_client
        self.tool_registry = tool_registry
        self.max_calls = max_calls
        self.confidence_threshold = confidence_threshold

    def run(self, seed: Dict[str, Any]) -> Dict[str, Any]:
        # [18] agent/models.py 에서 AgentState 실행하여 state 객체 생성
        #      state = 지금까지의 조사 결과 기록하는 곳
        state = AgentState(incident_id=seed["incident_id"], seed=seed)
        state.current_confidence = float(seed.get("confidence_initial", 0.5))
        state.record_confidence("initial", seed.get("trigger_description", "Triage 판정"))

        termination_reason = None
        final_verdict = None
        max_cycles = self.max_calls + 3  # LLM이 종료 판단을 안 내려도 무한루프에 빠지지 않도록 하는 안전장치

        # [2026-09-17 추가] 직전 턴에 종료 관문이 거부한 사유. 다음 reason() 호출에
        # 실어 보내서 LLM이 "왜 거부당했는지"를 알게 한다. 한 번 전달하면 초기화한다.
        gate_rejection_reason = None
        # [2026-09-17 추가] 같은 사유로 연속 거부되는 걸 감지해 사이클 낭비 없이
        # 조기에 강제 종료 턴으로 넘어가기 위한 카운터.
        consecutive_rejections = 0
        MAX_CONSECUTIVE_REJECTIONS = 2

        # [20] 루프 시작! LLM한테 판단 맡김 agent/gemini_client.py 실행
        for _ in range(max_cycles):
            # [23] agent/gemini_client.py 통해 Gemini가 분석한 결과 반환
            # [2026-09-17 수정] confidence_threshold와 gate_rejection_reason을 매 턴 함께
            # 전달 — LLM이 신뢰도 임계값 도달 여부와 직전 거부 사실을 스스로 확인할 수 있게 함
            decision = self.llm_client.reason(
                state,
                self.tool_registry,
                confidence_threshold=self.confidence_threshold,
                gate_rejection_reason=gate_rejection_reason,
            )
            gate_rejection_reason = None  # 이번 턴 프롬프트에 이미 실어 보냈으니 초기화

            # [24] 방금 받은 분석 결과를 state에 기록
            self._apply_decision(state, decision)
            state.pending_observations = []

            # [25] 종료 조건 1 : LLM이 "이제 끝내자"고 했는가?
            if decision.get("next_action") == "terminate":
                termination_reason = (
                    decision.get("termination_reason") or TerminationReason.NO_MORE_EVIDENCE.value
                )

                # [2026-09-17 추가] 종료 관문: "confidence_sufficient"로 종료하려는
                # 경우에만 적용한다. no_more_evidence(더 볼 로그가 없다는 판단)는
                # 계층 수와 무관하게 합리적일 수 있어 차단하지 않는다.
                # unknowns가 남아있는 것 자체는 차단 사유가 아니다 — confidence가
                # 충분하면 remaining_unknowns로 보고서에 남긴 채 정상 종료하는 것이
                # 정상 흐름이다.
                if termination_reason == TerminationReason.CONFIDENCE_SUFFICIENT.value:
                    confidence_not_met = state.current_confidence < self.confidence_threshold
                    # [2026-09-17 수정] investigated_layers(LLM이 자유 텍스트로 붙이는
                    # evidence.layer 값) 대신, 실제 성공한 tool_calls의 서로 다른
                    # tool_name 개수로 계층 다양성을 판단한다. 관찰된 문제: fetch_auth_log와
                    # fetch_audit_log 결과를 LLM이 둘 다 layer="auth"로 라벨링하면
                    # investigated_layers가 1개로 집계돼 게이트가 계속 거부하고,
                    # LLM은 이미 관련 도구를 다 썼다고 판단해 새 도구를 못 찾아 max_cycles를
                    # 소진하는 사례가 발견됨. tool_name 기준은 시스템이 직접 기록한
                    # 사실이라 이런 라벨링 불일치에 영향받지 않는다.
                    successful_tool_names = {t.tool_name for t in state.tool_calls if t.success}
                    distinct_tools_used = len(successful_tool_names)
                    single_layer_only = distinct_tools_used <= 1

                    # [2026-09-17 추가] seed에 src_ip가 있는 사건(외부 IP 관련 의심 사건)은
                    # fetch_network_log로 해당 IP의 네트워크 활동(추가 통신 여부)을 반드시
                    # 확인해야 한다. 실제 실행에서 이 계층을 빼먹고도 confidence만으로
                    # 종료를 승인받는 사례가 관찰되어(외부 통신 유무는 반박/지지 증거 모두에
                    # 중요한 신호이므로) 명시적으로 강제한다.
                    seed_has_src_ip = bool(state.seed.get("src_ip"))
                    network_tool_used = "fetch_network_log" in successful_tool_names
                    missing_network_check = seed_has_src_ip and not network_tool_used

                    if confidence_not_met or single_layer_only or missing_network_check:
                        reasons = []
                        if confidence_not_met:
                            reasons.append(
                                f"실제 신뢰도({state.current_confidence:.2f})가 "
                                f"임계값({self.confidence_threshold}) 미달"
                            )
                        if single_layer_only:
                            reasons.append(f"서로 다른 도구 {distinct_tools_used}종류만 사용됨(1개 이하)")
                        if missing_network_check:
                            reasons.append(
                                f"seed에 src_ip({state.seed.get('src_ip')})가 있는데 "
                                "fetch_network_log로 네트워크 활동을 확인하지 않음"
                            )
                        reason_text = ", ".join(reasons)
                        state.notes.append(f"종료 관문 발동 — 종료 거부: {reason_text}")

                        # [2026-09-17 추가] 같은 사유로 연속 거부되면(LLM이 새 도구를
                        # 찾지 못하거나 confidence 재평가도 안 하는 경우), 사이클을
                        # 낭비하지 않고 강제 종료 턴으로 넘어가 지금까지의 증거로
                        # 판정을 확정짓는다. (실제 사례: 이 안전장치 없이는 동일 사유로
                        # 8회 연속 거부되며 max_cycles를 거의 다 소진한 바 있음.)
                        consecutive_rejections += 1
                        if consecutive_rejections >= MAX_CONSECUTIVE_REJECTIONS:
                            state.notes.append(
                                f"연속 {consecutive_rejections}회 종료 거부 후에도 진전이 없어 "
                                "강제 종료 턴으로 전환합니다."
                            )
                            termination_reason = TerminationReason.NO_MORE_EVIDENCE.value
                            final_decision = self.llm_client.reason(
                                state,
                                self.tool_registry,
                                confidence_threshold=self.confidence_threshold,
                                force_terminate=True,
                            )
                            self._apply_decision(state, final_decision)
                            final_verdict = final_decision.get("final_verdict") or self._derive_fallback_verdict(state)
                            break

                        gate_rejection_reason = reason_text  # 다음 턴 프롬프트에 실어 보냄
                        continue  # 종료 거부 — 다음 사이클로 넘어가 계속 조사

                consecutive_rejections = 0  # 정상 종료 승인 — 카운터 리셋
                final_verdict = decision.get("final_verdict") or self._derive_fallback_verdict(state)
                break

            # [26] 종료 조건 2 : 벌써 8번(max_calls) 다 썼는가?
            if len(state.tool_calls) >= self.max_calls:
                termination_reason = TerminationReason.MAX_CALL_REACHED.value

                # [2026-09-17 수정] max_call 도달 시, 도구 호출 없이 판정만 요청하는
                # 마무리 턴을 1회 추가로 호출한다 (기존엔 이 시점 decision에
                # final_verdict가 없어 항상 자체 폴백만 썼음).
                final_decision = self.llm_client.reason(
                    state,
                    self.tool_registry,
                    confidence_threshold=self.confidence_threshold,
                    force_terminate=True,
                )
                self._apply_decision(state, final_decision)
                final_verdict = final_decision.get("final_verdict") or self._derive_fallback_verdict(state)
                break

            # [27] 종료 조건 1,2로 안 끝났으면 = LLM이 "도구를 더 부르자"고 한 것 -> 진짜 tool 실행
            # [39] 결과 반환해서 돌아옴
            self._execute_tool_call(state, decision.get("tool_call") or {})
            # [40] confidence 체크
            # confidence가 충분해도(0.85 넘어도) 여기선 그냥 메모만 하나 남기고 끝
            # break 없기 때문에, 다시 llm_client.reason() 부르러 감 루프!
            if state.current_confidence >= self.confidence_threshold:
                state.notes.append("신뢰도 임계값 도달 — 다음 사이클에서 종료 여부 재확인 필요")
        else:
            termination_reason = TerminationReason.MAX_CALL_REACHED.value
            # [2026-09-17 추가] 안전장치(max_cycles 전부 소진)로 빠진 경우도 동일하게
            # 마무리 턴을 한 번 시도한다.
            final_decision = self.llm_client.reason(
                state,
                self.tool_registry,
                confidence_threshold=self.confidence_threshold,
                force_terminate=True,
            )
            self._apply_decision(state, final_decision)
            final_verdict = final_decision.get("final_verdict") or self._derive_fallback_verdict(state)

        # [41] state 안에 쌓은 조사 결과를 agent/report.py의 build_investigation_result() 넘겨서 최종 JSON 생성
        result = build_investigation_result(state, termination_reason, final_verdict)
        result["statistics"]["tool_calls_max"] = self.max_calls
        # [42] 조사 결과를 반환 agent/pipeline.py로 돌아감
        return result

    # ------------------------------------------------------------------
    # [2026-09-17 추가] LLM이 강제 종료 턴(force_terminate=True)에서도
    # final_verdict를 못 준 경우를 대비한 최후 안전망. report.py의
    # build_investigation_result()가 기대하는 필드(verdict/confidence/severity/
    # attack_type/affected_systems/summary/reasoning)를 그대로 맞췄다.
    # ------------------------------------------------------------------
    def _derive_fallback_verdict(self, state: AgentState) -> Dict[str, Any]:
        if state.current_confidence >= self.confidence_threshold:
            verdict_type = VerdictType.THREAT_CONFIRMED.value
        elif state.contradicting_evidence and not state.evidence:
            verdict_type = VerdictType.FALSE_POSITIVE.value
        else:
            verdict_type = VerdictType.INCONCLUSIVE.value

        leading_hyp = max(state.hypotheses.values(), key=lambda h: h.confidence, default=None)

        if state.current_confidence >= 0.7:
            severity = "HIGH"
        elif state.current_confidence >= 0.4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        affected_systems = sorted(state.investigated_layers) if state.investigated_layers else []

        supporting = "; ".join(e.description for e in state.evidence[-3:]) or "충분한 지지 증거를 확보하지 못함"
        used_tools = sorted({t.tool_name for t in state.tool_calls if t.success})

        return {
            "verdict": verdict_type,
            "confidence": round(state.current_confidence, 3),
            "severity": severity,
            "attack_type": leading_hyp.title if leading_hyp else "unknown",
            "affected_systems": affected_systems,
            "summary": (
                f"최대 조사 횟수({self.max_calls}회) 또는 최대 사이클에 도달해 강제 종료됨. "
                f"현재 신뢰도 {state.current_confidence:.2f} 기준 잠정 판단: {verdict_type}. "
                f"최근 근거: {supporting}"
            ),
            # [2026-09-17 추가] reasoning — LLM이 직접 낸 것이 아니라 시스템이 자동
            # 계산한 폴백임을 명시하고, 어떤 근거(confidence vs threshold 비교)로만
            # 판단했는지(개별 신호 확인은 없었음을) 남긴다.
            "reasoning": (
                f"[자동 폴백 판정 — LLM이 final_verdict를 제공하지 않아 시스템이 자체 계산함] "
                f"사용된 도구: {', '.join(used_tools) if used_tools else '없음'}. "
                f"누적 confidence({state.current_confidence:.2f})와 threshold({self.confidence_threshold}) "
                f"비교만으로 verdict_type을 결정했으며, 개별 신호 확인 과정은 거치지 않았습니다."
            ),
        }

    # ------------------------------------------------------------------
    # LLM 판단 결과를 State에 반영 (State / Evidence 관리 영역과 맞닿는 지점)
    # ------------------------------------------------------------------
    def _apply_decision(self, state: AgentState, decision: Dict[str, Any]) -> None:
        if "facts" in decision:
            state.facts = decision["facts"]
        if "unknowns" in decision:
            state.unknowns = decision["unknowns"]

        for h in decision.get("hypotheses", []) or []:
            state.hypotheses[h["hyp_id"]] = Hypothesis(
                hyp_id=h["hyp_id"],
                title=h.get("title", ""),
                description=h.get("description", ""),
                confidence=h.get("confidence", 0.0),
                status=h.get("status", "active"),
            )

        for ev in decision.get("new_evidence", []) or []:
            contradicting = bool(ev.get("contradicting", False))
            contribution = float(ev.get("confidence_contribution", 0.0))
            sequence = len(state.evidence) + len(state.contradicting_evidence) + 1
            evidence = Evidence.new(
                sequence=sequence,
                time=ev.get("time"),
                layer=ev.get("layer", "unknown"),
                event_type=ev.get("event_type", ""),
                description=ev.get("description", ""),
                source_log=ev.get("source_log", ""),
                supporting_hypothesis=ev.get("supporting_hypothesis", []),
                contradicting_hypothesis=ev.get("contradicting_hypothesis", []),
                confidence_contribution=contribution,
            )
            state.add_evidence(evidence, contradicting=contradicting)

            delta = -abs(contribution) if contradicting else contribution
            stage_label = f"after_tool_{len(state.tool_calls)}"
            state.update_confidence(delta, stage_label, evidence.description)

        if decision.get("investigation_notes"):
            state.notes.extend(decision["investigation_notes"])

        if decision.get("attack_timeline"):
            state.attack_timeline = decision["attack_timeline"]

    # ------------------------------------------------------------------
    # Tool 연결·실행 계층 호출 + 제어(중복 방지, 실패 처리)
    # ------------------------------------------------------------------
    # [28] tool 호출
    def _execute_tool_call(self, state: AgentState, tool_call: Dict[str, Any]) -> None:
        name = tool_call.get("tool_name")
        args = tool_call.get("args") or {}

        if not name:
            state.notes.append("LLM이 next_action=call_tool을 선택했지만 tool_call을 채우지 않았습니다.")
            return

        if state.already_called(name, args):
            state.notes.append(f"중복 호출 스킵: {name}({args}) — 이미 조회된 조합입니다.")
            return

        try:
            # [29] 인자 형식 맞는지 검사
            self.tool_registry.validate_args(name, args)
            # [30] ★진짜 tool 함수 실행 agent/tools/registry.py의 call 함수 실행
            # [37] agent/tools/registry.py로부터 조사 결과 반환
            result = self.tool_registry.call(name, args)
            # [38] 이 도구 + 이 조건 조합은 이미 썼다고 표시 (중복 방지)
            state.mark_called(name, args)
            state.tool_calls.append(
                ToolCallRecord(
                    sequence=len(state.tool_calls) + 1,
                    tool_name=name,
                    input=args,
                    result_count=result.get("count", 0),
                    result_summary=result.get("summary", ""),
                    success=True,
                )
            )

            # [39] 이번 호출을 "기록"으로 남김 - 최종 JSON의 tools_called[] 배열에 그대로 나오는 부분
            state.pending_observations.append({"tool_name": name, "args": args, "result": result})
        except (ToolValidationError, KeyError, NotImplementedError) as exc:
            state.mark_called(name, args)
            error_msg = str(exc)
            state.tool_calls.append(
                ToolCallRecord(
                    sequence=len(state.tool_calls) + 1,
                    tool_name=name,
                    input=args,
                    result_count=0,
                    result_summary="호출 실패",
                    success=False,
                    error=error_msg,
                )
            )
            # [2026-09-17 추가] 실패도 성공 케이스와 동일한 채널(pending_observations)로
            # LLM에 전달한다 — prompts.py의 raw_observations_since_last_turn에 그대로
            # 실려서 다음 턴에 LLM이 실패 원인을 볼 수 있게 됨.
            state.pending_observations.append(
                {
                    "tool_name": name,
                    "args": args,
                    "result": {
                        "count": 0,
                        "summary": f"도구 호출 실패: {error_msg}",
                        "records": [],
                        "error": error_msg,
                    },
                }
            )
            state.notes.append(f"도구 호출 실패({name}): {error_msg} — 조사는 계속 진행됩니다.")
        except Exception as exc:  # 예상치 못한 오류도 조사 전체를 중단시키지 않는다
            state.mark_called(name, args)
            error_msg = str(exc)
            state.tool_calls.append(
                ToolCallRecord(
                    sequence=len(state.tool_calls) + 1,
                    tool_name=name,
                    input=args,
                    result_count=0,
                    result_summary="예외 발생",
                    success=False,
                    error=error_msg,
                )
            )
            state.pending_observations.append(
                {
                    "tool_name": name,
                    "args": args,
                    "result": {
                        "count": 0,
                        "summary": f"도구 호출 중 예외 발생: {error_msg}",
                        "records": [],
                        "error": error_msg,
                    },
                }
            )
            state.notes.append(f"도구 호출 중 예외({name}): {error_msg}")