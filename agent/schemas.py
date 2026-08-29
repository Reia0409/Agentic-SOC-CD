from __future__ import annotations

import ipaddress
from typing import Any, Mapping


SUBMIT_TOOL_NAME = "submit_detection_result"

CLASSIFICATIONS = {"malicious_bot", "benign_bot", "human", "undetermined"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
STATUSES = {"completed", "no_data", "partial"}


def terminal_tool_schema() -> dict[str, Any]:
    evidence_schema = {
        "type": "object",
        "properties": {
            "type": {"type": "string", "description": "근거 종류"},
            "value": {"type": "string", "description": "도구 결과에서 확인된 근거 값"},
        },
        "required": ["type", "value"],
        "additionalProperties": False,
    }
    assessment_schema = {
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "판정 대상 IP 주소"},
            "classification": {
                "type": "string",
                "enum": sorted(CLASSIFICATIONS),
                "description": "IP 행동 분류",
            },
            "threat_type": {
                "type": "string",
                "description": "위협 유형. 위협이 아니면 none",
            },
            "severity": {
                "type": "string",
                "enum": sorted(SEVERITIES),
                "description": "위험도",
            },
            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "판정 신뢰도 0~1",
            },
            "rationale": {
                "type": "string",
                "description": "도구 결과에 근거한 간결한 판정 이유",
            },
            "evidence": {
                "type": "array",
                "items": evidence_schema,
                "description": "판정을 뒷받침하는 관찰 근거",
            },
            # 도구팀 「공통 스키마 정의」 스키마 C 와 필드·타입을 일치시킨다.
            # (IPinfo Lite .mmdb 기준. asn 은 "AS16509" 형태의 문자열이다)
            "enrichment": {
                "type": "object",
                "properties": {
                    "country": {"type": ["string", "null"], "description": "출처 국가명"},
                    "country_code": {"type": ["string", "null"], "description": "ISO 국가 코드"},
                    "asn": {"type": ["string", "null"], "description": 'AS 번호. 예 "AS16509"'},
                    "as_org": {"type": ["string", "null"], "description": "AS 조직명"},
                    "as_domain": {"type": ["string", "null"], "description": "AS 조직 도메인"},
                },
                "required": ["country", "country_code", "asn", "as_org", "as_domain"],
                "additionalProperties": False,
            },
            "investigation_required": {
                "type": "boolean",
                "description": "조사 에이전트로 전달할지 여부",
            },
            "requested_checks": {
                "type": "array",
                "items": {"type": "string"},
                "description": "조사 에이전트가 확인해야 할 작업",
            },
        },
        "required": [
            "ip",
            "classification",
            "threat_type",
            "severity",
            "confidence",
            "rationale",
            "evidence",
            "enrichment",
            "investigation_required",
            "requested_checks",
        ],
        "additionalProperties": False,
    }
    return {
        "name": SUBMIT_TOOL_NAME,
        "description": (
            "감지 분석을 끝내고 최종 IP 판정과 조사 에이전트 전달 대상을 제출한다. "
            "필요한 로그 및 IP 조회가 모두 끝났을 때만 사용한다."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": sorted(STATUSES),
                    "description": "분석 완료 상태",
                },
                "summary": {"type": "string", "description": "전체 분석 요약"},
                "observed_ip_count": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "집계 도구에서 관찰한 전체 IP 수",
                },
                "assessments": {
                    "type": "array",
                    "maxItems": 50,
                    "items": assessment_schema,
                    "description": "판정한 IP 목록",
                },
            },
            "required": ["status", "summary", "observed_ip_count", "assessments"],
            "additionalProperties": False,
        },
    }


class SubmissionValidationError(ValueError):
    pass


def validate_submission(
    value: Mapping[str, Any],
    observed_ips: set[str] | None = None,
) -> dict[str, Any]:
    """최종 제출을 검증한다.

    observed_ips 를 주면 **도구 결과와 기계적으로 대조**한다. 프롬프트로 "도구 결과에서만
    근거를 가져오라"고 지시하는 것은 부탁이지 보장이 아니다. 모델이 존재하지 않는 IP를
    지어내거나 관찰 수를 부풀리는 것을 여기서 막는다.
    """
    _require_keys(value, {"status", "summary", "observed_ip_count", "assessments"}, "result")
    status = value["status"]
    if status not in STATUSES:
        raise SubmissionValidationError(f"지원하지 않는 status: {status}")

    summary = _require_string(value["summary"], "summary")
    observed_count = value["observed_ip_count"]
    if isinstance(observed_count, bool) or not isinstance(observed_count, int) or observed_count < 0:
        raise SubmissionValidationError("observed_ip_count는 0 이상의 정수여야 합니다.")

    raw_assessments = value["assessments"]
    if not isinstance(raw_assessments, list) or len(raw_assessments) > 50:
        raise SubmissionValidationError("assessments는 최대 50개의 배열이어야 합니다.")
    if observed_count < len(raw_assessments):
        raise SubmissionValidationError("observed_ip_count가 assessments 개수보다 작습니다.")
    if status == "no_data" and (observed_count != 0 or raw_assessments):
        raise SubmissionValidationError("no_data 상태에는 관찰 IP나 판정이 없어야 합니다.")

    assessments = [_validate_assessment(item, index) for index, item in enumerate(raw_assessments)]

    # --- 도구 결과와 대조 (환각 차단) --------------------------------------
    if observed_ips is not None:
        unknown = sorted({item["ip"] for item in assessments} - observed_ips)
        if unknown:
            raise SubmissionValidationError(
                f"도구 결과에 없는 IP를 판정했습니다: {unknown}. "
                f"집계 도구가 돌려준 IP만 판정할 수 있습니다."
            )
        if observed_ips and observed_count != len(observed_ips):
            raise SubmissionValidationError(
                f"observed_ip_count가 {observed_count}인데 집계 도구가 돌려준 IP는 "
                f"{len(observed_ips)}개입니다. 도구 결과의 IP 수를 그대로 쓰세요."
            )
        missing = sorted(observed_ips - {item["ip"] for item in assessments})
        if missing:
            raise SubmissionValidationError(
                f"판정이 빠진 IP가 있습니다: {missing}. 관찰한 모든 IP를 판정해야 합니다."
            )

    return {
        "status": status,
        "summary": summary,
        "observed_ip_count": observed_count,
        "assessments": assessments,
    }


def _validate_assessment(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SubmissionValidationError(f"assessments[{index}]는 객체여야 합니다.")
    required = {
        "ip",
        "classification",
        "threat_type",
        "severity",
        "confidence",
        "rationale",
        "evidence",
        "enrichment",
        "investigation_required",
        "requested_checks",
    }
    _require_keys(value, required, f"assessments[{index}]")

    ip = _require_string(value["ip"], f"assessments[{index}].ip")
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise SubmissionValidationError(f"유효하지 않은 IP 주소: {ip}") from exc

    classification = value["classification"]
    if classification not in CLASSIFICATIONS:
        raise SubmissionValidationError(f"지원하지 않는 classification: {classification}")
    severity = value["severity"]
    if severity not in SEVERITIES:
        raise SubmissionValidationError(f"지원하지 않는 severity: {severity}")

    confidence = value["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise SubmissionValidationError("confidence는 숫자여야 합니다.")
    if not 0 <= float(confidence) <= 1:
        raise SubmissionValidationError("confidence는 0과 1 사이여야 합니다.")

    investigation_required = value["investigation_required"]
    if not isinstance(investigation_required, bool):
        raise SubmissionValidationError("investigation_required는 boolean이어야 합니다.")
    if classification == "malicious_bot" and not investigation_required:
        raise SubmissionValidationError("malicious_bot은 조사 대상으로 전달해야 합니다.")

    evidence = value["evidence"]
    if not isinstance(evidence, list):
        raise SubmissionValidationError("evidence는 배열이어야 합니다.")
    normalized_evidence: list[dict[str, str]] = []
    for evidence_index, item in enumerate(evidence):
        if not isinstance(item, Mapping):
            raise SubmissionValidationError("evidence 항목은 객체여야 합니다.")
        _require_keys(item, {"type", "value"}, f"evidence[{evidence_index}]")
        normalized_evidence.append(
            {
                "type": _require_string(item["type"], "evidence.type"),
                "value": _require_string(item["value"], "evidence.value"),
            }
        )

    requested_checks = value["requested_checks"]
    if not isinstance(requested_checks, list) or not all(
        isinstance(item, str) and item.strip() for item in requested_checks
    ):
        raise SubmissionValidationError("requested_checks는 비어 있지 않은 문자열 배열이어야 합니다.")
    if investigation_required and (not normalized_evidence or not requested_checks):
        raise SubmissionValidationError("조사 대상에는 evidence와 requested_checks가 필요합니다.")

    enrichment = value["enrichment"]
    if not isinstance(enrichment, Mapping):
        raise SubmissionValidationError("enrichment는 객체여야 합니다.")
    # 도구팀 스키마 C 와 동일한 키·타입. asn 은 "AS16509" 형태의 문자열이다.
    enrichment_keys = ("country", "country_code", "asn", "as_org", "as_domain")
    _require_keys(enrichment, set(enrichment_keys), "enrichment")
    for key in enrichment_keys:
        if enrichment[key] is not None and not isinstance(enrichment[key], str):
            raise SubmissionValidationError(f"enrichment.{key}는 문자열 또는 null이어야 합니다.")

    return {
        "ip": ip,
        "classification": classification,
        "threat_type": _require_string(value["threat_type"], "threat_type"),
        "severity": severity,
        "confidence": float(confidence),
        "rationale": _require_string(value["rationale"], "rationale"),
        "evidence": normalized_evidence,
        "enrichment": {key: enrichment[key] for key in enrichment_keys},
        "investigation_required": investigation_required,
        "requested_checks": list(requested_checks),
    }


def _require_keys(value: Mapping[str, Any], required: set[str], path: str) -> None:
    keys = set(value.keys())
    missing = required - keys
    extra = keys - required
    if missing:
        raise SubmissionValidationError(
            f"{path} 필수 필드 누락: {sorted(missing)} (제출된 필드: {sorted(keys)})"
        )
    if extra:
        raise SubmissionValidationError(f"{path} 알 수 없는 필드: {sorted(extra)}")


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SubmissionValidationError(f"{path}는 비어 있지 않은 문자열이어야 합니다.")
    return value.strip()
