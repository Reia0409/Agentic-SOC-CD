# tests/

조사 에이전트의 각 구성요소를 검증하는 테스트 모음입니다. 크게 두 종류로 나뉩니다:
**단위/통합 테스트**(API 호출 없이, 코드 로직 자체를 검증)와 **재현성 검증**
(`test_consistency.py`, 실제 Gemini API를 호출해 판정의 일관성을 측정).

## 실행 방법

모든 테스트는 프로젝트 루트에서 `python -m tests.<파일명>` 형태로 실행합니다
(`tests/`가 패키지라 상대 import를 쓰므로, `python tests/test_loop.py`처럼
직접 실행하면 import 에러가 날 수 있습니다).

```bash
# 단위/통합 테스트 (API 키 불필요, 몇 초 내 완료)
python -m tests.test_loop
python -m tests.test_fetch_audit_log
python -m tests.test_seed_generation
python -m tests.test_raw_log_ingestion
python -m tests.test_pipeline

# 재현성 검증 (실제 Gemini API 호출, 시간이 걸리고 일일/분당 한도 소모)
python -m tests.test_consistency --runs 8
```

## 파일 목록

| 파일 | 검증 대상 | API 호출 |
|---|---|---|
| `test_loop.py` | `InvestigationAgent` 전체 흐름 — 종료 관문, 중복 호출 방지, max_call 강제 종료, 도구 실패 처리, `real/` 자동 탐색 등 9개 테스트. `FakeLLMClient`로 LLM 응답을 스크립트화해서 검증 | ❌ 안 함 |
| `test_fetch_audit_log.py` | `fetch_audit_log`의 파싱/필터링 로직 | ❌ 안 함 |
| `test_seed_generation.py` | `SeedGenerator`의 우선순위 정렬 | ❌ 안 함 |
| `test_raw_log_ingestion.py` | `fetch_recent_raw_logs`의 4계층 수집 | ❌ 안 함 |
| `test_pipeline.py` | raw log → seed → 조사까지 전체 파이프라인 통합 | ❌ 안 함 |
| `test_consistency.py` | 동일 seed를 N회 반복 실행해 verdict 일관성 + confidence 표준편차 측정 | ✅ 실제 호출 |

## `test_loop.py` — `FakeLLMClient`로 로직만 검증

이 테스트는 실제 LLM을 부르지 않고, 미리 정해둔 `decision` 딕셔너리를 순서대로
반환하는 `FakeLLMClient`를 씁니다. `loop.py`의 제어 로직(게이트, 재시도, 안전장치)이
의도대로 동작하는지만 확인하는 것이 목적이라, 프롬프트 문구를 바꿔도 이 테스트
자체는 영향받지 않습니다 — 대신 프롬프트를 바꾼 뒤에는 `test_consistency.py`로
실제 판정 품질을 확인해야 합니다.

9개 테스트가 각각 확인하는 것:

- `test_happy_path_terminates_with_threat_confirmed` — 정상 흐름(4계층 조사 후
  THREAT_CONFIRMED 종료)
- `test_format_text_report_renders_expected_sections` — 텍스트 리포트 포맷
- `test_duplicate_tool_call_is_skipped` — 동일 `(tool, args)` 재호출 차단
- `test_max_call_forces_termination` — `max_calls` 도달 시 강제 종료
- `test_tool_failure_does_not_stop_investigation` — 도구 실패해도 조사 계속
- `test_confidence_sufficient_blocked_when_single_tool_type` — 도구 1종류만
  쓴 채로는 confidence_sufficient 종료 불가 (게이트)
- `test_confidence_sufficient_allows_remaining_unknowns` — unknowns가 남아있어도
  confidence_sufficient 종료는 허용 (unknowns 자체는 차단 사유 아님)
- `test_src_ip_seed_requires_network_log` — `src_ip` 있는 seed는 network 계층
  확인 강제
- `test_real_tool_auto_discovery` — `agent/tools/real/`에 파일명=함수명이
  일치하는 파일을 추가하면 자동으로 연결되는지

새 게이트 조건이나 종료 로직을 추가할 때는, 여기에 해당 조건을 검증하는 테스트를
같이 추가하는 것을 권장합니다.

## `test_consistency.py` — 실제 판정 재현성 검증

`tests/` 안에 있지만 성격이 다릅니다. 단위 테스트처럼 "코드가 맞게 짜였는지"가
아니라 **"LLM이 실제로 안정적으로 판단하는지"**를 검증합니다. `agent/prompts/`의
원칙을 수정한 뒤에는 반드시 이 스크립트로 재검증하는 것을 권장합니다.

```bash
python -m tests.test_consistency --runs 8
```

`SEED` 딕셔너리를 원하는 사건 시나리오로 바꿔서 씁니다. 실제 검증에 쓸 로그는
`scenarios/`의 생성 스크립트로 만듭니다 — 자세한 사용법과 지금까지 검증한
시나리오 목록은 `scenarios/README.md`를 참고하세요.

**주의**: 이 스크립트는 실제 Gemini API를 호출합니다. 무료 티어는 분당 15회,
일일 500회 한도가 있으니, 급하게 여러 시나리오를 연달아 검증하려 하면 하루
안에 한도를 다 쓸 수 있습니다.

## 새 테스트를 추가할 때

- 코드 로직(게이트, 파싱, 페이지네이션 등) 검증이면 `FakeLLMClient`나 가짜
  데이터를 써서 API 호출 없이 실행되게 만드세요 — 이래야 CI에서도 안전하게
  돌릴 수 있습니다.
- 프롬프트/판단 기준 자체가 잘 작동하는지 보고 싶다면 `test_consistency.py`를
  쓰거나, 그 패턴을 참고해 새 스크립트를 만드세요.