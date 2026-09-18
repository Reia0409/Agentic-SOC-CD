# agent/prompts/

조사 에이전트(`InvestigationAgent`)의 시스템 프롬프트를 관리하는 패키지입니다.

## 구조

```
agent/prompts/
├── __init__.py           # 프롬프트 "조립" 로직만 (yaml을 읽어서 문자열로 합침)
└── investigation.yaml     # 프롬프트 "내용" — 역할/원칙/스키마/규칙
```

**내용을 고칠 땐 `investigation.yaml`만 수정하면 됩니다.** `__init__.py`는
건드릴 필요가 거의 없습니다.

## 왜 이렇게 나눴는지

원래는 `agent/prompts.py` 하나에 프롬프트 전체가 파이썬 문자열로 하드코딩돼
있었는데, 판단 기준을 여러 차례 고치는 과정에서 내용 하나 바꾸려고 매번 코드
전체를 열어야 하는 게 불편했습니다. 내용(yaml)과 조립 로직(py)을 분리해서,
비개발자도 `investigation.yaml`만 보고 원칙 문구를 수정할 수 있게 했습니다.

**`agent/seed_prompts.py`(seed 생성용 프롬프트)는 이 리팩터링 대상이 아닙니다.**
1차 탐지가 확정되면 이 코드베이스에서 통째로 빠질 예정이라, 지금 같이 옮기면
이중 작업이 됩니다.

## `investigation.yaml`의 섹션

| 섹션 | 내용 |
|---|---|
| `role` | 에이전트의 역할 소개 (역할, 임무) |
| `principles` | 원칙 1~7 목록. 각 항목은 `id`/`title`/`text` |
| `forced_termination_notice` | max_call 도달 시 마무리 턴에서 붙는 강제 지시 |
| `output_schema` | LLM이 지켜야 하는 JSON 출력 스키마 (예시 포함) |
| `rules` | 스키마 필드별 세부 규칙 (confidence 산정 기준, contradicting 정의 등) |

### 지금까지 쌓인 원칙 (principles) 요약

1. 증거 기반 조사 + 도구로 확인 안 한 사실(IP 평판 등) 근거 사용 금지
2. 동적 도구 선택 (모든 계층 다 조회하지 않기)
3. 중복 호출 금지
4. 종료 판단 — 게이트 조건(confidence/도구종류/network 확인) + 거부 시 대응
5. 계층 간 연결 — IP/시간 이어붙이기 + seed 단서로 첫 조회 계층 결정
6. audit 단독 증거의 함정 — sudo 파일 접근만으로 결론 내리지 않기, 판단 기준
   (정상/침해 신호), INCONCLUSIVE의 confidence 범위(0.45~0.60)
7. 계정/인증 관련 사건의 Q1(시도범위)/Q2(인증강도)/Q3(후속행위) 체크리스트

새 사건 유형(권한 상승, 데이터 유출, 지속성 확보 등)에 전용 원칙이 필요해지면
같은 패턴(구체적 서사를 못박기보다, 재사용 가능한 질문/체크리스트 구조로)으로
`principles`에 항목을 추가하는 것을 권장합니다 — 특정 시나리오에만 맞는 confidence
숫자를 못박는 방식은 verdict 방향까지 고정하지 못하고 다른 유형에 일반화가
안 되는 문제가 실제로 있었습니다 (원칙 7번의 1차 수정 시도에서 확인).

## `__init__.py`가 하는 일

- `investigation.yaml`을 읽어 `role` → `## 핵심 원칙`(principles 순회) →
  `## 강제 종료 턴 안내` → `## 사용 가능한 도구`(`{tool_schema}` 플레이스홀더) →
  `## 출력 형식`(output_schema) → `규칙:`(rules) 순서로 이어붙여
  `SYSTEM_PROMPT_TEMPLATE`을 만듭니다.
- `{tool_schema}` 치환은 `.format()`이 아니라 `.replace()`를 씁니다 —
  `output_schema` 안에 JSON 예시가 통째로 들어있어 중괄호가 많은데, `.format()`을
  쓰려면 그 중괄호를 전부 `{{ }}`로 이스케이프해야 해서 yaml 가독성이 크게
  떨어지기 때문입니다.
- `build_system_prompt(tool_registry)` / `build_user_prompt(state, ...)`는
  기존 `agent/prompts.py`와 이름·시그니처가 동일해서, 이 함수들을 쓰는
  `gemini_client.py` 등의 코드는 전혀 수정할 필요가 없습니다.

## yaml 수정 시 주의

- 각 `principles` 항목의 `text`는 `|` 블록 스칼라로 작성하세요 (여러 줄, 들여쓰기
  그대로 보존).
- `output_schema`/`rules`는 문자열 안에 JSON 예시를 그대로 담고 있어서, 중괄호를
  이스케이프할 필요가 없습니다 — `.format()`이 아니라 `.replace()`로 치환되기
  때문입니다.
- yaml을 고친 뒤에는 반드시 `python -m tests.test_loop`로 9개 테스트가 여전히
  통과하는지 확인하고, 가능하면 `test_consistency.py`로 재현성도 재검증하세요.