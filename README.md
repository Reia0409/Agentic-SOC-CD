# Agentic-SOC

"에이전트개발-9/9" 문서의 조사 에이전트 설계를 파이썬으로 구현한 것입니다.
Triage/감지 에이전트가 파이프라인에서 빠지면서, raw log를 직접 받아 LLM이
스스로 seed를 생성하고 우선순위를 매긴 뒤 심층 조사까지 하는 구조로 확장했습니다.

> **2026-09-17~18 업데이트 요약**: 파서 3종 개선(publickey 인식, web↔network 연결
> 복구, USER_CMD 누락 수정), 조사 루프 고도화(종료 관문, 무한거부 루프 버그 수정,
> src_ip 기반 network 계층 강제, evidence 중복 생성 방지, confidence-verdict 정합성
> 규칙), 판정 재현성 100% 달성(여러 사건 유형 검증 완료), 프롬프트를 `agent/prompts/`
> 패키지 + yaml로 리팩터링. 자세한 변경 이력은 팀 작업 로그 문서 참고.

## 전체 흐름 (한눈에)

```
Raw Log 수집 (agent/raw_log_ingestion.py)
      ↓
Seed 생성 - 경량 LLM Triage (agent/seed_generation.py + seed_prompts.py)
      ↓
우선순위 판단 (같은 곳, priority로 정렬)
      ↓
심층 조사 루프 - Agent Loop (agent/loop.py, 충분할 때까지 반복)
   판단(agent/prompts/) → Tool 호출(agent/tools/) → 증거 반영 → 종료 판단
      ↓
보고서 출력 (agent/report.py)
```

`main.py` 하나로 이 전체 흐름을 실행합니다: `python main.py`

**참고**: `agent/seed_generation.py`/`agent/seed_prompts.py`(1차 탐지·seed 생성)는
1차 탐지 단계가 별도 팀 파트로 확정되면 이 코드베이스에서 분리될 예정입니다.
조사 에이전트(`agent/loop.py` 이하)는 "이미 seed를 받았다"는 전제로 설계되어 있고,
이 부분이 지속적인 고도화의 중심입니다.

## 배포 방식

이 프로젝트는 **EC2 서버 안에 코드가 직접 올라가서, 서버의 로그 파일 경로에
직접 접근**하는 방식으로 동작합니다 (S3 등 별도 로그 저장소를 거치지 않습니다).
`agent/tools/real/fetch_*.py`는 `.env`에 지정된 경로의 로그 파일을 읽습니다 —
로컬 개발 중에는 샘플 로그 경로를, EC2에 배포된 상태에서는 실제 시스템 로그
경로(`/var/log/auth.log` 등)를 가리키면 되고, 코드 수정은 필요 없습니다.

## 폴더 구조

```
Agentic-SOC/
├── agent/
│   ├── __init__.py           # 패키지 진입점, 주요 클래스를 한 곳에서 import 가능하게 re-export
│   ├── loop.py                # Agent Loop 총괄 + 제어(중복/max_call/실패처리/종료판단/게이트)
│   ├── models.py              # State / Evidence 관리 (AgentState, Evidence, Hypothesis)
│   ├── prompts/                # 조사 루프 시스템 프롬프트 (패키지, yaml로 분리됨)
│   │   ├── README.md
│   │   ├── __init__.py         # yaml을 읽어 프롬프트 문자열로 조립하는 로직만
│   │   └── investigation.yaml  # 역할/원칙 1~7/출력스키마/규칙 — 순수 프롬프트 내용
│   ├── seed_prompts.py         # seed 생성(경량 triage) 전용 프롬프트 (별도 유지, 위 참고)
│   ├── seed_generation.py      # SeedGenerator — raw log에서 seed 후보 + 우선순위 추출
│   ├── raw_log_ingestion.py    # 최근 N분 raw log를 4계층(web/auth/audit/network) 수집
│   ├── pipeline.py             # raw log → seed → 우선순위 → 심층조사 전체 연결
│   ├── claude_client.py        # Claude API 클라이언트
│   ├── gemini_client.py        # Gemini API 클라이언트 (기본값, 무료 티어 가능)
│   ├── report.py               # 최종 investigation_result 조립 + 텍스트 리포트 변환
│   └── tools/
│       ├── __init__.py
│       ├── registry.py         # Tool 연결·실행 계층 (ToolRegistry, build_default_registry)
│       ├── mock_tools.py       # 실제 구현 전 로컬 테스트용 목업 핸들러
│       ├── parsers/             # 각 로그 형식 전용 파서 (파일 읽기/페이지네이션과 분리됨)
│       │   ├── README.md
│       │   ├── auth_parser.py       # auth.log(syslog) — ssh_login/sudo/pam 분류
│       │   ├── audit_parser.py      # audit.log — ENRICHED 포맷 + 멀티라인 조립
│       │   ├── network_parser.py    # Suricata eve.json — http 서브필드 포함
│       │   ├── nginx_json_parser.py # nginx JSON access log
│       │   └── apache_parser.py     # (미사용, 다른 환경 대비 보관)
│       └── real/                # 팀원들이 실제 구현 파일을 넣는 곳 (파일명=도구명이면 자동 연결)
│           ├── README.md
│           ├── fetch_web_log.py        # nginx access.log 실제 구현 (로그 파일 경로 직접 접근)
│           ├── fetch_auth_log.py       # auth.log(syslog) 실제 구현 + 페이지네이션
│           ├── fetch_audit_log.py      # auditd raw 텍스트 실제 구현 + 페이지네이션
│           ├── fetch_network_log.py    # Suricata eve.json 실제 구현 + 페이지네이션
│           └── resolve_ip_geo.py       # IP 지리정보 실제 구현 (외부 API, 현재 기본 제외)
├── scenarios/                # 판정 재현성 검증용 합성 로그 생성 스크립트 (별도 README 참고)
├── backend/                # 기존 Flask 백엔드 (건드리지 않음)
├── scripts/                 # 개발용 보조 스크립트 (프로덕션 코드 아님)
│   ├── fetch_sample_from_ec2.py  # SSH로 EC2에서 4계층 샘플 로그를 한 번에 받아오는 스크립트
│   └── local_e2e_test.py         # (구버전) 초기 검증용 스크립트, 지금은 real/ tool로 대체됨
├── tests/
│   ├── test_loop.py              # Agent Loop 전체 흐름 검증 (FakeLLMClient, 9개 테스트)
│   ├── test_fetch_audit_log.py   # fetch_audit_log 파싱/필터링 검증
│   ├── test_seed_generation.py   # SeedGenerator 우선순위 정렬 검증
│   ├── test_raw_log_ingestion.py # fetch_recent_raw_logs 4계층 수집 검증
│   ├── test_pipeline.py          # 전체 파이프라인 통합 검증
│   └── test_consistency.py       # 동일 seed 반복 실행으로 판정 재현성(verdict 일관성,
│                                  # confidence 표준편차) 측정. scenarios/의 시나리오와 함께 사용
├── main.py                 # 실행 진입점
├── .env.example             # .env로 복사해서 실제 키/경로를 채워 넣는 템플릿
├── .gitignore                # .env, .venv/, __pycache__/, sample_*.log 등 제외
└── requirements.txt          # pyyaml 포함 (agent/prompts/ yaml 파싱용)
```

| 원래 역할 분담 문서 항목 | 위치 |
| --- | --- |
| Agent Loop 총괄 | `agent/loop.py` (`InvestigationAgent.run`) |
| State / Evidence 관리 | `agent/models.py` (`AgentState`, `Evidence`, `Hypothesis`) |
| Tool 연결·실행 계층 | `agent/tools/` (`ToolRegistry`, `build_default_registry`) |
| Agent 판단·Prompt | `agent/prompts/` + `agent/claude_client.py`(Claude) / `agent/gemini_client.py`(Gemini) |
| Agent 제어 + 최종 산출물 | `agent/loop.py`의 종료/중복/실패/게이트 처리 + `agent/report.py` |
| 보고서 출력 | `agent/report.py` (`build_investigation_result`, `format_text_report`) |
| (추가) raw log 수집 · seed 생성 | `agent/raw_log_ingestion.py`, `agent/seed_generation.py`, `agent/seed_prompts.py` |
| (추가) 전체 파이프라인 연결 | `agent/pipeline.py` (`run_investigation_pipeline`) |
| (추가) 판정 재현성 검증 | `tests/test_consistency.py` + `scenarios/` |

## 설치 및 실행

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
cp .env.example .env
```

`.env`에 최소 이 항목들을 채웁니다:

```
GEMINI_API_KEY=발급받은_키          # Google AI Studio 무료 티어
HOST=web-01
RAW_LOG_WINDOW_MINUTES=10
```

그리고 아래처럼 실행:

```bash
# 단위 테스트 (API 키 불필요, 가짜 LLM 사용)
python -m tests.test_loop
python -m tests.test_fetch_audit_log
python -m tests.test_seed_generation
python -m tests.test_raw_log_ingestion
python -m tests.test_pipeline

# 실제 실행 (진짜 Gemini API 호출)
python main.py

# 판정 재현성 검증 (진짜 API 호출, 시나리오당 8회 권장 — scenarios/README.md 참고)
python -m tests.test_consistency --runs 8
```

## 로그 파일 경로 설정

`agent/tools/real/fetch_*.py` 4개 파일은 **환경변수로 지정된 로그 파일 경로를
직접 읽습니다.** 로컬 개발 중에는 샘플 로그를, EC2에 배포된 상태에서는 실제
시스템 로그 경로를 가리키면 되며 코드는 그대로입니다.

```bash
# (개발 중) EC2에서 4계층 샘플 로그를 로컬로 받아와 테스트할 때
python scripts/fetch_sample_from_ec2.py --all
```

`.env`에 추가 (왼쪽은 로컬 개발용 예시, EC2 배포 시에는 실제 시스템 로그 경로로 교체):

```
WEB_LOG_LOCAL_PATH=sample_logs/sample_web.log         # 예: /var/log/nginx/access.log
AUTH_LOG_LOCAL_PATH=sample_logs/sample_auth.log       # 예: /var/log/auth.log
AUDIT_LOG_LOCAL_PATH=sample_logs/sample_audit.log     # 예: /var/log/audit/audit.log
NETWORK_LOG_LOCAL_PATH=sample_logs/sample_network.log # 예: Suricata eve.json 경로
RAW_LOG_LOCAL_MAX_LINES=10   # 무료 티어 분당 토큰 한도 보호용, 429 에러 나면 더 낮추기
```

이 상태로 `python main.py`를 실행하면, `agent/raw_log_ingestion.py`와
`agent/tools/real/fetch_*.py`가 이 경로의 파일들을 읽어서 seed 생성부터
보고서 생성까지 끝까지 실행합니다.

**EC2 배포 시 주의**: 실제 시스템 로그(예: `/var/log/audit/audit.log`)는 보통
root 소유 640 권한이라, 이 프로세스를 실행하는 계정이 읽기 권한을 가지고
있는지 확인이 필요합니다. 권한이 없으면 tool이 `permission_denied`로
명확히 알려주니 원인 파악이 쉽습니다 (아래 "인프라 관련 알아둘 것" 참고).

### 아직 실제 구현이 없는 도구 제외하기

`get_process_tree`, `resolve_ip_geo`는 아직 실제 구현이 없거나(전자) 검증
우선순위가 아니라서(후자) 목업 데이터가 섞이면 안 될 때가 있습니다.
`build_default_registry(exclude=[...])`로 특정 도구를 아예 등록에서 뺄 수
있습니다 — 목업 폴백조차 되지 않고, LLM이 그 도구의 존재 자체를 모르게 됩니다.

```python
tool_registry = build_default_registry(exclude=["get_process_tree", "resolve_ip_geo"])
```

## LLM 연결

`agent/gemini_client.py`의 `GeminiClient`와 `agent/claude_client.py`의
`ClaudeClient`는 **완전히 동일한 인터페이스**(`.reason(state, tool_registry, ...)`,
`.complete_json(system_prompt, user_prompt)`)를 제공하므로 서로 갈아끼울 수
있습니다. `agent/prompts/`의 프롬프트는 모델에 종속되지 않는 순수 텍스트라
그대로 재사용됩니다.

기본값은 Gemini(`gemini-3.5-flash-lite`, 무료 티어)이고, `main.py`는
`LLM_PROVIDER=anthropic` 환경변수로 Claude로 전환할 수 있습니다.

무료 티어는 **분당 15회, 일일 500회** 요청 한도가 있습니다 (조사 1건당 LLM 호출이
여러 번 나감). `RAW_LOG_LOCAL_MAX_LINES`로 페이로드를 줄이거나 `InvestigationAgent
(max_calls=...)`를 너무 크게 잡지 않는 것으로 조절합니다. 일일 한도에 걸리면
`google.genai.errors.ClientError: 429 RESOURCE_EXHAUSTED`(quotaId에
`PerDay`가 포함)가 뜨며, UTC 자정 기준으로 리셋됩니다.

## 동작 방식 (설계 메모)

### raw log → seed 생성
`agent/seed_generation.py`의 `SeedGenerator`가 4계층 raw log를 정규화 없이
그대로 LLM에게 넘기고, "조사할 가치가 있는 후보"를 우선순위와 함께 뽑아옵니다.
후보가 0개일 수도, 여러 개일 수도 있습니다. `agent/pipeline.py`가 우선순위
순서대로 각 seed를 `InvestigationAgent.run()`에 넘깁니다.

### 심층 조사 루프
문서의 Stage 1(현황 파악) / Stage 2(증거 결정) / Stage 3(도구 호출)은
개념적으로는 분리돼 있지만, 실제 LLM 호출은 **사이클당 1회**로 묶었습니다.
매 호출마다 LLM이 facts/hypotheses/unknowns를 갱신하고, 동시에 다음 행동
(`call_tool` 또는 `terminate`)까지 결정하는 ReAct 스타일 루프입니다.

```
seed 입력
  ↓
LLM 판단 (facts/hypotheses/unknowns 갱신 + 다음 행동 결정)  ─┐
  ↓                                                          │
call_tool? → Tool 실행 → 결과를 pending_observations에 저장 ─┘ (반복)
  ↓
terminate 요청? → 종료 관문 통과? → 최종 investigation_result 생성
                → 통과 못하면 거부 사유 전달하고 계속 조사 (아래 참고)
```

### 종료 관문 (게이트)
`termination_reason`을 `confidence_sufficient`로 종료하려면 아래를 모두
만족해야 승인됩니다 (미달이면 거부되고 조사가 강제로 계속됨):

- 실제 `current_confidence`가 `confidence_threshold` 이상
- 서로 다른 도구를 2종류 이상 사용
- seed에 `src_ip`가 있으면 `fetch_network_log`를 최소 1회 사용

또한 `confidence`가 0.45~0.60 범위(애매한 확신도)면 verdict는 반드시
`INCONCLUSIVE`여야 합니다 — 애매한 확신으로 확정 판정을 내리는 것을 금지합니다.

게이트가 거부하면 그 사유를 다음 턴 프롬프트에 명시적으로 전달합니다
(`gate_rejection_reason`). 동일 사유로 연속 2회 거부되면 사이클을 낭비하지
않고 강제 종료 턴(도구 호출 없이 판정만 요청)으로 전환합니다.

### tool 설계 원칙 — "파싱은 파서가, 파일 읽기/페이지네이션은 tool wrapper가, 의미 해석은 전부 LLM"
`agent/tools/real/`의 4개 tool은 얇은 wrapper이고, 실제 파싱 로직은
`agent/tools/parsers/`에 분리되어 있습니다 (자세한 내용은 각 폴더의 README 참고).
uid/session_type/auth_method 같은 필드까지는 구조화해서 반환하지만, "이게
위협인지 아닌지"는 절대 tool이 판단하지 않고 전부 LLM(프롬프트의 원칙)에
맡깁니다.

### 계층 간 연결
`agent/prompts/investigation.yaml`에 "한 계층에서 IP/시간을 확인했으면 다음
도구 호출 시 그 IP/시간대를 조건으로 그대로 써서 사건을 연결하라"는 원칙이
명시돼 있습니다 (audit↔auth는 pid로, web→audit/network는 같은 src_ip·시간대로).
또한 "seed의 trigger_description에 등장하는 단서(업로드/URI 등 web 관련,
SSH/로그인 등 auth 관련)로 첫 조회 계층을 결정하라"는 지침도 있습니다 —
계정 관련 사건에만 익숙해져서 웹 기반 사건에서 `fetch_web_log`를 빠뜨리는
문제를 실제로 발견해 추가한 규칙입니다. 별도의 "조인 엔진" 코드 없이 LLM의
판단으로 여러 계층의 사실을 하나의 공격 시나리오로 엮습니다.

## 종료 조건 (3가지 중 하나)

1. `confidence_sufficient` — 위 종료 관문을 통과해 `terminate` 승인
2. `no_more_evidence` — LLM이 더 조사할 로그가 없다고 판단 (게이트 미적용, 다만
   src_ip 있는데 network 미확인 상태면 notes에 경고 기록)
3. `max_call_reached` — `InvestigationAgent(max_calls=...)`에 설정한 호출 상한 도달
   시, 도구 호출 없이 판정만 요청하는 마무리 턴을 1회 추가로 시도

## 제어 로직

- **중복 조사 방지**: 동일 `(tool_name, args)` 조합은 `AgentState.already_called()`로
  걸러져 실제 도구가 다시 호출되지 않습니다 (인자에 리스트/딕셔너리가 와도 안전하게
  처리).
- **실패 처리**: 도구 호출 예외는 `tool_calls`에 `success=False`로 기록되고,
  실패 사유가 성공 케이스와 동일한 채널(`pending_observations`)로 LLM에게 전달되어
  다음 턴에 원인을 알고 대응할 수 있습니다.
- **증거 중복 방지**: 같은 관찰 사실을 요약 형태로 다시 evidence화하는 것을 금지해,
  `confidence_progression`이 같은 사실을 두 번 반영해 요동치는 걸 막습니다.

## 실제 팀원 구현과 연결하는 방법

`agent/tools/real/`에 파일명·함수명이 도구 이름과 똑같은 파일을 넣으면
`build_default_registry()`가 자동으로 그 함수를 사용합니다. 자세한 내용은
`agent/tools/real/README.md`를 참고하세요.

## 보고서 출력 형식

`agent/report.py`가 만드는 것:

- `build_investigation_result(state, ...)` — `evidence_chain`, `contradicting_evidence`,
  `attack_timeline`, `confidence_progression`, `final_verdict`(reasoning 포함),
  `remaining_unknowns` 등을 포함한 JSON
- `format_text_report(result)` — 위 JSON을 사람이 읽는 텍스트로 변환

```
INVESTIGATION RESULT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Incident INC-SSH-BF-01

Initial Hypothesis
SSH 브루트포스 공격 후 시스템 침입 시도

Investigation Findings
E1 [Auth] 77.239.124.213 IP로부터 발생한 399건의 인증 로그 분석 결과, 모든 시도가 실패

Timeline
04:07:24 첫 번째 SSH 브루트포스 시도 감지
04:23:46 마지막 인증 실패 시도 기록

Provisional Conclusion
외부 IP(77.239.124.213)가 브루트포스를 시도했으나 시스템 침해로 이어지지 않았습니다.

Supporting Evidence 1
Contradicting Evidence 0
Unresolved 없음

Investigation Confidence 0.95
```

- `E1, E2...`와 `[Auth]/[Audit]/[Apache]/[Suricata]` 라벨은 `sequence` 순서와
  `source_log` 문자열에서 자동으로 매깁니다 (`contradicting_evidence`에도 동일하게
  `sequence`/`layer`가 포함됩니다).
- `Provisional Conclusion`은 `final_verdict.summary`에 LLM이 직접 쓰는 1~2문장입니다.
  `final_verdict.reasoning`에는 판단 과정(어떤 신호를 확인했는지)이 별도로 담깁니다.
- `Unresolved`는 종료 시점의 `state.unknowns`를 그대로 노출합니다.

## 판정 신뢰성 검증

`tests/test_consistency.py`로 동일한 seed를 여러 번 반복 실행해 verdict 일관성과
confidence 표준편차를 측정합니다. 지금까지 검증한 시나리오와 결과는
`scenarios/README.md`를 참고하세요. 검증 결과 요약:

- 계정/sudo 접근(정상), 웹셸 업로드-실행(침해): **100% 완전 일관**
- 비밀번호 브루트포스(침해), 계정 탐색 후 로그인(애매): **88%** — 남은 이탈은 대부분
  "증거 부족 시 정직하게 INCONCLUSIVE로 물러서는" 의도된 동작
- 데이터 유출, 권한 상승, 지속성 확보: 검증 진행 중 (API 일일 한도 제약)

## 인프라 관련 알아둘 것 (실측 결과, 2026-09-13~17)

- audit 로그 파일은 NDJSON이 아니라 **ENRICHED 포맷의 raw 텍스트**입니다.
  `\x1d`(GS) 구분자로 raw/enriched가 붙어있으므로, 텍스트를 나눌 때
  `str.splitlines()`가 아니라 `text.split("\n")`을 반드시 써야 합니다
  (`splitlines()`는 `\x1d`도 줄바꿈으로 취급해 ENRICHED 절반을 통째로 날려버립니다).
- **web 계층은 nginx JSON 로그**를 씁니다(apache 아님). 실측 결과 nginx 로그의
  `src_ip`에 이미 실제 클라이언트 IP가 정상적으로 찍혀 있어(당초 우려했던 loopback
  문제 없음) 그대로 쓰면 됩니다. `apache_parser.py`는 다른 환경 대비용으로만 보관
  중이며 현재 미사용입니다.
- Suricata(network 계층)는 nginx↔백엔드 사이 loopback 트래픽을 캡처해 `src_ip`가
  `127.0.0.1` 등 내부 IP로 찍히는 경우가 있습니다. 진짜 클라이언트 IP는 Suricata가
  파싱한 `http.xff` 필드에 있으므로, `fetch_network_log`의 `src_ip` 필터는 `xff`도
  함께 확인합니다.
- 실제 시스템 로그 파일(예: `/var/log/audit/audit.log`)은 보통 root 소유 640
  권한이므로, 에이전트를 실행하는 프로세스 계정에 읽기 권한이 있는지 확인이
  필요합니다. 권한이 없으면 tool이 `permission_denied`로 명확히 구분해 알려줍니다.

## 아직 남은 것

- **`get_process_tree`, `resolve_ip_geo` 미구현/보류** — 현재 `main.py`에서
  `exclude`로 제외 중
- **`gemini_client.py`의 JSON 파싱 견고성** — LLM이 가끔 JSON 응답에 markdown
  리스트 문법(`- key: value`)을 섞어 넣어 파싱이 깨지는 사례 발견. trailing comma
  보정 로직으로는 처리 안 되는 새로운 유형이라 별도 보강 필요
- **`contradicting_evidence` 라벨링 완전 정확도** — LLM이 조사 도중 가설을
  재해석하는 과정에서, 이미 지지 증거로 처리된 사실을 다시 반박 증거로 잘못
  라벨링하는 사례가 드물게 있음 (최종 verdict/confidence 자체는 정확했음)
- **판정 재현성 지표 자체의 개선** — 현재의 "최다 verdict 비율" 지표는 "자신
  있게 틀리는 것"과 "정직하게 불확실성을 인정하는 것"을 구분하지 못함. confidence
  구간별로 분리해서 측정하는 방식 검토 필요
- **Validator 재조사 훅** — 이번 개발 범위에서는 미구현
- **실전(EC2) 환경 검증** — 지금까지의 재현성 검증은 전부 로컬 합성 로그 기준.
  실제 수집된 로그, 동시다발 사건, Sigma 룰이 실제로 만드는 seed 형태에 대한
  검증이 아직 없음