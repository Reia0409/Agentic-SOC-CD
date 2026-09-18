# agent/tools/parsers/

각 로그 형식을 "텍스트 → 구조화된 이벤트 리스트"로 변환하는 순수 파싱 로직만
모아둔 폴더입니다. S3/로컬 파일 선택, 페이지네이션, tool 인터페이스 맞추기는
`agent/tools/real/`이 담당하고, 여기는 파싱 자체에만 집중합니다.

## 파일 목록

| 파일 | 담당 로그 | 사용하는 tool |
|---|---|---|
| `auth_parser.py` | auth.log (syslog) | `fetch_auth_log` |
| `audit_parser.py` | audit.log (auditd, ENRICHED 포맷) | `fetch_audit_log`, `raw_log_ingestion.py`(수집 계층)에서도 재사용 |
| `network_parser.py` | Suricata eve.json | `fetch_network_log` |
| `nginx_json_parser.py` | nginx access log (JSON) | `fetch_web_log` |
| `apache_parser.py` | Apache 공백구분 로그 | **현재 미사용** — 다른 환경/서버가 이 형식을 쓸 경우 대비 보관 |

## `auth_parser.py`

`Failed password`, `Accepted password`, `Accepted publickey`, `sudo`, `pam_unix` 등의
패턴을 정규식으로 분류해 `{event_type, user, source_ip, result, auth_method,
timestamp, raw_log_ref}` 공통 스키마로 반환합니다.

- `auth_method`는 `"password"` / `"publickey"` / `None`(sudo/pam은 인증 방식이
  로그에 안 나타남) — 프롬프트의 원칙 7번(Q2: 인증 강도)이 이 필드를 직접 참고합니다.
- syslog 형식은 한 줄에 연도가 없어서(`Sep 14 09:04:37`), `reference_year`
  파라미터로 호출 시점의 연도를 넘겨줘야 절대 시각이 나옵니다. 연말/연초 경계를
  걸친 조회는 정확하지 않을 수 있습니다.
- `limit`/`offset` 페이지네이션은 여기서 하지 않습니다 — 이 파서는 "조건에 맞는
  전체 목록"까지만 책임지고, 페이지 자르기는 `fetch_auth_log.py`가 담당합니다.

## `audit_parser.py`

가장 복잡한 파서입니다. audit.log는 **ENRICHED 포맷**이라 한 이벤트가 여러 줄
(`SYSCALL`/`CWD`/`PATH`/`EXECVE`/`PROCTITLE`)에 걸쳐 나오고, 각 줄 안에서도
raw 부분과 enriched 부분이 `\x1d`(GS, 0x1d) 구분자로 붙어있습니다.

**중요한 함정**: `text.splitlines()`를 쓰면 안 됩니다. 파이썬의 `splitlines()`는
`\x1c`/`\x1d`/`\x1e` 같은 제어 문자도 줄바꿈으로 취급해서, ENRICHED 구분자가
있는 줄을 raw/enriched가 합쳐지기도 전에 둘로 쪼개버립니다. 반드시
`text.split("\n")`을 쓰세요.

- `SYSCALL` 레코드가 없고 `USER_CMD`(PAM sudo)만 있는 사건도, `include_user_cmd=True`
  (기본값)로 호출하면 놓치지 않고 조립합니다. `fetch_audit_log.py`가 이 값을
  안 넘겨서 한동안 이 기능이 죽어있었던 적이 있으니, 새로 감싸는 코드를 만들 때
  이 인자를 빠뜨리지 마세요.
- `session_type`은 `auid`가 unset(`4294967295`)이면 `non_interactive`, 아니면
  `interactive`로 파생됩니다.
- `EXECVE`의 `argv`는 각 인자가 평문(`"..."`로 시작) 또는 hex 인코딩일 수 있어
  둘 다 디코딩해서 `exec_args`로 합칩니다.

## `network_parser.py`

Suricata eve.json(한 줄 = JSON 이벤트 하나)을 그대로 읽습니다.

- `event_type == "http"`인 레코드는 `http` 서브객체에서 `xff`/`url`/`http_method`/
  `status`를 추가로 뽑아 반환합니다. Suricata가 nginx↔백엔드 사이 loopback
  트래픽을 캡처해 `src_ip`가 `127.0.0.1` 등 내부 IP인 경우가 있는데, 진짜
  클라이언트 IP는 `xff`에만 있기 때문입니다.
- `src_ip` 필터는 `record["src_ip"]` **또는** `xff`와 매칭됩니다 — 둘 중
  하나만 맞아도 통과합니다. 합성 로그를 만들 때 이 방향(어느 필드에 어떤
  IP가 들어가는지)을 헷갈리면 필터가 안 걸리니 주의하세요.
- `direction`(internal/outbound/inbound) 계산은 하지 않습니다 — 호스트 자신의
  IP를 사전 등록하는 단계가 이 시스템엔 없어서, `src_ip`/`dst_ip`를 그대로
  반환하고 어느 쪽이 공격자인지는 LLM이 판단합니다.

## `nginx_json_parser.py`

nginx JSON access log(한 줄 = JSON 이벤트 하나)를 읽습니다. 실측 결과 이
로그의 `src_ip`엔 이미 실제 클라이언트 IP가 정상적으로 찍혀 있어(loopback
문제 없음), 별도 프록시 계층 대응 없이 그대로 씁니다. 다만 `xff_orig` 필드도
`xff`로 함께 반환해, 다른 프록시 계층이 있는 환경에도 대비합니다.

## `apache_parser.py` (미사용)

원래 web 계층 파서 후보였으나, 실제 로그가 이 형식(공백 구분 14필드)이 아니라
nginx JSON이라는 게 실측으로 확인되어 `nginx_json_parser.py`로 교체됐습니다.
지우지 않고 남겨둔 이유는 다른 환경/서버가 실제로 이 형식을 쓸 수 있어서입니다.
**web↔network 연결이 안 될 때, 원인이 이 파일이라고 오해하지 마세요** — 실제로
한 번 이런 오진단이 있었고, 진짜 원인은 `network_parser.py`가 `xff` 필드를
안 뽑고 있던 것이었습니다.

## 새 로그 형식을 지원해야 한다면

1. 이 폴더에 `<형식>_parser.py`를 새로 만들고, "텍스트 → 이벤트 리스트" 순수
   함수만 작성하세요 (S3/로컬 선택, 페이지네이션은 넣지 마세요).
2. `agent/tools/real/`에 이 파서를 가져다 쓰는 얇은 wrapper를 만드세요
   (`agent/tools/real/README.md` 참고).
3. 합성 로그로 테스트할 때는 실제 형식(ENRICHED 구분자, JSON 필드명 등)을
   최대한 정확히 재현하세요 — `scenarios/README.md`에 자주 나는 실수(시간 계산,
   필드 방향)가 정리되어 있습니다.