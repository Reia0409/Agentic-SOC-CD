"""
tools/parsers/auth_parser.py
auth 로그 한 줄 파싱 + auth 시각 변환.
"""

import re #로그가 자유형 문장이라 정규식 사용
from datetime import datetime, timezone #timezonedms UTC를 붙이기 위해 사용

# Failed password [for invalid user] <user> from <ip>
_FAIL_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)   # "Failed password for invalid user root from 1.2.3.4"
# Accepted <method> for <user> from <ip>
_ACCEPT_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)"
)   # "Accepted password for admin from 1.2.3.4"


def parse_auth_line(line: str) -> dict | None:
    """auth 한 줄 → 스키마 A 이벤트(auth). 실패/스킵 대상은 None."""
    ts = line[:15].strip()   # 'Aug 27 10:57:25'

    # 로그인 실패
    m = _FAIL_RE.search(line)
    if m:
        return {
            "layer": "auth",
            "ts": ts,
            "src_ip": m.group("ip"),
            "event_type": "login_fail",
            "detail": {
                "user": m.group("user"),
                "invalid_user": "invalid user" in line,
                "method": "password", #실패는 항상 password이므로 고정
            },
            "raw": line.rstrip("\n"),
        }

    # 로그인 성공
    m = _ACCEPT_RE.search(line)
    if m:
        return {
            "layer": "auth",
            "ts": ts,
            "src_ip": m.group("ip"),
            "event_type": "login_success",
            "detail": {
                "user": m.group("user"),
                "invalid_user": False, #성공했으니 유효 계정 무조건 False
                "method": m.group("method"),
            },
            "raw": line.rstrip("\n"),
        }

    # 그 외 (kex, CRON 등) event_type은 중간 범위에서는 None으로 처리
    return None


def auth_ts_to_dt(ts_str: str, year: int) -> datetime | None:
    """'Aug 27 10:57:25' + 연도 → UTC datetime."""
    try:
        dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc) #tzinfo을 UTC로 변환
    except ValueError:
        return None