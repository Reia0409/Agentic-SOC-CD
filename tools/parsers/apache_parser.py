"""
tools/parsers/apache_parser.py
apache 로그 한 줄 파싱 + apache 시각 변환.
"""

import shlex #따옴표 묶인 필드를 통째로 잘라줌
from datetime import datetime #datetime 변환


def parse_apache_line(line: str) -> dict | None:
    """apache 한 줄 → 스키마 A 이벤트(web). 실패 시 None."""
    try:
        parts = shlex.split(line)
    except ValueError:
        return None

    if len(parts) < 13:
        return None

    ts       = parts[0] #시각
    src_ip   = parts[2] #클라이언트 IP
    req_line = parts[6] #"GET / HTTP/1.1" 통째로
    status   = parts[7] # HTTP 상태코드
    ua       = parts[12] # User-Agent

    req_parts = req_line.split()
    method = req_parts[0] if len(req_parts) >= 1 else ""
    uri    = req_parts[1] if len(req_parts) >= 2 else ""

    try:
        status = int(status)
    except ValueError:
        status = 0

    return {
        "layer": "web",
        "ts": ts,
        "src_ip": src_ip,
        "event_type": "web_request",
        "detail": { #레이어별 고유 정보는 detail 안에 격리 
            "method": method,
            "uri": uri,
            "status": status,
            "ua": ua,
        },
        "raw": line.rstrip("\n"), #원본 한 줄 보존(나중에 상세조사/증거체인)
    }


def apache_ts_to_dt(ts_str: str) -> datetime | None:
    """'2026-08-27T11:58:29.882399Z' → UTC datetime."""
    try:
        # python 3.11이상 버전을 사용해야 정상 처리 가능
        return datetime.fromisoformat(ts_str) #ISO 8601 문자열 파싱 
    except ValueError:
        return None