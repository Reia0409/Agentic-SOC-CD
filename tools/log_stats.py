"""
tools/log_stats.py
도구① 본체. 로그 파일을 읽어 window 구간의 이벤트를 IP별 통계로 집계한다.
실제 파싱·집계·제외는 parsers/ 안의 조각들이 담당. 본체는 조립만.
"""

import os
from datetime import datetime, timezone, timedelta ## timedelta 추가됨 (window 계산용)
from dotenv import load_dotenv

from tools.base import success, failure
from tools.registry import register

# 조각들 import
from tools.parsers.apache_parser import parse_apache_line, apache_ts_to_dt
from tools.parsers.auth_parser import parse_auth_line, auth_ts_to_dt
from tools.parsers.filters import is_excluded
from tools.parsers.aggregator import aggregate_by_ip

# 로그 경로 (.env)
load_dotenv()
APACHE_LOG_PATH = os.getenv("APACHE_LOG_PATH", "logs/apache_sample.log")
AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "logs/auth_sample.log")


@register(
    name="aggregate_logs",
    description="최근 로그를 IP별 통계로 집계한다. 에이전트가 가장 먼저 호출한다.",
    input_schema={
        "type": "object",
        "properties": {
            "minutes": {"type": "integer", "description": "분석 구간 길이(분). 기본 10."},
            "end_time": {"type": "string", "description": "구간 끝 시각(UTC ISO8601). 생략 시 현재."},
        },
        "required": [],
    },
)
def aggregate_logs(minutes: int = 10, end_time: str = None) -> dict:
    """로그 파일을 읽어 window 구간의 이벤트를 IP별 통계로 집계."""

    # 1. window 계산
    #end_time을 주면 그걸 파싱, 없으면 현재 시각
    end_dt = datetime.fromisoformat(end_time) if end_time else datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(minutes=minutes)
    year = end_dt.year

    events = [] # 모든 이벤트를 담을 리스트

    # 2. apache 읽기→파싱→시각변환→구간필터→제외필터→수집
    try:
        with open(APACHE_LOG_PATH, encoding="utf-8") as f:
            for line in f:                      #파일을 한줄 씩(메모리 효율적)
                event = parse_apache_line(line) #파서가 스키마 A 이벤트로 변환
                if event is None:
                    continue
                dt = apache_ts_to_dt(event["ts"]) # 문자열 ts → datetime
                if dt is None or not (start_dt <= dt <= end_dt):
                    continue
                if is_excluded(event):            # 서버 자기 IP 등 제외 대상이면 버림
                    continue
                events.append(event)              # 다 통과하면 수집
    except FileNotFoundError:
        return failure(f"apache 로그 없음: {APACHE_LOG_PATH}")

    # 3. auth 구조 동일, 파서만 auth용으로
    try:
        with open(AUTH_LOG_PATH, encoding="utf-8") as f:
            for line in f:
                event = parse_auth_line(line)
                if event is None:
                    continue
                dt = auth_ts_to_dt(event["ts"], year)
                if dt is None or not (start_dt <= dt <= end_dt):
                    continue
                event["ts"] = dt.isoformat()  # ★ 추가: auth ts를 ISO로 통일 (apache와 형식 맞춤)
                if is_excluded(event):
                    continue
                events.append(event)
    except FileNotFoundError:
        return failure(f"auth 로그 없음: {AUTH_LOG_PATH}")

    # 4. IP별 집계
    stats = aggregate_by_ip(events)

    return success({
        "window": {
            "start": start_dt.isoformat(),
            "end": end_dt.isoformat(),
            "minutes": minutes,
        },
        "ip_count": len(stats),
        "stats": stats,
    })