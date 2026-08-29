"""
tools/parsers/filters.py
집계에서 제외할 이벤트 판별 (제외 규칙).
"""

# 서버 자기 공인 IP (wp-cron 자기호출 → 외부 트래픽 아님)
_EXCLUDED_IPS = {
    "54.180.11.0",   # EC2 서버 자기 공인 IP
}


def is_excluded(event: dict) -> bool:
    """이 이벤트를 집계에서 제외할지 판단. True면 버림."""
    if event["src_ip"] in _EXCLUDED_IPS:
        return True
    return False