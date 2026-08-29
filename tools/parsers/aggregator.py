"""
tools/parsers/aggregator.py
스키마 A 이벤트 리스트 → IP별 통계(스키마 B).
"""

from collections import Counter


def _is_suspicious_ua(ua: str) -> bool:
    """UA가 잘림·빈값이면 True (위장은 못 잡음 → LLM 몫)."""
    if not ua or ua == "-":
        return True
    if len(ua) < 20:
        return True
    return False


def aggregate_by_ip(events: list) -> list:
    """스키마 A 이벤트 리스트 → IP별 통계(스키마 B) 리스트."""
    groups: dict = {} #빈 딕셔너리
    for e in events:
        ip = e["src_ip"]
        if ip not in groups:#이 ip가 딕셔너리에 없으면
            groups[ip] = [] #그 ip용 빈 리스트 만들기
        groups[ip].append(e) #이벤트를 그 ip리스트에 넣음

    result = []
    for ip, ip_events in groups.items(): #IP와 그 이벤트리스트 가져와서
        result.append(_summarize(ip, ip_events)) #묶음을 통계로 변환하고 resultdp 넣음
    return result


def _summarize(ip: str, events: list) -> dict:
    """한 IP의 이벤트들 → 통계 한 뭉치 (스키마 B)."""
    login_fail = 0
    login_success = 0
    invalid_user_count = 0
    wp_login_post = 0
    scan_404 = 0
    req_total = 0
    ua_counter = Counter() #UA 빈도 세는 특수용
    timestamps = [] #시각을 모을 리스트

    for e in events:
        timestamps.append(e["ts"])
        etype = e["event_type"]
        detail = e["detail"]

        if etype == "login_fail":
            login_fail += 1
            if detail.get("invalid_user"):
                invalid_user_count += 1
        elif etype == "login_success":
            login_success += 1
        elif etype == "web_request":
            req_total += 1
            ua_counter[detail.get("ua", "")] += 1 #UA의 등장 횟수
            if detail.get("status") == 404:
                scan_404 += 1
            if detail.get("method") == "POST" and "/wp-login.php" in detail.get("uri", ""):
                wp_login_post += 1

    top_ua = ua_counter.most_common(1)[0][0] if ua_counter else None #최빈 UA 1개 (리스트-> 튜플 -> 값)

    return {
        "ip": ip,
        "login_fail": login_fail,
        "login_success": login_success,
        "invalid_user_count": invalid_user_count,
        "wp_login_post": wp_login_post,
        "scan_404": scan_404,
        "req_total": req_total,
        "top_ua": top_ua,
        "ua_suspicious": _is_suspicious_ua(top_ua) if top_ua else False,
        "first_seen": min(timestamps) if timestamps else None,
        "last_seen": max(timestamps) if timestamps else None,
    }