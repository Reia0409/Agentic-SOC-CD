"""fetch_web_log 실제 구현 - EC2의 nginx access 로그를 읽어온다 (S3 또는 로컬 파일).

파일명 == 함수명 규칙에 따라 agent/tools/real/fetch_web_log.py 안의 fetch_web_log
함수만 있으면 agent/tools/registry.py의 build_default_registry()가 자동으로 이 함수를
mock_tools.py 대신 사용한다.

*** 2026-09-14 재교체: apache_parser.py -> nginx_json_parser.py ***
처음엔 web 담당 팀원의 apache_parser.py(공백 구분 14필드, shlex 기반)를 썼는데,
실제 sample_web.log를 열어보니 그 형식이 아니라 한 줄 = JSON 객체 하나인 nginx
JSON 로그였다 (count=0으로 전부 파싱 실패하는 걸 보고 발견함). 그래서
agent/tools/parsers/nginx_json_parser.py(실측 기반으로 새로 만듦)로 교체했다.
apache_parser.py 자체는 지우지 않았다 — 다른 환경/서버가 그 형식을 쓸 수도 있음.

*** 2026-09-17 확인: apache로 다시 바꿀 필요 없음 ***
"nginx만 가지고는 suricata와 연결 불가능하다"는 우려가 있었는데, 확인해보니
문제는 이 파일이 아니라 network_parser.py(Suricata eve.json 파서) 쪽이었다.
nginx JSON 로그는 이미 src_ip에 실제 클라이언트 IP가 있어서(아래 xff 관련
설명 참고) 정상 작동하고, Suricata는 loopback 트래픽을 보고 있어서 진짜
클라이언트 IP가 http.xff에만 있었다 — 그래서 network_parser.py에 xff/url/
http_method/status 파싱을 추가해서 web↔network join을 복구했다
(agent/tools/parsers/network_parser.py 참고). 이 파일은 그대로 nginx 유지.

*** src_ip/xff 관련: 실측 결과 loopback 문제가 없었다 ***
당초 우려(nginx 뒤라 src_ip가 loopback일 수 있음)와 달리, 실제 nginx JSON
로그는 src_ip에 이미 진짜 클라이언트 IP가 찍혀 있었다. 그래도 만약을 대비해
xff 필터도 같이 봐준다 (다른 프록시 계층이 있는 경우 대비).

*** limit/offset 페이지네이션 채택 (auth/network와 동일한 이유) ***

필요 환경변수 (.env에 추가):
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION
  WEB_LOG_BUCKET (기본값: ogwanwan-shop-bucket)

*** 로컬 테스트 모드 ***
.env에 WEB_LOG_LOCAL_PATH=sample_web.log 넣어두면 S3 대신 그 파일을 읽는다.

*** 권한 에러 처리 ***
로컬 파일이 root 소유 등으로 비root 프로세스가 못 읽는 경우 PermissionError를
명시적으로 잡아서 summary에 "권한 없음"이라고 남긴다 (예외로 죽지 않고, 조용히
빈 결과로 넘어가지도 않고, LLM이 원인을 알 수 있게).
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List

from ..parsers.nginx_json_parser import nginx_ts_to_dt, parse_nginx_json_line
from ._s3_common import daterange, list_and_read_text
from ..time_utils import parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"
S3_SOURCE_TYPE = "nginx"
DEFAULT_LIMIT = 200


def _read_source_text(host: str, start: datetime, end: datetime) -> "tuple[str, int, str]":
    """WEB_LOG_LOCAL_PATH가 있으면 로컬 파일을, 없으면 S3를 읽는다.
    반환값: (전체 텍스트, 스캔한 오브젝트/파일 개수, 소스 라벨)
    """
    local_path = os.environ.get("WEB_LOG_LOCAL_PATH")
    if local_path:
        if not os.path.exists(local_path):
            return "", 0, f"local:{local_path} (파일 없음)"
        try:
            with open(local_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read(), 1, f"local:{local_path}"
        except PermissionError:
            return "", 0, f"local:{local_path} (권한 없음)"

    import boto3  # 실제 호출 시에만 필요하므로 지연 import

    bucket = os.environ.get("WEB_LOG_BUCKET", DEFAULT_BUCKET)
    s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION"))

    chunks: List[str] = []
    scanned_objects = 0
    for date_str in daterange(start, end):
        prefix = f"raw/source_type={S3_SOURCE_TYPE}/host={host}/dt={date_str}/"
        text, count = list_and_read_text(s3, bucket, prefix)
        scanned_objects += count
        chunks.append(text)
    return (
        "\n".join(chunks),
        scanned_objects,
        f"s3://{bucket}/raw/source_type={S3_SOURCE_TYPE}/host={host}/",
    )


def _matches_filters(event: Dict[str, Any], args: Dict[str, Any]) -> bool:
    if "src_ip" in args:
        target = args["src_ip"]
        if event.get("src_ip") != target and event.get("xff") != target:
            return False
    if "method" in args and (event.get("method") or "").upper() != str(args["method"]).upper():
        return False
    if "path" in args and args["path"] not in (event.get("uri") or ""):
        return False
    if "status_code" in args and event.get("status") != args["status_code"]:
        return False
    return True


def fetch_web_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start = parse_iso(args["start_time"])
    end = parse_iso(args["end_time"])
    limit = int(args.get("limit", DEFAULT_LIMIT))
    offset = int(args.get("offset", 0))

    text, scanned_objects, source_label = _read_source_text(host, start, end)

    all_events: List[Dict[str, Any]] = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        event = parse_nginx_json_line(line)
        if event is None:
            continue

        dt = nginx_ts_to_dt(event.get("timestamp"))
        if dt is not None and not (start <= dt <= end):
            continue

        if not _matches_filters(event, args):
            continue

        all_events.append(event)

    total_matched = len(all_events)
    page = all_events[offset : offset + limit]
    has_more = (offset + limit) < total_matched

    if scanned_objects == 0:
        summary = (
            f"{source_label} 에서 {start.date()}~{end.date()} 구간에 데이터를 찾지 못했습니다. "
            "host 이름 또는 로컬 파일 경로가 맞는지 확인하세요."
        )
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={offset + limit})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start.isoformat()}~{end.isoformat()} 구간에서 ({source_label}) "
            f"조건에 맞는 web 요청 총 {total_matched}건 중 {page_desc} {len(page)}건 반환. "
            f"({more_desc}, method/uri/status/upstream까지 구조화)"
        )

    return {
        "count": len(page),
        "summary": summary,
        "records": page,
        "total_matched": total_matched,
        "has_more": has_more,
        "next_offset": offset + limit if has_more else None,
    }