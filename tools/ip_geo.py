"""
tools/ip_geo.py
위협으로 판정된 IP의 국가·ASN·조직 정보를 조회하는 도구.
"""

import ipaddress # IP 주소 문자열 검증, 사설/공인 판별
import os #환경변수 읽기
import maxminddb # .mmdb 바이너리 DB 조회 라이브러리
from dotenv import load_dotenv # .env 파일 읽기

from tools.base import success, failure
from tools.registry import register

# .env에서 DB 경로 읽기
load_dotenv()
DB_PATH = os.getenv("IPINFO_DB_PATH", "data/ipinfo_lite.mmdb")

# DB reader를 모듈 로드 시 한 번만 연다 (매 조회마다 열면 느림)
_reader = maxminddb.open_database(DB_PATH)


@register(
    name="resolve_ip_geo",
    description="위협으로 판정된 IP의 국가·ASN·AS조직 정보를 조회한다. 정상 IP에는 호출하지 않는다.",
    input_schema={
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "조회할 IP 주소 (예: 8.8.8.8)",
            },
        },
        "required": ["ip"], #ip는 필수 인자임을 명시
    },
)
def resolve_ip_geo(ip: str) -> dict:

    # 1. 입력이 유효한 IP인가?
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return failure("invalid_ip")        # "abc", "999.1.1.1" 등

    # 2. 사설·예약 IP는 조회 대상 아님
    if not ip_obj.is_global:
        return failure("private_ip")         # 10.x, 192.168.x, 127.x 등

    # 3. 공인 IP 조회
    result = _reader.get(ip)

    # 4. 공인인데 DB에 정보 없음
    if result is None:
        return failure("lookup_error")  

    # 5. 정상
    data = {
        "ip": ip,
        "country": result.get("country"),
        "country_code": result.get("country_code"),
        "asn": result.get("asn"),
        "as_org": result.get("as_name"),      # IPinfo는 조직명을 as_name으로 부름
        "as_domain": result.get("as_domain"), # 조직 도메인 (판별 참고용)
    }
    return success(data)