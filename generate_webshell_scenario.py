"""웹셸 업로드 -> 실행 -> 유출 시나리오 (계정/인증 무관, 웹 취약점 기반 공격).

지금까지 검증한 원칙 6/7번은 전부 "계정/인증 관련 사건"만 다뤘다. 이 시나리오는
로그인/sudo가 전혀 등장하지 않는 완전히 다른 공격 벡터라, 전용 판단 원칙이 없는
상태에서 일반 원칙(1번 증거기반조사, 5번 계층간연결)만으로 에이전트가 얼마나
안정적으로 대응하는지 검증하기 위한 것이다.

시나리오 개요:
  1. web: 공격자(198.51.100.77)가 업로드 엔드포인트로 shell.php를 업로드(POST 200)
  2. web: 곧이어 그 파일에 ?cmd= 파라미터로 명령 실행 요청(GET 200) - 웹셸 특유의 패턴
  3. audit: php-fpm(www-data)이 sh -c로 id/whoami/uname을 실행 - PHP 앱이 정상적으로는
     하지 않는 행위(php-fpm이 셸을 스폰하는 것 자체가 강한 침해 신호)
  4. network: 웹서버 -> 공격자 IP 아웃바운드 통신 + Suricata "Possible Webshell" alert

기존 sample_logs/*.log에 append한다.
"""

import json
import os

LOG_DIR = "sample_logs"
ATTACKER_IP = "198.51.100.77"
SERVER_IP = "10.0.7.236"
HOST = "web-01"

# ----------------------------------------------------------------------
# 1. web.log — 업로드 + 명령 실행 요청 (nginx JSON 포맷)
# ----------------------------------------------------------------------
web_events = [
    {
        "ts": "2026-09-14T18:05:00+00:00", "msec": "1789423500.000",
        "req_id": "wsh0001", "src_ip": ATTACKER_IP, "src_port": "55001",
        "dst_ip": SERVER_IP, "dst_port": "443", "scheme": "https", "host": "ogwanwan.shop",
        "method": "POST", "uri": "/wp-content/uploads/2026/09/shell.php",
        "proto": "HTTP/1.1", "status": "200", "bytes": "42", "rt": "0.031",
        "xff_orig": "", "ref": "", "ua": "python-requests/2.31.0",
        "upstream": "127.0.0.1:8080", "ustatus": "200",
    },
    {
        "ts": "2026-09-14T18:05:05+00:00", "msec": "1789423505.000",
        "req_id": "wsh0002", "src_ip": ATTACKER_IP, "src_port": "55002",
        "dst_ip": SERVER_IP, "dst_port": "443", "scheme": "https", "host": "ogwanwan.shop",
        "method": "GET", "uri": "/wp-content/uploads/2026/09/shell.php?cmd=id;whoami;uname+-a",
        "proto": "HTTP/1.1", "status": "200", "bytes": "128", "rt": "0.045",
        "xff_orig": "", "ref": "", "ua": "python-requests/2.31.0",
        "upstream": "127.0.0.1:8080", "ustatus": "200",
    },
]
web_lines = [json.dumps(e) for e in web_events]

# ----------------------------------------------------------------------
# 2. audit.log — php-fpm이 셸을 스폰하는 execve 체인 (ENRICHED 포맷)
# ----------------------------------------------------------------------
GS = "\x1d"
EPOCH_BASE = 1789423505
SERIAL_BASE = 9500

audit_lines = []


def make_execve_pair(serial, epoch, ppid, pid, uid_name, comm, exe, argv):
    syscall_line = (
        f"type=SYSCALL msg=audit({epoch}.001:{serial}): arch=c000003e syscall=59 "
        f"success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={ppid} pid={pid} "
        f"auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 "
        f"tty=(none) ses=4294967295 comm=\"{comm}\" exe=\"{exe}\" subj=unconfined key=\"exec\""
        f"{GS}ARCH=x86_64 SYSCALL=execve AUID=\"unset\" UID=\"{uid_name}\" GID=\"{uid_name}\" "
        f"EUID=\"{uid_name}\" SUID=\"{uid_name}\" FSUID=\"{uid_name}\" EGID=\"{uid_name}\" "
        f"SGID=\"{uid_name}\" FSGID=\"{uid_name}\""
    )
    argv_fields = " ".join(f'a{i}="{arg}"' for i, arg in enumerate(argv))
    execve_line = f"type=EXECVE msg=audit({epoch}.001:{serial}): argc={len(argv)} {argv_fields}"
    return [syscall_line, execve_line]


# php-fpm 워커(기존에 떠있는 프로세스, ppid=1로 가정)가 sh를 스폰
audit_lines += make_execve_pair(
    SERIAL_BASE + 1, EPOCH_BASE, ppid=1200, pid=9500,
    uid_name="www-data", comm="sh", exe="/usr/bin/dash",
    argv=["sh", "-c", "id;whoami;uname -a"],
)
# sh가 다시 id, whoami, uname을 자식으로 실행
audit_lines += make_execve_pair(
    SERIAL_BASE + 2, EPOCH_BASE + 1, ppid=9500, pid=9501,
    uid_name="www-data", comm="id", exe="/usr/bin/id", argv=["id"],
)
audit_lines += make_execve_pair(
    SERIAL_BASE + 3, EPOCH_BASE + 2, ppid=9500, pid=9502,
    uid_name="www-data", comm="whoami", exe="/usr/bin/whoami", argv=["whoami"],
)
audit_lines += make_execve_pair(
    SERIAL_BASE + 4, EPOCH_BASE + 3, ppid=9500, pid=9503,
    uid_name="www-data", comm="uname", exe="/usr/bin/uname", argv=["uname", "-a"],
)

# ----------------------------------------------------------------------
# 3. network.log — 웹서버 -> 공격자 아웃바운드 + alert
# ----------------------------------------------------------------------
network_lines = [
    json.dumps({
        "timestamp": "2026-09-14T18:05:06.000000+0000", "event_type": "flow",
        "src_ip": SERVER_IP, "dest_ip": ATTACKER_IP, "src_port": 44100,
        "dest_port": 8080, "proto": "TCP",
        "flow": {"state": "established", "pkts_toserver": 5, "pkts_toclient": 3},
    }),
    json.dumps({
        "timestamp": "2026-09-14T18:05:06.500000+0000", "event_type": "alert",
        "src_ip": ATTACKER_IP, "dest_ip": SERVER_IP, "src_port": 55002,
        "dest_port": 443, "proto": "TCP",
        "alert": {"signature": "ET WEB_SERVER Possible PHP Webshell Command Execution"},
    }),
]

# ----------------------------------------------------------------------
# append
# ----------------------------------------------------------------------
with open(os.path.join(LOG_DIR, "sample_web.log"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(web_lines) + "\n")

with open(os.path.join(LOG_DIR, "sample_audit.log"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(audit_lines) + "\n")

with open(os.path.join(LOG_DIR, "sample_network.log"), "a", encoding="utf-8") as f:
    f.write("\n".join(network_lines) + "\n")

print("웹셸 시나리오 로그 추가 완료.")
print()
print("test_consistency.py의 SEED를 아래로 교체하세요:")
print(
    """
SEED = {
    "incident_id": "CONSISTENCY-TEST-04",
    "detection_source": "llm_triage",
    "trigger_time": "2026-09-14T18:05:00+00:00",
    "trigger_description": "웹 애플리케이션 업로드 디렉터리에 PHP 파일 업로드 후 곧바로 명령 실행 파라미터로 접근 발생",
    "confidence_initial": 0.65,
    "severity_hint": "HIGH",
    "priority": 1,
    "host": "web-01",
    "src_ip": "198.51.100.77",
    "reasoning": "업로드 디렉터리에 PHP 파일이 생성된 직후 그 파일에 cmd 파라미터로 접근하는 패턴은 웹셸 업로드-실행 공격의 전형적인 시그니처입니다.",
}
"""
)