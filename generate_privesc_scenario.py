"""권한 상승(Privilege Escalation) 시나리오 - SUID 바이너리 악용으로 root 셸 획득.

핵심 판단 포인트: 정상 계정으로 정상 로그인(Q1/Q2 정상 신호) 후, 로컬에서
SUID 비트가 설정된 find 바이너리를 악용해 낮은 권한(uid=1001)에서 euid=0(root)로
전환되는 실행 체인. 지금까지의 시나리오와 달리 src_ip가 없는(순수 내부 행위)
사건이라 network 계층 강제 게이트가 어떻게 반응하는지도 함께 확인한다.

*** 시간 계산은 datetime으로 직접 명시 (지난 exfiltration 스크립트의 실수 반복 방지) ***
"""

import os
from datetime import datetime, timezone

LOG_DIR = "sample_logs"
VICTIM_USER = "developer"
HOST = "web-01"

EVENT_TIME = datetime(2026, 9, 14, 22, 0, 0, tzinfo=timezone.utc)
EPOCH_BASE = int(EVENT_TIME.timestamp())

# ----------------------------------------------------------------------
# 1. auth.log — 정상 공개키 로그인 (내부망 IP, src_ip 없음 시나리오)
# ----------------------------------------------------------------------
auth_lines = [
    f"Sep 14 22:00:00 ip-10-0-7-236 sshd[9800]: "
    f"Accepted publickey for {VICTIM_USER} from 10.0.7.100 port 51000 ssh2: "
    f"ED25519 SHA256:aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB6c",
    f"Sep 14 22:00:00 ip-10-0-7-236 sshd[9800]: pam_unix(sshd:session): "
    f"session opened for user {VICTIM_USER}(uid=1001) by (uid=0)",
]

# ----------------------------------------------------------------------
# 2. audit.log — find(SUID) 악용으로 root 셸 획득 -> id로 euid=0 확인
# ----------------------------------------------------------------------
GS = "\x1d"
SERIAL_BASE = 9800

audit_lines = []


def make_execve_pair(serial, offset_sec, ppid, pid, uid, euid, comm, exe, argv):
    epoch = EPOCH_BASE + offset_sec
    syscall_line = (
        f"type=SYSCALL msg=audit({epoch}.001:{serial}): arch=c000003e syscall=59 "
        f"success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={ppid} pid={pid} "
        f"auid=1001 uid={uid} gid=1001 euid={euid} suid={euid} fsuid={euid} egid=1001 "
        f"sgid=1001 fsgid=1001 tty=pts1 ses=101 comm=\"{comm}\" exe=\"{exe}\" "
        f"subj=unconfined key=\"exec\""
        f"{GS}ARCH=x86_64 SYSCALL=execve AUID=\"{VICTIM_USER}\" "
        f"UID=\"{VICTIM_USER if uid != 0 else 'root'}\" GID=\"{VICTIM_USER}\" "
        f"EUID=\"{'root' if euid == 0 else VICTIM_USER}\" SUID=\"{'root' if euid == 0 else VICTIM_USER}\" "
        f"FSUID=\"{'root' if euid == 0 else VICTIM_USER}\" EGID=\"{VICTIM_USER}\" "
        f"SGID=\"{VICTIM_USER}\" FSGID=\"{VICTIM_USER}\""
    )
    argv_fields = " ".join(f'a{i}="{arg}"' for i, arg in enumerate(argv))
    execve_line = f"type=EXECVE msg=audit({epoch}.001:{serial}): argc={len(argv)} {argv_fields}"
    return [syscall_line, execve_line]


# (1) find 명령으로 SUID 셸 스폰 시도 (find가 SUID root로 설정되어 있다고 가정)
audit_lines += make_execve_pair(
    SERIAL_BASE + 1, 10, ppid=9800, pid=9801, uid=1001, euid=0,
    comm="find", exe="/usr/bin/find",
    argv=["find", ".", "-exec", "/bin/sh", "-p", ";", "-quit"],
)
# (2) 그 결과로 얻은 셸에서 id 실행 -> euid=0(root)임을 확인하는 게 핵심 증거
audit_lines += make_execve_pair(
    SERIAL_BASE + 2, 12, ppid=9801, pid=9802, uid=1001, euid=0,
    comm="id", exe="/usr/bin/id", argv=["id"],
)
# (3) 획득한 root 권한으로 /etc/shadow 조회 (권한 상승의 목적)
audit_lines += make_execve_pair(
    SERIAL_BASE + 3, 15, ppid=9801, pid=9803, uid=1001, euid=0,
    comm="cat", exe="/usr/bin/cat", argv=["cat", "/etc/shadow"],
)

# ----------------------------------------------------------------------
# network.log는 의도적으로 추가하지 않음 (순수 로컬 권한 상승, src_ip 없는 seed)
# ----------------------------------------------------------------------

with open(os.path.join(LOG_DIR, "sample_auth.log"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(auth_lines) + "\n")

with open(os.path.join(LOG_DIR, "sample_audit.log"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(audit_lines) + "\n")

print("권한 상승 시나리오 로그 추가 완료.")
print(f"EPOCH_BASE={EPOCH_BASE} -> {datetime.fromtimestamp(EPOCH_BASE, tz=timezone.utc)}")
print()
print("test_consistency.py의 SEED (incident_id 확인! src_ip는 None):")
print(
    f"""
SEED = {{
    "incident_id": "CONSISTENCY-TEST-06",
    "detection_source": "llm_triage",
    "trigger_time": "2026-09-14T22:00:00+00:00",
    "trigger_description": "developer 계정 세션에서 SUID 바이너리(find)를 이용한 권한 상승 및 민감 파일(/etc/shadow) 접근 발생",
    "confidence_initial": 0.6,
    "severity_hint": "HIGH",
    "priority": 1,
    "host": "{HOST}",
    "src_ip": None,
    "reasoning": "일반 사용자 권한(uid=1001)의 세션에서 SUID 바이너리를 통해 euid=0(root)으로 전환된 뒤 민감 파일에 접근한 정황이 확인되어 권한 상승 공격 가능성이 높습니다.",
}}
"""
)