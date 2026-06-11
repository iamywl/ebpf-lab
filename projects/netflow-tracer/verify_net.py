#!/usr/bin/env python3
"""TCP 연결 추적기 자기검증 하네스.

검증 방식:
  1. 127.0.0.1 의 임의 포트에 로컬 TCP 리스너를 띄운다.
  2. eBPF 추적기(tcp_v4_connect kprobe)를 로드한다.
  3. net_workload 가 그 포트로 정해진 횟수만큼 TCP 연결을 시도한다.
  4. 추적기가 "그 PID 가 그 목적지로" 보낸 연결을 모두 관측했는지 비교한다.
  5. 관측 횟수 >= 시도 횟수 이고 목적지(IP:포트)가 일치하면 PASS.

사용 예::

    sudo python3 verify_net.py          # 기본 50회 연결
    sudo python3 verify_net.py 200      # 200회 연결
"""

from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
import threading
from collections import defaultdict
from pathlib import Path

from bcc import BPF

HERE = Path(__file__).resolve().parent
BPF_SOURCE = str(HERE / "bpf" / "tcpconnect.c")
WORKLOAD_SRC = HERE / "net_workload.c"
WORKLOAD_BIN = HERE / "net_workload"


def ip_str(daddr: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", daddr))


def ensure_workload() -> None:
    if WORKLOAD_BIN.exists() and WORKLOAD_BIN.stat().st_mtime >= WORKLOAD_SRC.stat().st_mtime:
        return
    print("net_workload.c 컴파일 중...", file=sys.stderr)
    subprocess.run(["cc", "-O2", "-Wall", "-o", str(WORKLOAD_BIN), str(WORKLOAD_SRC)], check=True)


def start_listener() -> tuple[socket.socket, int, threading.Event]:
    """127.0.0.1 의 임의 포트에 accept 루프 리스너를 띄우고 (소켓, 포트, 종료이벤트)를 반환."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(128)
    srv.settimeout(0.5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    threading.Thread(target=accept_loop, daemon=True).start()
    return srv, port, stop


def run() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    ensure_workload()

    srv, port, stop = start_listener()
    print(f"로컬 리스너 가동: 127.0.0.1:{port}", file=sys.stderr)

    print("eBPF TCP 연결 추적기 로드...", file=sys.stderr)
    bpf = BPF(src_file=BPF_SOURCE)

    events: list[tuple[int, int, int]] = []  # (pid, daddr, dport)
    lost = {"count": 0}

    def handle(_cpu, data, _size):
        e = bpf["events"].event(data)
        events.append((e.pid, e.daddr, socket.ntohs(e.dport)))

    def on_lost(n):
        lost["count"] += n

    bpf["events"].open_perf_buffer(handle, lost_cb=on_lost)

    print(f"net_workload 실행: 127.0.0.1:{port} 로 {count}회 연결...", file=sys.stderr)
    proc = subprocess.Popen([str(WORKLOAD_BIN), str(port), str(count)],
                            stdout=subprocess.PIPE, text=True)
    while proc.poll() is None:
        bpf.perf_buffer_poll(timeout=100)
    for _ in range(10):  # 남은 이벤트 배수(drain)
        bpf.perf_buffer_poll(timeout=100)

    out, _ = proc.communicate()
    stop.set()
    srv.close()

    payload = json.loads(out.strip())
    target_pid = payload["pid"]
    attempts = payload["attempts"]

    # 추적기가 "대상 PID 가 127.0.0.1:port 로" 보낸 연결만 집계
    observed = 0
    other_dests: dict[str, int] = defaultdict(int)
    for pid, daddr, dport in events:
        if pid != target_pid:
            continue
        dst = f"{ip_str(daddr)}:{dport}"
        if dst == f"127.0.0.1:{port}":
            observed += 1
        else:
            other_dests[dst] += 1

    print()
    print("=" * 60)
    print(f"  TCP 연결 추적 검증 결과")
    print("=" * 60)
    print(f"  대상 PID          : {target_pid}")
    print(f"  목적지            : 127.0.0.1:{port}")
    print(f"  workload 연결 시도: {attempts} 회   (성공 {payload['connected']} 회)")
    print(f"  추적기 관측       : {observed} 회")
    print(f"  추적기가 본 전체 이벤트 수: {len(events)} 개")
    if lost["count"]:
        print(f"  ⚠️ perf 버퍼 누락 이벤트: {lost['count']} 개")
    print("=" * 60)

    ok = observed >= attempts
    if ok:
        print("  ✅ 검증 통과: 추적기가 대상 목적지로의 모든 연결을 포착했습니다.")
        return 0
    print("  ❌ 검증 실패: 일부 연결이 누락되었습니다.")
    return 1


if __name__ == "__main__":
    sys.exit(run())
