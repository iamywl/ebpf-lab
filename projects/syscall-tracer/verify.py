#!/usr/bin/env python3
"""시스템콜 추적기 자기검증 하네스.

검증 방식:
  1. eBPF 추적기를 먼저 로드(트레이스포인트 부착)한다.
  2. 정해진 횟수의 시스템콜을 호출하는 workload 를 자식 프로세스로 실행한다.
  3. workload 가 출력한 기준값(ground truth)을 읽는다.
  4. 추적기가 그 PID 에 대해 관측한 횟수와 기준값을 비교한다.
  5. 모든 대상 시스템콜에서  관측값 >= 기준값  이면 PASS.

이 스크립트는 "추적기가 실제로 시스템콜을 빠짐없이 잡아내는가" 를 증명한다.

사용 예::

    sudo python3 verify.py            # 기본 3000회
    sudo python3 verify.py 10000      # 시스템콜당 10000회
"""

from __future__ import annotations

import ctypes
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from bcc import BPF
from bcc.syscall import syscall_name

HERE = Path(__file__).resolve().parent
BPF_SOURCE = str(HERE / "bpf" / "syscall_count.c")
WORKLOAD_SRC = HERE / "workload.c"
WORKLOAD_BIN = HERE / "workload"


def ensure_workload() -> None:
    """workload 바이너리가 없거나 소스보다 오래되면 컴파일한다."""
    if WORKLOAD_BIN.exists() and WORKLOAD_BIN.stat().st_mtime >= WORKLOAD_SRC.stat().st_mtime:
        return
    print("workload.c 컴파일 중...", file=sys.stderr)
    subprocess.run(
        ["cc", "-O2", "-Wall", "-o", str(WORKLOAD_BIN), str(WORKLOAD_SRC)],
        check=True,
    )


def run() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    ensure_workload()

    print("eBPF 추적기 로드(전체 프로세스 추적)...", file=sys.stderr)
    bpf = BPF(src_file=BPF_SOURCE)
    bpf["target"][ctypes.c_int(0)] = ctypes.c_uint(0xFFFFFFFF)  # 0xFFFFFFFF = 전체 추적

    # 추적기가 부착된 뒤에 workload 실행 → 시작 직후 시스템콜까지 모두 포착
    print(f"workload 실행 (시스템콜당 {count:,}회)...", file=sys.stderr)
    proc = subprocess.run(
        [str(WORKLOAD_BIN), str(count)],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(proc.stdout.strip())
    target_pid = payload["pid"]
    ground_truth: dict[str, int] = payload["ground_truth"]

    # 추적기가 해당 PID 에 대해 관측한 값 집계
    observed: dict[str, int] = defaultdict(int)
    for k, v in bpf["counts"].items():
        if k.tgid == target_pid:
            name = syscall_name(k.syscall_id).decode("utf-8", "replace")
            observed[name] = v.value

    # 비교 표 출력
    print()
    print(f"{'=' * 64}")
    print(f"  시스템콜 추적 검증 결과  (대상 PID = {target_pid}, 호출 {count:,}회 기준)")
    print(f"{'=' * 64}")
    header = f"  {'시스템콜':<10} {'기준값':>10} {'관측값':>10} {'차이':>8}   판정"
    print(header)
    print(f"  {'-' * 10} {'-' * 10} {'-' * 10} {'-' * 8}   ----")

    # 판정 기준 (양방향):
    #   하한: 관측값 >= 기준값      (누락 없음 — 프로세스는 명시한 것보다 적게 호출 못 함)
    #   상한: 관측값 <= 기준값+SLACK (과다집계 없음 — 차이는 libc/링커의 고정 시작 비용뿐)
    # SLACK 은 호출 횟수 N 과 무관한 작은 상수. 만약 추적기가 비례적으로 과다/과소 집계하면
    # N 을 키울 때 이 한계를 반드시 넘으므로 FAIL 로 잡힌다.
    slack = 200
    all_pass = True
    for name in sorted(ground_truth):
        expected = ground_truth[name]
        got = observed.get(name, 0)
        delta = got - expected
        ok = expected <= got <= expected + slack
        all_pass = all_pass and ok
        mark = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {name:<10} {expected:>10,} {got:>10,} {delta:>+8,}   {mark}")

    print(f"{'=' * 64}")
    total_expected = sum(ground_truth.values())
    total_observed = sum(observed.get(n, 0) for n in ground_truth)
    print(f"  합계: 기준 {total_expected:,}  /  관측 {total_observed:,}")
    print(f"  이 PID 가 호출한 전체 고유 시스템콜 종류: {len(observed)}개")
    print()

    if all_pass:
        print("  >>> 검증 통과: 추적기가 모든 대상 시스템콜을 정확히 포착했습니다. <<<")
        return 0
    print("  >>> 검증 실패: 일부 시스템콜이 누락되었습니다. <<<")
    return 1


if __name__ == "__main__":
    sys.exit(run())
