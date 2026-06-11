#!/usr/bin/env python3
"""실제 캡처 출력(examples/_sample_output, docs/captures)을 터미널 스크린샷 PNG 로 렌더링.
강의자료(docs/lecture/images/)의 '실제 실행 화면' 이미지를 재생성한다. 의존: Pillow, macOS 폰트.
사용: python3 scripts/render-screenshots.py
"""
import unicodedata
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs/lecture/images"
MONO = "/System/Library/Fonts/Menlo.ttc"          # 영문 등폭
KOR  = "/System/Library/Fonts/AppleSDGothicNeo.ttc" # 한글

SIZE = 22
mono = ImageFont.truetype(MONO, SIZE, index=0)
kor  = ImageFont.truetype(KOR, SIZE - 1, index=0)
tbar = ImageFont.truetype(KOR, 16, index=0)

# 셀(한 칸) 너비 = Menlo 숫자 폭
CELL = mono.getlength("0")
LINEH = SIZE + 9
PAD = 22
TBAR_H = 40

# 색 (다크 터미널, 점은 무채색으로 — 논문 톤과 통일)
BG, BAR, TEXT, DIM, PROMPT = "#1b1b1b", "#2d2d2d", "#e8e8e8", "#9aa0a6", "#cfcfcf"
DOTS = ["#6b6b6b", "#8a8a8a", "#a8a8a8"]

def is_wide(ch):
    if ch == "\t": return False
    return unicodedata.east_asian_width(ch) in ("W", "F")

def line_cells(s):
    return sum(2 if is_wide(c) else 1 for c in s)

def render(title, lines, outname):
    # 셀 폭 계산
    maxcells = max([line_cells(l) for l in lines] + [line_cells(title)+4])
    W = int(maxcells * CELL + 2 * PAD)
    H = int(TBAR_H + len(lines) * LINEH + 2 * PAD)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # 타이틀 바
    d.rectangle([0, 0, W, TBAR_H], fill=BAR)
    for i, c in enumerate(DOTS):
        cx = 18 + i * 20
        d.ellipse([cx, TBAR_H//2 - 6, cx + 12, TBAR_H//2 + 6], fill=c)
    tw = tbar.getlength(title)
    d.text(((W - tw) / 2, TBAR_H/2 - 9), title, font=tbar, fill=DIM)
    # 본문 — 셀 그리드에 글자 배치 (한글=2칸)
    y = TBAR_H + PAD
    for ln in lines:
        x = PAD
        col = 0
        for ch in ln:
            if ch == "\t":
                col = (col // 8 + 1) * 8; x = PAD + col * CELL; continue
            wide = is_wide(ch)
            f = kor if (wide or ord(ch) > 0x2500) else mono
            color = TEXT
            d.text((x, y - (1 if f is kor else 0)), ch, font=f, fill=color)
            step = 2 if wide else 1
            col += step; x = PAD + col * CELL
        y += LINEH
    img.save(OUT / outname)
    return img.size

def load(relpath, n=18, skip_blanks=True):
    txt = (REPO / relpath).read_text(encoding="utf-8", errors="replace").split("\n")
    out = []
    for l in txt:
        if skip_blanks and l.strip() == "" and (not out or out[-1].strip() == ""):
            continue
        out.append(l.rstrip())
        if len(out) >= n: break
    while out and out[-1].strip() == "":
        out.pop()
    return out

def prompt(cmd, body, n=16):
    return [f"ebpf@ossca-ebpf:~/ebpf-labs$ {cmd}"] + body[:n]

jobs = [
  ("hello.bt — 새 프로그램 실행 추적",
   prompt("sudo bpftrace 01_기본동작/hello.bt", load("examples/_sample_output/hello.txt")),
   "shot_hello.png"),
  ("opensnoop.bt — 파일 열기 추적",
   prompt("sudo bpftrace 02_시스템콜/opensnoop.bt", load("examples/_sample_output/opensnoop.txt")),
   "shot_opensnoop.png"),
  ("execsnoop.bt — 새 프로세스 실행 추적",
   prompt("sudo bpftrace 02_시스템콜/execsnoop.bt", load("examples/_sample_output/execsnoop.txt")),
   "shot_execsnoop.png"),
  ("syscall_top.bt — 프로세스별 시스템콜 집계",
   prompt("sudo bpftrace 02_시스템콜/syscall_top.bt", load("examples/_sample_output/syscall_top.txt")),
   "shot_syscall_top.png"),
  ("tcp_connect.bt — 나가는 TCP 접속 추적",
   prompt("sudo bpftrace 03_네트워크/tcp_connect.bt", load("examples/_sample_output/tcp_connect.txt")),
   "shot_tcp_connect.png"),
  ("tracer.py — PID별 시스템콜 실시간 추적",
   prompt("sudo python3 tracer.py --duration 3 --top 6", load("docs/captures/syscall-tracer/03_tracer_live.txt")),
   "shot_tracer_live.png"),
  ("netflow.py — 프로세스별 TCP 연결 실시간 추적",
   prompt("sudo python3 netflow.py --duration 6", load("docs/captures/netflow-tracer/03_netflow_live.txt")),
   "shot_netflow_live.png"),
  ("openat_latency.bt — 파일 열기 지연 히스토그램",
   prompt("sudo bpftrace 04_다양한주제/openat_latency.bt", load("examples/_sample_output/openat_latency.txt")),
   "shot_openat_latency.png"),
  ("runqlat.bt — CPU 대기시간 히스토그램",
   prompt("sudo bpftrace 04_다양한주제/runqlat.bt", load("examples/_sample_output/runqlat.txt")),
   "shot_runqlat.png"),
  ("cpu_profile.bt — CPU 점유 샘플링 프로파일",
   prompt("sudo bpftrace 04_다양한주제/cpu_profile.bt", load("examples/_sample_output/cpu_profile.txt")),
   "shot_cpu_profile.png"),
]
for title, lines, name in jobs:
    sz = render(title, lines, name)
    print(f"  {name}  {sz[0]}x{sz[1]}")
print("done")
