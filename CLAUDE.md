# CLAUDE.md — eBPF·운영체제 교육 프로젝트 (작업 지침 + 전체 계획)

> 이 저장소에서 작업하는 모든 기여자(사람·에이전트)가 따르는 **단일 기준 문서**. 새 세션 시작 시 먼저 읽는다.
> 한 줄 정체성: **"eBPF 실습으로 리눅스 커널·운영체제(OSTEP)를 함께 배우는 교육 과정"**.
> 원격 저장소: https://github.com/iamywl/ebpf-lab

last_updated: 2026-06-12

## 목차
- **[A. 작업 지침]** 1.목적 · 2.디렉터리 · 3.VM · 4.절대규칙 · 5.강의양식 · 6.코드표준 · 7.흐름/Git · 8.금지
- **[B. 전체 계획]** 9.커리큘럼(2과목) · 10.캡처/보강 · 11.현황 · 12.작업순서

---
# A. 작업 지침
---

## 1. 과목의 목적 (가장 중요)

- eBPF 도구를 돌리는 **실습**을 따라가다 보면 **운영체제 개념이 몸에 남게** 한다. "eBPF가 주연, OS가 따라온다."
- 모든 주제는 **3겹**으로: **📖 OSTEP 개념 → ⚙️ 리눅스 커널 구현(소스+개념+그림) → 🔬 eBPF 실측 → 🛠 직접 해보기**.
- 분량이 많으므로 **2개 과목(2학기)**: **과목1=기본(🟢 돌려보기)**, **과목2=심화(🔵 커널 소스)**. (상세 §9)

## 2. 디렉터리 구조

```
ebpf/
├── CLAUDE.md                      ← 본 문서(지침+계획 단일 기준)
├── README.md                      ← VM 사용법부터 실습까지 (입문자용, 그림 포함)
├── projects/                      ← 자기검증 포함 정식 추적기
│   ├── syscall-tracer/            ← tracepoint, PID별 시스템콜 + verify
│   └── netflow-tracer/            ← kprobe tcp_v4_connect, TCP 연결 + verify
├── examples/                      ← 짧고 다양한 예제(bpftrace/BCC) + _sample_output/
├── scripts/                       ← sync-to-vm.sh 등
└── docs/
    ├── 00_환경설정_가이드.md · 10_결과보고서.md · captures/(텍스트 실측)
    └── lecture/                   ← 강의자료(핵심)
        ├── README.md              ← 강의 인덱스(과목·주차·OS 트랙)
        ├── 00a/00b/00c_*.md       ← 입문자 온램프(터미널·C·용어집)
        ├── NN주차_*.md            ← eBPF 정규 주차
        ├── os/                    ← 운영체제 병행 트랙(OSTEP↔eBPF, V/C/P 모듈)
        └── images/ (+ images/os/) ← 강의용 실제 터미널 스크린샷
```
코드는 `projects/`·`examples/`, 문서는 `docs/`. 강의는 `docs/lecture/`. OS 모듈은 `docs/lecture/os/`에 **병행 트랙**(주차에 흡수하지 않고 링크).

## 3. 실행 환경 — 기존 tart VM만

- VM: tart **`ossca-ebpf-work`** (Ubuntu 24.04 / 커널 6.17 / aarch64). **새 VM 생성 금지**(`tart create/clone/pull` ✗).
- 켜기 `tart run ossca-ebpf-work --no-graphics &` → 접속 `ssh ossca-ebpf`(사용자 `ebpf`, passwordless sudo). eBPF는 **항상 `sudo`**.
- 설치됨: BCC(`*-bpfcc` 128종)·bpftrace·libbpf·bpftool·clang·BTF·auditd·gcc·tcpdump·strace·perf.
- 동기화 `scripts/sync-to-vm.sh` → VM `~/ebpf-labs/`. OSTEP 숙제 `~/ostep-homework/`. 데모 `~/ebpf-labs/_demo*/`.

## 4. 절대 규칙

**① 스크린샷·이미지 — 무조건 실제 캡처**
- 이미지는 **실제 터미널 화면을 그대로 캡처**한다. **생성·렌더링(Pillow로 터미널처럼 그리기 등) 절대 금지.**
- 방법: macOS `osascript`로 Terminal에서 명령 실행 → `screencapture -x -o -l<window-id>`(가려져도 정확) → 빈 여백만 크롭(내용 불변).
- 캡션은 정확히 "실제 터미널 화면 캡처". 내용은 VM 실제 실행 결과여야 함(원본 텍스트 `examples/_sample_output/`·`docs/captures/`).

**② 다이어그램 — 학술 논문(figure) 형식**
- 모든 다이어그램은 **논문에 실리는 그림(figure)** 처럼 만든다: **무채색(흰 배경·검은 선·검은 글자)**, serif 글꼴, 군더더기·장식·그림자·색 강조 **없이** 간결하게.
- mermaid 사용 시 각 블록 첫 줄에 **흑백 `%%{init ...}%%` 테마 지시자** 필수(`theme:base` + white/black themeVariables + `fontFamily:"Georgia, serif"`).
- **색으로 의미를 구분하지 않는다** — 형태·라벨·여백·선 종류(실선/점선)로만 구분.
- 그림에는 가능하면 **번호·캡션**(예: `_그림 3. 시스템콜 처리 흐름_`)을 붙여 논문처럼 인용 가능하게 한다.
- **예외: 스크린샷은 실제 터미널 색 그대로**(흑백 변환하지 않음 — 실측 화면이므로).

**③ eBPF 코드 함정**
- bpftrace **맵/식별자는 ASCII만**(`@by_process` ○ / `@한글` ✗ — 렉서가 비ASCII 거부). 한글은 주석·`printf`에만.
- BCC `bpf_trace_printk` 형식문자열은 **ASCII만**(한글 ✗). 한글 출력은 Python 쪽에서.

## 5. 강의 문서 작성 규약

- 한국어(원어 병기 가능). 상단 `last_updated:`. 표 헤더 정렬(`:---`), 코드블록 언어태그, 상대경로 링크.
- **주차 양식**:
  ```
  # [과목N] M주차 — 제목 (OSTEP X장 · eBPF Y)
  > 한 줄 + 🔰 입문자 온램프(용어집·C부록, 🟢/🔵 트랙 안내)
  ## 이번 주 지도 (📖OS개념 ↔ ⚙️커널 ↔ 🔬eBPF) 3열 대조표
  ## 1. <소주제>
     ### 📖 OSTEP에서는      (이론+장+숙제 명령)
     ### ⚙️ 리눅스 커널은     (개념+mermaid 그림 + 실제 소스 발췌: task_struct 필드/CFS 런큐/futex/ext4)
     ### 🔬 eBPF로 관찰      (실제 캡처 + 만든 명령 + 해석)
     ### 🛠 직접 해보기      (🟢 복붙 / 🔵 심화)
  ## 💡 핵심 요약 (3열 대조표)  ## ✅ 자가점검 퀴즈(<details>정답)  ## 📚 더 읽을거리
  ```
- ⚙️ 커널 절 깊이: **과목1=개념·그림 위주(소스 한두 줄)**, **과목2=구조체 필드·함수까지 깊게**.
- 각 절 **굵은 핵심 메시지 1줄**. 무거운 주차 상단 🔰 온램프([용어집](docs/lecture/00c_용어집_약어사전.md)·[C 미니부록](docs/lecture/00b_준비_C언어_미니부록.md)).

## 6. 코드 표준

- **Python**: PEP8(line 100)·타입힌트·`from __future__ import annotations`·bare `except` 금지·`pathlib`.
- **C(BPF)**: 명확 타입(`u32/u64`), 주석은 WHY, 헤더 충돌 시 미사용 인자 `void*`.
- **Shell**: `#!/usr/bin/env bash`+`set -euo pipefail`, `"$var"`. **Markdown**: GFM.

## 7. 작업 흐름 · Git · 정직성

- 개발: 로컬 작성 → `scripts/sync-to-vm.sh` → VM `sudo` 실행 → 동작 확인 → 실제 캡처.
- **"동작한다"는 실측으로 증명**(추적기=자기검증, 강의=실제 화면 캡처). 깨지는 학습용 데모는 `~/ebpf-labs/_demo*/`.
- 큰 분량은 병렬 에이전트로 텍스트 분담, **이미지 캡처는 메인이 직접**.
- 통계·캡처는 실제 결과만. 불확실하면 단정 금지.
- **커밋·푸시는 사용자 요청 시에만.** 보통 "내용 추가 → 검토 → 승인 시 푸시". 커밋 말미:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- 커밋 금지: 빌드 산출물(`workload`/`net_workload`/`__pycache__`). `_sample_output`은 증거이므로 유지.

## 8. 절대 하지 말 것

❌ 이미지 생성/렌더링 후 "캡처"라 표기 · ❌ 새 tart VM 생성 · ❌ bpftrace 맵/`bpf_trace_printk`에 한글 · ❌ 다이어그램에 색(스크린샷 제외) · ❌ 미검증 "완료" 보고 · ❌ 승인 없이 푸시 · ❌ OSTEP↔커널↔eBPF 3겹 형식 누락 · ❌ `docs/lecture/` 밖 강의·`projects/`/`examples/` 밖 코드 산재

---
# B. 전체 계획
---

## 9. 커리큘럼 계획 — 2개 과목

### 9.1 철학
한 주제 = `📖 OSTEP 개념 → ⚙️ 리눅스 커널 구현 → 🔬 eBPF 실측 → 🛠 직접`.
```
📖 OSTEP(왜·무엇) → ⚙️ 커널 구현(소스·자료구조) → 🔬 eBPF 실측(지금 내 시스템)
프로세스/스케줄링/메모리/락/파일 → task_struct/CFS런큐/페이지테이블/futex/ext4 → execsnoop/runqlat/page-faults/futex/biolatency
```
**eBPF가 주연, OS가 따라온다.** 추상 개념을 *직접 돌린 화면*으로 먼저 보고 이해.

### 9.2 학생이 다 알게 하는 원칙
- 선수지식 무가정(0주차 온램프 3종 + 매 주차 🔰). 🟢 돌려보기/🔵 이해 **두 트랙**.
- **전 주차 실측 캡처**(주제당 OSTEP 시뮬 + eBPF 실측). 매주 🛠 미니랩 + 3줄 해석.
- 학기당 2회 누적 체크포인트, 각 절 굵은 핵심 1줄. **3단 깊이**(핵심1줄→대조표→본문): 시간 없으면 앞 둘만.

### 9.3 📘 과목 1 (1학기) — "eBPF로 배우는 운영체제 입문" (🟢 중심, ⚙️ 개념·그림 위주)
| 주 | OS·커널 (OSTEP) | eBPF | 실측 캡처 | 병행 OS모듈 |
|:--:|:--|:--|:--|:--|
| 0 | 준비: 터미널·VM·C·용어 | 환경 | — | — |
| 1 | OS·커널이란, 왜 관찰로 배우나 | eBPF 큰 그림 | hello.bt | — |
| 2 | 커널/사용자 모드·시스템콜 (6장) | 첫 추적 | syscount, strace -c | [V2](docs/lecture/os/V2_제한적직접실행과_시스템콜.md) |
| 3 | 프로세스 fork/exec/exit (4–5장) | execsnoop | execsnoop, exitsnoop | [V1](docs/lecture/os/V1_프로세스와_CPU_API.md) |
| 4 | bpftrace 로 커널 들여다보기 | 원라이너·맵 | opensnoop, syscall_top | — |
| 5 | CPU 스케줄링 기초 (7장) | sched 추적 | scheduler.py + runqlat | [V3](docs/lecture/os/V3_CPU_스케줄링.md) |
| 6 | 가상메모리 기초·페이지폴트 (13·18장) | page-faults | mmap/brk, page-faults | [V4](docs/lecture/os/V4_가상메모리_주소공간_페이징.md) |
| 7 | 스레드·락 기초 (26·28장) | clone·futex | clone, futex, race 실증 | [C1](docs/lecture/os/C1_스레드와_API.md)·[C2](docs/lecture/os/C2_락_동기화_그리고_버그.md) |
| 8 | BCC + **실습① 시스템콜 추적기** | BCC·맵 | verify PASS, tracer | 〔체크포인트〕 |
| 9 | 파일·디렉터리·VFS 기초 (39–40장) | VFS 추적 | opensnoop, vfsstat, statsnoop | [P2](docs/lecture/os/P2_파일시스템과_VFS.md) |
| 10 | 디스크 I/O 기초 (36–37장) | 블록 추적 | biolatency | [P1](docs/lecture/os/P1_IO장치와_디스크.md) |
| 11 | 네트워크 기초 + **실습② TCP 추적기** | kprobe·perf | netflow, tcp_connect | — |
| 12 | 저널링·페이지 캐시 맛보기 (42장) | ext4·캐시 | ext4slower, cachestat | [P3](docs/lecture/os/P3_크래시일관성_저널링_캐시.md) |
| 13 | eBPF 도구 생태계 투어(BCC 128종)+안전성 개요 | 여러 도구 | execsnoop-bpfcc 등 | 〔체크포인트〕 |
| 14 | 종합·복습 + 1학기 미니 프로젝트 | 종합 | bpftool prog show | — |

### 9.4 📕 과목 2 (2학기) — "eBPF 심화: 커널 내부와 프로덕션" (🔵 중심, ⚙️ 소스 깊게)
| 주 | OS·커널 심화 (OSTEP) | eBPF·커널 내부 | 실측 캡처 |
|:--:|:--|:--|:--|
| 1 | eBPF 아키텍처 심화: 검증기·JIT·맵 내부 | 바이트코드·verifier 로그 | **검증기 거부**, prog dump |
| 2 | 프로그램 타입·부착지점 전체 | kprobe/uprobe/USDT/XDP/LSM | bpftrace -l, prog type |
| 3 | BTF·CO-RE·libbpf (프로덕션) | 스켈레톤·ringbuf | btf dump(task_struct) |
| 4 | ⚙️ 프로세스의 커널 표현 (6장 심화) | task_struct 필드 추적 | task_struct 필드 bpftrace |
| 5 | CPU 스케줄링 심화: CFS/EEVDF·MLFQ·추첨 (8–10장) | 런큐 소스·sched_switch | runqlat, cpudist, runqlen |
| 6 | 가상메모리 심화: 페이지테이블·TLB·교체정책 (15–22장) | mm 소스·폴트 핸들러 | page-faults, vmscan |
| 7 | 병행성 심화: CV·세마포어·버그·futex 내부 (29–33장) | futex 커널 경로 | offcputime, futex |
| 8 | 파일시스템 심화: inode·FFS·디렉터리 (39–41장) | VFS·inode 소스 | vfsstat, statsnoop, filetop |
| 9 | 크래시 일관성·저널링·LFS (42–43장) | ext4 jbd2 저널 | ext4slower, biosnoop |
| 10 | 네트워킹 심화: XDP/tc·Cilium | 패킷 경로·sk_buff | bpftool net, tcpstates, tcplife |
| 11 | 보안 심화: seccomp·LSM·Falco·Tetragon | LSM 훅·탐지 | capable-bpfcc, execsnoop |
| 12 | 관측·성능 심화: 프로파일링·플레임그래프·USDT | perf_event·스택 | profile, offcputime |
| 13 | eBPF 직접 제작 심화(libbpf 스켈레톤) | C·빌드 | 직접 만든 프로그램 로드 |
| 14 | 안전성·한계·미래(sched_ext 등) | 종합 | bpftool feature probe |
| 15 | 기말 프로젝트 발표 | 종합 설계 | 학생 산출물 |

### 9.5 OS 병행 트랙 (os/ 모듈 ↔ OSTEP ↔ eBPF) — 이미 제작됨
| 모듈 | OSTEP 장 | eBPF 실측 |
|:--|:--|:--|
| [V1 프로세스·CPU API](docs/lecture/os/V1_프로세스와_CPU_API.md) | 4–5 | execsnoop, exitsnoop |
| [V2 시스템콜·LDE](docs/lecture/os/V2_제한적직접실행과_시스템콜.md) | 6 | syscount, strace -c |
| [V3 CPU 스케줄링](docs/lecture/os/V3_CPU_스케줄링.md) | 7–10 | runqlat, cpudist + scheduler.py |
| [V4 가상메모리](docs/lecture/os/V4_가상메모리_주소공간_페이징.md) | 13–22 | mmap/brk, page-faults, cachestat |
| [C1 스레드](docs/lecture/os/C1_스레드와_API.md) | 26–27 | clone() |
| [C2 락·동기화·버그](docs/lecture/os/C2_락_동기화_그리고_버그.md) | 28–33 | futex, race.c 실증 |
| [P1 디스크 I/O](docs/lecture/os/P1_IO장치와_디스크.md) | 36–38 | biolatency, biosnoop |
| [P2 파일시스템·VFS](docs/lecture/os/P2_파일시스템과_VFS.md) | 39–41 | vfsstat, statsnoop |
| [P3 저널링·캐시](docs/lecture/os/P3_크래시일관성_저널링_캐시.md) | 42–43 | ext4slower, cachestat |
> 각 모듈은 🟢(돌려보기)/🔵(심화 커널 소스) 두 트랙으로 보강 예정. 과목1은 🟢, 과목2는 🔵 부분 사용.

### 9.6 분량 소화 레버
2개 과목 분리(1차) · 3단 깊이 · 두 트랙 라벨 · 누적 체크포인트 · 부별 치트시트 · 실측 우선.

## 10. 캡처·보강 계획

### 10.1 스샷 전 주차화 (현재 0인 주차 해소) — 캡처할 명령
| 주차/모듈 | 추가 캡처(실제 명령) |
|:--|:--|
| 과목1-2 / 과목2-4 | `strace -c ls`, `ps -eLf`, `syscount-bpfcc` |
| 역사(과목2-1 주변) | `sudo tcpdump -d 'tcp port 22'` ← **고전 cBPF 바이트코드** |
| 과목2-1 아키텍처 | `bpftool prog show`, `bpftool map show`, **검증기 거부**(NULL 검사 뺀 BCC 로드→verifier 에러) |
| 과목2-2 타입 | `bpftrace -l 'tracepoint:syscalls:*' \| head`, `bpftrace -l 'kprobe:*' \| wc -l` |
| 과목2-3 BTF | `bpftool btf dump file /sys/kernel/btf/vmlinux format c \| head`, `bpftool btf list` |
| BCC 입문/생태계 | `hello_bcc.py`, `ls /usr/sbin/*-bpfcc \| wc -l`, `opensnoop-bpfcc` |
| 보안/관측(과목2-11·12) | `execsnoop-bpfcc`, `biolatency-bpfcc`, `tcplife-bpfcc`, `capable-bpfcc` |
| examples/README | 나머지 예제 캡처(hello_bcc·killsnoop·tcp_accept·socket_count·tcp_retransmit·vfs_read_bytes·pagefaults) |
> 목표: 스샷 0 주차 0개. 모든 캡처는 **실제 터미널**(§4①). 톤은 실제 색 유지.

### 10.2 캡처 자원 (VM 실측 확인됨)
- `bpftool`(prog/map/btf/net) · `tcpdump -d`(cBPF 덤프) · `strace -c` · `perf` · `ss`/`ip`
- **BCC 도구 128종**(`/usr/sbin/*-bpfcc`): execsnoop/opensnoop/biolatency/tcplife/runqlat/cpudist/funccount/profile/capable/statsnoop/vfsstat/ext4slower …

### 10.3 OSTEP 숙제 매핑 (VM `~/ostep-homework/`)
cpu-intro·cpu-api·cpu-sched(·mlfq·lottery·multi) / vm-mechanism·vm-paging·vm-smalltables·vm-beyondphys(mem.c 실코드)·vm-beyondphys-policy / threads-intro·threads-api(main-race.c)·threads-locks·threads-cv·threads-sema·threads-bugs / file-disks·file-raid·file-implementation·file-ffs·file-journaling·file-lfs·file-ssd·file-integrity.
> 데모 보강: `race.c`/`threads_lock.c`(OSTEP main-race 확장, `-O0` 빌드해야 레이스 보임)·`mem.c`.

## 11. 현황 (2026-06-12)

**제작 완료(로컬, 일부 푸시됨)**
- eBPF 정규 15주차 + 강의 인덱스 + 온램프 3종(터미널·C·용어집)
- OS 병행 트랙 9모듈(os/, OSTEP↔eBPF) + OS 캡처 14장
- 정식 추적기 2종(자기검증) + 예제 15종(_sample_output) + 강의 실제 캡처 다수
- 다이어그램 흑백화 완료, README(VM 사용법) 완비

**대기/진행 예정**
- 2개 과목 구조로 재배치 + ⚙️ 커널 절(소스+그림) 신설 + 스샷 0 주차 해소(§10.1)
- os/ 모듈 🟢/🔵 두 트랙 보강

## 12. 작업 순서 (승인 시)
1. 통합 양식 확정(⚙️ 커널 절·치트시트·체크포인트·🟢/🔵 라벨).
2. **과목1 완성**(0~14주): 기존 주차 재배치 + ⚙️ 커널 절(개념·그림) + 전 주차 실측 캡처.
3. os/ 모듈 🟢/🔵 트랙 보강(병행 트랙 유지).
4. **과목2 완성**(1~15주): 커널 소스 깊이(task_struct·CFS·futex·ext4) + 생태계 + 기말.
5. QA(링크·펜스·이미지)·검토 → 승인 시 푸시.
> 예상 규모: 과목1 ≈ +1,500줄·캡처 30장+, 과목2 ≈ +2,000줄·캡처 30장+ (총 캡처 60장+).

---
*이 문서는 프로젝트의 단일 기준이다. 계획·규칙이 바뀌면 여기서 갱신하고 `last_updated`만 바꾼다.*
