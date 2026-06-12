# 운영체제 관찰 트랙 — OSTEP를 eBPF로 직접 본다

> 교재 **OSTEP(Operating Systems: Three Easy Pieces, 한국어판)** 의 세 기둥(가상화·병행성·영속성)을,
> 책의 그림·시뮬레이션으로 끝내지 않고 **돌아가는 리눅스 커널을 eBPF로 실시간 관찰**하며 배운다.
> 형식: 각 주제마다 **📖 OSTEP에서는 …** → **🔬 eBPF로는(실측) …**.

last_updated: 2026-06-12

> 모든 스크린샷은 실습 VM(Ubuntu 24.04 / 커널 6.17)에서 **실제 터미널을 캡처**한 것이다(생성·합성 아님).
> 참고 교재: [OSTEP 한국어판](https://pages.cs.wisc.edu/~remzi/OSTEP/Korean/) · 숙제: [ostep-homework](https://github.com/remzi-arpacidusseau/ostep-homework)

---

## 이 트랙을 왜 보나

OSTEP는 OS의 핵심을 "가상화 → 병행성 → 영속성" 세 조각으로 가르친다. 그런데 책의 많은 부분은
**시뮬레이터(파이썬 숙제)** 로 개념을 익힌다. eBPF는 그 개념이 **내 컴퓨터에서 실제로 일어나는 순간**을
숫자·히스토그램·로그로 보여준다. 그래서 우리는 **OSTEP로 개념을 잡고 → eBPF로 실물을 확인**한다.

```
OSTEP 시뮬레이션(이론)  ┐
                        ├──→  같은 개념을  ──→  eBPF 실측(실제 커널)
교과서 그림·모델        ┘
```

## 모듈 지도 (OSTEP 3부 ↔ eBPF)

### 1부. 가상화 (Virtualization) — OSTEP 4–24장
| 모듈 | OSTEP 장 | 핵심 개념 | eBPF 실측 도구 |
|:---|:---|:---|:---|
| [V1 · 프로세스와 CPU API](V1_프로세스와_CPU_API.md) | 4–5 | 프로세스, fork/exec/wait | `execsnoop` `exitsnoop` |
| [V2 · 제한적 직접 실행과 시스템콜](V2_제한적직접실행과_시스템콜.md) | 6 | 모드 전환·트랩·시스템콜 | `syscount` `strace -c` |
| [V3 · CPU 스케줄링](V3_CPU_스케줄링.md) | 7–10 | 런큐·컨텍스트 스위치·MLFQ | `runqlat` `cpudist` + OSTEP `scheduler.py` |
| [V4 · 가상메모리·주소공간·페이징](V4_가상메모리_주소공간_페이징.md) | 13–22 | 주소공간·페이지·TLB·교체 | `mmap/brk` 추적 `page-faults` `cachestat` |

### 2부. 병행성 (Concurrency) — OSTEP 25–34장
| 모듈 | OSTEP 장 | 핵심 개념 | eBPF 실측 도구 |
|:---|:---|:---|:---|
| [C1 · 스레드와 API](C1_스레드와_API.md) | 26–27 | 스레드=clone, 주소공간 공유 | `clone()` 추적 |
| [C2 · 락·동기화·병행성 버그](C2_락_동기화_그리고_버그.md) | 28–33 | 락·CV·세마포어·데이터 레이스 | `futex` 추적, `race.c` 실증 |

### 3부. 영속성 (Persistence) — OSTEP 35–50장
| 모듈 | OSTEP 장 | 핵심 개념 | eBPF 실측 도구 |
|:---|:---|:---|:---|
| [P1 · I/O 장치와 디스크](P1_IO장치와_디스크.md) | 36–38 | 디스크 접근시간·I/O 큐·RAID | `biolatency` `biosnoop` |
| [P2 · 파일시스템과 VFS](P2_파일시스템과_VFS.md) | 39–41 | 파일·inode·VFS·FFS | `vfsstat` `statsnoop` `opensnoop` |
| [P3 · 크래시 일관성·저널링·캐시](P3_크래시일관성_저널링_캐시.md) | 42–43 | 저널링·LFS·페이지 캐시 | `ext4slower` `cachestat` |

## 권장 학습 순서

1. 정규 강의 [2주차(커널·시스템콜)](../02주차_리눅스_커널과_사용자공간_시스템콜.md)·[7주차(bpftrace)](../07주차_bpftrace_입문.md)로 도구에 익숙해진 뒤,
2. 이 트랙을 **V1 → … → P3** 순서로(=OSTEP 순서) 따라가며, 각 모듈의 🛠 직접 해보기를 VM에서 실행한다.
3. OSTEP 숙제(`~/ostep-homework/`)의 시뮬레이션도 함께 돌려 "이론 ↔ 실측"을 대조한다.

## OSTEP 숙제 환경 (VM에 준비됨)

```bash
ssh ossca-ebpf
ls ~/ostep-homework            # cpu-sched, vm-paging, threads-locks, file-disks ...
# 예) 라운드로빈 스케줄링 시뮬레이션
python3 ~/ostep-homework/cpu-sched/scheduler.py -p RR -q 1 -l 5,5,5 -c
```

> 입문자는 [용어집](../00c_용어집_약어사전.md)·[C 미니부록](../00b_준비_C언어_미니부록.md)을 곁에 두세요.
