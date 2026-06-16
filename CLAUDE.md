# CLAUDE.md — eBPF·운영체제 교육 프로젝트 (작업 지침 + 전체 계획)

> 이 저장소에서 작업하는 모든 기여자(사람·에이전트)가 따르는 **단일 기준 문서**다. 새 세션 시작 시 먼저 읽는다.
> 한 줄 정체성: **"eBPF 실습으로 리눅스 커널·운영체제(OSTEP)를 함께 배우는 교육 과정"**.
> 강의자료는 그림·설명이 아니라 **로컬 tart VM에서 직접 실행·캡처한 실측 화면**을 전제로 한다.
> 원격 저장소: https://github.com/iamywl/ebpf-lab

last_updated: 2026-06-16

## 목차
- **[A. 작업 지침]** 1.목적 · 2.디렉터리 · 3.VM · 4.절대규칙 · 5.문서양식 · 6.코드표준 · 7.흐름/Git · 8.금지
- **[B. 전체 계획]** 9.커리큘럼(2과목) · 10.캡처/보강 · 11.현황 · 12.작업순서

---
# A. 작업 지침
---

## 1. 과목의 목적 (가장 중요)

- eBPF 도구를 돌리는 **실습**을 따라가다 보면 **운영체제 개념이 몸에 남게** 한다. "eBPF가 주연, OS가 따라온다."
- 모든 주제는 **4겹**으로 다룬다. 단순히 "이렇게 한다"가 아니라 **왜 이게 나왔는지의 이야기**부터 시작한다(§4④ 스토리라인).

  **📖 등장 배경·개념(OSTEP) → ⚙️ 리눅스 커널 구현(소스+그림) → 🔬 eBPF 실측(실제 캡처) → 🛠 직접 해보기**

  - **📖 등장 배경·개념**: 이 개념/도구가 없던 시절 무엇이 문제였나(구체적 고통) → 직전 방식(예: `/proc` 폴링, `strace`, 커널 모듈)의 한계 → OSTEP의 추상 개념 → 무엇이 나아졌나.
  - **⚙️ 커널 구현**: 추상 개념이 커널 안에서 어떤 자료구조·코드로 실현되나(`task_struct`·CFS 런큐·futex·ext4) + 흑백 다이어그램.
  - **🔬 eBPF 실측**: 지금 내 VM에서 실제로 돌린 `bpftrace`/BCC 출력(실제 터미널 캡처) + 해석.
  - **🛠 직접 해보기**: 복붙으로 끝나는 🟢 미니랩 + 한 걸음 더 가는 🔵 심화.
- 분량이 많으므로 **2개 과목(2학기)**으로 나눈다: **과목1=기본(🟢 돌려보기)**, **과목2=심화(🔵 커널 소스)**. (상세 §9)

## 2. 디렉터리 구조

```
ebpf/
├── CLAUDE.md                      ← 본 문서(지침+계획 단일 기준)
├── README.md                      ← VM 사용법부터 실습까지 (입문자용, 그림 포함)
├── projects/                      ← 자기검증 포함 정식 추적기
│   ├── syscall-tracer/            ← tracepoint, PID별 시스템콜 + verify
│   └── netflow-tracer/            ← kprobe tcp_v4_connect, TCP 연결 + verify
├── examples/                      ← 짧고 다양한 예제(bpftrace/BCC) + _sample_output/
├── labs/                          ← 제대로 된 BCC 도구 14종 + 08_고급(libbpf·XDP·uprobe·USDT·ringbuf)
├── scripts/                       ← sync-to-vm.sh 등
└── docs/
    ├── 00_환경설정_가이드.md · 10_결과보고서.md · captures/(텍스트 실측)
    └── lecture/                   ← 강의자료(핵심)
        ├── README.md              ← 강의 인덱스(과목·주차·OS 트랙·평가·루브릭)
        ├── 과목1_1학기_기본.md · 과목2_2학기_심화.md ← 실러버스
        ├── 00a/00b/00c_*.md       ← 입문자 온램프(터미널·C·용어집)
        ├── NN주차_*.md            ← eBPF 정규 주차(전부 🧭 동선 박스 보유)
        ├── os/                    ← 운영체제 병행 트랙(OSTEP↔eBPF, V/C/P 모듈)
        └── images/ (+ images/os/, images/more/, images/labs/) ← 강의용 실제 터미널 스크린샷
```
코드는 `projects/`·`examples/`·`labs/`, 문서는 `docs/`. 강의는 `docs/lecture/`. OS 모듈은 `docs/lecture/os/`에 **병행 트랙**으로 둔다(주차에 흡수하지 않고 링크). 기술 자체의 깊은 설명이 필요하면 한 곳에 쓰고 나머지는 링크한다(중복 작성 금지).

## 3. 실행 환경 — 기존 tart VM만

- VM: tart **`ossca-ebpf-work`** (Ubuntu 24.04 / 커널 6.17 / aarch64). **새 VM 생성 금지**(`tart create/clone/pull` ✗).
- 켜기 `tart run ossca-ebpf-work --no-graphics &` → 접속 `ssh ossca-ebpf`(사용자 `ebpf`, passwordless sudo). eBPF는 **항상 `sudo`**.
- 설치됨: BCC(`*-bpfcc` 128종)·bpftrace·libbpf·bpftool·clang·BTF·auditd·gcc·tcpdump·strace·perf.
- 동기화 `scripts/sync-to-vm.sh` → VM `~/ebpf-labs/`. OSTEP 숙제 `~/ostep-homework/`. 데모 `~/ebpf-labs/_demo*/`.
- 클러스터/VM이 꺼져 캡처가 불가능하면 출력을 지어내지 말고 작업을 멈추거나 "(미캡처)"로 명시한다(§7 정직성).

## 4. 절대 규칙

**① 스크린샷·이미지 — 무조건 실제 캡처**
- 이미지는 **실제 터미널 화면을 그대로 캡처**한다. **생성·렌더링(Pillow로 터미널처럼 그리기 등) 절대 금지.**
- 캡션은 정확히 "실제 터미널 화면 캡처". 내용은 VM 실제 실행 결과여야 한다(원본 텍스트 `examples/_sample_output/`·`docs/captures/`).
- **메인이 직접** 캡처한다(서브에이전트 ✗ — GUI 자동화·화면 녹화 권한 필요). **검증된 표준 절차**(2026-06-12 동작 확인):
  1. **텍스트 증거 먼저**: `ssh ossca-ebpf "<cmd>"` 출력을 `examples/_sample_output/`·`docs/captures/`에 저장한다(스샷과 내용 일치 보증).
  2. **Terminal에서 실행 + 창 크기 키우기**(출력 전부 보이게): osascript로 새 창에 `do script "clear; ssh ossca-ebpf \"<cmd>\"; echo; echo '[VM ossca-ebpf - kernel 6.17] <영문 캡션>'"` → `delay 5` → `set bounds of front window to {80,80,800,660}`. *캡션·echo는 영문/ASCII 권장*(터미널 폰트 깨짐 방지). bpftrace 맵 한글 금지 규칙(③)도 그대로 적용한다.
  3. **창 영역 캡처**: `B=$(osascript -e 'tell application "Terminal" to get bounds of front window')` 로 `{x1,y1,x2,y2}`(points) 취득 → `screencapture -x -o -R$x1,$y1,$((x2-x1)),$((y2-y1)) out.png`. Retina면 출력 px는 2배다(정상).
  4. **반드시 Read로 검증**: 캡처한 `out.png`를 Read 도구로 열어 **검은 화면·잘림이 아닌 실제 출력**인지 눈으로 확인한다. 잘리면 창을 더 키워 재캡처한다.
  5. **빈 여백만 크롭**(내용 불변) → `docs/lecture/images/...`에 배치 → 강의에 `![... (실제 터미널 캡처)](상대경로.png)`로 임베드 → 임시파일·열어둔 창 정리.
  > 가려진(occluded) 창까지 잡는 `screencapture -l<CGWindowID>` 는 CGWindowID가 필요한데 기본 `python3`에 `Quartz`(pyobjc)가 없어 이 환경에선 불가하다 → **영역(`-R`) 캡처가 기본**이다. 캡처 순간만 창을 앞면(`activate`)에 두면 된다.
  > ⚠️ **중복 금지**: 캡처 전 대상 주차 파일에 이미 같은 스샷(`grep '\.png'`)이 있는지 확인한다. §10.1 캡처 계획은 이미 완료되어 전 강의 파일이 실측 스샷을 보유한다 — 새로 만들지 않는다.

**② 다이어그램 — 학술 논문(figure) 형식, mermaid 흑백이 표준**
- 개념·아키텍처·흐름·관계 그림은 **반드시 mermaid**로 그린다. **ASCII 박스 다이어그램 금지**(한글은 더블폭이라 테두리가 어긋나 깨진다). 예외: 디렉터리 트리·표는 ASCII 그대로 둔다(그림이 아니다).
- 모든 mermaid 블록 첫 줄에 **흑백 `%%{init ...}%%` 테마 지시자** 필수(`theme:base` + white/black themeVariables + `fontFamily:"Georgia, serif"`). 저장소의 기존 블록과 동일한 지시자를 복사해 쓴다.
- **무채색만**(흰 배경·검은 선·검은 글자). **색으로 의미를 구분하지 않는다** — 형태(`[]`/`()`/`{}`)·라벨·여백·선 종류(실선/점선)로만 구분한다. `style ... fill:#색` 금지.
- 그림 바로 아래에 **번호·캡션** `_그림 N. 제목._` 을 붙여 논문처럼 인용 가능하게 한다.
- **예외: 스크린샷은 실제 터미널 색 그대로** 둔다(흑백 변환하지 않음 — 실측 화면이므로).

**③ eBPF 코드 함정**
- bpftrace **맵/식별자는 ASCII만**(`@by_process` ○ / `@한글` ✗ — 렉서가 비ASCII를 거부). 한글은 주석·`printf`에만 쓴다.
- BCC `bpf_trace_printk` 형식문자열은 **ASCII만**(한글 ✗). 한글 출력은 Python 쪽에서 한다.

**④ 독자 = 학부 3~4학년. "이 강의자료만 읽고 이해·실습·설명할 수 있다"가 기준**
- **검토 기준(완성 후 필수 self-review)**: 컴퓨터공학 3~4학년이 *사전지식 없이* 이 문서만 읽고 ⓐ 개념을 이해하고 ⓑ 실습을 따라 재현하고 ⓒ "이 개념이 왜·어떻게 동작하나"를 스스로 설명할 수 있는가? 못 한다면 미완성이다. 각 주차/모듈 작성 후 이 관점으로 다시 읽고 막히는 지점(용어 비약·맥락 누락·점프)을 메운다.
- **스토리라인 필수** — 모든 기술 주제는 "그냥 이렇게 한다"가 아니라 **왜 이게 나왔는지의 이야기**로 푼다. 최소 4요소를 명시한다:
  1. **등장 배경** — 이 개념/도구가 없던 시절 무엇이 문제였나(구체적 고통 사례. 예: "프로세스가 죽은 뒤 `/proc`로는 이름을 알 수 없다").
  2. **직전 기술과의 차이** — 직전 해결책(예: 커널 모듈, `strace`, `/proc` 폴링, O(1) 스케줄러)은 무엇이었고 어떤 한계가 있었나.
  3. **무엇이 나아졌나** — 새 기술(예: eBPF 검증기·맵, CFS, futex)이 그 한계를 *어떻게* 넘었나(메커니즘 수준).
  4. **트레이드오프** — 공짜는 없다. 새로 생긴 비용·제약·주의점(예: 검증기 보수성, 모드 전환 비용, 맵 메모리).
- **쉬운 이해 우선** — 어려운 개념은 ⓐ 한 문장 직관(비유 가능, 단 §5의 마케팅 표현은 금지) → ⓑ 정확한 정의 → ⓒ 내부 동작 순으로 쓴다. 용어는 **첫 등장 시 한 줄 풀이**. 큰 그림(흑백 다이어그램) 먼저, 디테일은 나중에.
- **흐름의 연속성** — 각 주차/절은 직전 무엇을 전제하는지, 이 주제가 과목 어디에 속하는지 첫머리에 한 줄로 밝힌다(🧭 동선 박스가 이 역할을 한다). 고립된 토막 지식 금지.

## 5. 문서 작성 규약

작성 스타일은 다음 규칙을 **모든 문서에 동일 적용**한다(사용자 확정 피드백).

1. **문체는 "~이다/한다/된다" 평서체.** 경어체("~합니다/해요") 사용 금지. (기존 경어체 문서는 §11·12 계획에 따라 점진 전환한다.)
2. **공학적 표현만.** "강력한", "마법처럼", "핵심 열쇠" 같은 문학적·마케팅 표현 금지. 동작·수치·메커니즘으로 말한다.
3. **깊이 확보.** 표면 설명 금지 — 내부 동작 메커니즘, 커널/OS 레벨 원리, 장애 시나리오, 트러블슈팅을 포함한다.
4. **실습 검증 필수.** 모든 개념/예제에 검증 명령어 + **실제 터미널 스크린샷 이미지**(§4①)를 붙인다. 출력을 지어내지 않는다.
5. **등장 배경 + 스토리라인 명시.** 각 기법이 왜 등장했는지, 직전 기술의 한계, 무엇이 나아졌는지, 트레이드오프를 이야기로 풀어 쓴다(§4④).
6. **학부 3~4학년 가독성.** 사전지식 없는 독자가 막히지 않도록 용어 첫 등장 풀이·직관 먼저·흐름 연속성을 지킨다(§4④). 작성 후 그 관점으로 재검토한다.

형식: 한국어(원어 병기 가능). 상단 `last_updated:` + 🧭 동선 박스. 표 헤더 정렬(`:---`), 코드블록 언어태그, 상대경로 링크.

- **주차 양식**:
  ```
  # M주차 — 제목 (OSTEP X장 · eBPF Y)
  > 한 줄 정체성
  last_updated:
  > 🧭 이번 주 동선 (📘과목1 N주차 · 📕과목2 M주차 · 실습 · OS모듈 · 이전/인덱스/다음)   ← 흐름 연속성(§4④)
  > 🔰 입문자 온램프(용어집·C부록 링크, 🟢/🔵 트랙 안내)
  ## 이번 주 학습 목표 (체크리스트)
  ## 이번 주 지도 (📖개념 ↔ ⚙️커널 ↔ 🔬eBPF 3열 대조표)
  ## 1. <소주제>
     ### 📖 등장 배경·개념     (왜 생겼나 · 직전 기술 한계 · 무엇이 나아졌나 · 트레이드오프 + OSTEP 장·숙제, §4④)
     ### ⚙️ 리눅스 커널은       (개념+mermaid 흑백 그림 + 실제 소스 발췌: task_struct·CFS·futex·ext4, 용어 첫등장 풀이)
     ### 🔬 eBPF로 관찰        (실제 캡처 + 만든 명령 + 해석)
     ### 🛠 직접 해보기        (🟢 복붙 미니랩 / 🔵 심화)
     ### 트러블슈팅           (흔한 실패 + 원인 + 복구) — 무거운 주차에 권장
  ## 💡 핵심 요약 (3열 대조표)  ## ✅ 자가점검 퀴즈(<details>정답)  ## 📚 더 읽을거리
  ```
- ⚙️ 커널 절 깊이: **과목1=개념·그림 위주(소스 한두 줄)**, **과목2=구조체 필드·함수까지 깊게**.
- 각 절 **굵은 핵심 메시지 1줄**. 무거운 주차 상단에 🔰 온램프([용어집](docs/lecture/00c_용어집_약어사전.md)·[C 미니부록](docs/lecture/00b_준비_C언어_미니부록.md))를 단다.

## 6. 코드 표준

- **Python**: PEP8(line 100)·타입힌트·`from __future__ import annotations`·bare `except` 금지·`pathlib`.
- **C(BPF)**: 명확 타입(`u32/u64`), 주석은 WHY, 헤더 충돌 시 미사용 인자 `void*`.
- **Shell**: `#!/usr/bin/env bash`+`set -euo pipefail`, `"$var"`. **YAML/매니페스트는 없음**(이 과정은 커널·eBPF). **Markdown**: GFM, 상대경로 링크.
- 매니페스트·예제를 싣기 전 실제 VM에서 `sudo` 실행으로 검증한 것만 싣는다.

## 7. 작업 흐름 · Git · 정직성

- 개발: 로컬 작성 → `scripts/sync-to-vm.sh` → VM `sudo` 실행 → 동작 확인 → 실제 캡처(§4①).
- **"동작한다"는 실측으로 증명한다**(추적기=자기검증, 강의=실제 화면 캡처). 깨지는 학습용 데모는 `~/ebpf-labs/_demo*/`에 둔다.
- **스크린샷 캡처는 메인이 직접** 수행한다(§4①, 서브에이전트 불가). 큰 분량의 **텍스트**는 병렬 에이전트로 분담하되, **VM 실측·캡처·검증은 메인 컨텍스트에서 직접** 한다(에이전트 타임아웃·환경 차이 방지).
- 한 번에 파일 전체를 Write로 쓰려다 타임아웃 난 전례가 있으므로 **큰 파일은 Read → 섹션별 Edit로 분할 처리**한다. 에이전트 프롬프트에는 "분량 상한·기존 구조 유지·실측 출력은 비워두고 메인이 채움"을 명시한다.
- 통계·캡처는 실제 결과만 쓴다. 불확실하면 단정하지 말고 "(미실측)"으로 표기한다.
- **커밋·푸시는 사용자 요청 시에만.** 보통 "내용 추가 → 검토 → 승인 시 푸시". 커밋 말미:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- 커밋 금지: 빌드 산출물(`workload`/`net_workload`/`__pycache__`). `_sample_output`은 증거이므로 유지한다.

## 8. 절대 하지 말 것

❌ 이미지 생성/렌더링 후 "캡처"라 표기 · ❌ 새 tart VM 생성 · ❌ bpftrace 맵/`bpf_trace_printk`에 한글 · ❌ 다이어그램에 색(스크린샷 제외)·ASCII 박스 그림 · ❌ **경어체·문학적/마케팅 표현**(§5) · ❌ **등장 배경·스토리(직전 기술 비교·개선점·트레이드오프) 누락**(§4④) · ❌ **사전지식 가정한 용어 비약**(학부생이 못 읽음, §4④) · ❌ 검증 명령/실측 캡처 없는 개념 서술 · ❌ 미검증 "완료" 보고 · ❌ 승인 없이 푸시 · ❌ OSTEP↔커널↔eBPF 4겹 형식 누락 · ❌ `docs/lecture/` 밖 강의·`projects/`/`examples/`/`labs/` 밖 코드 산재

---
# B. 전체 계획
---

## 9. 커리큘럼 계획 — 2개 과목

### 9.1 철학
한 주제 = `📖 등장 배경·개념(OSTEP) → ⚙️ 리눅스 커널 구현 → 🔬 eBPF 실측 → 🛠 직접`.
```
📖 왜 생겼나·직전 기술 한계·OSTEP 개념 → ⚙️ 커널 구현(소스·자료구조) → 🔬 eBPF 실측(지금 내 시스템)
프로세스/스케줄링/메모리/락/파일 → task_struct/CFS런큐/페이지테이블/futex/ext4 → execsnoop/runqlat/page-faults/futex/biolatency
```
**eBPF가 주연, OS가 따라온다.** 추상 개념을 *왜 생겼는지의 이야기*와 *직접 돌린 화면*으로 먼저 보고 이해한다.

### 9.2 학생이 다 알게 하는 원칙
- 선수지식 무가정(0주차 온램프 3종 + 매 주차 🔰). 🟢 돌려보기/🔵 이해 **두 트랙**.
- **전 주차 실측 캡처**(주제당 OSTEP 시뮬 + eBPF 실측). 매주 🛠 미니랩 + 3줄 해석.
- 학기당 2회 누적 체크포인트, 각 절 굵은 핵심 1줄. **3단 깊이**(핵심1줄→대조표→본문): 시간 없으면 앞 둘만.
- **완성 후 학부 3~4학년 관점 재검토**(§4④)로 스토리라인 연속성·용어 비약을 점검한다.

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
| [C3 조건변수·세마포어](docs/lecture/os/C3_조건변수_세마포어_이벤트기반.md) | 29–31 | epoll, cvsem |
| [P1 디스크 I/O](docs/lecture/os/P1_IO장치와_디스크.md) | 36–38 | biolatency, biosnoop |
| [P2 파일시스템·VFS](docs/lecture/os/P2_파일시스템과_VFS.md) | 39–41 | vfsstat, statsnoop |
| [P3 저널링·캐시](docs/lecture/os/P3_크래시일관성_저널링_캐시.md) | 42–43 | ext4slower, cachestat |
> 각 모듈은 🟢(돌려보기)/🔵(심화 커널 소스) 두 트랙으로 보강한다. 과목1은 🟢, 과목2는 🔵 부분을 쓴다. 전 모듈에 🧭 "이 모듈을 보는 시점" 박스가 있다.

### 9.6 분량 소화 레버
2개 과목 분리(1차) · 3단 깊이 · 두 트랙 라벨 · 누적 체크포인트 · 부별 치트시트 · 실측 우선.

## 10. 캡처·보강 계획

### 10.1 스샷 전 주차화 — **완료**
모든 정규 주차(15) + OS 모듈(10)이 실제 터미널 캡처를 1장 이상 보유한다(총 53장+). §10.1의 명령별 캡처 계획(`strace -c`, `tcpdump -d` cBPF, `bpftool prog/map/btf`, 검증기 거부, BCC 도구 등)은 이미 실행되었다. **신규 캡처는 §4① 중복 금지 규칙에 따라 기존 보유 여부를 먼저 확인**한다.

### 10.2 캡처 자원 (VM 실측 확인됨)
- `bpftool`(prog/map/btf/net) · `tcpdump -d`(cBPF 덤프) · `strace -c` · `perf` · `ss`/`ip`
- **BCC 도구 128종**(`/usr/sbin/*-bpfcc`): execsnoop/opensnoop/biolatency/tcplife/runqlat/cpudist/funccount/profile/capable/statsnoop/vfsstat/ext4slower …

### 10.3 OSTEP 숙제 매핑 (VM `~/ostep-homework/`)
cpu-intro·cpu-api·cpu-sched(·mlfq·lottery·multi) / vm-mechanism·vm-paging·vm-smalltables·vm-beyondphys(mem.c 실코드)·vm-beyondphys-policy / threads-intro·threads-api(main-race.c)·threads-locks·threads-cv·threads-sema·threads-bugs / file-disks·file-raid·file-implementation·file-ffs·file-journaling·file-lfs·file-ssd·file-integrity.

## 11. 현황 (2026-06-16)

**제작 완료(푸시됨)**
- eBPF 정규 15주차 + 강의 인덱스 + 온램프 3종(터미널·C·용어집).
- OS 병행 트랙 10모듈(os/, OSTEP↔eBPF) + OS 캡처 14장.
- 정식 추적기 2종(자기검증) + 예제 15종(_sample_output) + labs 14종 + 고급 5종.
- 다이어그램 흑백화, README(VM 사용법) 완비, 실측 캡처 53장+.
- **길찾기 개편**: 전 주차/OS모듈에 🧭 동선 박스, 02·04주차 신규 다이어그램, 수업운영(과제 제출·기말 30점 루브릭·labs 합격기준).

**대기/진행 예정 — 본 개정(§5 평서체 + §4④ 스토리라인)에 따른 보강**
- **문체 전환**: 기존 강의 50여 문서가 경어체다 → 평서체("~이다/한다")로 점진 전환(§5-1).
- **스토리라인 보강**: 각 주차 📖 절에 4요소(등장 배경·직전 기술 한계·개선·트레이드오프)가 명시됐는지 점검·보강(§4④).
- **학부생 가독성 재검토**: 용어 첫 등장 풀이·직관 먼저·점프 제거(§4④ self-review).

## 12. 작업 순서 (승인 시)

1. **CLAUDE.md 개정**(본 문서) — 4겹·스토리라인·평서체·학부생 자기검토 기준 확정. **(완료)**
2. **파일럿 전환**: 가장 기초인 1~2개 주차(예: 01·02주차)를 평서체 + 스토리라인 4요소 + 용어 풀이로 **완전 전환**해 다른 문서의 기준 예시로 삼는다. Read → 섹션별 Edit 분할(타임아웃 회피).
3. **나머지 주차 평서체 전환 + 스토리라인 보강**: 시험 묶음처럼 주차를 2~3개씩 에이전트에 위임하되, **VM 실측·캡처는 메인이 직접**. 경어체→평서체는 기계적 변환이 아니라 문장 단위로 검토(어색한 직역 금지).
4. **OS 모듈(os/) 동일 기준 적용** + 🟢/🔵 트랙 보강.
5. **학부 3~4학년 최종 통독(§4④)**: 각 과목을 한 권의 책으로 보고, 사전지식 없는 독자가 처음부터 읽어 ⓐ 이해 ⓑ 실습 재현 ⓒ 스스로 설명 가능한지 점검. 막히는 지점(용어 비약·맥락 점프·스토리 단절)을 목록화해 보강한다.
6. QA(링크·펜스·이미지·다이어그램 흑백·평서체) → 승인 시 푸시.

> 타임아웃 교훈: 큰 파일은 Write 한 번에 전체를 쓰지 말고 Read → 섹션별 Edit. 에이전트 프롬프트에는 "분량 상한·기존 구조 유지·실측 출력은 비워두고 메인이 채움"을 명시한다.

---
*이 문서는 프로젝트의 단일 기준이다. 계획·규칙이 바뀌면 여기서 갱신하고 `last_updated`만 바꾼다.*
