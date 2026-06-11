# eBPF 예제 모음 — 짧고 다양한 추적기 15선

> bpftrace 한두 줄로 "eBPF 가 이런 것도 되는구나"를 빠르게 체험하는 예제 모음입니다.
> 본 저장소의 두 정식 실습([syscall-tracer](../projects/syscall-tracer/) · [netflow-tracer](../projects/netflow-tracer/))이 "깊게 한 우물"이라면, 여기는 "넓게 맛보기"입니다.
>
> **아래 모든 출력은 실습 VM(Ubuntu 24.04 / 커널 6.17 / aarch64)에서 실제로 돌려 캡처한 것**입니다. 원본: [`_sample_output/`](./_sample_output/)

last_updated: 2026-06-11

---

## 0. 먼저 — 어떻게 실행하나

```bash
# 1) VM 접속 (처음이라면 → docs/lecture/00a 준비 가이드부터)
ssh ossca-ebpf

# 2) 예제 폴더로 이동
cd ~/ebpf-labs/examples

# 3) 실행 (eBPF 는 관리자 권한 필요 → sudo)
sudo bpftrace 01_기본동작/hello.bt        # bpftrace 스크립트(.bt)
sudo python3  01_기본동작/hello_bcc.py    # BCC 스크립트(.py)
```

> 💡 **멈춘 듯 보여도 정상입니다.** 추적기는 이벤트가 올 때까지 조용히 기다립니다.
> 집계형 예제는 **`Ctrl-C` 로 멈추는 순간** 결과가 정리되어 나옵니다.
> 처음 보는 단어는 [용어 사전](../docs/lecture/00c_용어집_약어사전.md)에서 찾으세요.

### 전체 목록

| 주제 | 파일 | 무엇을 보여주나 | 연계 강의 |
|:---|:---|:---|:---:|
| **① 기본 동작** | [hello.bt](01_기본동작/hello.bt) | eBPF 의 가장 단순한 형태(이벤트→실행) | [7주](../docs/lecture/07주차_bpftrace_입문.md) |
| | [hello_bcc.py](01_기본동작/hello_bcc.py) | 커널 C + 사용자 Python 두 얼굴 | [8주](../docs/lecture/08주차_BCC_입문_맵과_perf이벤트.md) |
| **② 시스템콜** | [syscall_top.bt](02_시스템콜/syscall_top.bt) | 프로세스별 시스템콜 횟수 집계 | [9주](../docs/lecture/09주차_실습1_시스템콜_추적기.md) |
| | [execsnoop.bt](02_시스템콜/execsnoop.bt) | 새로 실행되는 모든 프로그램 | [2·13주](../docs/lecture/02주차_리눅스_커널과_사용자공간_시스템콜.md) |
| | [opensnoop.bt](02_시스템콜/opensnoop.bt) | 누가 어떤 파일을 여나 | [9주](../docs/lecture/09주차_실습1_시스템콜_추적기.md) |
| | [killsnoop.bt](02_시스템콜/killsnoop.bt) | 누가 누구에게 시그널을 보내나 | [13주](../docs/lecture/13주차_eBPF_보안_LSM_Falco_Tetragon.md) |
| **③ 네트워크** | [tcp_connect.bt](03_네트워크/tcp_connect.bt) | 나가는 TCP 접속(목적지 IP:포트) | [10주](../docs/lecture/10주차_실습2_네트워크_연결_추적기.md) |
| | [tcp_accept.bt](03_네트워크/tcp_accept.bt) | 들어오는 접속을 받는 서버 | [12주](../docs/lecture/12주차_eBPF_네트워킹_XDP_tc_Cilium.md) |
| | [socket_count.bt](03_네트워크/socket_count.bt) | 프로세스별 소켓 생성 수 | [10주](../docs/lecture/10주차_실습2_네트워크_연결_추적기.md) |
| | [tcp_retransmit.bt](03_네트워크/tcp_retransmit.bt) | TCP 재전송(네트워크 품질 신호) | [14주](../docs/lecture/14주차_관측성과_성능분석_프로파일링.md) |
| **④ 다양한 주제** | [openat_latency.bt](04_다양한주제/openat_latency.bt) | 파일 열기 지연 히스토그램 | [14주](../docs/lecture/14주차_관측성과_성능분석_프로파일링.md) |
| | [vfs_read_bytes.bt](04_다양한주제/vfs_read_bytes.bt) | 프로세스별 파일 읽기 바이트 | [5·14주](../docs/lecture/05주차_프로그램_타입과_부착지점.md) |
| | [pagefaults.bt](04_다양한주제/pagefaults.bt) | 프로세스별 페이지 폴트(메모리) | [14주](../docs/lecture/14주차_관측성과_성능분석_프로파일링.md) |
| | [runqlat.bt](04_다양한주제/runqlat.bt) | CPU 대기시간 히스토그램(스케줄러) | [14주](../docs/lecture/14주차_관측성과_성능분석_프로파일링.md) |
| | [cpu_profile.bt](04_다양한주제/cpu_profile.bt) | CPU 를 누가 쓰나(샘플링 프로파일) | [14주](../docs/lecture/14주차_관측성과_성능분석_프로파일링.md) |

---

## ① eBPF 가 전반적으로 어떻게 도는가

eBPF 프로그램의 본질은 **"커널 안의 어떤 이벤트가 일어나면 → 내가 심은 코드가 실행된다"** 입니다.
가장 단순한 [hello.bt](01_기본동작/hello.bt) 로 그 흐름을 봅니다 — 새 프로그램이 실행될 때마다 인사합니다.

```bash
sudo bpftrace 01_기본동작/hello.bt
# 띄워둔 채 다른 창에서 ls, date 를 쳐보세요
```

실제 실행 화면(VM에서 캡처):

![hello.bt 실제 실행 화면](../docs/lecture/images/shot_hello.png)

```text
eBPF 시작! 새 프로그램 실행을 지켜봅니다. (다른 창에서 명령을 쳐보세요, Ctrl-C 로 종료)
안녕! PID 33239  (bash) 가 실행: /usr/bin/ls
안녕! PID 33240  (bash) 가 실행: /usr/bin/date
안녕! PID 33241  (bash) 가 실행: /bin/echo
```

[hello_bcc.py](01_기본동작/hello_bcc.py) 는 똑같은 일을 하되, **커널에서 도는 C 코드**와 **그것을 올리고 결과를 받는 Python** 으로 나뉜 eBPF 의 "두 얼굴"을 보여줍니다(8주차에서 자세히).

```text
안녕! PID 34028 (...) 가 새 프로그램을 실행했어요
안녕! PID 34029 (...) 가 새 프로그램을 실행했어요
```

---

## ② 시스템콜 관측하는 법

프로그램의 모든 외부 행동은 **시스템콜**로 드러납니다. 그래서 시스템콜을 보면 프로세스가 무엇을 하는지 알 수 있습니다.

**프로세스별 시스템콜 횟수** — [syscall_top.bt](02_시스템콜/syscall_top.bt) (`Ctrl-C` 로 멈추면 정리됨):

```text
@by_process[multipathd]: 18
@by_process[tart-guest-agen]: 43
@by_process[bpftrace]: 65
```

**새로 실행되는 프로그램** — [execsnoop.bt](02_시스템콜/execsnoop.bt):

```text
시각   실행한 프로세스 PID    실행 파일
06:41:07 bash             33481  /usr/bin/ls
06:41:07 bash             33483  /usr/bin/uname
```

**누가 어떤 파일을 여나** — [opensnoop.bt](02_시스템콜/opensnoop.bt):

```text
프로세스     PID    여는 파일
cat              33261  /etc/ld.so.cache
cat              33261  /lib/aarch64-linux-gnu/libc.so.6
```

**누가 시그널(kill)을 보내나** — [killsnoop.bt](02_시스템콜/killsnoop.bt) (`sig=15` 은 SIGTERM):

```text
보낸 프로세스 PID    -> 대상PID 시그널
bash             33226  -> 33274  sig=15
```

---

## ③ 네트워크 소켓 관측하는 법

"누가 어디로 접속하나"는 보안·관측의 핵심입니다(10·12주차).

**나가는 TCP 접속** — [tcp_connect.bt](03_네트워크/tcp_connect.bt) (다른 창에서 `curl` 실행):

```text
프로세스     PID    목적지 IP:포트
curl             33488  127.0.0.1:22
curl             33490  1.1.1.1:80
```

**들어오는 접속을 받는 서버** — [tcp_accept.bt](03_네트워크/tcp_accept.bt) (`python3 -m http.server` 띄우고 `curl`):

```text
시각   프로세스     PID    이벤트
06:41:16 python3          33495  새 연결 수락(accept)
06:41:16 python3          33495  새 연결 수락(accept)
```

**프로세스별 소켓 생성 수** — [socket_count.bt](03_네트워크/socket_count.bt):

```text
@sockets[curl]: 6
@sockets[sshd]: 12
```

**TCP 재전송** — [tcp_retransmit.bt](03_네트워크/tcp_retransmit.bt) (평소엔 드물어 0 일 수 있음 — "도구가 켜져 동작 중"이 핵심):

```text
TCP 재전송을 지켜봅니다... (드물게 발생, Ctrl-C 로 종료)
@retransmits: 0
```

---

## ④ eBPF 로 할 수 있는 다양한 주제들

eBPF 는 시스템콜·네트워크 말고도 **성능·메모리·스케줄러**까지 들여다봅니다.

**파일 열기 지연 분포** — [openat_latency.bt](04_다양한주제/openat_latency.bt) (히스토그램 = 성능 분석의 핵심):

![openat_latency.bt 실제 실행 화면 — 지연 히스토그램](../docs/lecture/images/shot_openat_latency.png)

```text
@latency_ns:
[512, 1K)           1047 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1K, 2K)             457 |@@@@@@@@@@@@@@@@@@@@@@                              |
[2K, 4K)             108 |@@@@@                                              |
[4K, 8K)              14 |                                                   |
```

**프로세스별 파일 읽기 바이트** — [vfs_read_bytes.bt](04_다양한주제/vfs_read_bytes.bt) (kprobe 로 커널 함수에 직접):

```text
@read_bytes[ls]: 49600
@read_bytes[cat]: 271168
```

**프로세스별 페이지 폴트** — [pagefaults.bt](04_다양한주제/pagefaults.bt) (메모리 관점):

```text
@faults[seq]: 70
@faults[uname]: 697
@faults[bash]: 1056
```

**CPU 대기시간 분포** — [runqlat.bt](04_다양한주제/runqlat.bt) (스케줄러 지연, 값 크면 CPU 경쟁 심함):

```text
@wait_us:
[1]                   17 |@@@@@@@@                                          |
[2, 4)                34 |@@@@@@@@@@@@@@@@                                   |
[4, 8)               110 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
```

**CPU 를 누가 쓰나(샘플링)** — [cpu_profile.bt](04_다양한주제/cpu_profile.bt) (플레임 그래프의 원리). 부하 주려면 다른 창에서 `yes > /dev/null`:

```text
@on_cpu[yes]: 198
@on_cpu[swapper/0]: 293
```

(`swapper/N` 은 "그 CPU 가 놀고 있었음"을 뜻합니다.)

---

## 더 배우려면

- **bpftrace 문법**을 제대로 → [7주차 강의](../docs/lecture/07주차_bpftrace_입문.md)
- **BCC(C+Python)** 로 직접 짜기 → [8주차](../docs/lecture/08주차_BCC_입문_맵과_perf이벤트.md)
- **자기검증까지 갖춘 정식 추적기** → [syscall-tracer](../projects/syscall-tracer/) · [netflow-tracer](../projects/netflow-tracer/)
- 모르는 코드·용어 → [C 미니부록](../docs/lecture/00b_준비_C언어_미니부록.md) · [용어 사전](../docs/lecture/00c_용어집_약어사전.md)
