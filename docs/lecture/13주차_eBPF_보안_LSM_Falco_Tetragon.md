# 13주차 — eBPF 보안: LSM·Falco·Tetragon
> 같은 커널 가시성을 이번엔 "방어"에 쓴다. 시스템콜을 거르는 seccomp 부터, 보안 결정을 내리는 LSM, 그리고 탐지(Falco)와 강제(Tetragon)까지
last_updated: 2026-06-11

> 🧭 **이번 주 동선**  ·  📘 과목1 13주차 🟢 (생태계 개요)  ·  📕 과목2 11주차 🔵 (LSM 훅·탐지)
> - 🔬 **실습(VM `ssh ossca-ebpf`)**: `labs/07_보안/file_guard.py` · `sudo capable-bpfcc` · `sudo execsnoop-bpfcc`
> - 🧵 **OS 트랙 함께 보기**: —
> - ↔️ **이동**: ⬅️ [12주차 XDP·tc·Cilium](12주차_eBPF_네트워킹_XDP_tc_Cilium.md) · 🏠 [강의 인덱스](README.md) · ➡️ [14주차 관측성·프로파일링](14주차_관측성과_성능분석_프로파일링.md)

## 이번 주 학습 목표
- 왜 eBPF 가 **런타임 보안**에 잘 맞는지(커널 전역 가시성 + 낮은 오버헤드)를 설명할 수 있다.
- **seccomp-bpf**(정적 시스템콜 허용/차단)의 동작과 한계를 안다.
- **LSM BPF**(리눅스 보안 모듈 훅에 eBPF 를 달아 보안 결정)를 seccomp 와 구분해 이해한다.
- **Falco**(시스템콜 기반 위협 **탐지**)와 **Tetragon**(eBPF 기반 관측 + 실시간 **강제**)의 역할과 차이를 안다.
- **탐지(detection) vs 강제(enforcement)** 의 구분을 명확히 한다.
- 우리 실습②(연결 추적)가 "비정상 목적지 연결 탐지" 같은 보안 패턴으로 어떻게 확장되는지 연결한다.

---

## 1. 왜 eBPF 가 런타임 보안에 좋은가

런타임 보안의 핵심 질문은 **"지금 이 시스템에서 수상한 일이 벌어지고 있는가?"** 다. 공격은 대부분 커널을 거치는 행위로 드러난다 — 셸 실행, 민감 파일 열기, 예상치 못한 외부 연결, 권한 상승 시도 등. 이 모든 것이 시스템콜·커널 함수 수준에서 보인다.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart TB
    subgraph U["사용자 공간"]
        ATT["😈 공격자 행위\n(셸 실행·파일 접근·외부 연결)"]
    end
    subgraph K["커널 공간"]
        SYS["시스템콜 / 커널 훅"]
        EBPF["🔍 eBPF 보안 센서"]
        SYS --> EBPF
    end
    ATT -->|"모든 행위는 커널을 거친다"| SYS
    EBPF -->|"이벤트/경보"| SEC["보안 도구\n(탐지·대응)"]
    style EBPF fill:#ffffff
```

eBPF 가 보안 센서로 적합한 이유:

| 강점 | 설명 |
|:---|:---|
| **전역 가시성** | 커널을 거치는 거의 모든 행위(시스템콜·네트워크·파일)를 한자리에서 본다 |
| **낮은 오버헤드** | 커널 안에서 필터링·집계하므로, 모든 이벤트를 사용자 공간으로 퍼 올리는 방식보다 가볍다 |
| **컨텍스트 풍부** | 프로세스·컨테이너·파드 정보를 함께 붙여 "누가" 했는지 식별 |
| **재부팅 불요** | 정책·센서를 동적으로 로드/교체 |

> 핵심: 보안은 "행위를 본다"에서 시작한다. 그리고 행위가 가장 잘 보이는 곳이 커널이며, 그곳을 안전하게 들여다보는 도구가 eBPF 다.

---

## 2. seccomp-bpf: 시스템콜의 정적 게이트

**seccomp(secure computing)** 는 프로세스가 호출할 수 있는 시스템콜을 제한하는 오래된 리눅스 기능이다. **seccomp-bpf** 는 여기에 (고전) BPF 필터를 붙여, **"이 프로세스는 이 시스템콜만 허용"** 같은 규칙을 건다. 컨테이너 런타임이 컨테이너의 공격 표면을 줄일 때 흔히 쓴다.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart LR
    P["프로세스의\n시스템콜 호출"] --> F{"seccomp-bpf 필터"}
    F -->|허용 목록에 있음| OK["ALLOW (정상 실행)"]
    F -->|목록에 없음| NO["차단: ERRNO / KILL"]
    style F fill:#ffffff
    style NO fill:#ffffff
```

seccomp-bpf 의 성격:

- **정적(static)**: 프로세스 시작 시 필터를 박아 두고, 이후 그 규칙으로 단순 매칭한다.
- **단순 판단**: 주로 "시스템콜 번호 + 인자(레지스터 값)" 수준에서 결정. 포인터가 가리키는 메모리 내용 같은 깊은 컨텍스트는 보기 어렵다.
- **장점**: 가볍고 검증된 방어. **단점**: 표현력이 제한적이고, 복잡한 정책엔 부족하다.

> seccomp-bpf 는 "이 방에선 이 문들만 쓸 수 있어"라고 **미리 못 박는** 방식이다. 유연하진 않지만 단단하다.

---

## 3. LSM BPF: 보안 결정을 내리는 훅

리눅스에는 **LSM(Linux Security Module)** 이라는 보안 훅 프레임워크가 있다. SELinux·AppArmor 가 이 위에서 동작한다. 커널은 민감한 동작(파일 열기, 소켓 연결, 프로세스 실행 등) 직전에 **LSM 훅**을 호출해 "이 동작을 허용할까?"를 묻는다.

**LSM BPF(BPF LSM)** 는 이 LSM 훅에 **eBPF 프로그램**을 달 수 있게 한 기능(커널 5.7+)이다. eBPF 가 보안 결정을 내려 **0(허용) 또는 음수 에러(거부)** 를 반환한다.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart LR
    ACT["민감한 커널 동작\n(예: file_open)"] --> HOOK{"LSM 훅\n+ eBPF 프로그램"}
    HOOK -->|"return 0"| ALLOW["허용"]
    HOOK -->|"return -EPERM"| DENY["거부 🚫"]
    style HOOK fill:#ffffff
    style DENY fill:#ffffff
```

seccomp 와 LSM BPF 의 결정적 차이:

| 구분 | seccomp-bpf | LSM BPF |
|:---|:---|:---|
| 거는 위치 | 시스템콜 진입부 | 커널 내부 **보안 의사결정 지점**(LSM 훅) |
| 컨텍스트 | 시스템콜 번호 + 레지스터 인자 | 커널 객체(파일·소켓·자격증명 등) 풍부한 정보 |
| 표현력 | 제한적(정적 매칭) | 높음(eBPF 로 복잡한 정책) |
| 결정 | 허용/차단/KILL 등 | 허용(0) / 거부(음수) |
| 최소 커널 | 오래전부터 | 5.7+ (CONFIG_BPF_LSM, 보통 부팅 옵션 필요) |

> seccomp 가 "문 목록을 미리 못 박기"라면, LSM BPF 는 "문 앞에서 그때그때 신분과 상황을 보고 판단하기"에 가깝다. 더 똑똑하지만 그만큼 신중히 써야 한다.

---

## 4. 탐지 vs 강제: 보안의 두 갈래

여기서 이번 주의 가장 중요한 개념을 못 박자.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart LR
    EV["수상한 행위 발생\n(예: 셸 실행)"] --> DET["🔍 탐지(detection)\n'일어났다'고 알림\n→ 경보·로그"]
    EV --> ENF["🛡 강제(enforcement)\n행위 자체를 막음\n→ 프로세스 종료·연결 차단"]
    style DET fill:#ffffff
    style ENF fill:#ffffff
```

| 구분 | 탐지(Detection) | 강제(Enforcement) |
|:---|:---|:---|
| 하는 일 | 의심 행위를 **관측하고 경보** | 의심 행위를 **실제로 차단** |
| 시점 | 보통 일어난 **직후**(사후 인지) | 일어나기 **전/중** 막음 |
| 위험 | 막진 못함(공격은 진행됨) | 잘못 막으면 정상 동작도 깨짐(오탐 비용 큼) |
| 비유 | CCTV·경보기 | 자동 잠금장치·차단봉 |
| 대표 도구 | **Falco** | **Tetragon**, LSM BPF |

> 둘은 대립이 아니라 단계다. 보통 **탐지로 시작**해 신뢰가 쌓이면 **강제로** 넘어간다. 강제는 강력한 만큼 오탐 한 번이 서비스 장애가 될 수 있어 신중함이 필요하다.

---

## 5. Falco: 시스템콜 기반 런타임 위협 탐지

**Falco** 는 CNCF 의 졸업(Graduated) 프로젝트로, 런타임 위협 **탐지**에 널리 쓰이는 오픈소스다. 시스템콜·커널 이벤트를 수집해 **룰 엔진**으로 평가하고, 룰에 걸리면 **경보(alert)** 를 낸다. 성격상 "관측·탐지" 중심이다.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart LR
    K["커널 이벤트\n(시스템콜 등, eBPF 수집)"] --> ENG["Falco 룰 엔진"]
    RULES["탐지 룰\n(YAML)"] --> ENG
    ENG -->|룰 매칭| ALERT["🚨 경보\n(stdout·로그·Slack·SIEM 등)"]
    style ENG fill:#ffffff
    style ALERT fill:#ffffff
```

전형적인 Falco 룰의 형태(개념용):

```yaml
- rule: Terminal shell in container
  desc: 컨테이너 안에서 대화형 셸이 실행됨 (수상함)
  condition: spawned_process and container and shell_procs
  output: "컨테이너에서 셸 실행 (user=%user.name command=%proc.cmdline)"
  priority: WARNING
```

Falco 가 잡아내는 전형적 위협 패턴:

- **예상치 못한 셸 실행**: 운영 중인 컨테이너 안에서 `bash`/`sh` 가 뜸 → 침입 의심.
- **민감 파일 접근**: `/etc/shadow`, 클라우드 자격증명 파일 등을 읽음.
- **예상치 못한 네트워크 연결**: 평소 안 하던 외부 IP 로 connect → **데이터 유출·C2 의심**.
- **권한 상승 시도**: setuid 호출, 컨테이너 탈출 정황.

> Falco 의 위치를 정확히: 기본적으로 **"탐지·경보"** 도구다. (대응은 보통 외부 연동 — 경보를 받아 다른 시스템이 조치.) 메모리 효율이 좋고 CNCF 생태계에서 오래 자리 잡은 폭넓은 탐지 도구로 알려져 있다.

---

## 6. Tetragon: 관측 + 실시간 강제

**Tetragon** 은 **Cilium 의 하위 프로젝트**(CNCF)로, eBPF 기반 **보안 관측(observability)** 에 더해 **실시간 강제(enforcement)** 까지 할 수 있는 것이 특징이다. 즉 의심 행위를 관측만 하는 게 아니라, 커널 안에서 **프로세스를 종료하거나 연결을 차단**하는 식의 조치를 취할 수 있다.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart TB
    K["커널 훅 (eBPF)\n프로세스·파일·네트워크"] --> TP["TracingPolicy\n(관측 대상 + 행동 정의)"]
    TP --> OBS["📊 관측: 이벤트 스트림\n(프로세스 계보 포함)"]
    TP --> ENF["🛡 강제: 커널 내 즉시 조치\n(예: SIGKILL, 연결 차단)"]
    style ENF fill:#ffffff
    style OBS fill:#ffffff
```

Tetragon 의 성격:

- **쿠버네티스 인지(aware)**: 이벤트에 파드·컨테이너·라벨 컨텍스트를 붙인다.
- **프로세스 계보**: "누가 누구를 실행했나"의 실행 트리를 추적해, 의심 행위의 출처를 안다.
- **인커널 강제**: 정책 위반 행위를 사용자 공간까지 올리지 않고 **커널 안에서 즉시** 막을 수 있어 빠르고 우회가 어렵다.
- 효율 면에서 CPU 사용이 낮은 편으로 알려져 있다(세부 수치는 환경·버전 의존이니 단정은 금물).

---

## 7. 한눈에 비교: seccomp vs LSM BPF vs Falco vs Tetragon

| 도구 | 계층 | 주된 성격 | 동작 | 비고 |
|:---|:---|:---|:---|:---|
| **seccomp-bpf** | 시스템콜 진입 | 강제(정적) | 허용 목록 외 시스템콜 차단 | 가볍고 단단, 표현력 제한 |
| **LSM BPF** | LSM 보안 훅 | 강제(동적) | eBPF 가 허용/거부 결정 | 풍부한 컨텍스트, 커널 5.7+ |
| **Falco** | 시스템콜/커널 이벤트 | **탐지 중심** | 룰 엔진으로 경보 | CNCF Graduated, 폭넓은 탐지 |
| **Tetragon** | 커널 훅(eBPF) | **관측 + 강제** | 이벤트 + 인커널 조치 | Cilium 하위(CNCF), 강제 가능 |

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart LR
    subgraph DETECT["🔍 탐지 위주"]
        FAL["Falco\n(경보)"]
    end
    subgraph ENFORCE["🛡 강제 가능"]
        SEC["seccomp"]
        LSM["LSM BPF"]
        TET["Tetragon"]
    end
    FAL -.->|신뢰 쌓이면 차단으로| TET
    style DETECT fill:#ffffff
    style ENFORCE fill:#ffffff
```

> 주의: 도구들의 세부 기능·성능은 버전과 환경에 따라 다르다. 시험·실무에서는 "Falco = 탐지 중심, Tetragon = 관측+강제, LSM BPF = 커널 보안 결정, seccomp = 정적 시스템콜 게이트"라는 **역할 구분**을 정확히 잡는 것이 핵심이다.

---

## 7.5 심화: 세 방어 계층을 "한 시스템콜의 일생"에 겹쳐 보기

seccomp · LSM BPF · 탐지 도구는 추상적으로 보면 헷갈리지만, **하나의 시스템콜이 거치는 시간선** 위에 올려 두면 위치가 또렷해진다. 프로세스가 `openat("/etc/shadow")` 를 부른 순간을 따라가 보자.

| 순서 | 지점 | 누가 개입하나 | 무엇을 보고 무엇을 할 수 있나 |
|:---:|:---|:---|:---|
| ① | 시스템콜 진입부 | **seccomp-bpf** | 시스템콜 번호·레지스터 인자. "이 시스템콜 자체를 허용/차단" (정적, 경로 문자열은 못 봄) |
| ② | 커널 내부 `security_file_open` 훅 | **BPF LSM** | 커널 `file`·`inode`·자격증명 객체. "이 파일을 이 주체가 여는 것을 허용(0)/거부(-EPERM)" (동적) |
| ③ | 동작 수행 직후/직전 관측 | **Falco / Tetragon** | 시스템콜·커널 이벤트 스트림. Falco는 룰 매칭 후 **경보**, Tetragon은 관측 + **인커널 조치(SIGKILL 등)** |

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart LR
    CALL["openat('/etc/shadow')"] --> S1{"① seccomp\n(시스템콜 게이트)"}
    S1 -->|허용| S2{"② BPF LSM\nsecurity_file_open"}
    S1 -->|차단| X1["ERRNO/KILL"]
    S2 -->|"return 0"| DO["파일 열기 수행"]
    S2 -->|"-EPERM"| X2["거부 🚫"]
    DO -. "이벤트 관측" .-> S3["③ Falco(경보) /\nTetragon(관측·강제)"]
```

핵심 통찰 세 가지:

- **계층이 다르면 볼 수 있는 컨텍스트가 다르다.** seccomp 는 "경로 문자열"을 못 보지만(인자는 사용자 메모리 포인터라 신뢰·해석이 까다롭다), LSM 훅은 이미 커널이 해석한 `file` 객체를 본다. 그래서 "특정 파일만 막기" 같은 정책은 seccomp 가 아니라 LSM 결이다.
- **탐지는 ③에서, 강제는 ①②(그리고 Tetragon)에서.** 탐지는 "일어난 일을 본다"이므로 동작 흐름을 굳이 막지 않아도 되지만, 강제는 동작 **경로 위에서** 결정해야 한다. 그래서 Falco 는 관측 지점에, LSM/seccomp/Tetragon 은 결정 경로에 선다.
- **여러 계층은 배타적이 아니라 중첩(defense in depth)이다.** 실무에선 seccomp 로 공격 표면을 줄이고, LSM 으로 민감 객체를 지키고, Falco/Tetragon 으로 이상 징후를 관측·대응한다 — 한 줄의 방어가 아니라 여러 겹이다.

### 7.6 심화: 위협 패턴을 "관측 가능한 신호"로 번역하기

13주차 본문이 든 위협 패턴(비정상 exec · 비정상 네트워크 · 민감 파일 · 권한 상승)은 추상적으로 들리지만, 결국 **특정 커널 이벤트의 조합**으로 환원된다. 탐지기를 설계한다는 것은 이 "번역"을 하는 일이다.

| 위협 패턴 | 관측할 신호(이벤트) | 대표 BCC 도구 |
|:---|:---|:---|
| 비정상 프로세스 실행 | `execve`/`execveat` 추적점 + argv + 부모 프로세스 계보 | `execsnoop-bpfcc` |
| 민감 파일 접근 | `openat` 추적점에서 경로가 `/etc/shadow` 등 감시 목록에 매칭 | `opensnoop-bpfcc` |
| 비정상 외부 연결 | `tcp_v4_connect` kprobe + 목적지 IP/포트가 화이트리스트 밖 | `tcpconnect-bpfcc` |
| 권한 상승 시도 | `cap_capable`(권한 검사) 추적, setuid 계열 호출 | `capable-bpfcc` |

> 💡 핵심: "탐지 룰"이라는 것은 마법이 아니라, **이벤트 + 조건 + 컨텍스트(누가/어디서)** 의 합이다. 우리가 9~10주에 손으로 만든 추적기에 "조건"과 "감시 목록"만 더하면 그대로 위협 탐지기가 된다 — 이것이 아래 실습 ①·③에서 직접 확인할 내용이다.

---

## 8. 실습②와의 연결: "비정상 목적지 연결 탐지"

우리 10주차 실습②(netflow-tracer)는 `tcp_v4_connect` 에 kprobe 를 걸어 **"어떤 프로세스가 어디로 TCP 연결을 하나"** 를 관측했다. 이건 사실 보안 탐지의 **기본 빌딩블록**이다.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart LR
    OUR["우리 실습②\nkprobe tcp_v4_connect\n→ 프로세스별 연결 관측"] --> STEP1["여기에 '허용 목적지 목록'을 더하면..."]
    STEP1 --> DET["🔍 탐지: 목록 밖 IP 로 연결 시 경보\n(= Falco 가 하는 일의 축소판)"]
    STEP1 --> ENF["🛡 강제: 목록 밖 연결을 차단\n(= Tetragon/LSM 이 하는 일의 축소판)"]
    style DET fill:#ffffff
    style ENF fill:#ffffff
```

- **탐지로 키우기**: 실습②의 출력에 "예상 목적지 화이트리스트"를 더하면, 목록 밖 IP 로의 연결을 **경보**할 수 있다. 이것이 Falco 류 "예상치 못한 네트워크 연결" 탐지의 본질이다.
- **강제로 키우기**: 같은 판단을 cgroup connect 훅이나 Tetragon 정책으로 옮기면, 비정상 연결을 **차단**할 수 있다.

즉 우리가 짠 작은 추적기는, 한 발만 더 나아가면 **런타임 보안 센서**가 된다. 같은 eBPF·같은 훅·같은 맵, 거기에 "정책"과 "조치"가 붙었을 뿐이다. 이것이 실습②가 12주(네트워킹)·13주(보안)의 "축소판 맛보기"였다는 말의 의미다.

---

## ⚙️ 리눅스 커널은 보안 결정을 어디서 내리나

리눅스는 보안 결정이 필요한 지점마다 **LSM(Linux Security Module) 훅**(`security_*` 함수)을 심어 둔다. 커널은 파일 열기·소켓 연결·프로세스 실행 직전에 이 훅을 호출해 "허용할지"를 묻고, SELinux·AppArmor 가 그 위에서 동작한다. **BPF LSM** 은 바로 이 훅에 eBPF 를 붙여 정책을 판단하게 한 것이다. 반면 **seccomp** 은 더 앞단인 **시스템콜 진입부**에서 시스템콜 자체를 거르는 고전 BPF 필터다. 즉 두 방어선은 거는 위치가 다르다.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#ffffff","primaryColor":"#ffffff","primaryBorderColor":"#000000","primaryTextColor":"#000000","secondaryColor":"#ffffff","secondaryBorderColor":"#000000","secondaryTextColor":"#000000","tertiaryColor":"#ffffff","tertiaryBorderColor":"#000000","tertiaryTextColor":"#000000","lineColor":"#000000","textColor":"#000000","mainBkg":"#ffffff","secondBkg":"#ffffff","clusterBkg":"#ffffff","clusterBorder":"#000000","edgeLabelBackground":"#ffffff","nodeBorder":"#000000","defaultLinkColor":"#000000","titleColor":"#000000","actorBkg":"#ffffff","actorBorder":"#000000","actorTextColor":"#000000","actorLineColor":"#000000","signalColor":"#000000","signalTextColor":"#000000","labelBoxBkgColor":"#ffffff","labelBoxBorderColor":"#000000","labelTextColor":"#000000","loopTextColor":"#000000","noteBkgColor":"#ffffff","noteBorderColor":"#000000","noteTextColor":"#000000","activationBkgColor":"#ffffff","activationBorderColor":"#000000","sequenceNumberColor":"#000000","cScale0":"#ffffff","cScale1":"#ffffff","cScale2":"#ffffff","cScale3":"#ffffff","cScale4":"#ffffff","cScale5":"#ffffff","cScale6":"#ffffff","cScale7":"#ffffff","cScale8":"#ffffff","cScale9":"#ffffff","cScale10":"#ffffff","cScale11":"#ffffff","cScaleLabel0":"#000000","cScaleLabel1":"#000000","cScaleLabel2":"#000000","cScaleLabel3":"#000000","cScaleLabel4":"#000000","cScaleLabel5":"#000000","cScaleLabel6":"#000000","cScaleLabel7":"#000000","cScaleLabel8":"#000000","cScaleLabel9":"#000000","cScaleLabel10":"#000000","cScaleLabel11":"#000000","pie1":"#ffffff","pie2":"#eeeeee","pie3":"#dddddd","pie4":"#cccccc","fontFamily":"Georgia, serif"}}}%%
flowchart TB
    APP["프로세스 동작"] --> SC["시스템콜 진입"]
    SC --> SECCOMP{"seccomp 필터"}
    SECCOMP -->|허용| HOOK["커널 내부 처리 중\nsecurity_* 훅"]
    SECCOMP -->|차단| BLOCK1["차단 (ERRNO/KILL)"]
    HOOK --> LSM{"BPF LSM 판단"}
    LSM -->|"허용(0)"| OK["동작 수행"]
    LSM -->|"거부(음수)"| BLOCK2["차단 🚫"]
    HOOK -.->|관측| LOG["이벤트 기록·경보"]
```

소스/구조: LSM 훅은 커널 `security/security.c` 와 각 `security_*` 호출 지점에 있고, BPF LSM 은 `CONFIG_BPF_LSM`(커널 5.7+) 으로 활성화된다.

---

## 📸 실제 실행 화면 (실제 터미널 캡처)

> 아래는 VM(커널 6.17 aarch64)에서 BCC 도구를 **실제 터미널에서 실행해 그대로 캡처**한 화면이다.

![execsnoop-bpfcc — 모든 프로세스 실행(execve)을 실시간 감시 (실제 터미널 캡처)](images/more/w13_execsnoop.png)

새로 뜨는 모든 프로세스의 PID·부모·명령줄이 보인다. 침입 탐지의 기본기 — "방금 무엇이 실행됐나"를 한눈에 본다.

![capable-bpfcc — 권한 검사(capability) 추적 (실제 터미널 캡처)](images/more/w13_capable.png)

커널이 어떤 권한(capability)을 누구에게 검사하는지 흐른다. 권한 상승(privilege escalation) 정황을 포착하는 데 활용한다.

---

## 💡 핵심 요약
- eBPF 는 **커널 전역 가시성 + 낮은 오버헤드 + 풍부한 컨텍스트**로 런타임 보안 센서에 적합하다.
- **seccomp-bpf**: 시스템콜의 **정적** 허용/차단. 가볍지만 표현력 제한.
- **LSM BPF**: LSM 보안 훅에 eBPF 를 달아 **동적 보안 결정**(허용 0 / 거부 음수). 커널 5.7+.
- **탐지 vs 강제**: 탐지는 알리기, 강제는 막기. 보통 탐지 → 강제 순으로 성숙.
- **Falco**: 시스템콜 기반 위협 **탐지·경보**(CNCF Graduated).
- **Tetragon**: Cilium 하위(CNCF), eBPF 관측 + **인커널 실시간 강제** 가능.
- 실습②(연결 관측)는 정책·조치를 더하면 "비정상 연결 탐지/차단" 보안 센서로 자란다.

---

## ✍️ 연습문제
1. seccomp-bpf 와 LSM BPF 가 "거는 위치"와 "다룰 수 있는 컨텍스트" 면에서 어떻게 다른지 설명하라.
2. "탐지로 충분한 상황"과 "강제가 필요한 상황"의 예를 각각 하나씩 들고, 강제를 택할 때의 위험을 적어라.
3. Falco 룰로 "컨테이너 안에서 `/etc/shadow` 를 읽으면 경보"를 만들 때, 어떤 시스템콜/이벤트를 봐야 할지 추론해 보라.
4. 우리 실습②를 "비정상 목적지 연결 탐지기"로 바꾸려면 어떤 자료구조(맵)와 로직을 추가해야 하는가?
5. 같은 탐지를 "차단"으로 바꾸려면 kprobe 관측만으로는 부족한 이유는? 어떤 훅이 필요한가?(힌트: 12주 cgroup connect, LSM)

---

## 🛠 실습 과제 — 탐지기를 직접 켜고 위협 신호를 본다

> VM 켜는 법·접속은 [실습 랩 README](../../README.md) 강의 1~2를 따른다. eBPF 로드 권한 때문에 모든 명령은 **VM 안에서 `sudo`** 로 실행한다. 도구 이름이 환경에 따라 `execsnoop-bpfcc` / `execsnoop` 로 다를 수 있으니, 막히면 `compgen -c | grep -i bpfcc` 로 설치된 도구를 먼저 확인하라.

```bash
# VM 켜고 접속 (Mac 터미널)
tart run ossca-ebpf-work --no-graphics &
until ssh ossca-ebpf 'true' 2>/dev/null; do echo "부팅 대기..."; sleep 2; done
ssh ossca-ebpf
```

### 과제 A — 민감 파일 접근 경보 (file_guard)

- **목표:** "누가 `/etc/shadow` 를 읽으려 했나"를 실시간으로 포착해, §5의 "민감 파일 접근" 탐지를 손으로 재현한다.
- **명령:**

```bash
# 창 1: 감시기 켜기 (openat 추적점 기반, /etc/shadow 접근 시 경보)
sudo python3 ~/ebpf-labs/labs/07_보안/file_guard.py

# 창 2(다른 SSH 창): 일부러 민감 파일을 건드려 본다
cat /etc/shadow            # 권한 거부되더라도 '접근 시도' 자체가 잡힌다
```

- **관찰:** 창 1에 접근을 시도한 **PID·프로세스 이름·사용자·경로**가 뜨는가? 창 2에서 내가 친 `cat` 과 일치하는가? (실패한 접근도 잡히는지 눈여겨보라 — 탐지는 "성공/실패"가 아니라 "시도"를 본다.)
- **질문:** 이 경보가 떴을 때 파일 읽기는 이미 일어났는가, 아직인가? 이것이 "탐지"의 시점적 특성과 어떻게 연결되는가?

### 과제 B — 프로세스 실행·권한 검사 감시 (execsnoop + capable)

- **목표:** 침입 탐지의 기본기인 "방금 무엇이 실행됐나"(비정상 exec)와 "누가 어떤 권한을 요구했나"(권한 상승)를 동시에 본다.
- **명령:**

```bash
# 창 1: 모든 프로세스 실행(execve)을 실시간 감시
sudo execsnoop-bpfcc

# 창 2: 권한(capability) 검사 추적 — 권한 상승 정황 포착
sudo capable-bpfcc

# 창 3: 부하를 만들어 본다 (예: 컨테이너 안 셸 흉내)
id; sudo -n true 2>/dev/null; ping -c1 127.0.0.1
```

- **관찰:** `execsnoop` 에 부모 PID(PPID)와 argv 가 보이는가 — "누가 누구를 실행했나"의 계보가 그려지는가? `capable` 에 `CAP_NET_RAW`(ping) 같은 권한 검사가 흐르는가?
- **질문:** §6에서 Tetragon 의 강점으로 "프로세스 계보"를 들었다. `execsnoop` 의 PPID 한 칸이 왜 보안 탐지에서 중요한가?

### 과제 C — 감시 경로 추가하기 (file_guard 확장)

- **목표:** 탐지기는 "정책(무엇을 감시할지)"을 바꿔 키운다. `--pattern` 으로 감시 대상을 넓혀, §7.6의 "위협 패턴 → 관측 신호" 번역을 직접 손본다.
- **명령:**

```bash
# /etc/shadow 외에 SSH 키·클라우드 자격증명 경로까지 감시 추가
sudo python3 ~/ebpf-labs/labs/07_보안/file_guard.py \
    --pattern /etc/shadow --pattern .ssh --pattern /etc/sudoers

# 다른 창에서:
cat ~/.ssh/known_hosts 2>/dev/null; cat /etc/sudoers 2>/dev/null
```

> `--pattern` 옵션이 없다면, file_guard.py 안에서 감시 경로 목록(문자열 매칭부)을 찾아 직접 한 줄 추가해 보라 — 어디를 고쳐야 하는지 찾는 것 자체가 학습이다.

- **관찰:** 새로 추가한 경로 접근만 골라서 경보가 뜨는가? 무관한 파일 읽기(`cat /etc/hostname`)는 조용한가? (오탐/미탐의 균형을 체감하라.)
- **질문(생각):** 같은 file_guard 로 **탐지**(경보만)는 했지만 **강제**(차단)는 못 한다. 접근을 실제로 막으려면 openat 추적점 관측만으로는 왜 부족하며, 어떤 훅(힌트: §3 LSM `security_file_open`)이 필요한가? 그리고 강제로 바꿀 때 감수해야 하는 위험(§4)은 무엇인가?

> **제출물(권장):** 과제 A·B 출력 캡처 + 과제 C에서 추가한 패턴과 그 결과 3~5줄 해석. "탐지와 강제의 차이"를 자기 말로 2~3문장 정리.

---

## ✅ 자가점검 퀴즈
1. seccomp-bpf 는 정적인가 동적인가, 그리고 주로 무엇을 본다고 했나?
<details><summary>정답</summary>정적이다. 주로 시스템콜 번호와 레지스터 인자를 본다(깊은 메모리 컨텍스트는 보기 어렵다).</details>

2. LSM BPF 에서 eBPF 프로그램이 "거부"를 표현하는 반환값은?
<details><summary>정답</summary>음수 에러 코드(예: -EPERM). 허용은 0.</details>

3. Falco 의 주된 성격은 탐지인가 강제인가?
<details><summary>정답</summary>탐지(detection) 중심이다. 룰 엔진으로 경보를 낸다(대응은 보통 외부 연동).</details>

4. Tetragon 이 Falco 와 구별되는 핵심 능력은?
<details><summary>정답</summary>관측에 더해 인커널 실시간 강제(enforcement) — 프로세스 종료·연결 차단 등 — 가 가능하다는 점.</details>

5. Tetragon 은 어떤 프로젝트의 하위 프로젝트이며 어느 재단 소속인가?
<details><summary>정답</summary>Cilium 의 하위 프로젝트이며 CNCF 프로젝트다.</details>

6. 우리 실습②(연결 관측)를 보안 탐지기로 만들려면 무엇을 더해야 하나?
<details><summary>정답</summary>"허용 목적지 목록(화이트리스트)"과, 목록 밖 연결을 경보(탐지) 또는 차단(강제)하는 로직.</details>

---

## 📚 더 읽을거리
- Falco 공식 문서(falco.org), CNCF 프로젝트 페이지.
- Tetragon 공식 사이트(tetragon.io)와 Cilium 문서 — 세부 기능·성능은 버전 의존이니 문서 기준 확인.
- 커널 문서: seccomp, BPF LSM(CONFIG_BPF_LSM) 관련.
- eBPF 런타임 보안 도구 비교 자료(Falco·Tetragon·Tracee 등). 수치는 환경 의존임에 유의.

출처: [Tetragon 공식](https://tetragon.io/) · [eBPF Runtime Security Tools 비교](https://www.decryptiondigest.com/blog/ebpf-runtime-security-tools-falco-tetragon)

---

## ⏭ 다음 주 예고
다음 [14주차](14주차_관측성과_성능분석_프로파일링.md)에서는 보안에서 잠시 벗어나 **관측성과 성능 분석·프로파일링**으로 간다. eBPF 로 CPU/지연을 프로파일링하고 플레임그래프를 뽑는 법, off-CPU 분석, 그리고 우리가 배운 추적 기술이 성능 문제 해결로 이어지는 길을 본다.
