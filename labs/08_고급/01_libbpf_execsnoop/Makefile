# libbpf + CO-RE execsnoop 빌드
# 파이프라인: vmlinux.h 생성 → BPF 오브젝트(clang -target bpf) → 스켈레톤(bpftool) → 사용자 프로그램(cc + libbpf)

ARCH := $(shell uname -m | sed 's/aarch64/arm64/; s/x86_64/x86/')
CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: all clean run
all: execsnoop

# 1) 커널 타입 헤더 (현재 커널의 BTF 에서 생성)
vmlinux.h:
	sudo $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2) BPF 프로그램을 BPF 바이트코드 오브젝트로 컴파일
execsnoop.bpf.o: execsnoop.bpf.c execsnoop.h vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c execsnoop.bpf.c -o execsnoop.bpf.o

# 3) 오브젝트에서 사용자 공간용 스켈레톤 헤더 생성
execsnoop.skel.h: execsnoop.bpf.o
	sudo $(BPFTOOL) gen skeleton execsnoop.bpf.o > execsnoop.skel.h

# 4) 사용자 공간 로더 컴파일 + libbpf 링크
execsnoop: execsnoop.c execsnoop.skel.h execsnoop.h
	cc -O2 -Wall execsnoop.c -o execsnoop -lbpf -lelf -lz

run: execsnoop
	sudo ./execsnoop

clean:
	rm -f execsnoop execsnoop.bpf.o execsnoop.skel.h vmlinux.h
