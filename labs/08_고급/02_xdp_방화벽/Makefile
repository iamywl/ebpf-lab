# XDP 방화벽 빌드 (libbpf)
ARCH := $(shell uname -m | sed 's/aarch64/arm64/; s/x86_64/x86/')
CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: all clean run
all: xdp_firewall

vmlinux.h:
	sudo $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

xdp_firewall.bpf.o: xdp_firewall.bpf.c vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c xdp_firewall.bpf.c -o xdp_firewall.bpf.o

xdp_firewall.skel.h: xdp_firewall.bpf.o
	sudo $(BPFTOOL) gen skeleton xdp_firewall.bpf.o > xdp_firewall.skel.h

xdp_firewall: xdp_firewall.c xdp_firewall.skel.h
	cc -O2 -Wall xdp_firewall.c -o xdp_firewall -lbpf -lelf -lz

run: xdp_firewall
	sudo ./xdp_firewall lo

clean:
	rm -f xdp_firewall xdp_firewall.bpf.o xdp_firewall.skel.h vmlinux.h
