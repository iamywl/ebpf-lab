# syscall-tracer 빌드/실행 단축 명령
# BPF 프로그램은 BCC 가 런타임에 컴파일하므로 별도 빌드가 없고,
# 검증용 workload(C) 만 컴파일하면 된다.

CC      ?= cc
CFLAGS  ?= -O2 -Wall

.PHONY: all verify trace clean

all: workload

workload: workload.c
	$(CC) $(CFLAGS) -o $@ $<

# 추적기 자기검증 (root 권한 필요)
verify: workload
	sudo python3 verify.py $(N)

# 5초간 전체 시스템콜 추적 데모
trace:
	sudo python3 tracer.py --duration 5

clean:
	rm -f workload
