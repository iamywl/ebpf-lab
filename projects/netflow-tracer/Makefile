# netflow-tracer 빌드/실행 단축 명령

CC      ?= cc
CFLAGS  ?= -O2 -Wall

.PHONY: all verify trace clean

all: net_workload

net_workload: net_workload.c
	$(CC) $(CFLAGS) -o $@ $<

# 추적기 자기검증 (root 권한 필요)
verify: net_workload
	sudo python3 verify_net.py $(N)

# 10초간 TCP 연결 실시간 추적
trace:
	sudo python3 netflow.py --duration 10

clean:
	rm -f net_workload
