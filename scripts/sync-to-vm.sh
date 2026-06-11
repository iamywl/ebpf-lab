#!/usr/bin/env bash
# 로컬 프로젝트 코드를 tart VM(ossca-ebpf) 의 ~/ebpf-labs/ 로 동기화한다.
# 사용법: scripts/sync-to-vm.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_HOST="ossca-ebpf"
REMOTE_DIR="ebpf-labs"

# 빌드 산출물은 제외하고 동기화 (projects 정식 실습 + examples 예제 모음)
rsync -az --delete \
  --exclude 'workload' \
  --exclude 'net_workload' \
  --exclude '__pycache__' \
  --exclude '_sample_output' \
  --exclude 'docs/captures' \
  -e "ssh" \
  "${REPO_DIR}/projects" \
  "${REPO_DIR}/examples" \
  "${REPO_DIR}/README.md" \
  "${SSH_HOST}:${REMOTE_DIR}/"

echo "동기화 완료 → ${SSH_HOST}:~/${REMOTE_DIR}/"
