#!/usr/bin/env bash
# Run sshm SSH integration tests against a Dockerized OpenSSH server.
# Usage: scripts/integration-sshd/start.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_DIR="$(mktemp -d -t sshm-itest-XXXXXX)"
KEY_PATH="${WORK_DIR}/test_key"
KEYS_DIR="${WORK_DIR}/keys"
CONTAINER_NAME="sshm-test-sshd"
PORT="${SSHM_TEST_PORT:-2222}"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

echo "→ Generating throwaway ed25519 key in ${WORK_DIR}"
ssh-keygen -t ed25519 -N "" -f "${KEY_PATH}" >/dev/null
mkdir -p "${KEYS_DIR}"
cp "${KEY_PATH}.pub" "${KEYS_DIR}/test.pub"

echo "→ Starting sshd container on :${PORT}"
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
docker run -d --name "${CONTAINER_NAME}" \
  -p "${PORT}:2222" \
  -v "${KEYS_DIR}:/keys:ro" \
  -e PUBLIC_KEY_FILE=/keys/test.pub \
  -e USER_NAME=tester \
  -e PASSWORD_ACCESS=false \
  -e SUDO_ACCESS=true \
  linuxserver/openssh-server:latest >/dev/null

echo "→ Waiting for sshd to accept connections"
for i in $(seq 1 60); do
  if nc -z 127.0.0.1 "${PORT}" 2>/dev/null; then
    # sshd may listen on TCP before the auth pipeline is ready
    sleep 1
    break
  fi
  sleep 0.5
done

echo "→ Running integration tests"
cd "${REPO_ROOT}"
SSHM_TEST_HOST="127.0.0.1:${PORT}" SSHM_TEST_KEY="${KEY_PATH}" \
  go test -tags=integration -v ./internal/ssh/...
