#!/usr/bin/env bash
# Run sshm SSH integration tests against a Dockerized OpenSSH server.
# Builds the image from scripts/integration-sshd/Dockerfile, mounts an
# ephemeral pubkey, waits for sshd, runs the integration test, cleans up.
#
# Usage: scripts/integration-sshd/start.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORK_DIR="$(mktemp -d -t sshm-itest-XXXXXX)"
KEY_PATH="${WORK_DIR}/test_key"
KEYS_DIR="${WORK_DIR}/keys"
CONTAINER_NAME="sshm-test-sshd"
IMAGE_TAG="sshm-test-sshd:local"
PORT="${SSHM_TEST_PORT:-2222}"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

echo "→ Building sshd test image from ${SCRIPT_DIR}"
docker build -q -t "${IMAGE_TAG}" "${SCRIPT_DIR}" >/dev/null

echo "→ Generating throwaway ed25519 key in ${WORK_DIR}"
ssh-keygen -t ed25519 -N "" -f "${KEY_PATH}" >/dev/null
mkdir -p "${KEYS_DIR}"
cp "${KEY_PATH}.pub" "${KEYS_DIR}/test.pub"

echo "→ Starting sshd container on :${PORT}"
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
docker run -d --name "${CONTAINER_NAME}" \
  -p "${PORT}:2222" \
  -v "${KEYS_DIR}:/keys:ro" \
  "${IMAGE_TAG}" >/dev/null

echo "→ Waiting for sshd to accept SSH handshakes"
READY=0
for i in $(seq 1 60); do
  if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -o BatchMode=yes -o ConnectTimeout=2 \
       -p "${PORT}" -i "${KEY_PATH}" tester@127.0.0.1 true 2>/dev/null; then
    READY=1
    break
  fi
  sleep 0.5
done
if [ "${READY}" -ne 1 ]; then
  echo "ERROR: sshd did not accept SSH handshakes within 30s" >&2
  docker logs "${CONTAINER_NAME}" >&2 || true
  exit 1
fi

echo "→ Running integration tests"
SSHM_TEST_HOST="127.0.0.1:${PORT}" SSHM_TEST_KEY="${KEY_PATH}" \
  go test -timeout 60s -tags=integration -v -C "${REPO_ROOT}" ./internal/ssh/...
