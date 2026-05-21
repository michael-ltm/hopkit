#!/usr/bin/env sh
# sshm bootstrap — baseline hardening for a fresh server.
# Idempotent: safe to run more than once. Requires root or sudo.
set -e

echo "=SSHM-BOOTSTRAP-START="

# 1. Package manager detection + baseline tooling.
if command -v dnf >/dev/null 2>&1; then PM="dnf install -y";
elif command -v apt-get >/dev/null 2>&1; then PM="apt-get install -y";
elif command -v yum >/dev/null 2>&1; then PM="yum install -y";
elif command -v apk >/dev/null 2>&1; then PM="apk add";
else PM=""; fi

# pkg_install runs the detected package manager; $PM intentionally
# word-splits into command + flags (POSIX sh has no arrays).
pkg_install() { $PM "$@"; }
if [ -n "$PM" ]; then
  pkg_install jq curl fail2ban >/dev/null 2>&1 || echo "warn: some packages failed to install"
fi

# 2. fail2ban on if available.
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
fi

# 3. Report sshd hardening state — do NOT change it here; that is an
#    explicit, separate user action. Bootstrap only reports.
echo "=SSHD-STATE="
grep -E "^\s*(PasswordAuthentication|PermitRootLogin)" /etc/ssh/sshd_config 2>/dev/null || echo "sshd_config unreadable"

echo "=SSHM-BOOTSTRAP-DONE="
