#!/bin/sh
# SSHM installer. Downloaded over HTTPS; hashes pinned to the signed release at deployment.
set -eu
main() {
  umask 077
  platform=$(uname -s); machine=$(uname -m)
  case "$platform" in
    Linux) os=linux ;;
    Darwin) os=darwin; if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then machine=arm64; fi ;;
    MINGW*|MSYS*|CYGWIN*) echo 'Use Windows PowerShell: irm https://sshm.yunmini.net/install.ps1 | iex' >&2; return 1 ;;
    *) echo "Unsupported operating system: $platform" >&2; return 1 ;;
  esac
  case "$machine" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "Unsupported architecture: $machine. Available: x64 and ARM64 (64-bit OS required)." >&2; return 1 ;; esac
  if [ "$os" = linux ] && command -v getconf >/dev/null 2>&1 && [ "$(getconf LONG_BIT 2>/dev/null || true)" = 32 ]; then
    echo 'A 64-bit Linux userland is required.' >&2; return 1
  fi
  case "$os-$arch" in
@@POSIX_ASSETS@@
    *) return 1 ;;
  esac
  version='@@VERSION@@'
  dir=${SSHM_INSTALL_DIR:-"$HOME/.local/bin"}
  case "$dir" in /*) ;; *) echo 'SSHM_INSTALL_DIR must be an absolute path.' >&2; return 1 ;; esac
  mkdir -p "$dir"
  work=$(mktemp -d "$dir/.sshm-install.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  trap 'exit 1' HUP INT TERM
  url="https://sshm.yunmini.net/downloads/sshm-$os-$arch"
  echo "Installing SSHM $version ($os/$arch)..."
  if command -v curl >/dev/null 2>&1; then
    curl --silent --show-error --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 --retry 2 --output "$work/sshm" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -T 180 -O "$work/sshm" "$url"
  else
    echo 'Install curl or wget and CA certificates with your package manager, then retry (apt/dnf/yum/apk/pacman/zypper).' >&2; return 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$work/sshm" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then actual=$(shasum -a 256 "$work/sshm" | awk '{print $1}')
  elif command -v openssl >/dev/null 2>&1; then actual=$(openssl dgst -sha256 "$work/sshm" | awk '{print $NF}')
  else echo 'SHA-256 tool missing: install sha256sum, shasum or openssl.' >&2; return 1; fi
  [ "$actual" = "$expected" ] || { echo 'SHA-256 mismatch; existing installation retained. Download a fresh installer and retry.' >&2; return 1; }
  chmod 755 "$work/sshm"
  observed=$("$work/sshm" version) || { echo 'Client cannot run on this OS; existing installation retained.' >&2; return 1; }
  [ "$observed" = "$version" ] || { echo 'Unexpected client version; installation cancelled.' >&2; return 1; }
  if [ -e "$dir/sshm" ] || [ -L "$dir/sshm" ]; then
    backup=$(mktemp "$dir/sshm.backup.XXXXXX")
    cp -p "$dir/sshm" "$backup" || { rm -f "$backup"; return 1; }
    echo "Previous binary: $backup"
  fi
  mv -f "$work/sshm" "$dir/sshm"
  if [ "${SSHM_NO_PATH:-0}" != 1 ] && [ "$dir" = "$HOME/.local/bin" ]; then
    line='export PATH="$HOME/.local/bin:$PATH"'
    for profile in "$HOME/.profile"; do
      [ -f "$profile" ] && grep -Fqx "$line" "$profile" && continue
      printf '\n# SSHM\n%s\n' "$line" >> "$profile"
    done
    case "${SHELL:-}" in
      */zsh) profile="$HOME/.zshrc" ;;
      */bash) profile="$HOME/.bashrc" ;;
      */fish) profile=''; mkdir -p "$HOME/.config/fish/conf.d"; fishline='contains -- "$HOME/.local/bin" $PATH; or set -gx PATH "$HOME/.local/bin" $PATH'; fishfile="$HOME/.config/fish/conf.d/sshm.fish"; if ! { [ -f "$fishfile" ] && grep -Fqx "$fishline" "$fishfile"; }; then printf '\n%s\n' "$fishline" >> "$fishfile"; fi ;;
      *) profile='' ;;
    esac
    if [ -n "$profile" ] && ! { [ -f "$profile" ] && grep -Fqx "$line" "$profile"; }; then printf '\n# SSHM\n%s\n' "$line" >> "$profile"; fi
  fi
  "$dir/sshm" cloud report-version --quiet >/dev/null 2>&1 || true
  echo "Installed: $dir/sshm"
  echo 'For this terminal: export PATH="$HOME/.local/bin:$PATH"'
  echo 'New terminals load PATH automatically. The website command also activates PATH immediately.'
  existing=$(command -v sshm 2>/dev/null || true)
  if [ -n "$existing" ] && [ "$existing" != "$dir/sshm" ]; then echo "Your current PATH also contains: $existing. Use the full installed path until you reopen your terminal."; fi
  if [ "${SSHM_INSTALL_INTEGRATIONS:-0}" = 1 ]; then "$dir/sshm" integrations install --app all --mcp; fi
}
main "$@"
