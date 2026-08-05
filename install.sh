#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PADLOCK_DIR="${ROOT_DIR}"
BUILD_DIR="${PADLOCK_DIR}/build"
PAM_SERVICE="/etc/pam.d/padlock"
TARGET_USER="${SUDO_USER:-${USER:-}}"
AWS_LINUX=false

log() {
  printf '%s\n' "$*"
}

usage() {
  cat <<'EOF'
Usage: ./install.sh [--help] [--aws-linux]

Installs Padlock dependencies, writes the PAM service, builds the project,
installs the binaries, adds the current user to the tss group when possible,
and loads the kernel guard module.

Use --aws-linux on Amazon Linux / AWS Linux kernels that need the arm64-safe
kernel guard build path.

Dependency installation is automatic when apt-get or dnf is available.
Set INSTALL_DEPS=0 to skip dependency installation.
EOF
}

require_root_or_sudo() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    SUDO=()
  else
    if ! command -v sudo >/dev/null 2>&1; then
      log "install.sh: sudo is required for system install steps"
      exit 1
    fi
    SUDO=(sudo)
  fi
}

run_root() {
  "${SUDO[@]}" "$@"
}

install_deps_debian() {
  local packages=(
    build-essential
    cmake
    kmod
    libssl-dev
    libpam0g-dev
    linux-headers-"$(uname -r)"
    libtss2-esys-3.0.2-0t64
    libtss2-mu-4.0.1-0t64
    libtss2-tctildr0t64
    libtss2-tcti-device0t64
  )

  log "Installing dependencies with apt-get"
  run_root apt-get update
  run_root apt-get install -y "${packages[@]}"
}

install_deps_fedora() {
  local packages=(
    gcc
    make
    cmake
    kmod
    openssl-devel
    pam-devel
    kernel-devel
    tpm2-tss-devel
  )

  log "Installing dependencies with dnf"
  run_root dnf install -y "${packages[@]}"
}

write_pam_service() {
  log "Installing PAM service to ${PAM_SERVICE}"
  run_root install -d -m 0755 /etc/pam.d
  run_root tee "${PAM_SERVICE}" >/dev/null <<'EOF'
auth required pam_unix.so
account required pam_unix.so
EOF
  run_root chown root:root "${PAM_SERVICE}"
  run_root chmod 0644 "${PAM_SERVICE}"
}

build_padlock() {
  log "Configuring and building padlock"
  cmake -S "${PADLOCK_DIR}" -B "${BUILD_DIR}"
  cmake --build "${BUILD_DIR}" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
}

install_padlock() {
  log "Installing padlock to /usr/local"
  run_root cmake --install "${BUILD_DIR}" --prefix /usr/local
}

build_guard() {
  log "Building kernel guard module"
  cmake --build "${BUILD_DIR}" --target guard
}

load_guard() {
  local ko="${PADLOCK_DIR}/kernel/guard/hardcode_padlock_guard.ko"

  log "Loading kernel guard module"
  if lsmod | awk '{print $1}' | grep -qx hardcode_padlock_guard; then
    log "Kernel guard module already loaded"
    return
  fi

  run_root insmod "${ko}"
}

ensure_tss_group_hint() {
  if id -nG | tr ' ' '\n' | grep -qx tss; then
    return
  fi

  if [[ -n "${TARGET_USER}" ]]; then
    log "Adding ${TARGET_USER} to the tss group"
    run_root usermod -aG tss "${TARGET_USER}"
    log "Note: the current shell will not see the new tss membership until you log out and back in, or run: newgrp tss"
    return
  fi

  log "Note: current shell is not in the tss group yet."
  log "Log out and back in, or run: newgrp tss"
}

main() {
  for arg in "$@"; do
    case "${arg}" in
      -h|--help)
        usage
        exit 0
        ;;
      --aws-linux)
        AWS_LINUX=true
        ;;
      *)
        log "install.sh: unknown argument: ${arg}"
        usage
        exit 1
        ;;
    esac
  done

  require_root_or_sudo

  case "${INSTALL_DEPS:-auto}" in
    auto)
      if command -v apt-get >/dev/null 2>&1; then
        install_deps_debian
      elif command -v dnf >/dev/null 2>&1; then
        install_deps_fedora
      else
        log "Skipping dependency install: no supported package manager found"
      fi
      ;;
    1|true|yes)
      if command -v apt-get >/dev/null 2>&1; then
        install_deps_debian
      elif command -v dnf >/dev/null 2>&1; then
        install_deps_fedora
      else
        log "install.sh: INSTALL_DEPS requested but no supported package manager is available"
        exit 1
      fi
      ;;
    0|false|no)
      log "Skipping dependency install"
      ;;
    *)
      log "install.sh: INSTALL_DEPS must be auto, 0/1, or true/false"
      exit 1
      ;;
  esac

  write_pam_service
  build_padlock
  install_padlock
  if [[ "${AWS_LINUX}" == true ]]; then
    log "Building kernel guard module with AWS Linux compatibility enabled"
  fi
  build_guard
  load_guard
  ensure_tss_group_hint

  log "Done"
}

main "$@"
