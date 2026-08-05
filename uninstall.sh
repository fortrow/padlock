#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PADLOCK_DIR="${ROOT_DIR}"
PAM_SERVICE="/etc/pam.d/padlock"
TPM_UEDEV_RULE="/etc/udev/rules.d/60-padlock-tpm.rules"
PADLOCK_BIN="/usr/local/bin/padlock"
PADLOCK_REAL_BIN="/usr/local/bin/padlock.real"
PADLOCK_LIB_DIR="/usr/local/lib64"
PADLOCK_INCLUDE_DIR="/usr/local/include/hardcode"
PADLOCK_KERNEL_MODULE="${PADLOCK_DIR}/kernel/guard/hardcode_padlock_guard.ko"
PADLOCK_BUILD_DIR="${PADLOCK_DIR}/build"
ENCLAVE_HOME="/enclave"
ENCLAVE_KEYSTORE_DIR="/enclave/keystore"
ENCLAVE_DISK_IMAGE="/enclave/.padlock/disk.img"
TPMADM_GROUP="tpmadm"

log() {
  printf '%s\n' "$*"
}

usage() {
  cat <<'EOF'
Usage: ./uninstall.sh [--help] [--keep-build]

Removes the Padlock system install, PAM and udev configuration, the kernel
guard module if it is loaded, and the known enclave disk-image artifacts.

Use --keep-build to leave the local build directory in place.
EOF
}

require_root_or_sudo() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    SUDO=()
  else
    if ! command -v sudo >/dev/null 2>&1; then
      log "uninstall.sh: sudo is required for system removal steps"
      exit 1
    fi
    SUDO=(sudo)
  fi
}

run_root() {
  "${SUDO[@]}" "$@"
}

remove_if_exists() {
  local path="$1"

  if [[ -e "${path}" || -L "${path}" ]]; then
    run_root rm -f "${path}"
  fi
}

unload_guard_module() {
  if lsmod | awk '{print $1}' | grep -qx hardcode_padlock_guard; then
    log "Unloading kernel guard module"
    run_root rmmod hardcode_padlock_guard || true
  fi
}

remove_system_accounts() {
  if getent passwd enclave >/dev/null 2>&1; then
    log "Removing enclave user"
    run_root userdel -r enclave || true
  fi

  if getent group enclave >/dev/null 2>&1; then
    log "Removing enclave group"
    run_root groupdel enclave || true
  fi

  if getent group "${TPMADM_GROUP}" >/dev/null 2>&1; then
    log "Removing ${TPMADM_GROUP} group"
    run_root groupdel "${TPMADM_GROUP}" || true
  fi
}

remove_guard_artifacts() {
  log "Removing kernel guard build artifacts"
  rm -f "${PADLOCK_DIR}/kernel/guard/hardcode_padlock_guard.o"
  rm -f "${PADLOCK_DIR}/kernel/guard/hardcode_padlock_guard.ko"
  rm -f "${PADLOCK_DIR}/kernel/guard/hardcode_padlock_guard.mod"
  rm -f "${PADLOCK_DIR}/kernel/guard/hardcode_padlock_guard.mod.c"
  rm -f "${PADLOCK_DIR}/kernel/guard/hardcode_padlock_guard.mod.o"
  rm -f "${PADLOCK_DIR}/kernel/guard/hardcode_padlock_guard.o.cmd"
  rm -f "${PADLOCK_DIR}/kernel/guard/.hardcode_padlock_guard.o.cmd"
  rm -f "${PADLOCK_DIR}/kernel/guard/.hardcode_padlock_guard.ko.cmd"
  rm -f "${PADLOCK_DIR}/kernel/guard/.hardcode_padlock_guard.mod.cmd"
  rm -f "${PADLOCK_DIR}/kernel/guard/.hardcode_padlock_guard.mod.o.cmd"
  rm -f "${PADLOCK_DIR}/kernel/guard/.modules.order.cmd"
  rm -f "${PADLOCK_DIR}/kernel/guard/Module.symvers"
  rm -f "${PADLOCK_DIR}/kernel/guard/modules.order"
}

remove_enclave_disk_image() {
  log "Removing enclave disk-image artifacts"
  if mountpoint -q "${ENCLAVE_KEYSTORE_DIR}" 2>/dev/null; then
    run_root umount "${ENCLAVE_KEYSTORE_DIR}" || true
  fi

  if [[ -e "${ENCLAVE_DISK_IMAGE}" || -L "${ENCLAVE_DISK_IMAGE}" ]]; then
    run_root chattr -i "${ENCLAVE_DISK_IMAGE}" 2>/dev/null || true
    run_root rm -f "${ENCLAVE_DISK_IMAGE}"
  fi

  run_root rmdir "${ENCLAVE_KEYSTORE_DIR}" 2>/dev/null || true
  run_root rmdir "${ENCLAVE_HOME}/.padlock" 2>/dev/null || true
}

main() {
  local keep_build=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      --keep-build)
        keep_build=true
        shift
        ;;
      *)
        log "uninstall.sh: unknown argument: $1"
        usage
        exit 1
        ;;
    esac
  done

  require_root_or_sudo

  unload_guard_module

  log "Removing Padlock install files"
  remove_if_exists "${PAM_SERVICE}"
  remove_if_exists "${TPM_UEDEV_RULE}"
  remove_if_exists "${PADLOCK_BIN}"
  remove_if_exists "${PADLOCK_REAL_BIN}"
  remove_if_exists "${PADLOCK_LIB_DIR}/libpadlock.so"
  remove_if_exists "${PADLOCK_LIB_DIR}/libpadlock.so.0"
  remove_if_exists "${PADLOCK_LIB_DIR}/libpadlock.so.0.1.0"
  remove_if_exists "${PADLOCK_LIB_DIR}/libpadlock.a"
  remove_if_exists "${PADLOCK_INCLUDE_DIR}/padlock.h"
  remove_if_exists "${PADLOCK_INCLUDE_DIR}/padlock_guard.h"

  run_root rmdir "${PADLOCK_INCLUDE_DIR}" 2>/dev/null || true
  run_root rmdir "/usr/local/include" 2>/dev/null || true

  remove_enclave_disk_image
  remove_guard_artifacts
  remove_system_accounts

  if [[ "${keep_build}" != true ]]; then
    log "Removing local build directory"
    rm -rf "${PADLOCK_BUILD_DIR}"
  fi

  if command -v udevadm >/dev/null 2>&1; then
    run_root udevadm control --reload-rules || true
    run_root udevadm trigger --subsystem-match=tpm || true
  fi

  log "Done"
}

main "$@"
