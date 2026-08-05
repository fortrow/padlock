#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PADLOCK_DIR="${ROOT_DIR}"
BUILD_DIR="${PADLOCK_DIR}/build"
PAM_SERVICE="/etc/pam.d/padlock"
TARGET_USER="${SUDO_USER:-${USER:-}}"
AWS_LINUX=false
AUTH_NO_PROMPT=false
USER_EXPLICIT=false
DISK_IMAGE=false
ENCLAVE_MODE=false
ENCLAVE_SIZE_INPUT=""
ENCLAVE_SIZE_BYTES=0
TPMADM_GROUP="tpmadm"
TPM_UEDEV_RULE="/etc/udev/rules.d/60-padlock-tpm.rules"
PADLOCK_BIN="/usr/local/bin/padlock"
PADLOCK_REAL_BIN="/usr/local/bin/padlock.real"
DISK_IMAGE_MARGIN_BYTES=$((64 * 1024 * 1024))
DISK_IMAGE_PATH=""
MOUNT_POINT=""
TARGET_HOME=""
KERNEL_BUILD_DIR=""

log() {
  printf '%s\n' "$*"
}

usage() {
  cat <<'EOF'
Usage: ./install.sh [--help] [--aws-linux] [--user <name>] [--auth-no-prompt] [--disk-img] [--enclave <size>]

Installs Padlock dependencies, writes the PAM service, builds the project,
installs the binaries, adds the current user to the tpmadm group when possible,
and loads the kernel guard module.

Use --aws-linux on Amazon Linux / AWS Linux kernels that need the arm64-safe
kernel guard build path.

Use --user <name> to set the user added to the tpmadm group.
Use --auth-no-prompt with --user <name> to install a PAM rule that trusts that
specific user without prompting for a password.
Use --disk-img to enable a disk-backed keystore layout.
Use --enclave <size> to create the enclave user, enable disk-backed storage,
and allocate an enclave keystore of the requested size.

Dependency installation is automatic when apt-get or dnf is available.
Set INSTALL_DEPS=0 to skip dependency installation.
EOF
}

detect_kernel_build_dir() {
  local kernel_release
  local candidate
  local candidates=(
    "/lib/modules/$(uname -r)/build"
    "/usr/src/kernels/$(uname -r)"
  )

  kernel_release="$(uname -r)"
  for candidate in "${candidates[@]}"; do
    if [[ -r "${candidate}/Makefile" ]]; then
      KERNEL_BUILD_DIR="${candidate}"
      return 0
    fi
  done

  log "install.sh: could not find kernel headers for ${kernel_release}"
  log "install.sh: looked for ${candidates[*]}"
  log "install.sh: install the matching kernel headers or set PADLOCK_KERNEL_BUILD explicitly"
  exit 1
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

run_as_user() {
  local user="$1"
  shift

  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    if command -v runuser >/dev/null 2>&1; then
      runuser -u "${user}" -- "$@"
      return
    fi

    if command -v su >/dev/null 2>&1; then
      local command_line
      printf -v command_line '%q ' "$@"
      su -s /bin/sh "${user}" -c "${command_line% }"
      return
    fi

    log "install.sh: neither runuser nor su is available for user switching"
    exit 1
  fi

  if ! command -v sudo >/dev/null 2>&1; then
    log "install.sh: sudo is required to run commands as ${user}"
    exit 1
  fi

  sudo -u "${user}" -- "$@"
}

validate_user_name() {
  case "$1" in
    ""|*[![:alnum:]_.@-]*)
      return 1
      ;;
  esac
  return 0
}

size_to_bytes() {
  local input="$1"
  local number
  local suffix
  local multiplier=1

  if [[ "${input}" =~ ^([0-9]+)([BbKkMmGgTt]?[Bb]?)?$ ]]; then
    number="${BASH_REMATCH[1]}"
    suffix="${BASH_REMATCH[2]}"
  else
    return 1
  fi

  case "${suffix^^}" in
    ""|B)
      multiplier=1
      ;;
    K|KB)
      multiplier=$((1024))
      ;;
    M|MB)
      multiplier=$((1024 * 1024))
      ;;
    G|GB)
      multiplier=$((1024 * 1024 * 1024))
      ;;
    T|TB)
      multiplier=$((1024 * 1024 * 1024 * 1024))
      ;;
    *)
      return 1
      ;;
  esac

  printf '%s\n' $((number * multiplier))
}

get_user_home() {
  local user="$1"
  local entry

  entry="$(getent passwd "${user}" || true)"
  if [[ -z "${entry}" ]]; then
    return 1
  fi

  printf '%s\n' "${entry}" | awk -F: '{print $6}'
}

configure_disk_image_paths() {
  local home_dir="$1"

  MOUNT_POINT="${home_dir}/keystore"
  DISK_IMAGE_PATH="${home_dir}/.padlock/disk.img"
}

install_deps_debian() {
  local packages=(
    build-essential
    cmake
    e2fsprogs
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
    e2fsprogs
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

  if [[ "${AUTH_NO_PROMPT}" == true ]]; then
    if ! validate_user_name "${TARGET_USER}"; then
      log "install.sh: --auth-no-prompt requires a valid --user <name>"
      exit 1
    fi

    printf 'auth required pam_succeed_if.so user = %s\n' "${TARGET_USER}" | run_root tee "${PAM_SERVICE}" >/dev/null
  else
    run_root tee "${PAM_SERVICE}" >/dev/null <<'EOF'
auth required pam_unix.so
account required pam_unix.so
EOF
  fi
  run_root chown root:root "${PAM_SERVICE}"
  run_root chmod 0644 "${PAM_SERVICE}"
}

build_padlock() {
  log "Configuring and building padlock"
  if [[ -z "${KERNEL_BUILD_DIR}" ]]; then
    detect_kernel_build_dir
  fi
  run_root rm -rf "${BUILD_DIR}"
  cmake -S "${PADLOCK_DIR}" -B "${BUILD_DIR}" -DPADLOCK_KERNEL_BUILD="${KERNEL_BUILD_DIR}"
  cmake --build "${BUILD_DIR}" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
}

clean_kernel_guard_artifacts() {
  run_root rm -f \
    "${PADLOCK_DIR}/kernel/guard"/.hardcode_padlock_guard.* \
    "${PADLOCK_DIR}/kernel/guard"/hardcode_padlock_guard.ko \
    "${PADLOCK_DIR}/kernel/guard"/hardcode_padlock_guard.mod \
    "${PADLOCK_DIR}/kernel/guard"/hardcode_padlock_guard.mod.c \
    "${PADLOCK_DIR}/kernel/guard"/hardcode_padlock_guard.mod.o \
    "${PADLOCK_DIR}/kernel/guard"/hardcode_padlock_guard.o \
    "${PADLOCK_DIR}/kernel/guard"/hardcode_padlock_guard.o.cmd \
    "${PADLOCK_DIR}/kernel/guard"/Module.symvers \
    "${PADLOCK_DIR}/kernel/guard"/modules.order
}

install_padlock() {
  log "Installing padlock to /usr/local"
  run_root cmake --install "${BUILD_DIR}" --prefix /usr/local
  run_root ldconfig
  if [[ "${ENCLAVE_MODE}" == true ]]; then
    run_root mv "${PADLOCK_BIN}" "${PADLOCK_REAL_BIN}"
  fi
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

ensure_group_exists() {
  local group_name="$1"

  if getent group "${group_name}" >/dev/null 2>&1; then
    return
  fi

  log "Creating group ${group_name}"
  run_root groupadd "${group_name}"
}

add_root_group_members_to_tpmadm() {
  local group_line
  local members
  local member
  local member_list=()

  group_line="$(getent group root || true)"
  members="${group_line##*:}"

  if [[ -z "${members}" || "${members}" == "${group_line}" ]]; then
    return
  fi

  IFS=',' read -ra member_list <<< "${members}"
  for member in "${member_list[@]}"; do
    if [[ -n "${member}" ]]; then
      log "Adding ${member} from root group to ${TPMADM_GROUP}"
      run_root usermod -aG "${TPMADM_GROUP}" "${member}"
    fi
  done
}

add_target_user_to_tpmadm() {
  if [[ -n "${TARGET_USER}" ]]; then
    log "Adding ${TARGET_USER} to the ${TPMADM_GROUP} group"
    run_root usermod -aG "${TPMADM_GROUP}" "${TARGET_USER}"
    log "Note: the current shell will not see the new ${TPMADM_GROUP} membership until you log out and back in, or run: newgrp ${TPMADM_GROUP}"
  fi
}

write_tpm_udev_rule() {
  log "Installing TPM udev rule to ${TPM_UEDEV_RULE}"
  run_root install -d -m 0755 /etc/udev/rules.d
  run_root tee "${TPM_UEDEV_RULE}" >/dev/null <<EOF
KERNEL=="tpm*", OWNER="tss", GROUP="${TPMADM_GROUP}", MODE="0660"
EOF
  run_root chmod 0644 "${TPM_UEDEV_RULE}"
  run_root udevadm control --reload-rules || true
  run_root udevadm trigger --subsystem-match=tpm || true
}

apply_tpm_permissions() {
  local device
  local devices=()

  ensure_group_exists "${TPMADM_GROUP}"
  add_root_group_members_to_tpmadm
  add_target_user_to_tpmadm
  write_tpm_udev_rule

  shopt -s nullglob
  for device in /dev/tpm* /dev/tpmrm*; do
    [[ -e "${device}" ]] || continue
    devices+=("${device}")
  done
  shopt -u nullglob

  if [[ ${#devices[@]} -eq 0 ]]; then
    log "No TPM devices found to update"
    return
  fi

  for device in "${devices[@]}"; do
    log "Setting ${device} ownership to tss:${TPMADM_GROUP}"
    run_root chown tss:"${TPMADM_GROUP}" "${device}"
    run_root chmod 0660 "${device}"
  done
}

setup_enclave_user() {
  local enclave_home="/enclave"

  if ! getent passwd enclave >/dev/null 2>&1; then
    log "Creating system user enclave"
    run_root useradd -m -d "${enclave_home}" -s /sbin/nologin -U enclave
  else
    log "Updating existing enclave user"
    run_root usermod -d "${enclave_home}" -s /sbin/nologin enclave
  fi

  run_root install -d -o enclave -g enclave -m 0750 "${enclave_home}"
  TARGET_USER="enclave"
  TARGET_HOME="${enclave_home}"
}

resolve_target_home() {
  if [[ -n "${TARGET_HOME}" ]]; then
    return 0
  fi

  TARGET_HOME="$(get_user_home "${TARGET_USER}")"
}

create_disk_image() {
  local home_dir="$1"
  local store_size_bytes="$2"
  local image_size_bytes=$((store_size_bytes + DISK_IMAGE_MARGIN_BYTES))
  local fstab_line

  configure_disk_image_paths "${home_dir}"

  log "Creating disk image at ${DISK_IMAGE_PATH}"
  run_root install -d -m 0700 "$(dirname "${DISK_IMAGE_PATH}")"
  run_root install -d -m 0700 "${MOUNT_POINT}"
  run_root truncate -s "${image_size_bytes}" "${DISK_IMAGE_PATH}"
  run_root mkfs.ext4 -F -m 0 -L padlock "${DISK_IMAGE_PATH}"
  run_root chown root:root "${DISK_IMAGE_PATH}"
  run_root chmod 0600 "${DISK_IMAGE_PATH}"

  fstab_line="${DISK_IMAGE_PATH} ${MOUNT_POINT} ext4 loop,nodev,nosuid,noexec 0 0"
  if ! grep -qF "${fstab_line}" /etc/fstab; then
    log "Adding disk image to /etc/fstab"
    printf '%s\n' "${fstab_line}" | run_root tee -a /etc/fstab >/dev/null
  fi

  log "Mounting disk image"
  run_root mount -a
}

allocate_store_in_disk_image() {
  local home_dir="$1"
  local store_size="$2"
  local alloc_bin="${PADLOCK_BIN}"

  log "Allocating encrypted store inside disk image"
  if [[ "${ENCLAVE_MODE}" == true ]]; then
    alloc_bin="${PADLOCK_REAL_BIN}"
  fi

  if [[ ! -x "${alloc_bin}" ]]; then
    log "install.sh: expected ${alloc_bin} to exist before enclave allocation"
    exit 1
  fi
  run_as_user "${TARGET_USER}" env HOME="${home_dir}" PADLOCK_STORE_ROOT="${MOUNT_POINT}" "${alloc_bin}" allocate "${store_size}"
}

lock_disk_image() {
  if [[ -z "${DISK_IMAGE_PATH}" ]]; then
    return
  fi

  log "Locking disk image ${DISK_IMAGE_PATH}"
  run_root chown root:root "${DISK_IMAGE_PATH}"
  run_root chmod 0600 "${DISK_IMAGE_PATH}"
  run_root chattr +i "${DISK_IMAGE_PATH}"
}

install_enclave_wrapper() {
  local home_dir="$1"

  log "Installing enclave padlock wrapper to ${PADLOCK_BIN}"
  run_root mv -f "${PADLOCK_BIN}" "${PADLOCK_REAL_BIN}"
  run_root tee "${PADLOCK_BIN}" >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail

PADLOCK_REAL_BIN="${PADLOCK_REAL_BIN}"
PADLOCK_STORE_ROOT="${MOUNT_POINT}"

case "\${1:-}" in
  allocate)
    printf '%s\n' "padlock: allocate is disabled in enclave mode" >&2
    exit 1
    ;;
  get)
    if [[ \$# -ne 2 ]]; then
      printf '%s\n' "Usage: padlock get <key>" >&2
      exit 2
    fi
    exec sudo -u "${TARGET_USER}" env HOME="${home_dir}" PADLOCK_STORE_ROOT="\${PADLOCK_STORE_ROOT}" "\${PADLOCK_REAL_BIN}" get "\$2"
    ;;
  set)
    if [[ \$# -ne 3 ]]; then
      printf '%s\n' "Usage: padlock set <key> <value>" >&2
      exit 2
    fi
    exec sudo -u "${TARGET_USER}" env HOME="${home_dir}" PADLOCK_STORE_ROOT="\${PADLOCK_STORE_ROOT}" "\${PADLOCK_REAL_BIN}" set "\$2" "\$3"
    ;;
  *)
    printf '%s\n' "Usage: padlock get <key> | padlock set <key> <value>" >&2
    exit 2
    ;;
esac
EOF
  run_root chmod 0755 "${PADLOCK_BIN}"
}

setup_disk_image_keystore() {
  local home_dir="$1"
  local store_size="$2"
  local store_size_bytes
  local image_dir

  store_size_bytes="$(size_to_bytes "${store_size}")"
  configure_disk_image_paths "${home_dir}"
  image_dir="$(dirname "${DISK_IMAGE_PATH}")"
  create_disk_image "${home_dir}" "${store_size_bytes}"
  run_root chown "${TARGET_USER}:${TARGET_USER}" "${image_dir}"
  run_root chmod 0700 "${image_dir}"
  run_root chown "${TARGET_USER}:${TARGET_USER}" "${MOUNT_POINT}"
  run_root chmod 0700 "${MOUNT_POINT}"
  allocate_store_in_disk_image "${home_dir}" "${store_size}"
  run_root chown "${TARGET_USER}:${TARGET_USER}" "${image_dir}"
  run_root chmod 0700 "${image_dir}"
  run_root chown "${TARGET_USER}:${TARGET_USER}" "${MOUNT_POINT}"
  run_root chmod 0700 "${MOUNT_POINT}"
  lock_disk_image
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      --aws-linux)
        AWS_LINUX=true
        shift
        ;;
      --disk-img)
        DISK_IMAGE=true
        shift
        ;;
      --user)
        if [[ $# -lt 2 ]]; then
          log "install.sh: --user requires a username"
          exit 1
        fi
        if ! validate_user_name "$2"; then
          log "install.sh: --user must be a valid username"
          exit 1
        fi
        TARGET_USER="$2"
        USER_EXPLICIT=true
        shift 2
        ;;
      --auth-no-prompt)
        AUTH_NO_PROMPT=true
        shift
        ;;
      --enclave)
        if [[ $# -lt 2 ]]; then
          log "install.sh: --enclave requires a size"
          exit 1
        fi
        if ! ENCLAVE_SIZE_BYTES="$(size_to_bytes "$2")"; then
          log "install.sh: --enclave size must be a number with optional K, M, G, or T suffix"
          exit 1
        fi
        ENCLAVE_MODE=true
        DISK_IMAGE=true
        ENCLAVE_SIZE_INPUT="$2"
        ENCLAVE_SIZE_BYTES="${ENCLAVE_SIZE_BYTES}"
        AWS_LINUX=true
        AUTH_NO_PROMPT=true
        TARGET_USER="enclave"
        USER_EXPLICIT=true
        shift 2
        ;;
      *)
        log "install.sh: unknown argument: $1"
        usage
        exit 1
        ;;
    esac
  done

  if [[ "${ENCLAVE_MODE}" == true && "${TARGET_USER}" != "enclave" ]]; then
    log "install.sh: --enclave requires the target user to be enclave"
    exit 1
  fi

  if [[ "${ENCLAVE_MODE}" == true && "${AUTH_NO_PROMPT}" != true ]]; then
    AUTH_NO_PROMPT=true
  fi

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
  clean_kernel_guard_artifacts
  build_padlock
  install_padlock
  if [[ "${AWS_LINUX}" == true ]]; then
    log "Building kernel guard module with AWS Linux compatibility enabled"
  fi
  build_guard
  load_guard
  if [[ "${ENCLAVE_MODE}" == true ]]; then
    setup_enclave_user
  fi

  apply_tpm_permissions

  if [[ "${ENCLAVE_MODE}" == true ]]; then
    setup_disk_image_keystore "${TARGET_HOME}" "${ENCLAVE_SIZE_INPUT}"
    install_enclave_wrapper "${TARGET_HOME}"
  elif [[ "${DISK_IMAGE}" == true ]]; then
    resolve_target_home
    if [[ -n "${ENCLAVE_SIZE_INPUT}" ]]; then
      setup_disk_image_keystore "${TARGET_HOME}" "${ENCLAVE_SIZE_INPUT}"
    fi
  fi

  log "Done"
}

main "$@"
