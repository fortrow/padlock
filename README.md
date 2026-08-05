# Padlock

Padlock is a Linux keystore. It stores a hidden append-only key/value file in each user's home directory, encrypts the store at rest, and keeps older key/value pairs in place so reads return the last matching entry.

## What It Does

- Creates a fixed-size store file, for example `~/.padlock/store.plk`.
- Fills unused space with random bytes.
- Encrypts the store data with AES-256-XTS.
- Seals a helper secret through TPM data in `~/.padlock/tpm/`; that helper is used to derive the header password, which protects the store key.
- Uses direct TPM2 ESAPI calls to create, load, and unseal the sealed helper secret.
- Prompts once for the user's Linux password, verifies it through PAM, and derives the header password through the TPM-backed helper path.
- Appends key/value pairs instead of overwriting them.
- Reads scan to the end of the file so duplicate keys resolve to the most recent value.

## What It Is For

Padlock is meant to be the local keystore layer for Hardcode authentication and credential workflows. The intent is to keep sensitive secrets encrypted at rest, tied to the local machine through TPM state, while still letting the user authenticate through the standard Linux login path.

## Install

The installer script auto-detects `apt-get` or `dnf` and installs the matching build dependencies before building and loading Padlock.

### Ubuntu or Debian

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libpam0g-dev linux-headers-$(uname -r) \
  libtss2-esys-3.0.2-0t64 libtss2-mu-4.0.1-0t64 libtss2-tctildr0t64 libtss2-tcti-device0t64
```

### Notes

- `build-essential` provides `cc`, `make`, and the C toolchain.
- `cmake` provides the project generator and build orchestration.
- `libssl-dev` provides the OpenSSL headers and libraries used for AES and HMAC/KDF work.
- `libpam0g-dev` provides the PAM headers used to validate the login password.
- `libtss2-esys-3.0.2-0t64`, `libtss2-mu-4.0.1-0t64`, `libtss2-tctildr0t64`, and `libtss2-tcti-device0t64` provide the TPM2 runtime libraries used by the direct ESAPI path.
- `linux-headers-$(uname -r)` provides the headers needed to build the guard module.
- The machine needs access to `/dev/tpmrm0` or `/dev/tpm0`.
- The user running `padlock` must have access to the `tss` group on the active session.

### Fedora

```bash
sudo dnf install -y gcc make cmake openssl-devel pam-devel kernel-devel kmod tpm2-tss-devel
```

Notes:

- `gcc` and `make` provide the C toolchain and build driver.
- `cmake` provides the project generator and build orchestration.
- `openssl-devel` provides the OpenSSL headers and libraries used for AES and HMAC/KDF work.
- `pam-devel` provides the PAM headers used to validate the login password.
- `tpm2-tss-devel` provides the TPM2 headers and libraries used by the direct ESAPI path.
- `kernel-devel` provides the headers needed to build the guard module.
- `kmod` provides `insmod`, `lsmod`, and `rmmod` if they are not already present.
- The machine needs access to `/dev/tpmrm0` or `/dev/tpm0`.
- The user running `padlock` must have access to the `tss` group on the active session.

## Build

```bash
cmake -S apps/padlock -B apps/padlock/build
cmake --build apps/padlock/build
```

This produces:

- `apps/padlock/build/libpadlock.so`
- `apps/padlock/build/libpadlock.a`
- `apps/padlock/build/padlock`

### Build the kernel guard module

```bash
cmake --build apps/padlock/build --target guard
```

This produces:

- `apps/padlock/kernel/guard/hardcode_padlock_guard.ko`

### Load the kernel guard module

The build target leaves the module in the source tree. Load it directly with `insmod`:

```bash
sudo insmod apps/padlock/kernel/guard/hardcode_padlock_guard.ko
```

Verify that it loaded and created the device node:

```bash
lsmod | rg hardcode_padlock_guard
ls -l /dev/hardcode_padlock_guard
```

To unload it:

```bash
sudo rmmod hardcode_padlock_guard
```

`modprobe hardcode_padlock_guard` only works after the module has been installed into `/lib/modules/$(uname -r)` and `depmod -a` has been run. If you are testing from a build tree, use `insmod` against the built `.ko` file.

## Test

```bash
ctest --test-dir apps/padlock/build --output-on-failure
```

The test suite exercises:

- constant-time compare helpers
- secure zeroing
- allocation of a new store
- appending key/value pairs
- duplicate-key reads returning the last stored value

## Install

Preferred setup for a fresh machine:

```bash
./apps/padlock/install.sh
```

That script installs the dependencies, writes the PAM service, builds padlock, installs the binaries, adds the user to `tss`, and loads the guard module.

Configure and build first:

```bash
cmake -S apps/padlock -B apps/padlock/build
cmake --build apps/padlock/build
```

Then install with an explicit prefix:

```bash
cmake --install apps/padlock/build --prefix /usr
```

To stage into a package root, use `DESTDIR` with the install step:

```bash
DESTDIR=/tmp/stage cmake --install apps/padlock/build --prefix /usr
```

The install step places:

- `libpadlock.so` in `/usr/lib`
- `libpadlock.a` in `/usr/lib`
- `padlock` in `/usr/bin`
- `hardcode/padlock.h` in `/usr/include/hardcode`
- `hardcode/padlock_guard.h` in `/usr/include/hardcode`

### Runtime Setup

#### TPM device access

The TPM helper path opens `/dev/tpmrm0` first and falls back to `/dev/tpm0`.
On Ubuntu and Debian systems those devices are typically owned by `tss`, so add the user to that group:

```bash
sudo usermod -aG tss ryan
```

The new group membership does not apply to an existing shell session. Log out and log back in, or start a fresh session with:

```bash
newgrp tss
```

You can verify access with:

```bash
id
ls -l /dev/tpmrm0 /dev/tpm0
```

#### PAM service

The `padlock` CLI should use a dedicated PAM service named `padlock` with a password-only stack. This avoids inheriting the host `common-auth` stack, which can pull in modules such as `pam_pkcs11` and block password verification even when the Unix password is correct.

Create `/etc/pam.d/padlock` with:

```pam
auth required pam_unix.so
account required pam_unix.so
```

Make sure the file is readable by the CLI at runtime:

```bash
sudo chown root:root /etc/pam.d/padlock
sudo chmod 0644 /etc/pam.d/padlock
```

If your distribution already has a clean password-only PAM include that you trust, you can adapt the service to use it. Do not point `padlock` at a stack that requires smart cards or other hardware tokens unless that is explicitly what you want.

### Kernel Guard

The guard module exposes `/dev/hardcode_padlock_guard` and uses ioctl calls to:

- register a file as protected
- begin a write session for the current `tgid`
- end that write session
- query the current protection state

While a protected file has no active write session, the module denies write permission, truncation, unlink, and rename attempts for that inode.

## Usage

### Allocate a store

```bash
padlock allocate 2GB
```

Or specify a custom path:

```bash
padlock allocate 2GB /home/ryan/.padlock/custom.plk
```

### Set a value

```bash
padlock set api_key "super-secret-value"
```

With an explicit path:

```bash
padlock set api_key "super-secret-value" /home/ryan/.padlock/custom.plk
```

### Get a value

```bash
padlock get api_key
```

The command prompts once for the Linux password, authenticates it with PAM, derives the header password, unseals the TPM-backed secret, and returns the most recent matching value.

## Files It Creates

- `~/.padlock/store.plk` - encrypted keystore file
- `~/.padlock/tpm/header-hmac.pub` - TPM public blob for the sealed secret
- `~/.padlock/tpm/header-hmac.priv` - TPM private blob for the sealed secret

## Common Setup Problems

- `padlock: authentication: Permission denied` usually means the PAM stack is not password-only, or the typed password was rejected by the active PAM policy.
- `TPM access denied while deriving header password` usually means the active session is not in the `tss` group yet.
- `Esys_Create() ... inconsistent attributes` means the TPM object template is wrong; this was fixed by removing the caller-incompatible `SENSITIVEDATAORIGIN` attribute from the sealed object template.
- If `command -v padlock` shows `/usr/local/bin/padlock`, make sure you installed the updated binary there as well as under `/usr/bin`, or call the binary explicitly by path.

## Remaining Work

This is a working prototype, not a finished security product. The remaining work is:

- Define rotation and backup behavior for the sealed secret blobs and the store file.
- Add corruption detection and recovery for truncated or partially-written stores.
- Add a real policy for key deletion, record compaction, and store growth.
- Add a service wrapper or helper for boot-time store mount/unseal if you want the file loaded before the first lookup.

## Security Notes

- The TPM-sealed secret is only a helper used during header password derivation. The store key itself is still protected by the encrypted header.
- The user password is still the security boundary for the header. TPM protects the secret that HMACs that password; it does not make a weak password strong.
- The current implementation uses PAM to verify the typed password once and direct TPM2 ESAPI calls to create, load, and unseal the TPM blob.
- The kernel guard module is a hardening layer for registered files, not a defense against a compromised kernel or a user who can bypass the guard device.
- The TPM device must still be reachable from the current user or through system permissions for the direct ESAPI path to work.
