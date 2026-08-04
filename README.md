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

```bash
cmake --install apps/padlock/build
```

Use `PREFIX=/usr` or `DESTDIR=/tmp/stage` if you want to stage installation.

The install step places:

- `libpadlock.so` in `$(PREFIX)/lib`
- `libpadlock.a` in `$(PREFIX)/lib`
- `padlock` in `$(PREFIX)/bin`
- `hardcode/padlock.h` in `$(PREFIX)/include/hardcode`
- `hardcode/padlock_guard.h` in `$(PREFIX)/include/hardcode`

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
