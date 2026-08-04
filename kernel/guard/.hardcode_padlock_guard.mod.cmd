savedcmd_hardcode_padlock_guard.mod := printf '%s\n'   hardcode_padlock_guard.o | awk '!x[$$0]++ { print("./"$$0) }' > hardcode_padlock_guard.mod
