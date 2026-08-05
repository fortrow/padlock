obj-m += hardcode_padlock_guard.o

ccflags-y += -I$(src)/../../include
CFLAGS_hardcode_padlock_guard.o += -mfunction-return=thunk-inline -mindirect-branch=thunk-inline
CFLAGS_hardcode_padlock_guard.o += -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
OBJECT_FILES_NON_STANDARD_hardcode_padlock_guard.o := y
