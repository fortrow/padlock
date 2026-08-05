CC ?= cc
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

NAME := padlock
VERSION := 0.1.0
BUILD_DIR := build
SRC_DIR := src
INCLUDE_DIR := include
TEST_DIR := tests
KERNEL_DIR := kernel/guard
KERNEL_BUILD ?= /lib/modules/$(shell uname -r)/build

CFLAGS ?= -O2 -g
CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -fPIC -I$(INCLUDE_DIR)
LDLIBS ?= -lcrypto -lpam
LDFLAGS ?=

LIB := $(BUILD_DIR)/lib$(NAME).so
STATIC_LIB := $(BUILD_DIR)/lib$(NAME).a
OBJECTS := $(BUILD_DIR)/padlock.o
TEST_BIN := $(BUILD_DIR)/padlock_test
CLI_BIN := $(BUILD_DIR)/padlock

.PHONY: all clean install test guard guard-clean

all: $(LIB) $(STATIC_LIB) $(CLI_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/padlock.o: $(SRC_DIR)/padlock.c $(INCLUDE_DIR)/hardcode/padlock.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DPADLOCK_VERSION=\"$(VERSION)\" -c $< -o $@

$(LIB): $(OBJECTS)
	$(CC) -shared -Wl,-soname,lib$(NAME).so -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(STATIC_LIB): $(OBJECTS)
	ar rcs $@ $^

$(TEST_BIN): $(TEST_DIR)/padlock_test.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -l$(NAME) $(LDLIBS) -Wl,-rpath,'$$ORIGIN' -o $@

$(CLI_BIN): $(SRC_DIR)/padlock_cli.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -l$(NAME) $(LDLIBS) -Wl,-rpath,'$$ORIGIN' -o $@

test: $(TEST_BIN)
	$(TEST_BIN)

install: all
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)/hardcode
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(LIB) $(DESTDIR)$(LIBDIR)/lib$(NAME).so
	install -m 0755 $(CLI_BIN) $(DESTDIR)$(PREFIX)/bin/padlock
	install -m 0644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/lib$(NAME).a
	install -m 0644 $(INCLUDE_DIR)/hardcode/padlock.h $(DESTDIR)$(INCLUDEDIR)/hardcode/padlock.h
	install -m 0644 $(INCLUDE_DIR)/hardcode/padlock_guard.h $(DESTDIR)$(INCLUDEDIR)/hardcode/padlock_guard.h

guard:
	$(MAKE) -C $(KERNEL_BUILD) M=$(abspath $(KERNEL_DIR)) modules

guard-clean:
	$(MAKE) -C $(KERNEL_BUILD) M=$(abspath $(KERNEL_DIR)) clean

clean:
	rm -rf $(BUILD_DIR)
