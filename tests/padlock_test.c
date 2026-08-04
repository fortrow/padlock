#define _POSIX_C_SOURCE 200809L

#include "hardcode/padlock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int assert_true(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "padlock test failed: %s\n", message);
        return 1;
    }
    return 0;
}

int main(void)
{
    char secret[] = "hardcode";
    char same[] = "hardcode";
    char different[] = "hardfail";
    char path[256];
    char home[256];
    unsigned char *value = 0;
    uint32_t value_length = 0;

    if (assert_true(strcmp(padlock_version(), "0.1.0") == 0, "version should match")) {
        return 1;
    }

    if (assert_true(padlock_constant_time_equals(secret, same, sizeof(secret)) == 1, "equal buffers should match")) {
        return 1;
    }

    if (assert_true(padlock_constant_time_equals(secret, different, sizeof(secret)) == 0, "different buffers should not match")) {
        return 1;
    }

    snprintf(home, sizeof(home), "/tmp/padlock-home-%ld", (long) getpid());
    mkdir(home, 0700);
    setenv("HOME", home, 1);
    padlock_secure_zero(secret, sizeof(secret));
    for (size_t index = 0; index < sizeof(secret); index++) {
        if (assert_true(secret[index] == 0, "secure zero should clear buffer")) {
            return 1;
        }
    }

    snprintf(path, sizeof(path), "/tmp/padlock-test-%ld.plk", (long) getpid());
    if (assert_true(padlock_allocate(path, 16384, "header-password") == 0, "allocate should create store")) {
        return 1;
    }
    if (assert_true(padlock_set(path, "header-password", "key1", "one", 3) == 0, "set key1=one should succeed")) {
        return 1;
    }
    if (assert_true(padlock_set(path, "header-password", "key2", "two", 3) == 0, "set key2=two should succeed")) {
        return 1;
    }
    if (assert_true(padlock_set(path, "header-password", "key1", "updated", 7) == 0, "duplicate key update should append")) {
        return 1;
    }
    if (assert_true(padlock_get(path, "header-password", "key1", &value, &value_length) == 0, "get key1 should succeed")) {
        return 1;
    }
    if (assert_true(value_length == 7 && memcmp(value, "updated", 7) == 0, "get should return last duplicate key value")) {
        padlock_free(value);
        return 1;
    }
    padlock_free(value);
    unlink(path);

    puts("padlock tests passed");
    return 0;
}
