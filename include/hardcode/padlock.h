#ifndef HARDCODE_PADLOCK_H
#define HARDCODE_PADLOCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
  #if defined(PADLOCK_BUILD)
    #define PADLOCK_API __declspec(dllexport)
  #else
    #define PADLOCK_API __declspec(dllimport)
  #endif
#else
  #define PADLOCK_API __attribute__((visibility("default")))
#endif

PADLOCK_API const char *padlock_version(void);
PADLOCK_API int padlock_constant_time_equals(const void *left, const void *right, size_t length);
PADLOCK_API void padlock_secure_zero(void *buffer, size_t length);
PADLOCK_API int padlock_parse_size(const char *value, uint64_t *bytes);
PADLOCK_API int padlock_default_store_path(char *buffer, size_t buffer_length);
PADLOCK_API int padlock_allocate(const char *path, uint64_t size, const char *password);
PADLOCK_API int padlock_set(const char *path, const char *password, const char *key, const void *value, uint32_t value_length);
PADLOCK_API int padlock_get(const char *path, const char *password, const char *key, unsigned char **value, uint32_t *value_length);
PADLOCK_API int padlock_derive_header_password(const char *login_password, char *output, size_t output_length);
PADLOCK_API int padlock_derive_user_header_password(const char *username, char *output, size_t output_length);
PADLOCK_API void padlock_free(void *value);

#ifdef __cplusplus
}
#endif

#endif
