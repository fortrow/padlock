#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L

#include "hardcode/padlock.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef PADLOCK_VERSION
#define PADLOCK_VERSION "0.1.0"
#endif

#define PADLOCK_MAGIC "PADLOCK"
#define PADLOCK_SECRET_MAGIC "PLSECRET"
#define PADLOCK_HEADER_SIZE 4096u
#define PADLOCK_SALT_SIZE 16u
#define PADLOCK_IV_SIZE 16u
#define PADLOCK_XTS_KEY_SIZE 64u
#define PADLOCK_TPM_KEY_SIZE 32u
#define PADLOCK_SECRET_SIZE 72u
#define PADLOCK_MIN_SIZE 8192u
#define PADLOCK_KDF_ITERATIONS 200000
#define PADLOCK_TPM_DIR ".padlock/tpm"
#define PADLOCK_TPM_SECRET_PUBLIC "header-hmac.pub"
#define PADLOCK_TPM_SECRET_PRIVATE "header-hmac.priv"

typedef struct {
    uint64_t total_size;
    uint64_t write_offset;
    unsigned char salt[PADLOCK_SALT_SIZE];
    unsigned char iv[PADLOCK_IV_SIZE];
    unsigned char encrypted_secret[128];
    uint32_t encrypted_secret_size;
} padlock_header;

static int padlock_tpm_write_public_blob(FILE *file, const TPM2B_PUBLIC *blob);
static int padlock_tpm_write_private_blob(FILE *file, const TPM2B_PRIVATE *blob);
static int padlock_tpm_read_public_blob(FILE *file, TPM2B_PUBLIC *blob);
static int padlock_tpm_read_private_blob(FILE *file, TPM2B_PRIVATE *blob);

static uint64_t align16(uint64_t value)
{
    return (value + 15u) & ~15u;
}

static void put_u32(unsigned char *target, uint32_t value)
{
    target[0] = (unsigned char) (value & 0xffu);
    target[1] = (unsigned char) ((value >> 8u) & 0xffu);
    target[2] = (unsigned char) ((value >> 16u) & 0xffu);
    target[3] = (unsigned char) ((value >> 24u) & 0xffu);
}

static uint32_t get_u32(const unsigned char *source)
{
    return ((uint32_t) source[0])
        | ((uint32_t) source[1] << 8u)
        | ((uint32_t) source[2] << 16u)
        | ((uint32_t) source[3] << 24u);
}

static void put_u64(unsigned char *target, uint64_t value)
{
    for (size_t index = 0; index < 8u; index++) {
        target[index] = (unsigned char) ((value >> (index * 8u)) & 0xffu);
    }
}

static uint64_t get_u64(const unsigned char *source)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8u; index++) {
        value |= ((uint64_t) source[index]) << (index * 8u);
    }
    return value;
}

static int ensure_directory_tree(const char *path)
{
    char copy[PATH_MAX];
    size_t length;

    if (path == 0) {
        return -1;
    }

    length = strlen(path);
    if (length == 0 || length >= sizeof(copy)) {
        return -1;
    }

    memcpy(copy, path, length + 1u);
    for (char *cursor = copy + 1; *cursor != '\0'; cursor++) {
        if (*cursor != '/') {
            continue;
        }
        *cursor = '\0';
        if (mkdir(copy, 0700) != 0 && errno != EEXIST) {
            return -1;
        }
        chmod(copy, 0700);
        *cursor = '/';
    }

    if (mkdir(copy, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    chmod(copy, 0700);
    return 0;
}

static int padlock_tpm_paths(
    char *directory,
    size_t directory_length,
    char *public_path,
    size_t public_length,
    char *private_path,
    size_t private_length
)
{
    const char *home = getenv("HOME");

    if (home == 0) {
        return -1;
    }

    if (snprintf(directory, directory_length, "%s/%s", home, PADLOCK_TPM_DIR) >= (int) directory_length) {
        return -1;
    }
    if (snprintf(public_path, public_length, "%s/%s", directory, PADLOCK_TPM_SECRET_PUBLIC) >= (int) public_length) {
        return -1;
    }
    if (snprintf(private_path, private_length, "%s/%s", directory, PADLOCK_TPM_SECRET_PRIVATE) >= (int) private_length) {
        return -1;
    }
    return 0;
}

static void padlock_tpm_free_tcti(TSS2_TCTI_CONTEXT **tcti)
{
    if (tcti != 0 && *tcti != 0) {
        Tss2_TctiLdr_Finalize(tcti);
    }
}

static int padlock_tpm_connect(ESYS_CONTEXT **esys, TSS2_TCTI_CONTEXT **tcti)
{
    TSS2_RC rc;
    TSS2_ABI_VERSION abi = TSS2_ABI_VERSION_CURRENT;

    if (esys == 0 || tcti == 0) {
        return -1;
    }

    *tcti = 0;
    *esys = 0;

    rc = Tss2_TctiLdr_Initialize("device:/dev/tpmrm0", tcti);
    if (rc != TSS2_RC_SUCCESS) {
        rc = Tss2_TctiLdr_Initialize("device:/dev/tpm0", tcti);
    }
    if (rc != TSS2_RC_SUCCESS) {
        padlock_tpm_free_tcti(tcti);
        return -1;
    }

    rc = Esys_Initialize(esys, *tcti, &abi);
    if (rc != TSS2_RC_SUCCESS) {
        padlock_tpm_free_tcti(tcti);
        *esys = 0;
        return -1;
    }
    return 0;
}

static void padlock_tpm_disconnect(ESYS_CONTEXT **esys, TSS2_TCTI_CONTEXT **tcti)
{
    if (esys != 0 && *esys != 0) {
        Esys_Finalize(esys);
    }
    padlock_tpm_free_tcti(tcti);
}

static int padlock_tpm_write_blob(
    FILE *file,
    const void *blob,
    size_t blob_size,
    TSS2_RC (*marshal)(const void *, uint8_t *, size_t, size_t *)
)
{
    uint8_t *buffer;
    size_t offset = 0;
    size_t written = 0;
    int result = -1;

    buffer = calloc(1u, blob_size);
    if (buffer == 0) {
        return -1;
    }

    if (marshal(blob, buffer, blob_size, &offset) != TSS2_RC_SUCCESS) {
        goto done;
    }

    written = fwrite(buffer, 1u, offset, file);
    result = written == offset ? 0 : -1;

done:
    padlock_secure_zero(buffer, blob_size);
    free(buffer);
    return result;
}

static int padlock_tpm_read_blob(
    FILE *file,
    void *blob,
    size_t blob_size,
    TSS2_RC (*unmarshal)(const uint8_t *, size_t, size_t *, void *)
)
{
    long file_size;
    size_t offset = 0;
    uint8_t *buffer = 0;
    int result = -1;

    if (fseek(file, 0, SEEK_END) != 0) {
        return -1;
    }

    file_size = ftell(file);
    if (file_size <= 0 || (size_t) file_size > blob_size) {
        return -1;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        return -1;
    }

    buffer = malloc((size_t) file_size);
    if (buffer == 0) {
        return -1;
    }

    if (fread(buffer, 1u, (size_t) file_size, file) != (size_t) file_size) {
        goto done;
    }

    if (unmarshal(buffer, (size_t) file_size, &offset, blob) != TSS2_RC_SUCCESS || offset != (size_t) file_size) {
        goto done;
    }

    result = 0;

done:
    padlock_secure_zero(buffer, (size_t) file_size > 0 ? (size_t) file_size : 0u);
    free(buffer);
    return result;
}

static int padlock_tpm_build_primary_template(TPM2B_PUBLIC *public_template)
{
    if (public_template == 0) {
        return -1;
    }

    memset(public_template, 0, sizeof(*public_template));
    public_template->publicArea.type = TPM2_ALG_RSA;
    public_template->publicArea.nameAlg = TPM2_ALG_SHA256;
    public_template->publicArea.objectAttributes =
        TPMA_OBJECT_USERWITHAUTH
        | TPMA_OBJECT_RESTRICTED
        | TPMA_OBJECT_DECRYPT
        | TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN;
    public_template->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    public_template->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    public_template->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    public_template->publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    public_template->publicArea.parameters.rsaDetail.keyBits = 2048;
    public_template->publicArea.parameters.rsaDetail.exponent = 0;
    public_template->publicArea.unique.rsa.size = 0;
    public_template->size = 0;
    return 0;
}

static int padlock_tpm_build_seal_template(TPM2B_SENSITIVE_CREATE *in_sensitive, TPM2B_PUBLIC *public_template, const unsigned char secret[32])
{
    if (in_sensitive == 0 || public_template == 0 || secret == 0) {
        return -1;
    }

    memset(in_sensitive, 0, sizeof(*in_sensitive));
    in_sensitive->sensitive.userAuth.size = 0;
    in_sensitive->sensitive.data.size = PADLOCK_TPM_KEY_SIZE;
    memcpy(in_sensitive->sensitive.data.buffer, secret, in_sensitive->sensitive.data.size);

    memset(public_template, 0, sizeof(*public_template));
    public_template->publicArea.type = TPM2_ALG_KEYEDHASH;
    public_template->publicArea.nameAlg = TPM2_ALG_SHA256;
    public_template->publicArea.objectAttributes =
        TPMA_OBJECT_USERWITHAUTH
        | TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN;
    public_template->publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    public_template->publicArea.unique.keyedHash.size = 0;
    public_template->size = 0;
    return 0;
}

static int padlock_tpm_create_sealed_secret(
    ESYS_CONTEXT *esys,
    const char *public_path,
    const char *private_path,
    const unsigned char secret[32]
)
{
    TPM2B_PUBLIC primary_public = {0};
    TPM2B_PUBLIC seal_public = {0};
    TPM2B_SENSITIVE_CREATE primary_sensitive = {0};
    TPM2B_SENSITIVE_CREATE seal_sensitive = {0};
    TPM2B_DATA outside_info = {0};
    TPML_PCR_SELECTION creation_pcr = {0};
    TPM2B_AUTH empty_auth = {0};
    ESYS_TR primary_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC *out_primary_public = 0;
    TPM2B_CREATION_DATA *primary_creation_data = 0;
    TPM2B_DIGEST *primary_creation_hash = 0;
    TPMT_TK_CREATION *primary_creation_ticket = 0;
    TPM2B_PRIVATE *out_private = 0;
    TPM2B_PUBLIC *out_public = 0;
    TPM2B_CREATION_DATA *seal_creation_data = 0;
    TPM2B_DIGEST *seal_creation_hash = 0;
    TPMT_TK_CREATION *seal_creation_ticket = 0;
    FILE *public_file = 0;
    FILE *private_file = 0;
    int result = -1;

    if (padlock_tpm_build_primary_template(&primary_public) != 0
        || padlock_tpm_build_seal_template(&seal_sensitive, &seal_public, secret) != 0) {
        return -1;
    }

    if (Esys_TR_SetAuth(esys, ESYS_TR_RH_OWNER, &empty_auth) != TSS2_RC_SUCCESS) {
        return -1;
    }

    if (Esys_CreatePrimary(
        esys,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &primary_sensitive,
        &primary_public,
        &outside_info,
        &creation_pcr,
        &primary_handle,
        &out_primary_public,
        &primary_creation_data,
        &primary_creation_hash,
        &primary_creation_ticket
    ) != TSS2_RC_SUCCESS) {
        goto done;
    }

    if (Esys_TR_SetAuth(esys, primary_handle, &empty_auth) != TSS2_RC_SUCCESS) {
        goto done;
    }

    if (Esys_Create(
        esys,
        primary_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &seal_sensitive,
        &seal_public,
        &outside_info,
        &creation_pcr,
        &out_private,
        &out_public,
        &seal_creation_data,
        &seal_creation_hash,
        &seal_creation_ticket
    ) != TSS2_RC_SUCCESS) {
        goto done;
    }

    public_file = fopen(public_path, "wb");
    private_file = fopen(private_path, "wb");
    if (public_file == 0 || private_file == 0) {
        goto done;
    }

    if (padlock_tpm_write_public_blob(public_file, out_public) != 0
        || padlock_tpm_write_private_blob(private_file, out_private) != 0) {
        goto done;
    }

    result = 0;

done:
    if (public_file != 0) {
        fclose(public_file);
    }
    if (private_file != 0) {
        fclose(private_file);
    }
    if (primary_handle != ESYS_TR_NONE) {
        Esys_FlushContext(esys, primary_handle);
    }
    Esys_Free(out_primary_public);
    Esys_Free(primary_creation_data);
    Esys_Free(primary_creation_hash);
    Esys_Free(primary_creation_ticket);
    Esys_Free(out_private);
    Esys_Free(out_public);
    Esys_Free(seal_creation_data);
    Esys_Free(seal_creation_hash);
    Esys_Free(seal_creation_ticket);
    return result;
}

static int padlock_tpm_unseal_secret(
    ESYS_CONTEXT *esys,
    const char *public_path,
    const char *private_path,
    unsigned char key[32]
)
{
    TPM2B_PUBLIC *seal_public = 0;
    TPM2B_PRIVATE *seal_private = 0;
    TPM2B_PUBLIC parent_public = {0};
    TPM2B_SENSITIVE_CREATE parent_sensitive = {0};
    TPM2B_DATA outside_info = {0};
    TPML_PCR_SELECTION creation_pcr = {0};
    TPM2B_AUTH empty_auth = {0};
    ESYS_TR primary_handle = ESYS_TR_NONE;
    ESYS_TR loaded_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC *out_primary_public = 0;
    TPM2B_CREATION_DATA *primary_creation_data = 0;
    TPM2B_DIGEST *primary_creation_hash = 0;
    TPMT_TK_CREATION *primary_creation_ticket = 0;
    TPM2B_SENSITIVE_DATA *unsealed = 0;
    FILE *public_file = 0;
    FILE *private_file = 0;
    int result = -1;

    public_file = fopen(public_path, "rb");
    private_file = fopen(private_path, "rb");
    if (public_file == 0 || private_file == 0) {
        goto done;
    }

    seal_public = calloc(1u, sizeof(*seal_public));
    seal_private = calloc(1u, sizeof(*seal_private));
    if (seal_public == 0 || seal_private == 0) {
        goto done;
    }

    if (padlock_tpm_read_public_blob(public_file, seal_public) != 0
        || padlock_tpm_read_private_blob(private_file, seal_private) != 0) {
        goto done;
    }

    if (padlock_tpm_build_primary_template(&parent_public) != 0) {
        goto done;
    }

    if (Esys_TR_SetAuth(esys, ESYS_TR_RH_OWNER, &empty_auth) != TSS2_RC_SUCCESS) {
        goto done;
    }

    if (Esys_CreatePrimary(
        esys,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &parent_sensitive,
        &parent_public,
        &outside_info,
        &creation_pcr,
        &primary_handle,
        &out_primary_public,
        &primary_creation_data,
        &primary_creation_hash,
        &primary_creation_ticket
    ) != TSS2_RC_SUCCESS) {
        goto done;
    }

    if (Esys_TR_SetAuth(esys, primary_handle, &empty_auth) != TSS2_RC_SUCCESS) {
        goto done;
    }

    if (Esys_Load(
        esys,
        primary_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        seal_private,
        seal_public,
        &loaded_handle
    ) != TSS2_RC_SUCCESS) {
        goto done;
    }

    if (Esys_TR_SetAuth(esys, loaded_handle, &empty_auth) != TSS2_RC_SUCCESS) {
        goto done;
    }

    if (Esys_Unseal(
        esys,
        loaded_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &unsealed
    ) != TSS2_RC_SUCCESS || unsealed == 0 || unsealed->size < PADLOCK_TPM_KEY_SIZE) {
        goto done;
    }

    memcpy(key, unsealed->buffer, PADLOCK_TPM_KEY_SIZE);
    result = 0;

done:
    if (public_file != 0) {
        fclose(public_file);
    }
    if (private_file != 0) {
        fclose(private_file);
    }
    if (primary_handle != ESYS_TR_NONE) {
        Esys_FlushContext(esys, primary_handle);
    }
    if (loaded_handle != ESYS_TR_NONE) {
        Esys_FlushContext(esys, loaded_handle);
    }
    Esys_Free(out_primary_public);
    Esys_Free(primary_creation_data);
    Esys_Free(primary_creation_hash);
    Esys_Free(primary_creation_ticket);
    Esys_Free(unsealed);
    free(seal_public);
    free(seal_private);
    return result;
}

static int padlock_tpm_ensure_sealed_key(unsigned char key[32])
{
    char directory[PATH_MAX] = {0};
    char public_path[PATH_MAX] = {0};
    char private_path[PATH_MAX] = {0};
    unsigned char random_key[32];
    ESYS_CONTEXT *esys = 0;
    TSS2_TCTI_CONTEXT *tcti = 0;
    int result = -1;

    if (padlock_tpm_paths(directory, sizeof(directory), public_path, sizeof(public_path), private_path, sizeof(private_path)) != 0) {
        return -1;
    }
    if (ensure_directory_tree(directory) != 0) {
        return -1;
    }

    if (access(public_path, R_OK) != 0 || access(private_path, R_OK) != 0) {
        if (RAND_bytes(random_key, sizeof(random_key)) != 1) {
            return -1;
        }
        if (padlock_tpm_connect(&esys, &tcti) != 0) {
            padlock_secure_zero(random_key, sizeof(random_key));
            return -1;
        }
        result = padlock_tpm_create_sealed_secret(esys, public_path, private_path, random_key);
        padlock_secure_zero(random_key, sizeof(random_key));
        padlock_tpm_disconnect(&esys, &tcti);
        if (result != 0) {
            return -1;
        }
    }

    if (padlock_tpm_connect(&esys, &tcti) != 0) {
        return -1;
    }
    result = padlock_tpm_unseal_secret(esys, public_path, private_path, key);
    padlock_tpm_disconnect(&esys, &tcti);
    return result;
}

const char *padlock_version(void)
{
    return PADLOCK_VERSION;
}

int padlock_constant_time_equals(const void *left, const void *right, size_t length)
{
    const unsigned char *left_bytes = (const unsigned char *) left;
    const unsigned char *right_bytes = (const unsigned char *) right;
    unsigned char diff = 0;

    if (left == 0 || right == 0) {
        return left == right && length == 0;
    }

    for (size_t index = 0; index < length; index++) {
        diff |= (unsigned char) (left_bytes[index] ^ right_bytes[index]);
    }

    return diff == 0;
}

void padlock_secure_zero(void *buffer, size_t length)
{
    volatile unsigned char *bytes = (volatile unsigned char *) buffer;

    if (buffer == 0) {
        return;
    }

    while (length > 0) {
        *bytes++ = 0;
        length--;
    }
}

void padlock_free(void *value)
{
    free(value);
}

int padlock_derive_header_password(const char *login_password, char *output, size_t output_length)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned char hmac_key[32];
    unsigned int digest_length = 0;
    static const char hex[] = "0123456789abcdef";

    if (login_password == 0 || login_password[0] == '\0' || output == 0 || output_length < 65u) {
        return -1;
    }

    if (padlock_tpm_ensure_sealed_key(hmac_key) != 0) {
        return -1;
    }

    if (HMAC(
        EVP_sha256(),
        hmac_key,
        (int) sizeof(hmac_key),
        (const unsigned char *) login_password,
        strlen(login_password),
        digest,
        &digest_length
    ) == 0 || digest_length != 32u) {
        padlock_secure_zero(hmac_key, sizeof(hmac_key));
        return -1;
    }

    for (size_t index = 0; index < digest_length; index++) {
        output[index * 2u] = hex[(digest[index] >> 4u) & 0x0fu];
        output[index * 2u + 1u] = hex[digest[index] & 0x0fu];
    }
    output[digest_length * 2u] = '\0';
    padlock_secure_zero(digest, sizeof(digest));
    padlock_secure_zero(hmac_key, sizeof(hmac_key));
    return 0;
}

int padlock_parse_size(const char *value, uint64_t *bytes)
{
    char *end = 0;
    unsigned long long number;
    uint64_t multiplier = 1u;

    if (value == 0 || bytes == 0 || value[0] == '\0') {
        return -1;
    }

    errno = 0;
    number = strtoull(value, &end, 10);
    if (errno != 0 || end == value) {
        return -1;
    }

    if (strcasecmp(end, "KB") == 0 || strcasecmp(end, "K") == 0) {
        multiplier = 1024ull;
    } else if (strcasecmp(end, "MB") == 0 || strcasecmp(end, "M") == 0) {
        multiplier = 1024ull * 1024ull;
    } else if (strcasecmp(end, "GB") == 0 || strcasecmp(end, "G") == 0) {
        multiplier = 1024ull * 1024ull * 1024ull;
    } else if (strcasecmp(end, "B") != 0 && end[0] != '\0') {
        return -1;
    }

    if (number > ULLONG_MAX / multiplier) {
        return -1;
    }

    *bytes = (uint64_t) number * multiplier;
    return 0;
}

int padlock_default_store_path(char *buffer, size_t buffer_length)
{
    const char *home = getenv("HOME");
    int written;

    if (home == 0 || buffer == 0 || buffer_length == 0) {
        return -1;
    }

    written = snprintf(buffer, buffer_length, "%s/.padlock/store.plk", home);
    return written > 0 && (size_t) written < buffer_length ? 0 : -1;
}

static int ensure_parent_directory(const char *path)
{
    char copy[PATH_MAX];
    char *slash;

    if (snprintf(copy, sizeof(copy), "%s", path) >= (int) sizeof(copy)) {
        return -1;
    }

    slash = strrchr(copy, '/');
    if (slash == 0) {
        return 0;
    }
    *slash = '\0';

    if (mkdir(copy, 0700) == 0 || errno == EEXIST) {
        chmod(copy, 0700);
        return 0;
    }
    return -1;
}

static int derive_header_key(const char *password, const unsigned char salt[PADLOCK_SALT_SIZE], unsigned char key[32])
{
    if (password == 0 || password[0] == '\0') {
        return -1;
    }

    return PKCS5_PBKDF2_HMAC(
        password,
        (int) strlen(password),
        salt,
        PADLOCK_SALT_SIZE,
        PADLOCK_KDF_ITERATIONS,
        EVP_sha256(),
        32,
        key
    ) == 1 ? 0 : -1;
}

static int encrypt_secret(const char *password, padlock_header *header, const unsigned char xts_key[PADLOCK_XTS_KEY_SIZE])
{
    unsigned char key[32];
    unsigned char secret[PADLOCK_SECRET_SIZE];
    EVP_CIPHER_CTX *ctx = 0;
    int out_len = 0;
    int final_len = 0;
    int ok = -1;

    memset(secret, 0, sizeof(secret));
    memcpy(secret, PADLOCK_SECRET_MAGIC, strlen(PADLOCK_SECRET_MAGIC));
    memcpy(secret + 8u, xts_key, PADLOCK_XTS_KEY_SIZE);

    if (derive_header_key(password, header->salt, key) != 0) {
        goto done;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == 0) {
        goto done;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), 0, key, header->iv) != 1) {
        goto done;
    }
    if (EVP_EncryptUpdate(ctx, header->encrypted_secret, &out_len, secret, (int) sizeof(secret)) != 1) {
        goto done;
    }
    if (EVP_EncryptFinal_ex(ctx, header->encrypted_secret + out_len, &final_len) != 1) {
        goto done;
    }

    header->encrypted_secret_size = (uint32_t) (out_len + final_len);
    ok = 0;

done:
    if (ctx != 0) {
        EVP_CIPHER_CTX_free(ctx);
    }
    padlock_secure_zero(key, PADLOCK_TPM_KEY_SIZE);
    padlock_secure_zero(secret, sizeof(secret));
    return ok;
}

static int decrypt_secret(const char *password, const padlock_header *header, unsigned char xts_key[PADLOCK_XTS_KEY_SIZE])
{
    unsigned char key[32];
    unsigned char secret[PADLOCK_SECRET_SIZE + 16u];
    EVP_CIPHER_CTX *ctx = 0;
    int out_len = 0;
    int final_len = 0;
    int ok = -1;

    memset(secret, 0, sizeof(secret));
    if (header->encrypted_secret_size > sizeof(header->encrypted_secret)) {
        return -1;
    }
    if (derive_header_key(password, header->salt, key) != 0) {
        goto done;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == 0) {
        goto done;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), 0, key, header->iv) != 1) {
        goto done;
    }
    if (EVP_DecryptUpdate(ctx, secret, &out_len, header->encrypted_secret, (int) header->encrypted_secret_size) != 1) {
        goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, secret + out_len, &final_len) != 1) {
        goto done;
    }
    if ((size_t) (out_len + final_len) < PADLOCK_SECRET_SIZE) {
        goto done;
    }
    if (memcmp(secret, PADLOCK_SECRET_MAGIC, strlen(PADLOCK_SECRET_MAGIC)) != 0) {
        goto done;
    }

    memcpy(xts_key, secret + 8u, PADLOCK_XTS_KEY_SIZE);
    ok = 0;

done:
    if (ctx != 0) {
        EVP_CIPHER_CTX_free(ctx);
    }
    padlock_secure_zero(key, PADLOCK_TPM_KEY_SIZE);
    padlock_secure_zero(secret, sizeof(secret));
    return ok;
}

static int write_header(FILE *file, const padlock_header *header)
{
    unsigned char buffer[PADLOCK_HEADER_SIZE];

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, PADLOCK_MAGIC, strlen(PADLOCK_MAGIC));
    put_u32(buffer + 8u, 1u);
    put_u64(buffer + 16u, PADLOCK_HEADER_SIZE);
    put_u64(buffer + 24u, header->total_size);
    put_u64(buffer + 32u, header->write_offset);
    memcpy(buffer + 40u, header->salt, PADLOCK_SALT_SIZE);
    memcpy(buffer + 56u, header->iv, PADLOCK_IV_SIZE);
    put_u32(buffer + 72u, header->encrypted_secret_size);
    memcpy(buffer + 76u, header->encrypted_secret, sizeof(header->encrypted_secret));

    if (fseeko(file, 0, SEEK_SET) != 0) {
        return -1;
    }
    return fwrite(buffer, 1u, sizeof(buffer), file) == sizeof(buffer) ? 0 : -1;
}

static int read_header(FILE *file, padlock_header *header)
{
    unsigned char buffer[PADLOCK_HEADER_SIZE];

    if (fseeko(file, 0, SEEK_SET) != 0) {
        return -1;
    }
    if (fread(buffer, 1u, sizeof(buffer), file) != sizeof(buffer)) {
        return -1;
    }
    if (memcmp(buffer, PADLOCK_MAGIC, strlen(PADLOCK_MAGIC)) != 0 || get_u32(buffer + 8u) != 1u) {
        return -1;
    }

    memset(header, 0, sizeof(*header));
    header->total_size = get_u64(buffer + 24u);
    header->write_offset = get_u64(buffer + 32u);
    memcpy(header->salt, buffer + 40u, PADLOCK_SALT_SIZE);
    memcpy(header->iv, buffer + 56u, PADLOCK_IV_SIZE);
    header->encrypted_secret_size = get_u32(buffer + 72u);
    memcpy(header->encrypted_secret, buffer + 76u, sizeof(header->encrypted_secret));

    if (header->total_size < PADLOCK_MIN_SIZE
        || header->write_offset < PADLOCK_HEADER_SIZE
        || header->write_offset > header->total_size
        || header->encrypted_secret_size > sizeof(header->encrypted_secret)) {
        return -1;
    }
    return 0;
}

static int crypt_xts(
    int encrypt,
    const unsigned char xts_key[PADLOCK_XTS_KEY_SIZE],
    uint64_t file_offset,
    const unsigned char *input,
    unsigned char *output,
    size_t length
)
{
    EVP_CIPHER_CTX *ctx = 0;
    unsigned char tweak[16];
    int out_len = 0;
    int final_len = 0;
    int ok = -1;

    memset(tweak, 0, sizeof(tweak));
    put_u64(tweak, file_offset / 16u);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == 0) {
        goto done;
    }

    if ((encrypt
        ? EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), 0, xts_key, tweak)
        : EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), 0, xts_key, tweak)) != 1) {
        goto done;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if ((encrypt
        ? EVP_EncryptUpdate(ctx, output, &out_len, input, (int) length)
        : EVP_DecryptUpdate(ctx, output, &out_len, input, (int) length)) != 1) {
        goto done;
    }
    if ((encrypt
        ? EVP_EncryptFinal_ex(ctx, output + out_len, &final_len)
        : EVP_DecryptFinal_ex(ctx, output + out_len, &final_len)) != 1) {
        goto done;
    }

    ok = (size_t) (out_len + final_len) == length ? 0 : -1;

done:
    if (ctx != 0) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return ok;
}

int padlock_allocate(const char *path, uint64_t size, const char *password)
{
    FILE *file = 0;
    unsigned char chunk[65536];
    unsigned char xts_key[PADLOCK_XTS_KEY_SIZE];
    padlock_header header;
    uint64_t remaining;
    int ok = -1;

    if (path == 0 || password == 0 || size < PADLOCK_MIN_SIZE) {
        return -1;
    }
    if (ensure_parent_directory(path) != 0) {
        return -1;
    }

    file = fopen(path, "wb+");
    if (file == 0) {
        return -1;
    }
    chmod(path, 0600);

    remaining = size;
    while (remaining > 0) {
        size_t amount = remaining > sizeof(chunk) ? sizeof(chunk) : (size_t) remaining;
        if (RAND_bytes(chunk, (int) amount) != 1 || fwrite(chunk, 1u, amount, file) != amount) {
            goto done;
        }
        remaining -= amount;
    }

    memset(&header, 0, sizeof(header));
    header.total_size = size;
    header.write_offset = PADLOCK_HEADER_SIZE;
    if (RAND_bytes(header.salt, PADLOCK_SALT_SIZE) != 1
        || RAND_bytes(header.iv, PADLOCK_IV_SIZE) != 1
        || RAND_bytes(xts_key, PADLOCK_XTS_KEY_SIZE) != 1) {
        goto done;
    }

    if (encrypt_secret(password, &header, xts_key) != 0 || write_header(file, &header) != 0) {
        goto done;
    }

    ok = 0;

done:
    if (file != 0) {
        fclose(file);
    }
    padlock_secure_zero(chunk, sizeof(chunk));
    padlock_secure_zero(xts_key, sizeof(xts_key));
    return ok;
}

int padlock_set(const char *path, const char *password, const char *key, const void *value, uint32_t value_length)
{
    FILE *file = 0;
    padlock_header header;
    unsigned char xts_key[PADLOCK_XTS_KEY_SIZE];
    unsigned char *plain = 0;
    unsigned char *cipher = 0;
    size_t key_length;
    uint64_t plain_length;
    uint64_t padded_length;
    int ok = -1;

    if (path == 0 || password == 0 || key == 0 || value == 0) {
        return -1;
    }

    key_length = strlen(key);
    if (key_length == 0 || key_length > 255u) {
        return -1;
    }

    file = fopen(path, "rb+");
    if (file == 0 || read_header(file, &header) != 0 || decrypt_secret(password, &header, xts_key) != 0) {
        goto done;
    }

    plain_length = 1u + key_length + 4u + value_length;
    padded_length = align16(plain_length);
    if (padded_length < 16u || header.write_offset + padded_length > header.total_size) {
        goto done;
    }

    plain = calloc(1u, (size_t) padded_length);
    cipher = malloc((size_t) padded_length);
    if (plain == 0 || cipher == 0) {
        goto done;
    }

    plain[0] = (unsigned char) key_length;
    memcpy(plain + 1u, key, key_length);
    put_u32(plain + 1u + key_length, value_length);
    memcpy(plain + 1u + key_length + 4u, value, value_length);

    if (crypt_xts(1, xts_key, header.write_offset, plain, cipher, (size_t) padded_length) != 0) {
        goto done;
    }
    if (fseeko(file, (off_t) header.write_offset, SEEK_SET) != 0
        || fwrite(cipher, 1u, (size_t) padded_length, file) != padded_length) {
        goto done;
    }

    header.write_offset += padded_length;
    if (write_header(file, &header) != 0) {
        goto done;
    }
    ok = 0;

done:
    if (file != 0) {
        fclose(file);
    }
    if (plain != 0) {
        padlock_secure_zero(plain, (size_t) padded_length);
        free(plain);
    }
    free(cipher);
    padlock_secure_zero(xts_key, sizeof(xts_key));
    return ok;
}

int padlock_get(const char *path, const char *password, const char *key, unsigned char **value, uint32_t *value_length)
{
    FILE *file = 0;
    padlock_header header;
    unsigned char xts_key[PADLOCK_XTS_KEY_SIZE];
    unsigned char cipher[16];
    unsigned char block[16];
    unsigned char *found = 0;
    size_t key_length;
    uint32_t found_length = 0;
    uint64_t offset = PADLOCK_HEADER_SIZE;
    int ok = -1;

    if (path == 0 || password == 0 || key == 0 || value == 0 || value_length == 0) {
        return -1;
    }
    *value = 0;
    *value_length = 0;
    key_length = strlen(key);

    file = fopen(path, "rb");
    if (file == 0 || read_header(file, &header) != 0 || decrypt_secret(password, &header, xts_key) != 0) {
        goto done;
    }

    while (offset + sizeof(block) <= header.write_offset) {
        unsigned char key_size;
        uint32_t current_value_length;
        uint64_t prefix_length;
        uint64_t entry_length;
        uint64_t padded_length;
        unsigned char *entry_cipher = 0;
        unsigned char *entry_plain = 0;
        unsigned char *prefix_cipher = 0;
        unsigned char *prefix_plain = 0;

        if (fseeko(file, (off_t) offset, SEEK_SET) != 0 || fread(cipher, 1u, sizeof(cipher), file) != sizeof(cipher)) {
            goto done;
        }
        if (crypt_xts(0, xts_key, offset, cipher, block, sizeof(block)) != 0) {
            goto done;
        }

        key_size = block[0];
        if (key_size == 0) {
            goto done;
        }

        prefix_length = align16(1u + key_size + 4u);
        if (offset + prefix_length > header.write_offset) {
            goto done;
        }

        prefix_cipher = malloc((size_t) prefix_length);
        prefix_plain = malloc((size_t) prefix_length);
        if (prefix_cipher == 0 || prefix_plain == 0) {
            free(prefix_cipher);
            free(prefix_plain);
            goto done;
        }
        if (fseeko(file, (off_t) offset, SEEK_SET) != 0
            || fread(prefix_cipher, 1u, (size_t) prefix_length, file) != prefix_length
            || crypt_xts(0, xts_key, offset, prefix_cipher, prefix_plain, (size_t) prefix_length) != 0) {
            free(prefix_cipher);
            free(prefix_plain);
            goto done;
        }

        current_value_length = get_u32(prefix_plain + 1u + key_size);
        entry_length = 1u + key_size + 4u + current_value_length;
        padded_length = align16(entry_length);
        if (padded_length < 16u || offset + padded_length > header.write_offset) {
            padlock_secure_zero(prefix_plain, (size_t) prefix_length);
            free(prefix_cipher);
            free(prefix_plain);
            goto done;
        }

        entry_cipher = malloc((size_t) padded_length);
        entry_plain = malloc((size_t) padded_length);
        if (entry_cipher == 0 || entry_plain == 0) {
            padlock_secure_zero(prefix_plain, (size_t) prefix_length);
            free(prefix_cipher);
            free(prefix_plain);
            free(entry_cipher);
            free(entry_plain);
            goto done;
        }
        if (fseeko(file, (off_t) offset, SEEK_SET) != 0
            || fread(entry_cipher, 1u, (size_t) padded_length, file) != padded_length
            || crypt_xts(0, xts_key, offset, entry_cipher, entry_plain, (size_t) padded_length) != 0) {
            padlock_secure_zero(prefix_plain, (size_t) prefix_length);
            free(prefix_cipher);
            free(prefix_plain);
            free(entry_cipher);
            free(entry_plain);
            goto done;
        }

        if ((size_t) key_size == key_length && memcmp(entry_plain + 1u, key, key_length) == 0) {
            unsigned char *replacement = malloc(current_value_length + 1u);
            if (replacement == 0) {
                free(entry_cipher);
                free(entry_plain);
                goto done;
            }
            memcpy(replacement, entry_plain + 1u + key_size + 4u, current_value_length);
            replacement[current_value_length] = '\0';
            free(found);
            found = replacement;
            found_length = current_value_length;
        }

        padlock_secure_zero(prefix_plain, (size_t) prefix_length);
        free(prefix_cipher);
        free(prefix_plain);
        padlock_secure_zero(entry_plain, (size_t) padded_length);
        free(entry_cipher);
        free(entry_plain);
        offset += padded_length;
    }

    if (found == 0) {
        goto done;
    }
    *value = found;
    *value_length = found_length;
    found = 0;
    ok = 0;

done:
    if (file != 0) {
        fclose(file);
    }
    free(found);
    padlock_secure_zero(xts_key, sizeof(xts_key));
    return ok;
}
static int padlock_tpm_write_public_blob(FILE *file, const TPM2B_PUBLIC *blob)
{
    return padlock_tpm_write_blob(file, blob, sizeof(*blob), (TSS2_RC (*)(const void *, uint8_t *, size_t, size_t *)) Tss2_MU_TPM2B_PUBLIC_Marshal);
}

static int padlock_tpm_write_private_blob(FILE *file, const TPM2B_PRIVATE *blob)
{
    return padlock_tpm_write_blob(file, blob, sizeof(*blob), (TSS2_RC (*)(const void *, uint8_t *, size_t, size_t *)) Tss2_MU_TPM2B_PRIVATE_Marshal);
}

static int padlock_tpm_read_public_blob(FILE *file, TPM2B_PUBLIC *blob)
{
    return padlock_tpm_read_blob(file, blob, sizeof(*blob), (TSS2_RC (*)(const uint8_t *, size_t, size_t *, void *)) Tss2_MU_TPM2B_PUBLIC_Unmarshal);
}

static int padlock_tpm_read_private_blob(FILE *file, TPM2B_PRIVATE *blob)
{
    return padlock_tpm_read_blob(file, blob, sizeof(*blob), (TSS2_RC (*)(const uint8_t *, size_t, size_t *, void *)) Tss2_MU_TPM2B_PRIVATE_Unmarshal);
}
