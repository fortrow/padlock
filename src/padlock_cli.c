#include "hardcode/padlock.h"

#include <errno.h>
#include <ctype.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define PADLOCK_PAM_SERVICE "padlock"

static void usage(FILE *stream)
{
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  padlock allocate <size> [path]\n");
    fprintf(stream, "  padlock set <key> <value> [path]\n");
    fprintf(stream, "  padlock get <key> [path]\n");
}

static int resolve_path(int argc, char **argv, int index, char *buffer, size_t length)
{
    if (argc > index) {
        return snprintf(buffer, length, "%s", argv[index]) > 0 ? 0 : -1;
    }
    return padlock_default_store_path(buffer, length);
}

static int prompt_password(const char *prompt, char *password, size_t password_length)
{
    struct termios old_terminal;
    struct termios new_terminal;
    int terminal_changed = 0;
    size_t length;

    if (password == 0 || password_length == 0) {
        return -1;
    }

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    if (tcgetattr(STDIN_FILENO, &old_terminal) == 0) {
        new_terminal = old_terminal;
        new_terminal.c_lflag &= (tcflag_t) ~ECHO;
        terminal_changed = tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_terminal) == 0;
    }

    if (fgets(password, (int) password_length, stdin) == 0) {
        if (terminal_changed) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_terminal);
        }
        fputc('\n', stderr);
        return -1;
    }

    if (terminal_changed) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_terminal);
    }
    fputc('\n', stderr);

    length = strlen(password);
    if (length > 0 && password[length - 1u] == '\n') {
        password[length - 1u] = '\0';
    }
    return password[0] == '\0' ? -1 : 0;
}

static void secure_zero(char *buffer, size_t length)
{
    volatile char *bytes = buffer;
    while (length > 0) {
        *bytes++ = '\0';
        length--;
    }
}

static void copy_message(char *buffer, size_t length, const char *message)
{
    if (buffer == 0 || length == 0) {
        return;
    }

    if (message == 0) {
        buffer[0] = '\0';
        return;
    }

    snprintf(buffer, length, "%s", message);
}

static void copy_pam_message(char *buffer, size_t length, int pam_code, pam_handle_t *pamh)
{
    const char *message;

    if (buffer == 0 || length == 0) {
        return;
    }

    message = pam_strerror(pamh, pam_code);
    if (message == 0 || message[0] == '\0') {
        snprintf(buffer, length, "PAM %d", pam_code);
        return;
    }

    snprintf(buffer, length, "PAM %d: %s", pam_code, message);
}

struct pam_password_state {
    const char *password;
};

static int pam_no_prompt_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    (void) num_msg;
    (void) msg;
    (void) resp;
    (void) appdata_ptr;
    return PAM_CONV_ERR;
}

static int pam_password_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    struct pam_password_state *state = appdata_ptr;
    struct pam_response *responses;

    if (num_msg <= 0 || msg == 0 || resp == 0 || state == 0 || state->password == 0) {
        return PAM_CONV_ERR;
    }

    responses = calloc((size_t) num_msg, sizeof(*responses));
    if (responses == 0) {
        return PAM_BUF_ERR;
    }

    for (int index = 0; index < num_msg; index++) {
        switch (msg[index]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON:
                responses[index].resp = malloc(strlen(state->password) + 1u);
                if (responses[index].resp == 0) {
                    for (int cleanup = 0; cleanup < index; cleanup++) {
                        free(responses[cleanup].resp);
                    }
                    free(responses);
                    return PAM_BUF_ERR;
                }
                memcpy(responses[index].resp, state->password, strlen(state->password) + 1u);
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                responses[index].resp = 0;
                break;
            default:
                for (int cleanup = 0; cleanup < index; cleanup++) {
                    free(responses[cleanup].resp);
                }
                free(responses);
                return PAM_CONV_ERR;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;
}

static int pam_service_is_passwordless_for_user(const char *username)
{
    FILE *file;
    char line[512];
    char expected[384];
    int expected_length;

    if (username == 0 || username[0] == '\0') {
        return 0;
    }

    file = fopen("/etc/pam.d/padlock", "r");
    if (file == 0) {
        return 0;
    }

    expected_length = snprintf(expected, sizeof(expected), "auth required pam_succeed_if.so user = %s", username);
    if (expected_length <= 0 || (size_t) expected_length >= sizeof(expected)) {
        fclose(file);
        return 0;
    }

    while (fgets(line, sizeof(line), file) != 0) {
        char *start = line;
        char *end;

        while (*start != '\0' && isspace((unsigned char) *start)) {
            start++;
        }

        end = start + strlen(start);
        while (end > start && isspace((unsigned char) end[-1])) {
            *--end = '\0';
        }

        if (*start == '\0' || *start == '#') {
            continue;
        }

        if (strcmp(start, expected) != 0) {
            fclose(file);
            return 0;
        }
    }

    fclose(file);
    return 1;
}

static int authenticate_with_pam(const char *username, const char *password, int no_prompt, char *reason, size_t reason_length)
{
    struct pam_conv conv;
    struct pam_password_state state;
    pam_handle_t *pamh = 0;
    struct passwd *pwd;
    int result;

    if (reason != 0 && reason_length > 0) {
        reason[0] = '\0';
    }

    if (username == 0 || username[0] == '\0') {
        pwd = getpwuid(getuid());
        if (pwd == 0 || pwd->pw_name == 0) {
            copy_message(reason, reason_length, "could not resolve current user");
            return -1;
        }
        username = pwd->pw_name;
    }

    if (!no_prompt && (password == 0 || password[0] == '\0')) {
        errno = EINVAL;
        copy_message(reason, reason_length, "empty password");
        return -1;
    }

    state.password = password;
    conv.conv = no_prompt ? pam_no_prompt_conversation : pam_password_conversation;
    conv.appdata_ptr = no_prompt ? 0 : &state;

    result = pam_start(PADLOCK_PAM_SERVICE, username, &conv, &pamh);
    if (result != PAM_SUCCESS) {
        errno = EACCES;
        copy_pam_message(reason, reason_length, result, pamh);
        return -1;
    }

    result = pam_authenticate(pamh, 0);

    if (result != PAM_SUCCESS) {
        copy_pam_message(reason, reason_length, result, pamh);
    }
    pam_end(pamh, result);
    if (result == PAM_SUCCESS) {
        return 0;
    }

    errno = EACCES;
    return -1;
}

static int derive_header_password(const char *username, char *header_password, size_t header_password_length, char *reason, size_t reason_length)
{
    char login_password[512];
    char prompt[128];
    int result;
    int no_prompt;

    if (username == 0 || username[0] == '\0') {
        username = "user";
    }

    no_prompt = pam_service_is_passwordless_for_user(username);

    if (!no_prompt) {
        if (snprintf(prompt, sizeof(prompt), "Enter the password for '%s': ", username) <= 0) {
            errno = EINVAL;
            return -1;
        }

        if (prompt_password(prompt, login_password, sizeof(login_password)) != 0) {
            errno = EIO;
            copy_message(reason, reason_length, "could not read password");
            return -1;
        }
    } else {
        login_password[0] = '\0';
    }

    if (authenticate_with_pam(username, no_prompt ? 0 : login_password, no_prompt, reason, reason_length) != 0) {
        secure_zero(login_password, sizeof(login_password));
        return -1;
    }

    if (no_prompt) {
        result = padlock_derive_user_header_password(username, header_password, header_password_length);
    } else {
        result = padlock_derive_header_password(login_password, header_password, header_password_length);
    }
    secure_zero(login_password, sizeof(login_password));
    if (result != 0) {
        if (errno == EACCES) {
            copy_message(reason, reason_length, "TPM access denied while deriving header password");
        } else if (errno != 0) {
            char detail[128];
            snprintf(detail, sizeof(detail), "header password derivation failed: %s", strerror(errno));
            copy_message(reason, reason_length, detail);
        } else {
            errno = EIO;
            copy_message(reason, reason_length, "header password derivation failed");
        }
    }
    return result;
}

static void report_failure(const char *action)
{
    if (errno != 0) {
        fprintf(stderr, "padlock: %s: %s\n", action, strerror(errno));
        return;
    }

    fprintf(stderr, "padlock: %s failed\n", action);
}

static void report_failure_with_detail(const char *action, const char *detail)
{
    if (detail != 0 && detail[0] != '\0') {
        fprintf(stderr, "padlock: %s: %s\n", action, detail);
        return;
    }

    report_failure(action);
}

int main(int argc, char **argv)
{
    char path[4096];
    char header_password[65];
    char auth_error[256];
    const char *username = getenv("USER");
    struct passwd *pwd;
    int result;

    if (username == 0 || username[0] == '\0') {
        pwd = getpwuid(getuid());
        if (pwd != 0 && pwd->pw_name != 0) {
            username = pwd->pw_name;
        }
    }

    if (argc < 2) {
        usage(stderr);
        return 2;
    }

    if (strcmp(argv[1], "allocate") == 0) {
        uint64_t size = 0;
        if (argc < 3 || argc > 4 || padlock_parse_size(argv[2], &size) != 0) {
            usage(stderr);
            return 2;
        }
        if (resolve_path(argc, argv, 3, path, sizeof(path)) != 0) {
            fprintf(stderr, "padlock: could not resolve store path\n");
            return 1;
        }
        if (derive_header_password(username, header_password, sizeof(header_password), auth_error, sizeof(auth_error)) != 0) {
            secure_zero(header_password, sizeof(header_password));
            report_failure_with_detail("authentication", auth_error);
            return 1;
        }
        if (padlock_allocate(path, size, header_password) != 0) {
            secure_zero(header_password, sizeof(header_password));
            report_failure("allocation");
            return 1;
        }
        secure_zero(header_password, sizeof(header_password));
        printf("allocated %s\n", path);
        return 0;
    }

    if (strcmp(argv[1], "set") == 0) {
        if (argc < 4 || argc > 5) {
            usage(stderr);
            return 2;
        }
        if (resolve_path(argc, argv, 4, path, sizeof(path)) != 0) {
            fprintf(stderr, "padlock: could not resolve store path\n");
            return 1;
        }
        if (derive_header_password(username, header_password, sizeof(header_password), auth_error, sizeof(auth_error)) != 0) {
            secure_zero(header_password, sizeof(header_password));
            report_failure_with_detail("authentication", auth_error);
            return 1;
        }
        if (padlock_set(path, header_password, argv[2], argv[3], (uint32_t) strlen(argv[3])) != 0) {
            secure_zero(header_password, sizeof(header_password));
            report_failure("set");
            return 1;
        }
        secure_zero(header_password, sizeof(header_password));
        return 0;
    }

    if (strcmp(argv[1], "get") == 0) {
        unsigned char *value = 0;
        uint32_t value_length = 0;
        if (argc < 3 || argc > 4) {
            usage(stderr);
            return 2;
        }
        if (resolve_path(argc, argv, 3, path, sizeof(path)) != 0) {
            fprintf(stderr, "padlock: could not resolve store path\n");
            return 1;
        }
        result = derive_header_password(username, header_password, sizeof(header_password), auth_error, sizeof(auth_error));
        if (result != 0) {
            secure_zero(header_password, sizeof(header_password));
            report_failure_with_detail("authentication", auth_error);
            return 1;
        }
        if (padlock_get(path, header_password, argv[2], &value, &value_length) != 0) {
            secure_zero(header_password, sizeof(header_password));
            report_failure("lookup");
            return 1;
        }
        secure_zero(header_password, sizeof(header_password));
        fwrite(value, 1u, value_length, stdout);
        fputc('\n', stdout);
        padlock_free(value);
        return 0;
    }

    usage(stderr);
    return 2;
}
