#include "hardcode/padlock.h"

#include <pwd.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

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

    if (fgets(password, sizeof(password), stdin) == 0) {
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

struct pam_password_state {
    const char *password;
};

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

static int authenticate_with_pam(const char *password)
{
    struct pam_conv conv;
    struct pam_password_state state;
    pam_handle_t *pamh = 0;
    const char *user = getenv("USER");
    struct passwd *pwd;
    int result;

    if (password == 0 || password[0] == '\0') {
        return -1;
    }

    if (user == 0 || user[0] == '\0') {
        pwd = getpwuid(getuid());
        if (pwd == 0 || pwd->pw_name == 0) {
            return -1;
        }
        user = pwd->pw_name;
    }

    state.password = password;
    conv.conv = pam_password_conversation;
    conv.appdata_ptr = &state;

    result = pam_start("login", user, &conv, &pamh);
    if (result != PAM_SUCCESS) {
        return -1;
    }

    result = pam_authenticate(pamh, 0);
    if (result == PAM_SUCCESS) {
        result = pam_acct_mgmt(pamh, 0);
    }

    pam_end(pamh, result);
    return result == PAM_SUCCESS ? 0 : -1;
}

static int derive_header_password(char *header_password, size_t header_password_length)
{
    char login_password[512];
    int result;

    if (prompt_password("Linux password: ", login_password, sizeof(login_password)) != 0) {
        return -1;
    }

    if (authenticate_with_pam(login_password) != 0) {
        secure_zero(login_password, sizeof(login_password));
        return -1;
    }

    result = padlock_derive_header_password(login_password, header_password, header_password_length);
    secure_zero(login_password, sizeof(login_password));
    return result;
}

int main(int argc, char **argv)
{
    char path[4096];
    char header_password[65];
    int result;

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
        if (derive_header_password(header_password, sizeof(header_password)) != 0
            || padlock_allocate(path, size, header_password) != 0) {
            secure_zero(header_password, sizeof(header_password));
            fprintf(stderr, "padlock: allocation failed\n");
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
        if (derive_header_password(header_password, sizeof(header_password)) != 0
            || padlock_set(path, header_password, argv[2], argv[3], (uint32_t) strlen(argv[3])) != 0) {
            secure_zero(header_password, sizeof(header_password));
            fprintf(stderr, "padlock: set failed\n");
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
        result = derive_header_password(header_password, sizeof(header_password));
        if (result != 0 || padlock_get(path, header_password, argv[2], &value, &value_length) != 0) {
            secure_zero(header_password, sizeof(header_password));
            fprintf(stderr, "padlock: key not found or header password invalid\n");
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
