#include "file_encrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s encrypt <input> <output> [-p password]   Encrypt a file\n"
        "  %s decrypt <input> <output> [-p password]   Decrypt a file\n"
        "  %s dir-encrypt <directory>   [-p password]  Encrypt all files recursively\n"
        "  %s dir-decrypt <directory>   [-p password]  Decrypt all .fe files recursively\n",
        prog, prog, prog, prog);
}

static char *read_password(const char *prompt)
{
    struct termios old, t;
    char *pass = NULL;
    size_t cap = 128;
    ssize_t len;

    pass = malloc(cap);
    if (!pass) return NULL;

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    tcgetattr(STDIN_FILENO, &old);
    t = old;
    t.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);

    len = getline(&pass, &cap, stdin);

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fprintf(stderr, "\n");

    if (len <= 0) { free(pass); return NULL; }
    if (pass[len - 1] == '\n') pass[--len] = '\0';

    if (len == 0) { free(pass); return NULL; }
    return pass;
}

static const char *err_msg(int code)
{
    switch (code) {
    case FE_ERR_OPEN_INPUT:   return "cannot open input file";
    case FE_ERR_OPEN_OUTPUT:  return "cannot open output file";
    case FE_ERR_READ:         return "read error";
    case FE_ERR_WRITE:        return "write error";
    case FE_ERR_ENCRYPT:      return "encryption failed";
    case FE_ERR_DECRYPT:      return "decryption failed (wrong password?)";
    case FE_ERR_KEY_DERIVE:   return "key derivation failed";
    case FE_ERR_INVALID_FILE: return "not an encrypted file or wrong format";
    default:                  return "unknown error";
    }
}

static void dir_log(const char *path, int error, void *userdata)
{
    (void)userdata;
    fprintf(stderr, "  WARN %s: %s\n", path, err_msg(error));
}

static char *find_arg(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], flag) == 0)
            return argv[i + 1];
    return NULL;
}

static int has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], flag) == 0)
            return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *mode = argv[1];

    if (has_flag(argc, argv, "-h") || has_flag(argc, argv, "--help")) {
        usage(argv[0]);
        return 0;
    }

    /* file modes: encrypt/decrypt need 2 positional args + optional -p */
    if (strcmp(mode, "encrypt") == 0 || strcmp(mode, "decrypt") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }

        const char *in  = argv[2];
        const char *out = argv[3];
        char *password  = find_arg(argc, argv, "-p");

        if (password) {
            password = strdup(password);
        } else {
            password = read_password("Password: ");
            if (!password) {
                fprintf(stderr, "Error: empty password\n");
                return 1;
            }
        }

        if (strcmp(mode, "encrypt") == 0 && !find_arg(argc, argv, "-p")) {
            char *confirm = read_password("Confirm password: ");
            if (!confirm || strcmp(password, confirm) != 0) {
                fprintf(stderr, "Error: passwords do not match\n");
                free(password);
                free(confirm);
                return 1;
            }
            free(confirm);
        }

        int rc;
        if (strcmp(mode, "encrypt") == 0)
            rc = fe_encrypt(in, out, password);
        else
            rc = fe_decrypt(in, out, password);

        free(password);

        if (rc != FE_OK) {
            fprintf(stderr, "Error: %s\n", err_msg(rc));
            return 1;
        }

        fprintf(stderr, "Done.\n");
        return 0;
    }

    /* dir modes: dir-encrypt/dir-decrypt need 1 positional arg + optional -p */
    if (strcmp(mode, "dir-encrypt") == 0 || strcmp(mode, "dir-decrypt") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }

        const char *dir = argv[2];
        char *password  = find_arg(argc, argv, "-p");

        if (password) {
            password = strdup(password);
        } else {
            password = read_password("Password: ");
            if (!password) {
                fprintf(stderr, "Error: empty password\n");
                return 1;
            }
        }

        if (strcmp(mode, "dir-encrypt") == 0 && !find_arg(argc, argv, "-p")) {
            char *confirm = read_password("Confirm password: ");
            if (!confirm || strcmp(password, confirm) != 0) {
                fprintf(stderr, "Error: passwords do not match\n");
                free(password);
                free(confirm);
                return 1;
            }
            free(confirm);
        }

        int rc;
        if (strcmp(mode, "dir-encrypt") == 0) {
            fprintf(stderr, "Encrypting directory: %s\n", dir);
            rc = fe_encrypt_dir(dir, password, dir_log, NULL);
        } else {
            fprintf(stderr, "Decrypting directory: %s\n", dir);
            rc = fe_decrypt_dir(dir, password, dir_log, NULL);
        }

        free(password);

        if (rc != FE_OK && rc != -1) {
            fprintf(stderr, "Error: %s\n", err_msg(rc));
            return 1;
        }

        fprintf(stderr, "Done.\n");
        return 0;
    }

    usage(argv[0]);
    return 1;
}
