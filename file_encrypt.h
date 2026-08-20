#ifndef FILE_ENCRYPT_H
#define FILE_ENCRYPT_H

#include <stddef.h>

#define FE_OK              0
#define FE_ERR_OPEN_INPUT  1
#define FE_ERR_OPEN_OUTPUT 2
#define FE_ERR_READ        3
#define FE_ERR_WRITE       4
#define FE_ERR_ENCRYPT     5
#define FE_ERR_DECRYPT     6
#define FE_ERR_KEY_DERIVE  7
#define FE_ERR_INVALID_FILE 8

#define FE_SALT_LEN        16
#define FE_IV_LEN          16
#define FE_KEY_LEN         32
#define FE_PBKDF2_ITER     100000
#define FE_MAGIC           "FE1"
#define FE_EXT             ".frieren"
#define FE_EXT_LEN         (sizeof(FE_EXT) - 1)

typedef void (*fe_log_fn)(const char *path, int error, void *userdata);

int fe_encrypt(const char *in_path, const char *out_path, const char *password);
int fe_decrypt(const char *in_path, const char *out_path, const char *password);

int fe_encrypt_dir(const char *dir, const char *password, fe_log_fn log, void *userdata);
int fe_decrypt_dir(const char *dir, const char *password, fe_log_fn log, void *userdata);

#endif
