#define _XOPEN_SOURCE 700
#include "file_encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ftw.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

static int derive_key_iv(const char *password,
                         const unsigned char *salt,
                         unsigned char *key, unsigned char *iv)
{
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           salt, FE_SALT_LEN,
                           FE_PBKDF2_ITER,
                           EVP_sha256(),
                           FE_KEY_LEN, key) != 1)
        return FE_ERR_KEY_DERIVE;

    if (RAND_bytes(iv, FE_IV_LEN) != 1)
        return FE_ERR_KEY_DERIVE;

    return FE_OK;
}

static int derive_key_iv_from_salt(const char *password,
                                   const unsigned char *salt,
                                   unsigned char *key)
{
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           salt, FE_SALT_LEN,
                           FE_PBKDF2_ITER,
                           EVP_sha256(),
                           FE_KEY_LEN, key) != 1)
        return FE_ERR_KEY_DERIVE;

    return FE_OK;
}

int fe_encrypt(const char *in_path, const char *out_path, const char *password)
{
    FILE *fin = NULL, *fout = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char salt[FE_SALT_LEN];
    unsigned char iv[FE_IV_LEN];
    unsigned char key[FE_KEY_LEN];
    unsigned char buf_in[4096];
    unsigned char buf_out[4096 + EVP_MAX_BLOCK_LENGTH];
    int out_len = 0;
    int ret = FE_OK;

    fin = fopen(in_path, "rb");
    if (!fin) return FE_ERR_OPEN_INPUT;

    fout = fopen(out_path, "wb");
    if (!fout) { fclose(fin); return FE_ERR_OPEN_OUTPUT; }

    if (RAND_bytes(salt, FE_SALT_LEN) != 1) {
        ret = FE_ERR_ENCRYPT;
        goto done;
    }

    ret = derive_key_iv(password, salt, key, iv);
    if (ret != FE_OK) goto done;

    if (fwrite(FE_MAGIC, 1, 3, fout) != 3 ||
        fwrite(salt, 1, FE_SALT_LEN, fout) != FE_SALT_LEN ||
        fwrite(iv, 1, FE_IV_LEN, fout) != FE_IV_LEN) {
        ret = FE_ERR_WRITE;
        goto done;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { ret = FE_ERR_ENCRYPT; goto done; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ret = FE_ERR_ENCRYPT;
        goto done;
    }

    for (;;) {
        size_t n = fread(buf_in, 1, sizeof(buf_in), fin);
        if (n == 0) break;

        if (EVP_EncryptUpdate(ctx, buf_out, &out_len, buf_in, (int)n) != 1) {
            ret = FE_ERR_ENCRYPT;
            goto done;
        }

        if (fwrite(buf_out, 1, (size_t)out_len, fout) != (size_t)out_len) {
            ret = FE_ERR_WRITE;
            goto done;
        }
    }

    if (ferror(fin)) { ret = FE_ERR_READ; goto done; }

    if (EVP_EncryptFinal_ex(ctx, buf_out, &out_len) != 1) {
        ret = FE_ERR_ENCRYPT;
        goto done;
    }

    if (out_len > 0 && fwrite(buf_out, 1, (size_t)out_len, fout) != (size_t)out_len) {
        ret = FE_ERR_WRITE;
        goto done;
    }

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (ret != FE_OK) remove(out_path);
    return ret;
}

int fe_decrypt(const char *in_path, const char *out_path, const char *password)
{
    FILE *fin = NULL, *fout = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char magic[3];
    unsigned char salt[FE_SALT_LEN];
    unsigned char iv[FE_IV_LEN];
    unsigned char key[FE_KEY_LEN];
    unsigned char buf_in[4096];
    unsigned char buf_out[4096 + EVP_MAX_BLOCK_LENGTH];
    int out_len = 0;
    int ret = FE_OK;

    fin = fopen(in_path, "rb");
    if (!fin) return FE_ERR_OPEN_INPUT;

    fout = fopen(out_path, "wb");
    if (!fout) { fclose(fin); return FE_ERR_OPEN_OUTPUT; }

    if (fread(magic, 1, 3, fin) != 3 ||
        memcmp(magic, FE_MAGIC, 3) != 0) {
        ret = FE_ERR_INVALID_FILE;
        goto done;
    }

    if (fread(salt, 1, FE_SALT_LEN, fin) != FE_SALT_LEN ||
        fread(iv, 1, FE_IV_LEN, fin) != FE_IV_LEN) {
        ret = FE_ERR_READ;
        goto done;
    }

    ret = derive_key_iv_from_salt(password, salt, key);
    if (ret != FE_OK) goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { ret = FE_ERR_DECRYPT; goto done; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ret = FE_ERR_DECRYPT;
        goto done;
    }

    for (;;) {
        size_t n = fread(buf_in, 1, sizeof(buf_in), fin);
        if (n == 0) break;

        if (EVP_DecryptUpdate(ctx, buf_out, &out_len, buf_in, (int)n) != 1) {
            ret = FE_ERR_DECRYPT;
            goto done;
        }

        if (fwrite(buf_out, 1, (size_t)out_len, fout) != (size_t)out_len) {
            ret = FE_ERR_WRITE;
            goto done;
        }
    }

    if (ferror(fin)) { ret = FE_ERR_READ; goto done; }

    if (EVP_DecryptFinal_ex(ctx, buf_out, &out_len) != 1) {
        ret = FE_ERR_DECRYPT;
        goto done;
    }

    if (out_len > 0 && fwrite(buf_out, 1, (size_t)out_len, fout) != (size_t)out_len) {
        ret = FE_ERR_WRITE;
        goto done;
    }

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (ret != FE_OK) remove(out_path);
    return ret;
}

struct dir_ctx {
    const char *password;
    fe_log_fn   log;
    void       *userdata;
};

static struct dir_ctx *g_dir_ctx;

static int encrypt_file_in_place(const char *path, const char *password)
{
    char tmp[PATH_MAX];
    int rc;

    snprintf(tmp, sizeof(tmp), "%s%s", path, FE_EXT);

    rc = fe_encrypt(path, tmp, password);
    if (rc != FE_OK) return rc;

    if (unlink(path) != 0) {
        remove(tmp);
        return FE_ERR_WRITE;
    }

    return FE_OK;
}

static int decrypt_file_in_place(const char *path, const char *password)
{
    size_t len = strlen(path);
    char orig[PATH_MAX];
    char tmp[PATH_MAX + 4];
    int rc;

    if (len < FE_EXT_LEN || strcmp(path + len - FE_EXT_LEN, FE_EXT) != 0)
        return FE_ERR_INVALID_FILE;

    memcpy(orig, path, len - FE_EXT_LEN);
    orig[len - FE_EXT_LEN] = '\0';

    snprintf(tmp, sizeof(tmp), "%s.tmp", orig);

    rc = fe_decrypt(path, tmp, password);
    if (rc != FE_OK) return rc;

    if (unlink(path) != 0) {
        remove(tmp);
        return FE_ERR_WRITE;
    }

    if (rename(tmp, orig) != 0)
        return FE_ERR_WRITE;

    return FE_OK;
}

static int walk_encrypt_cb(const char *fpath, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)ftwbuf;

    if (typeflag != FTW_F)
        return 0;

    size_t len = strlen(fpath);
    if (len >= FE_EXT_LEN && strcmp(fpath + len - FE_EXT_LEN, FE_EXT) == 0)
        return 0;

    int rc = encrypt_file_in_place(fpath, g_dir_ctx->password);
    if (rc != FE_OK && g_dir_ctx->log)
        g_dir_ctx->log(fpath, rc, g_dir_ctx->userdata);

    return 0;
}

static int walk_decrypt_cb(const char *fpath, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)ftwbuf;

    if (typeflag != FTW_F)
        return 0;

    size_t len = strlen(fpath);
    if (len < FE_EXT_LEN || strcmp(fpath + len - FE_EXT_LEN, FE_EXT) != 0)
        return 0;

    int rc = decrypt_file_in_place(fpath, g_dir_ctx->password);
    if (rc != FE_OK && g_dir_ctx->log)
        g_dir_ctx->log(fpath, rc, g_dir_ctx->userdata);

    return 0;
}

int fe_encrypt_dir(const char *dir, const char *password,
                   fe_log_fn log, void *userdata)
{
    struct dir_ctx ctx;
    ctx.password = password;
    ctx.log      = log;
    ctx.userdata = userdata;
    g_dir_ctx    = &ctx;

    return nftw(dir, walk_encrypt_cb, 64, FTW_PHYS);
}

int fe_decrypt_dir(const char *dir, const char *password,
                   fe_log_fn log, void *userdata)
{
    struct dir_ctx ctx;
    ctx.password = password;
    ctx.log      = log;
    ctx.userdata = userdata;
    g_dir_ctx    = &ctx;

    return nftw(dir, walk_decrypt_cb, 64, FTW_PHYS);
}
