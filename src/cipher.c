#include "cipher.h"
#include <openssl/err.h>
#include <stdio.h>

#define IS_MODE_CCM(ctx) (STR_EQUAL(strrchr(ctx->name, '-'), "-CCM"))
#define IS_OP_DECRYPT(ctx) (ctx->mode == DECRYPT)

#define MAX_CIPHER_TABLE_SIZE 256
#define TAG_LEN 16

typedef struct name_cipher_map {
    const char *name;
    const EVP_CIPHER *cipher;
} name_cipher_map;

static name_cipher_map cipher_table[MAX_CIPHER_TABLE_SIZE];
static int table_size;

int get_padding_code(const char *name) {
    if (IS_NULL(name) || STR_EQUAL(name, "NONE")) {
        return 0;
    } else if (STR_EQUAL(name, "PKCS7") || STR_EQUAL(name, "PKCS5")) {
        return EVP_PADDING_PKCS7;
    } else if (STR_EQUAL(name, "ISO10126-2")) {
        return EVP_PADDING_ISO10126;
    } else if (STR_EQUAL(name, "X9.23")) {
        return EVP_PADDING_ANSI923;
    } else if (STR_EQUAL(name, "ISO7816-4")) {
        return EVP_PADDING_ISO7816_4;
    } else {
        // TODO: handle an supported padding scheme
        // TEMP: disable padding :-(
        return 0;
    }
}


cipher_context* create_cipher_context(OSSL_LIB_CTX *libctx, const char *name, const char *padding_name) {
    cipher_context *new_context = (cipher_context*)malloc(sizeof(cipher_context));
    EVP_CIPHER_CTX *new_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(new_ctx);
    new_context->name = name;
    new_context->context = new_ctx;
    new_context->cipher = EVP_CIPHER_fetch(libctx, name, NULL);
    if (IS_NULL(new_context->cipher) || IS_NULL(new_context->context)) {
        return NULL;
    }
    new_context->padding = get_padding_code(padding_name);
    return new_context;
}

void cipher_init(cipher_context * ctx, byte in_buf[], int in_len, unsigned char *key, unsigned char *iv, int iv_len, int mode) {
    EVP_CipherInit_ex(ctx->context, ctx->cipher, NULL, NULL, NULL, mode);
    ctx->mode = mode;
    if (IS_MODE_CCM(ctx)) {
        EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_CCM_SET_IVLEN, iv_len, 0);
        EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_CCM_SET_TAG, TAG_LEN, mode == ENCRYPT ? 0 : (in_buf + in_len - TAG_LEN));
    }
    if (!EVP_CipherInit_ex(ctx->context, NULL, NULL, key, iv, mode)) {
        ERR_print_errors_fp(stderr);
    }
    EVP_CIPHER_CTX_set_padding(ctx->context, ctx->padding);
}

void cipher_update(cipher_context *ctx, byte out_buf[], int *out_len_ptr, byte in_buf[], int in_len) {
    if (IS_MODE_CCM(ctx)) {
        EVP_CipherUpdate(ctx->context, NULL, out_len_ptr, NULL, IS_OP_DECRYPT(ctx) ? in_len-TAG_LEN : in_len);
    }

    if (!EVP_CipherUpdate(ctx->context, out_buf, out_len_ptr, in_buf,
                        (IS_MODE_CCM(ctx) && IS_OP_DECRYPT(ctx)) ? in_len-TAG_LEN : in_len)) {
        ERR_print_errors_fp(stderr);
    }
}

void cipher_do_final(cipher_context *ctx, byte *out_buf, int *out_len_ptr) {
    if (!EVP_CipherFinal_ex(ctx->context, out_buf, out_len_ptr)) {
        ERR_print_errors_fp(stderr);
    }

    if (ctx->mode == ENCRYPT && IS_MODE_CCM(ctx)) {
        *out_len_ptr = TAG_LEN;
        EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_CCM_GET_TAG, TAG_LEN, out_buf);
    }
}

void free_cipher(cipher_context *ctx) {
    EVP_CIPHER_CTX_free(ctx->context);
    EVP_CIPHER_free(ctx->cipher);
    free(ctx);
}
