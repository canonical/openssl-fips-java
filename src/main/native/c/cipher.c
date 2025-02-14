/*
 * Copyright (C) Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "cipher.h"
#include <openssl/err.h>
#include <stdio.h>

#define IS_MODE_CCM(ctx) (STR_EQUAL(strrchr(ctx->name, '-'), "-CCM"))
#define IS_MODE_GCM(ctx) (STR_EQUAL(strrchr(ctx->name, '-'), "-GCM"))
#define IS_MODE_EAX(ctx) (STR_EQUAL(strrchr(ctx->name, '-'), "-EAX"))
#define IS_MODE_OCB(ctx) (STR_EQUAL(strrchr(ctx->name, '-'), "-OCB"))

#define IS_OP_DECRYPT(ctx) (ctx->mode == DECRYPT)

#define MAX_CIPHER_TABLE_SIZE 256
#define TAG_LEN 16

void print_byte_array(byte *array, int length) {
    printf("[ ");
    for (int i = 0; i < length; i++) {
        printf("%d", array[i]);
        if (i < length-1) {
            printf(", ");
        }
    }
    printf(" ]\n");
}
 
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
    memset(new_context->gcm_tag, 0, GCM_TAG_LEN);
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

void cipher_update_aad(cipher_context *ctx, int *out_len_ptr, byte aad_buf[], int aad_len) {
    // Just ignore if the algorithm does not support AAD ?
    if (IS_MODE_CCM(ctx) || IS_MODE_GCM(ctx) || IS_MODE_EAX(ctx) || IS_MODE_OCB(ctx)) {
        cipher_update(ctx, NULL, out_len_ptr, aad_buf, aad_len);
    }
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
    if (ctx->mode == DECRYPT && IS_MODE_GCM(ctx)) {
        EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_GCM_SET_TAG, TAG_LEN, ctx->gcm_tag);
    }

    if (!EVP_CipherFinal_ex(ctx->context, out_buf, out_len_ptr)) {
        ERR_print_errors_fp(stderr);
    }

    if (ctx->mode == ENCRYPT) {
        if(IS_MODE_CCM(ctx)) {
            *out_len_ptr = TAG_LEN;
            EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_CCM_GET_TAG, TAG_LEN, out_buf);
        } else if(IS_MODE_GCM(ctx)) {
            EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_GCM_GET_TAG, TAG_LEN, ctx->gcm_tag);
        }
    }
}

void free_cipher(cipher_context *ctx) {
    EVP_CIPHER_CTX_free(ctx->context);
    EVP_CIPHER_free(ctx->cipher);
    free(ctx);
}
