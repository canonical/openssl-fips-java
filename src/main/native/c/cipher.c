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

static inline int is_mode_CCM(cipher_context *ctx) {
    const char* suffix = NULL;
    return ctx != NULL && (suffix = strrchr(ctx->name,'-')) != NULL
	    && str_equal(suffix, "-CCM");
}

static inline int is_mode_GCM(cipher_context *ctx) {
    const char* suffix = NULL;
    return ctx != NULL && (suffix = strrchr(ctx->name, '-')) != NULL
	    && str_equal(suffix, "-GCM");
}

static inline int is_mode_EAX(cipher_context *ctx) {
    const char* suffix = NULL;
    return ctx != NULL && (suffix = strrchr(ctx->name, '-')) != NULL
            && str_equal(suffix, "-EAX");
}

static inline int is_mode_OCB(cipher_context *ctx) {
    const char* suffix = NULL;
    return ctx != NULL && (suffix = strrchr(ctx->name, '-')) != NULL
            && str_equal(suffix, "-OCB");
}

static inline int is_op_decrypt(cipher_context *ctx) {
    return ctx != NULL && ctx->op_mode == OP_DECRYPT;
}

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
    if (name == NULL || str_equal(name, "NONE")) {
        return 0;
    } else if (str_equal(name, "PKCS7") || str_equal(name, "PKCS5")) {
        return EVP_PADDING_PKCS7;
    } else if (str_equal(name, "ISO10126-2")) {
        return EVP_PADDING_ISO10126;
    } else if (str_equal(name, "X9.23")) {
        return EVP_PADDING_ANSI923;
    } else if (str_equal(name, "ISO7816-4")) {
        return EVP_PADDING_ISO7816_4;
    } else {
        // TODO: handle an supported padding scheme
        // TEMP: disable padding :-(
        return 0;
    }
}

cipher_context* create_cipher_context(OSSL_LIB_CTX *libctx, const char *name, const char *padding_name) {
    cipher_context *new_context = (cipher_context*)malloc(sizeof(cipher_context));
    if (new_context == NULL) {
        return NULL;
    }
    memset(new_context, 0, sizeof(cipher_context));
    new_context->op_mode = OP_UNDEFINED;
    EVP_CIPHER_CTX *new_ctx = EVP_CIPHER_CTX_new();
    if (new_ctx == NULL) {
        goto error;
    }

    EVP_CIPHER_CTX_init(new_ctx);
    new_context->name = strdup(name);
    if (new_context->name == NULL) {
        goto error;
    }
    new_context->context = new_ctx;
    new_context->cipher = EVP_CIPHER_fetch(libctx, name, NULL);
    if (new_context->cipher == NULL || new_context->context == NULL) {
        goto error;
    }

    new_context->op_mode = OP_UNDEFINED;
    new_context->padding = get_padding_code(padding_name);
    memset(new_context->gcm_tag, 0, GCM_TAG_LEN);
    new_context->key = NULL;
    new_context->iv = NULL;
    new_context->initial_bytes = NULL;
    return new_context;

error:
    free_cipher(&new_context);
    return NULL;
}

jssl_status cipher_init(cipher_context *ctx, byte in_buf[], int in_len, unsigned char *key, int key_len, unsigned char *iv, int iv_len, int op_mode) {
    if (key != NULL) {
        ctx->key = (unsigned char *) malloc(key_len);
        if (ctx->key == NULL) return FAIL_OOM;
        memcpy(ctx->key, key, key_len);
    }

    if (iv != NULL) {
        ctx->iv = (unsigned char *) malloc(iv_len);
        if (ctx->iv == NULL) return FAIL_OOM;
        memcpy(ctx->iv, iv, iv_len);
    }

    if (in_buf != NULL) {
        ctx->initial_bytes = (byte *) malloc(in_len);
        if (ctx->initial_bytes == NULL) return FAIL_OOM;
        memcpy(ctx->initial_bytes, in_buf, in_len);
    }

    if (!EVP_CipherInit_ex(ctx->context, ctx->cipher, NULL, NULL, NULL, op_mode)) {
        ERR_print_errors_fp(stderr);
        return FAIL_EVP;
    }

    ctx->op_mode = op_mode;
    if (is_mode_CCM(ctx)) {
        EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_CCM_SET_IVLEN, iv_len, 0);
        EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_CCM_SET_TAG, TAG_LEN, op_mode == OP_ENCRYPT ? 0 : (in_buf + in_len - TAG_LEN));
    }

    if (!EVP_CipherInit_ex(ctx->context, NULL, NULL, ctx->key, ctx->iv, op_mode)) {
        ERR_print_errors_fp(stderr);
        return FAIL_EVP;
    }
    EVP_CIPHER_CTX_set_padding(ctx->context, ctx->padding);
    return SUCCESS;
}

jssl_status cipher_update_aad(cipher_context *ctx, int *out_len_ptr, byte aad_buf[], int aad_len) {
    // Just ignore if the algorithm does not support AAD ?
    if (is_mode_CCM(ctx) || is_mode_GCM(ctx) || is_mode_EAX(ctx) || is_mode_OCB(ctx)) {
        return cipher_update(ctx, NULL, out_len_ptr, aad_buf, aad_len);
    }
    return FAIL_OPERATION_UNSUPPORTED;
}

jssl_status cipher_update(cipher_context *ctx, byte out_buf[], int *out_len_ptr, byte in_buf[], int in_len) {
    if (is_mode_CCM(ctx)) {
        if (!EVP_CipherUpdate(ctx->context, NULL, out_len_ptr, NULL, is_op_decrypt(ctx) ? in_len-TAG_LEN : in_len)) {
            ERR_print_errors_fp(stderr);
	    return FAIL_EVP;
	}
    }

    if (!EVP_CipherUpdate(ctx->context, out_buf, out_len_ptr, in_buf,
                        (is_mode_CCM(ctx) && is_op_decrypt(ctx)) ? in_len-TAG_LEN : in_len)) {
        ERR_print_errors_fp(stderr);
	return FAIL_EVP;
    }
    return SUCCESS;
}

jssl_status cipher_do_final(cipher_context *ctx, byte *out_buf, int *out_len_ptr) {
    if (ctx->op_mode == OP_DECRYPT && is_mode_GCM(ctx)) {
        EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_GCM_SET_TAG, TAG_LEN, ctx->gcm_tag);
    }

    if (!EVP_CipherFinal_ex(ctx->context, out_buf, out_len_ptr)) {
        ERR_print_errors_fp(stderr);
        return FAIL_EVP;
    }

    if (ctx->op_mode == OP_ENCRYPT) {
        if(is_mode_CCM(ctx)) {
            *out_len_ptr = TAG_LEN;
            EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_CCM_GET_TAG, TAG_LEN, out_buf);
        } else if(is_mode_GCM(ctx)) {
            EVP_CIPHER_CTX_ctrl(ctx->context, EVP_CTRL_GCM_GET_TAG, TAG_LEN, out_buf + *out_len_ptr);
            *out_len_ptr += TAG_LEN;
        }
    }
    return SUCCESS;
}

void free_cipher(cipher_context **pctx) {
    if (pctx == NULL || *pctx == NULL) {
        return;
    }

    if ((*pctx)->name != NULL) {
	// name was strdup'd
        free((void*)((*pctx)->name));
    }

    if ((*pctx)->key != NULL) {
        OPENSSL_cleanse((*pctx)->key, EVP_CIPHER_CTX_get_key_length((*pctx)->context));
        free((*pctx)->key);
    }

    if ((*pctx)->iv != NULL) {
        OPENSSL_cleanse((*pctx)->iv, EVP_CIPHER_CTX_get_iv_length((*pctx)->context));
        free((*pctx)->iv);
    }

    if ((*pctx)->initial_bytes != NULL) {
        free((*pctx)->initial_bytes);
    }

    EVP_CIPHER_CTX_free((*pctx)->context);
    EVP_CIPHER_free((*pctx)->cipher);
    OPENSSL_cleanse(*pctx, sizeof(cipher_context));  // zero gcm_tag and other fields
    free(*pctx);
    *pctx = NULL;
}
