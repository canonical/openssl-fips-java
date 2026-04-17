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
#ifndef _INCLUDE_CIPHER_H
#define _INCLUDE_CIPHER_H
#include <openssl/evp.h>
#include <openssl/types.h>
#include <jssl.h>

#define OP_UNDEFINED -1
#define OP_DECRYPT 0
#define OP_ENCRYPT 1
#define GCM_TAG_LEN 16
#define MAX_BLOCK_LENGTH EVP_MAX_BLOCK_LENGTH

typedef struct cipher_context {
    const char *name;
    EVP_CIPHER_CTX *context;
    EVP_CIPHER* cipher;
    int op_mode;
    int padding;
    byte gcm_tag[GCM_TAG_LEN];
    unsigned char *key;
    unsigned char *iv;
    byte *initial_bytes; //track here for cleanup
} cipher_context;

cipher_context* create_cipher_context(OSSL_LIB_CTX *libctx, const char *name, const char *padding_name);

jssl_status cipher_init(cipher_context * ctx, byte in[], int in_len, unsigned char *key, int key_len, unsigned char *iv, int iv_len, int op_mode);

jssl_status cipher_update_aad(cipher_context *ctx, int *out_len_ptr, byte aad[], int aad_len);

jssl_status cipher_update(cipher_context *ctx, byte out[], int *out_len_ptr, byte in[], int in_len);

jssl_status cipher_do_final(cipher_context *ctx, byte *out, int *out_len_ptr);

void free_cipher(cipher_context **ctx);
#endif //_INCLUDE_CIPHER_H
