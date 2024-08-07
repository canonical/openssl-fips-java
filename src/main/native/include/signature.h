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
#include "jssl.h"
#include <openssl/evp.h>

typedef enum sv_type { INVALID, SV_RSA, SV_ED25519, SV_ED448 } sv_type;
typedef enum sv_state { UNINITIALISED, SIGN, VERIFY } sv_state;
typedef enum sv_padding_mode { NONE, PSS } sv_padding_mode;

/* Let us support RSA with PSS padding only, for now */
/* The JCE Signature API also supports the output length param 
 * for HMAC.
 * See: https://www.openssl.org/docs/man3.0/man3/EVP_MAC_fetch.html
 */ 
typedef struct sv_params {
    int salt_length;
    char *digest_type;
    EVP_MD *digest;
    sv_padding_mode padding;
    char *mgf1_digest_type;
    EVP_MD *mgf1_digest;
} sv_params;

/* We must be able to translate Java's PublicKey and PrivateKey objects
 * to values of this struct type.
 */
typedef struct sv_key {
    EVP_PKEY_CTX *ctx;
    char *type; //unused
} sv_key;

sv_key *sv_init_key(OSSL_LIB_CTX *libctx, EVP_PKEY *key);

typedef struct sv_context {
    sv_state state;
    sv_type type;
    sv_key *key;
    byte *data;
    int length;
    EVP_MD_CTX *mctx;
} sv_context;

sv_params *sv_create_params(OSSL_LIB_CTX *libctx, int salt_length, sv_padding_mode padding, char *digest, char *mgf1_digest);
sv_context *sv_init(OSSL_LIB_CTX *libctx, sv_key *key, sv_params *params, sv_state op, sv_type type);
int sv_update(sv_context *ctx, byte *data, size_t length);
int sv_sign(sv_context *ctx, byte *signature, size_t *signature_length);
int sv_verify(sv_context *ctx, byte *signature, size_t sig_length);

void free_sv_params(sv_params *params);
void free_sv_key(sv_key *key);
void free_sv_context(sv_context *context);
