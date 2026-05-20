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
#include "mac.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>

mac_params *init_mac_params(char *cipher, char *digest, byte *iv, size_t iv_length, size_t output_length) {
    mac_params *new = (mac_params*)malloc(sizeof(mac_params));
    if (new == NULL) return NULL;
    new->cipher_name = cipher;
    new->digest_name = digest;
    new->iv = iv;
    new->iv_length = iv_length;
    new->output_length = output_length;
    return new;
}

static int set_params(EVP_MAC_CTX *ctx, mac_params *params) {
    OSSL_PARAM _params[8];
    int n_params = 0;
    if (params->cipher_name != NULL) {
        _params[n_params++] = OSSL_PARAM_construct_utf8_string("cipher", params->cipher_name, 0);
    }
    if (params->digest_name != NULL) {
        _params[n_params++] = OSSL_PARAM_construct_utf8_string("digest", params->digest_name, 0);
    }
    if (params->iv != NULL) {
        _params[n_params++] = OSSL_PARAM_construct_octet_string("iv", params->iv, params->iv_length);
    }
    _params[n_params] = OSSL_PARAM_construct_end();
    return EVP_MAC_CTX_set_params(ctx, _params);
}

mac_context *mac_init(OSSL_LIB_CTX *libctx, char *algorithm, byte *key, size_t key_length, mac_params *params, int *oom) {
    mac_context *new_ctx = (mac_context *)malloc(sizeof(mac_context));
    if (new_ctx == NULL) {
        if (oom) *oom = 1;
        return NULL;
    }
    new_ctx->ctx = NULL;

    EVP_MAC *mac = EVP_MAC_fetch(libctx, algorithm, "provider=fips");
    if (mac == NULL) {
        goto error;
    }
    new_ctx->ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (new_ctx->ctx == NULL) {
        goto error;
    }
    if (params != NULL && set_params(new_ctx->ctx, params) == 0) {
        goto error;
    }
    if (0 == EVP_MAC_init(new_ctx->ctx, (const unsigned char*)key, key_length, NULL)) {
        goto error;
    }
    return new_ctx;

error:
    free_mac_context(&new_ctx);
    return NULL;
}

jssl_status mac_update(mac_context *ctx, byte *input, size_t input_size) {
    if (0 == EVP_MAC_update(ctx->ctx, input, input_size)) {
        return FAIL_EVP;
    }
    return SUCCESS;
}

jssl_status mac_final(mac_context *ctx, byte *output, size_t *bytes_written, size_t output_size) {
    if (0 == EVP_MAC_final(ctx->ctx, output, bytes_written, output_size)) {
        return FAIL_EVP;
    }
    return SUCCESS;
}

jssl_status mac_final_with_input(mac_context *ctx, byte *input, size_t input_size,
                     byte *output, size_t *bytes_written, size_t output_size) {
    jssl_status rc = mac_update(ctx, input, input_size);
    if (rc != SUCCESS)
        return rc;
    return mac_final(ctx, output, bytes_written, output_size);
}

size_t get_mac_length(mac_context *mac) {
    return EVP_MAC_CTX_get_mac_size(mac->ctx);    
}

void free_mac_context(mac_context **pmac) {
    if (pmac == NULL || *pmac == NULL) {
        return;
    }
    EVP_MAC_CTX_free((*pmac)->ctx);
    free(*pmac);
    *pmac = NULL;
}
