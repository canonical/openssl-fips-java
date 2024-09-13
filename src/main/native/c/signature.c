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
#include "signature.h"
#include "jssl.h"
#include <openssl/rsa.h>
#include <openssl/core_names.h>

sv_key *sv_init_key(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey) {
    sv_key *key = (sv_key*)malloc(sizeof(sv_key));
    key->ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (key->ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    return key;
}
  
sv_params *sv_create_params(OSSL_LIB_CTX *libctx, int salt_length, sv_padding_mode padding, char *digest, char *mgf1_digest) {
    sv_params *params = (sv_params*) malloc(sizeof(sv_params));
    params->padding = padding;
    if (padding == PSS) {
        params->salt_length = salt_length;
    } else {
        params->salt_length = -1; //ignore
    }

    params->digest_type = digest;
    if (digest != NULL) {
        params->digest = EVP_MD_fetch(libctx, digest, NULL);
    }

    if (padding == PSS) {
        params->mgf1_digest_type = mgf1_digest;
        params->mgf1_digest = EVP_MD_fetch(libctx, mgf1_digest, NULL);
    } else {
        params->mgf1_digest_type = NULL;
        params->mgf1_digest = NULL;
    }
    return params;
}

sv_context *sv_init(OSSL_LIB_CTX *libctx, sv_key *key, sv_params *params, sv_state op, sv_type type) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return NULL;
    }

    OSSL_PARAM ossl_params[4];
    int n_params = 0;
    if (params->padding == PSS) {
        ossl_params[n_params++] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                             OSSL_PKEY_RSA_PAD_MODE_PSS, 0);
        if (params->salt_length > 0) {
            ossl_params[n_params++] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
                                             &(params->salt_length));
        }

        if (params->mgf1_digest != NULL) {
            ossl_params[n_params++] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST,
                                             params->mgf1_digest_type, strlen(params->mgf1_digest_type));  
        }
    }
    ossl_params[n_params] = OSSL_PARAM_construct_end();

    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(key->ctx);
    if (op == SIGN) {
        if (EVP_DigestSignInit_ex(md_ctx, NULL, params->digest_type, libctx, NULL, pkey, ossl_params) <= 0) {
            return NULL;
        }
    } else {
        if (EVP_DigestVerifyInit_ex(md_ctx, NULL, params->digest_type, libctx, NULL, pkey, ossl_params) <= 0) {
            return NULL;
        }
    }

    sv_context *new_context = (sv_context*) malloc(sizeof(sv_context));
    new_context->state = op;
    new_context->type = type;
    new_context->key = key;
    new_context->data = NULL;
    new_context->length = 0;
    new_context->mctx = md_ctx;
    return new_context;
 
}

int sv_update(sv_context *ctx, byte *data, size_t length) {
    if (ctx->type == SV_ED25519 || ctx->type == SV_ED448) {
        ctx->data = data;
        ctx->length = length;
        return 1;
    }

    if (ctx->state == SIGN && (EVP_DigestSignUpdate(ctx->mctx, data, length) < 0)) {
        return 0;
    }

    if(ctx->state == VERIFY && (EVP_DigestVerifyUpdate(ctx->mctx, data, length) < 0)) {
        return 0; 
    }

    return 1;
}

int sv_sign(sv_context *ctx, byte *signature, size_t *signature_length) {
    if (ctx->type == SV_ED25519 || ctx->type == SV_ED448) {
        return EVP_DigestSign(ctx->mctx, signature, signature_length, ctx->data, ctx->length);
    }
    return EVP_DigestSignFinal(ctx->mctx, signature, signature_length);
}

int sv_verify(sv_context *ctx, byte *signature, size_t sig_length) {
    if (ctx->type == SV_ED25519 || ctx->type == SV_ED448) {
        return EVP_DigestVerify(ctx->mctx, signature, sig_length, ctx->data, ctx->length);
    }
    return EVP_DigestVerifyFinal(ctx->mctx, signature, sig_length);
}

void free_sv_params(sv_params *params) {
    // TODO: EVP_MD_free fails
    /*if (params->digest)
        EVP_MD_free(params->digest);
    if (params->mgf1_digest)
        EVP_MD_free(params->mgf1_digest);
    */
    free(params);
}

void free_sv_key(sv_key *key) {
    EVP_PKEY_CTX_free(key->ctx);
    free(key);
}

void free_sv_context(sv_context *context) {
    EVP_MD_CTX_free(context->mctx);
    free(context);
}
