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
#include "keyagreement.h"

key_agreement* init_key_agreement(key_agreement_algorithm algo, OSSL_LIB_CTX *libctx) {
    key_agreement agreement = {0};
    key_agreement *new_agreement = (key_agreement*)malloc(sizeof(key_agreement));
    *new_agreement = agreement;
    new_agreement->algorithm = algo;
    new_agreement->libctx = libctx;
}

void set_private_key(key_agreement *agreement, EVP_PKEY *private_key) {
    agreement->private_key = private_key; 
}

void set_peer_key(key_agreement *agreement, EVP_PKEY *peer_public_key) {
    agreement->peer_public_key = peer_public_key;
}

shared_secret *generate_shared_secret(key_agreement *agreement) {
    EVP_PKEY_CTX *ctx = NULL;
    byte *secret_bytes = NULL;
    shared_secret *secret = NULL;

    if (agreement->private_key == NULL || agreement->peer_public_key == NULL) {
        goto error;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(agreement->libctx, agreement->private_key, NULL);
    if (ctx == NULL) {
        goto error;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto error;
    }

    if (EVP_PKEY_derive_set_peer(ctx, agreement->peer_public_key) <= 0) {
        goto error;
    }

    size_t secret_length = 0;
    if (EVP_PKEY_derive(ctx, NULL, &secret_length) <= 0) {
        goto error;
    }

    secret_bytes = OPENSSL_malloc(secret_length);

    if (secret_bytes == NULL) {
        goto error;
    }

    if (EVP_PKEY_derive(ctx, secret_bytes, &secret_length) <= 0) {
        goto error;
    }

    secret = (shared_secret*)malloc(sizeof(shared_secret));
    secret->bytes = secret_bytes;
    secret->length = secret_length;
    agreement->secret = secret;
    EVP_PKEY_CTX_free(ctx);
    return secret;

error:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }

    if (secret_bytes != NULL) {
        OPENSSL_free(secret_bytes);
    }

    return NULL;
}

int get_shared_secret(key_agreement *agreement, byte secret[]) {
    if (secret != NULL) {
        memcpy(secret, agreement->secret->bytes, agreement->secret->length);
    }
    return agreement->secret->length;
}

EVP_PKEY *generate_key(key_agreement_algorithm algo) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];
    if (algo == DIFFIE_HELLMAN) {
        if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL))) {
            goto error;
        }
        params[0] = OSSL_PARAM_construct_utf8_string("group", "ffdhe2048", 0);
        params[1] = OSSL_PARAM_construct_end();
    } else {
        if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
            goto error;
        }
        params[0] = OSSL_PARAM_construct_utf8_string("group", "prime256v1", 0);
        params[1] = OSSL_PARAM_construct_end();
    }

    if(EVP_PKEY_keygen_init(pctx) <= 0) {
        goto error;
    }

    EVP_PKEY_CTX_set_params(pctx, params);

    if(EVP_PKEY_keygen(pctx, &key) <= 0) {
        goto error;
    }

error:
    if ( pctx != NULL ) {
        EVP_PKEY_CTX_free(pctx);
    }

    return key;
}

void free_shared_secret(shared_secret **pthis) {
    if (pthis == NULL || *pthis == NULL)
        return;
    free((*pthis)->bytes);
    free(*pthis);
    *pthis = NULL;
}

void free_key_agreement(key_agreement **pthis) {
    if (pthis == NULL || *pthis == NULL) {
        return;
    }
    EVP_PKEY_free((*pthis)->private_key);
    EVP_PKEY_free((*pthis)->peer_public_key);
    free(*pthis);
    *pthis = NULL;
}
