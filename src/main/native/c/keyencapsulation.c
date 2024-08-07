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
#include "keyencapsulation.h"
#include <openssl/pem.h>
#include <openssl/encoder.h>
#include <stdlib.h>
#include <openssl/err.h>

# define TEST_ptr(a)          (a)
# define TEST_true(a)         ((a) != 0)

int rsa_keygen(OSSL_LIB_CTX *libctx, int bits, EVP_PKEY **pub, EVP_PKEY **priv)
{
    int ret = 0;
    unsigned char *pub_der = NULL;
    const unsigned char *pp = NULL;
    size_t len = 0;
    OSSL_ENCODER_CTX *ectx = NULL;

    if (!TEST_ptr(*priv = EVP_PKEY_Q_keygen(libctx, NULL, "RSA", bits))
        || !TEST_ptr(ectx =
                     OSSL_ENCODER_CTX_new_for_pkey(*priv,
                                                   EVP_PKEY_PUBLIC_KEY,
                                                   "DER", "type-specific",
                                                   NULL))
        || !TEST_true(OSSL_ENCODER_to_data(ectx, &pub_der, &len)))
        goto err;
    pp = pub_der;
    if (NULL == (d2i_PublicKey(EVP_PKEY_RSA, pub, &pp, len)))
        goto err;
    ret = 1;
err:
    OSSL_ENCODER_CTX_free(ectx);
    OPENSSL_free(pub_der);
    return ret;
}


kem_keyspec *init_kem_keyspec(OSSL_LIB_CTX *libctx) {
    EVP_PKEY *public_key = NULL;
    EVP_PKEY *private_key = NULL;
    rsa_keygen(libctx, 4096, &public_key, &private_key);
    init_kem_keyspec_with_key(public_key, private_key, libctx);
}

kem_keyspec *init_kem_keyspec_with_key(EVP_PKEY *rsa_pub_key, EVP_PKEY *rsa_priv_key, OSSL_LIB_CTX *libctx) {
    kem_keyspec *spec = (kem_keyspec*)malloc(sizeof(kem_keyspec));
    spec->public_key = rsa_pub_key;
    spec->private_key = rsa_priv_key; 
    spec->libctx = libctx;
    spec->secret = NULL;
    spec->wrapped_key = NULL;
    spec->secret_length = 0;
    spec->wrapped_key_length = 0;
    return spec;
}

void free_kem_keyspec(kem_keyspec *spec) {
    free(spec->wrapped_key);
    free(spec->secret);
    free(spec);
}

EVP_PKEY_CTX *initialize_encapsulation(kem_keyspec *spec) {
    size_t wrapped_key_length = 0;
    size_t secret_length = 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(spec->libctx, spec->public_key, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        return NULL;
    }

    if (EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE") <= 0) {
        return NULL;
    }

    if (EVP_PKEY_encapsulate(ctx, NULL, &wrapped_key_length, NULL, &secret_length) <= 0) {
        return NULL;
    }

    spec->secret_length = secret_length;
    spec->wrapped_key_length = wrapped_key_length;
    spec->secret = (byte *)malloc(secret_length);
    spec->wrapped_key = (byte *)malloc(wrapped_key_length);

    return ctx;
}

EVP_PKEY_CTX *initialize_decapsulation(kem_keyspec *spec) {
    size_t secret_length = 0;
    if (spec->wrapped_key == NULL || spec->wrapped_key_length <= 0) {
        return NULL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(spec->libctx, spec->private_key, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        return NULL;
    }

    if (EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE") <= 0) {
        return NULL;
    }

    if (EVP_PKEY_decapsulate(ctx, NULL, &secret_length, spec->wrapped_key, spec->wrapped_key_length) <= 0) {
        return NULL;
    }

    spec->secret = OPENSSL_malloc(secret_length);
    spec->secret_length = secret_length;

    return ctx;
}

int get_secret_size(kem_keyspec *spec, int is_encap) {
    if (is_encap)
        initialize_encapsulation(spec);
    else
        initialize_decapsulation(spec);

    return spec->secret_length;
}

int get_encapsulation_size(kem_keyspec *spec, int is_encap) {
    if (is_encap)
        initialize_encapsulation(spec);
    else
        initialize_decapsulation(spec);

    return spec->wrapped_key_length;
}


int generate_and_wrap(kem_keyspec *spec) {
    EVP_PKEY_CTX *ctx = initialize_encapsulation(spec);

    if (spec->secret == NULL || spec->wrapped_key == NULL) {
        return 1;
    }

    if (EVP_PKEY_encapsulate(ctx, spec->wrapped_key, &(spec->wrapped_key_length), spec->secret, &(spec->secret_length)) <= 0) {
        return 1;
    }
    return 0;
}

int set_wrapped_key(kem_keyspec *spec, byte *wrapped_key, int length) {
    spec->wrapped_key = wrapped_key;
    spec->wrapped_key_length = length;
}

int unwrap(kem_keyspec *spec) {
    EVP_PKEY_CTX *ctx = initialize_decapsulation(spec);
    if (spec->secret == NULL) {
        return 1;
    }

    if (EVP_PKEY_decapsulate(ctx, spec->secret, &spec->secret_length, spec->wrapped_key, spec->wrapped_key_length) <= 0) {
        return 1;
    }
    return 0;
}
