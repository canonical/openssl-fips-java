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
#include <openssl/evp.h>
#include <openssl/decoder.h>

#include "jssl.h"

/* FIPS-safe decoder functions using OSSL_DECODER API
 * These functions properly route through the FIPS provider and respect
 * provider boundaries, avoiding direct key structure manipulation.
 */
EVP_PKEY *decode_private_key_fips(byte* bytes, size_t length, OSSL_LIB_CTX *libctx) {
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    const byte *data = bytes;
    size_t data_len = length;

    if (libctx == NULL) {
        libctx = jssl_libctx();
    }

    /* Create decoder context for private keys in DER format
     * This will automatically detect the key type (RSA, EC, Ed25519, Ed448, etc.)
     * and route through the appropriate provider (FIPS in our case)
     */
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, NULL,
                                         OSSL_KEYMGMT_SELECT_KEYPAIR,
                                         libctx, NULL);

    if (dctx == NULL) {
        return NULL;
    }

    /* Decode the DER data into an EVP_PKEY */
    if (OSSL_DECODER_from_data(dctx, &data, &data_len) != 1 || data_len != 0) {
        pkey = NULL;
    }

    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

EVP_PKEY *decode_public_key_fips(byte* bytes, size_t length, OSSL_LIB_CTX *libctx) {
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    const byte *data = bytes;
    size_t data_len = length;

    if (libctx == NULL) {
        libctx = jssl_libctx();
    }

    /* Create decoder context for public keys in DER format */
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, NULL,
                                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                         libctx, NULL);

    if (dctx == NULL) {
        return NULL;
    }

    /* Decode the DER data into an EVP_PKEY */
    if (OSSL_DECODER_from_data(dctx, &data, &data_len) != 1 || data_len != 0) {
        pkey = NULL;
    }

    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

