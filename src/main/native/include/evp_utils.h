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
#ifndef _INCLUDE_EVP_UTILS_H
#define _INCLUDE_EVP_UTILS_H
#include <openssl/evp.h>
#include "jssl.h"

#define CASTPTR(TYPE, a) (TYPE *)(a)

/* FIPS-safe decoder-based functions using OSSL_DECODER */
EVP_PKEY *decode_private_key_fips(byte* bytes, size_t length, OSSL_LIB_CTX *libctx);
EVP_PKEY *decode_public_key_fips(byte* bytes, size_t length, OSSL_LIB_CTX *libctx);

/*
 * DER-encode part of an EVP_PKEY via OSSL_ENCODER. selection is an EVP_PKEY_*
 * selection flag (e.g. EVP_PKEY_KEYPAIR, EVP_PKEY_PUBLIC_KEY) and structure the
 * encoding structure name ("PrivateKeyInfo" / "SubjectPublicKeyInfo"). On
 * success returns 1 and stores a freshly allocated buffer in *out (the caller
 * frees it with OPENSSL_free, cleansing first for private material); returns 0
 * on failure with *out left NULL.
 */
int encode_pkey_der(EVP_PKEY *pkey, int selection, const char *structure,
                    unsigned char **out, size_t *out_len);
#endif // _INCLUDE_EVP_UTILS_H
