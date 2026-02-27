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
#include "jssl.h"

#define CASTPTR(TYPE, a) (TYPE *)(a)

/* Legacy functions - still using d2i_* (DEPRECATED for FIPS) */
EVP_PKEY *create_private_key(int type, byte* bytes, size_t length);
EVP_PKEY *create_public_key(byte* bytes, size_t length);

/* FIPS-safe decoder-based functions using OSSL_DECODER */
EVP_PKEY *decode_private_key_fips(byte* bytes, size_t length, OSSL_LIB_CTX *libctx);
EVP_PKEY *decode_public_key_fips(byte* bytes, size_t length, OSSL_LIB_CTX *libctx);

