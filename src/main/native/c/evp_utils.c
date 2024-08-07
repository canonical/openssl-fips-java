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
#include <openssl/x509.h>

#include "jssl.h"

extern OSSL_LIB_CTX *global_libctx;

EVP_PKEY *create_private_key(int type, byte* bytes, size_t length) {
    return d2i_PrivateKey_ex(type, NULL, (const byte**)&bytes, length, global_libctx, NULL);
}

EVP_PKEY *create_public_key(byte* bytes, size_t length) {
    return d2i_PUBKEY_ex(NULL, (const byte**) &bytes, length, global_libctx, NULL);
}

