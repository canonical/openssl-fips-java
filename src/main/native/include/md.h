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

typedef struct md_context {
    EVP_MD_CTX *ossl_ctx;
    OSSL_LIB_CTX *libctx;
} md_context;

md_context *md_init(OSSL_LIB_CTX *libctx, const char *algorithm);
int md_update(md_context *ctx, byte *input, size_t input_length);
int md_digest(md_context *ctx, byte *output, int *output_length);
void free_md_context(md_context *ctx);
