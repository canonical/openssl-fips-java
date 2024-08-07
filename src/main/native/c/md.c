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
#include "md.h"

md_context *md_init(OSSL_LIB_CTX *libctx, const char *algorithm) {
    md_context *new = (md_context*)malloc(sizeof(md_context));
    new->libctx = libctx;
    EVP_MD *md = EVP_MD_fetch(libctx, algorithm, NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex2(ctx, md, NULL)) {
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
        free(new);
        return NULL;
    }
    EVP_MD_free(md);
    new->ossl_ctx = ctx;
    return new; 
}

int md_update(md_context *ctx, byte *input, size_t input_length) {
    if (!EVP_DigestUpdate(ctx->ossl_ctx, input, input_length)) {
        free_md_context(ctx);
        return 0;
    }
    return 1;
}

int md_digest(md_context *ctx, byte *output, int *output_length) {
    if (!EVP_DigestFinal_ex(ctx->ossl_ctx, output, output_length)) {
        free_md_context(ctx);
        return 0;
    }
    return 1;
}

void free_md_context(md_context *ctx) {
    EVP_MD_CTX_free(ctx->ossl_ctx);
    free(ctx);
}

