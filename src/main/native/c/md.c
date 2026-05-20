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

md_context *md_init(OSSL_LIB_CTX *libctx, const char *algorithm, int *oom) {
    md_context *new = NULL;
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;

    new = (md_context*)malloc(sizeof(md_context));
    if (new == NULL) {
        if (oom) *oom = 1;
        return NULL;
    }
    new->libctx = libctx;
    new->ossl_ctx = NULL;

    md = EVP_MD_fetch(libctx, algorithm, NULL);
    if (md == NULL) {
        goto error;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto error;
    }

    if (!EVP_DigestInit_ex2(ctx, md, NULL)) {
        goto error;
    }

    EVP_MD_free(md);
    new->ossl_ctx = ctx;
    return new;

error:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    free(new);
    return NULL;
}

jssl_status md_update(md_context *ctx, byte *input, size_t input_length) {
    if (!EVP_DigestUpdate(ctx->ossl_ctx, input, input_length)) {
        return FAIL_EVP;
    }
    return SUCCESS;
}

jssl_status md_digest(md_context *ctx, byte *output, int *output_length) {
    unsigned int len = 0;
    if (!EVP_DigestFinal_ex(ctx->ossl_ctx, output, &len)) {
        return FAIL_EVP;
    }
    *output_length = (int)len;
    return SUCCESS;
}

void free_md_context(md_context **pctx) {
    if (pctx == NULL || *pctx == NULL) {
        return;
    }
    EVP_MD_CTX_free((*pctx)->ossl_ctx);
    free(*pctx);
    *pctx = NULL;
}

