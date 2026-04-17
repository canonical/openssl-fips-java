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
#include "jssl.h"
#include "kdf.h"
#include <stdlib.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

kdf_spec *create_pbkdf_spec(byte *password, int pass_len, byte *salt, int salt_len, unsigned int iter) {
    pbkdf_spec *new = NULL;
    kdf_spec *new_spec = NULL;

    new = (pbkdf_spec*)malloc(sizeof(pbkdf_spec));
    if (new == NULL) goto error;
    new->password = NULL;
    new->salt = NULL;

    new->password = (byte *)malloc(pass_len);
    if (new->password == NULL) goto error;
    memcpy(new->password, password, pass_len);
    new->password_length = pass_len;

    new->salt = (byte *)malloc(salt_len);
    if (new->salt == NULL) goto error;
    memcpy(new->salt, salt, salt_len);
    new->salt_length = salt_len;

    new->iterations = iter;

    new_spec = (kdf_spec*)malloc(sizeof(kdf_spec));
    if (new_spec == NULL) goto error;
    new_spec->pbkdf = new;
    return new_spec;

error:
    if (new != NULL) {
        if (new->password) { OPENSSL_cleanse(new->password, pass_len); free(new->password); }
        if (new->salt)     { OPENSSL_cleanse(new->salt, salt_len);     free(new->salt); }
        free(new);
    }
    return NULL;
}

kdf_params *create_pbkdf_params(char *algorithm) {
    pbkdf_params *new = NULL;
    kdf_params *new_params = NULL;

    new = (pbkdf_params*)malloc(sizeof(pbkdf_params));
    if (new == NULL) goto error;
    new->digest_algorithm = algorithm;

    new_params = (kdf_params *)malloc(sizeof(kdf_params));
    if (new_params == NULL) goto error;
    new_params->pbkdf = new;
    return new_params;

error:
    free(new);
    return NULL;
}

static void populate_pbkdf2_params(OSSL_PARAM *ossl_params, kdf_spec *spec, kdf_params *params) {
    int nparams = 0;
    ossl_params[nparams++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                              spec->pbkdf->password, spec->pbkdf->password_length);
    ossl_params[nparams++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, spec->pbkdf->salt,
                                                              spec->pbkdf->salt_length);
    if (spec->pbkdf->iterations > 0) {
        ossl_params[nparams++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &(spec->pbkdf->iterations));
    }
    ossl_params[nparams++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, params->pbkdf->digest_algorithm, 0);
    ossl_params[nparams++] = OSSL_PARAM_construct_end();
}

kdf_spec *create_hkdf_spec(byte *salt, int saltlen, byte *info, int infolen, byte *key, int keylen) {
    hkdf_spec *new = NULL;
    kdf_spec *new_spec = NULL;

    new = (hkdf_spec*)malloc(sizeof(hkdf_spec));
    if (new == NULL) goto error;
    new->salt = NULL;
    new->info = NULL;
    new->key  = NULL;

    new->salt = (byte *)malloc(saltlen);
    if (new->salt == NULL) goto error;
    memcpy(new->salt, salt, saltlen);
    new->salt_length = saltlen;

    new->info = (byte *)malloc(infolen);
    if (new->info == NULL) goto error;
    memcpy(new->info, info, infolen);
    new->info_length = infolen;

    new->key = (byte *)malloc(keylen);
    if (new->key == NULL) goto error;
    memcpy(new->key, key, keylen);
    new->key_length = keylen;

    new_spec = (kdf_spec*)malloc(sizeof(kdf_spec));
    if (new_spec == NULL) goto error;
    new_spec->hkdf = new;
    return new_spec;

error:
    if (new != NULL) {
        if (new->salt) { OPENSSL_cleanse(new->salt, saltlen); free(new->salt); }
        if (new->info) { OPENSSL_cleanse(new->info, infolen); free(new->info); }
        if (new->key)  { OPENSSL_cleanse(new->key,  keylen);  free(new->key); }
        free(new);
    }
    return NULL;
}

kdf_params *create_hkdf_params(char *algorithm) {
    hkdf_params *new = NULL;
    kdf_params *new_params = NULL;

    new = (hkdf_params*)malloc(sizeof(hkdf_params));
    if (new == NULL) goto error;
    new->digest_algorithm = algorithm;

    new_params = (kdf_params *)malloc(sizeof(kdf_params));
    if (new_params == NULL) goto error;
    new_params->hkdf = new;
    return new_params;

error:
    free(new);
    return NULL;
}

static void populate_hkdf_params(OSSL_PARAM *ossl_params, kdf_spec *spec, kdf_params *params) {
    int nparams = 0;
    ossl_params[nparams++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, spec->hkdf->key, spec->hkdf->key_length);
    ossl_params[nparams++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, spec->hkdf->info, spec->hkdf->info_length);
    ossl_params[nparams++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, spec->hkdf->salt, spec->hkdf->salt_length);
    ossl_params[nparams++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, params->hkdf->digest_algorithm, 0);
    ossl_params[nparams++] = OSSL_PARAM_construct_end();
}

static void populate_params(OSSL_PARAM *ossl_params, kdf_spec *spec, kdf_params *params, kdf_type type) {
    switch (type) {
        case PBKDF2:
            populate_pbkdf2_params(ossl_params, spec, params);           
            break;
        case HKDF:
            populate_hkdf_params(ossl_params, spec, params);
            break;
        default:
            printf("Not supported yet.\n");
    }
}

static char *get_kdf_name(kdf_type type) {
    switch (type) {
        case PBKDF2:
            return "PBKDF2";
        case HKDF:
            return "HKDF";
        default:
            return "UNSUPPORTED";
    }
}
    
jssl_status kdf_derive(OSSL_LIB_CTX *libctx, kdf_spec *spec, kdf_params *params, byte *keydata, int keylength, kdf_type type) {
    OSSL_PARAM ossl_params[8];
    populate_params(ossl_params, spec, params, type);

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    jssl_status ret = SUCCESS;

    kdf = EVP_KDF_fetch(libctx, get_kdf_name(type), NULL);
    if (kdf == NULL) {
        ret = FAIL_EVP;
        goto error;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        ret = FAIL_EVP;
        goto error;
    }

    int rc = EVP_KDF_derive(kctx, keydata, keylength, ossl_params);
    if (!rc) ret = FAIL_EVP;

error:
    if (kctx != NULL) {
        EVP_KDF_CTX_free(kctx);
    }

    if (kdf != NULL) {
        EVP_KDF_free(kdf);
    }

    return ret;
}
        
void free_kdf_spec(kdf_spec **pspec, kdf_type type) {
    if (pspec == NULL || *pspec == NULL) return;
    if (type == PBKDF2) {
        pbkdf_spec *p = (*pspec)->pbkdf;
        if (p != NULL) {
            if (p->password) { OPENSSL_cleanse(p->password, p->password_length); free(p->password); }
            if (p->salt)     { OPENSSL_cleanse(p->salt, p->salt_length);         free(p->salt); }
            OPENSSL_cleanse(p, sizeof(pbkdf_spec));
            free(p);
        }
    } else {
        hkdf_spec *h = (*pspec)->hkdf;
        if (h != NULL) {
            if (h->key)  { OPENSSL_cleanse(h->key,  h->key_length);  free(h->key); }
            if (h->salt) { OPENSSL_cleanse(h->salt, h->salt_length); free(h->salt); }
            if (h->info) { OPENSSL_cleanse(h->info, h->info_length); free(h->info); }
            OPENSSL_cleanse(h, sizeof(hkdf_spec));
            free(h);
        }
    }
    free(*pspec);
    *pspec = NULL;
}

void free_kdf_params(kdf_params **pparams, kdf_type type) {
    if (pparams == NULL || *pparams == NULL) return;
    void *contained = (type == PBKDF2) ? (void *)(*pparams)->pbkdf
                                       : (void *)(*pparams)->hkdf;
    free(contained);
    free(*pparams);
    *pparams = NULL;
}
