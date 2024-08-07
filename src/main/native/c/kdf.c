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

kdf_spec *create_pbkdf_spec(byte *password, int pass_len, byte *salt, int salt_len, unsigned int iter) {
    pbkdf_spec *new = (pbkdf_spec*)malloc(sizeof(pbkdf_spec));
    new->password=password;
    new->password_length = pass_len;
    new->salt = salt;
    new->salt_length = salt_len;
    new->iterations = iter;

    kdf_spec *new_spec = (kdf_spec*)malloc(sizeof(kdf_spec));
    new_spec->pbkdf = new;

    return new_spec;
}

kdf_params *create_pbkdf_params(char *algorithm) {
    pbkdf_params *new = (pbkdf_params*)malloc(sizeof(pbkdf_params));
    new->digest_algorithm = algorithm;

    kdf_params *new_params = (kdf_params *)malloc(sizeof(kdf_params));
    new_params->pbkdf = new;
    return new_params;
}

static void populate_pbkdf2_params(OSSL_PARAM *ossl_params, kdf_spec *spec, kdf_params *params) {
    int nparams = 0;
    ossl_params[nparams++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                              spec->pbkdf->password, spec->pbkdf->password_length);
    ossl_params[nparams++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, spec->pbkdf->salt,
                                                              spec->pbkdf->salt_length);
    if (spec->pbkdf->iterations <= 0) {
        ossl_params[nparams++] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &(spec->pbkdf->iterations));
    }
    ossl_params[nparams++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, params->pbkdf->digest_algorithm, 0);
    ossl_params[nparams++] = OSSL_PARAM_construct_end();
}

kdf_spec *create_hkdf_spec(byte *salt, int saltlen, byte *info, int infolen, byte *key, int keylen) {
    hkdf_spec *new = (hkdf_spec*)malloc(sizeof(hkdf_spec));
    new->salt = salt;
    new->salt_length = saltlen;
    new->info = info;
    new->info_length = infolen;
    new->key = key;
    new->key_length = keylen;

    kdf_spec *new_spec = (kdf_spec*)malloc(sizeof(kdf_spec));
    new_spec->hkdf = new;

    return new_spec;
}

kdf_params *create_hkdf_params(char *algorithm) {
    hkdf_params *new = (hkdf_params*)malloc(sizeof(hkdf_params));
    new->digest_algorithm = algorithm;

    kdf_params *new_params = (kdf_params *)malloc(sizeof(kdf_params));
    new_params->hkdf = new;
    return new_params;
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
    
int kdf_derive(OSSL_LIB_CTX *libctx, kdf_spec *spec, kdf_params *params, byte *keydata, int keylength, kdf_type type) {
    OSSL_PARAM ossl_params[8];
    populate_params(ossl_params, spec, params, type);

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    kdf = EVP_KDF_fetch(libctx, get_kdf_name(type), NULL);
    if (kdf == NULL) {
        return 0;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        return 0;
    }

    return EVP_KDF_derive(kctx, keydata, keylength, ossl_params);
}
        
void free_kdf_spec(kdf_spec *spec) {
    void *contained = (void*)spec->hkdf;
    free(contained);
    free(spec);
}

void free_kdf_params(kdf_params *params) {
    void *contained = (void*) params->hkdf;
    free(contained);
    free(params);
}
