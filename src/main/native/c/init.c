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
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdio.h>
#include "jni.h"

/* Global libctx handle. Will be initializaed in JNI_OnLoad */
OSSL_LIB_CTX *global_libctx = NULL;

/* Loading the FIPS provider is often not enough to get openssl's full functionality.
   We also should load the base provider. The base provider does not provide for
   any crypto functionality, but has other functionality like the encoders for example.

   These two comments saved my day:
   https://github.com/openssl/openssl/issues/13773#issuecomment-756225529
   https://github.com/openssl/openssl/issues/13773#issuecomment-756233808
*/ 

OSSL_LIB_CTX* load_openssl_provider(const char *name, const char* conf_file_path) {
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

    if (OSSL_PROVIDER_available(libctx, "fips")) {
        // The FIPS module has been loaded by default.
        // The base module should also be loaded and the default model not loaded.
        // There's nothing more to do. This is the Ubuntu Pro setup.
        return libctx;
    }

    if (!OSSL_LIB_CTX_load_config(libctx, conf_file_path)) {
        ERR_print_errors_fp(stderr);
    }

    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, name);
    if (NULL == prov) {
        fprintf(stderr, "Failed to load the %s provider:\n", name);
        ERR_print_errors_fp(stderr);
    }

    return libctx;
}

OSSL_LIB_CTX* load_openssl_fips_provider(const char* conf_file_path) {
    load_openssl_provider("fips", conf_file_path);
}

OSSL_LIB_CTX* load_openssl_base_provider(const char* conf_file_path) {
    load_openssl_provider("base", conf_file_path);
}

int JNI_OnLoad(JavaVM* vm, void *reserved) {
    global_libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    return JNI_VERSION_21;
}
