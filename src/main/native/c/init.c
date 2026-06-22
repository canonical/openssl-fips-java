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
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include "jni.h"

static OSSL_LIB_CTX *global_libctx = NULL;
static OSSL_PROVIDER *pbase, *pfips;

/* A NULL ctx here means JNI_OnLoad did not run; not reachable in normal use. */
OSSL_LIB_CTX* jssl_libctx(void) {
    OSSL_LIB_CTX *ctx = __atomic_load_n(&global_libctx, __ATOMIC_ACQUIRE);
    if (ctx == NULL) {
        fputs("jssl: global_libctx is NULL; JNI_OnLoad did not run or memory is corrupted\n", stderr);
        abort();
    }
    return ctx;
}

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
        OSSL_LIB_CTX_free(libctx);
        return NULL;
    }

    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(libctx, name);
    if (NULL == prov) {
        OSSL_LIB_CTX_free(libctx);
        return NULL;
    }

    if (strcmp("fips", name) == 0) {
        pfips = prov;
    } else {
        pbase = prov;
    }
    return libctx;
}

OSSL_LIB_CTX* load_openssl_fips_provider(const char* conf_file_path) {
    OSSL_LIB_CTX *libctx = load_openssl_provider("fips", conf_file_path);
    if (libctx == NULL) {
        return NULL;
    }
    if (!EVP_set_default_properties(libctx, "fips=yes")) {
        unload_libctx(libctx);
        return NULL;
    }
    return libctx;
}

OSSL_LIB_CTX* load_openssl_base_provider(const char* conf_file_path) {
    return load_openssl_provider("base", conf_file_path);
}


void unload_libctx(OSSL_LIB_CTX *libctx) {
    if (pfips != NULL) OSSL_PROVIDER_unload(pfips);
    if (pbase != NULL) OSSL_PROVIDER_unload(pbase);
    if (libctx != NULL) OSSL_LIB_CTX_free(libctx);
}

static void unload_global_libctx() {
    OSSL_LIB_CTX *ctx = __atomic_exchange_n(&global_libctx, NULL, __ATOMIC_ACQ_REL);
    unload_libctx(ctx);
}

/*
 * Note on OPENSSL_CUSTOM_CONF and the config file:
 *
 * When the FIPS provider is not already available by default (i.e. outside the
 * Ubuntu Pro auto-FIPS setup), we load OpenSSL's configuration from the file
 * named by the OPENSSL_CUSTOM_CONF environment variable, or from
 * /usr/local/ssl/openssl.cnf if that variable is not set. That config decides
 * which provider gets loaded as "fips".
 *
 * Both the environment variable and the config file it points to are TRUSTED
 * inputs. Anyone who can change either of them can choose which OpenSSL provider
 * module is loaded into this process. We use secure_getenv, so the variable is
 * ignored when the process is running with elevated privileges (setuid/setgid),
 * but in every other case the caller is responsible for protecting these inputs.
 *
 * In deployments where FIPS compliance is required, make sure the config file
 * (and the directory containing it) is owned by root and not writable by
 * untrusted users, so that "fips" cannot be redirected to a non-validated
 * module.
 */
int JNI_OnLoad(JavaVM* vm, void *reserved) {
    const char *default_cnf = "/usr/local/ssl/openssl.cnf";
    const char *custom_cnf = secure_getenv("OPENSSL_CUSTOM_CONF");
    const char *conf = custom_cnf != NULL ? custom_cnf : default_cnf;
    OSSL_LIB_CTX *ctx = load_openssl_fips_provider(conf);
    if (ctx == NULL) {
        return JNI_ERR;
    }
    if (!OSSL_PROVIDER_available(ctx, "base")) {
        pbase = OSSL_PROVIDER_load(ctx, "base");
        if (pbase == NULL) {
            unload_libctx(ctx);
            return JNI_ERR;
        }
    }
    __atomic_store_n(&global_libctx, ctx, __ATOMIC_RELEASE);
    return JNI_VERSION_10;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    unload_global_libctx();
}
