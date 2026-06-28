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
#include <jni.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

#include "jssl.h"
#include "jni_utils.h"
#include "evp_utils.h"
#include "OpenSSLKeyPairGenerator.h"

JNIEXPORT jobjectArray JNICALL
Java_com_canonical_openssl_keypairgenerator_OpenSSLKeyPairGenerator_generateKeyPair0
  (JNIEnv *env, jclass clazz, jstring algorithm, jstring group) {

    EVP_PKEY     *pkey      = NULL;
    EVP_PKEY_CTX *pctx      = NULL;
    unsigned char *priv_der = NULL;
    unsigned char *pub_der  = NULL;
    size_t priv_len         = 0;
    size_t pub_len          = 0;
    const char *algo_c      = NULL;
    const char *group_c     = NULL;
    jobjectArray result     = NULL;
    jbyteArray privArr      = NULL;
    jbyteArray pubArr       = NULL;
    OSSL_PARAM params[2];

    if (algorithm == NULL || group == NULL) {
        throwProviderException(env, "algorithm and group must not be null");
        return NULL;
    }

    algo_c  = (*env)->GetStringUTFChars(env, algorithm, NULL);
    if (algo_c == NULL) {
        goto cleanup;
    }
    group_c = (*env)->GetStringUTFChars(env, group, NULL);
    if (group_c == NULL) {
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new_from_name(jssl_libctx(), algo_c, NULL);
    if (pctx == NULL) {
        throwProviderException(env, "EVP_PKEY_CTX_new_from_name failed");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        throwProviderException(env, "EVP_PKEY_keygen_init failed");
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_GROUP_NAME, (char *)group_c, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        throwProviderException(env, "EVP_PKEY_CTX_set_params failed");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0 || pkey == NULL) {
        throwProviderException(env, "EVP_PKEY_keygen failed");
        goto cleanup;
    }

    if (!encode_pkey_der(pkey, EVP_PKEY_KEYPAIR, "PrivateKeyInfo",
                     &priv_der, &priv_len)) {
        throwProviderException(env, "private key DER encoding failed");
        goto cleanup;
    }

    if (!encode_pkey_der(pkey, EVP_PKEY_PUBLIC_KEY, "SubjectPublicKeyInfo",
                     &pub_der, &pub_len)) {
        throwProviderException(env, "public key DER encoding failed");
        goto cleanup;
    }

    {
        jclass byteArrayClass = (*env)->FindClass(env, "[B");
        if (byteArrayClass == NULL) {
            goto cleanup;
        }

        result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
        if (result == NULL) {
            goto cleanup;
        }

        privArr = byte_array_to_jbyteArray(env, priv_der, (int)priv_len);
        if (privArr == NULL) {
            result = NULL;
            goto cleanup;
        }
        (*env)->SetObjectArrayElement(env, result, 0, privArr);

        pubArr = byte_array_to_jbyteArray(env, pub_der, (int)pub_len);
        if (pubArr == NULL) {
            result = NULL;
            goto cleanup;
        }
        (*env)->SetObjectArrayElement(env, result, 1, pubArr);
    }

cleanup:
    if (priv_der != NULL) {
        OPENSSL_cleanse(priv_der, priv_len);
        OPENSSL_free(priv_der);
    }
    if (pub_der != NULL) {
        OPENSSL_free(pub_der);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (algo_c != NULL) {
        (*env)->ReleaseStringUTFChars(env, algorithm, algo_c);
    }
    if (group_c != NULL) {
        (*env)->ReleaseStringUTFChars(env, group, group_c);
    }
    return result;
}
