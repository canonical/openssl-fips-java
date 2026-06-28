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
#include <openssl/bn.h>
#include <openssl/param_build.h>

#include "jssl.h"
#include "jni_utils.h"
#include "evp_utils.h"
#include "RSAKeyPairGenerator.h"

/*
 * RSA key generation against the FIPS library context. The modulus size and
 * public exponent are validated on the Java side (FIPS 186-5); here we build
 * the key with EVP_PKEY_keygen so generation, the approved DRBG and the
 * pairwise-consistency self-test all stay inside the FIPS module boundary.
 *
 * publicExponent is an unsigned big-endian integer (BigInteger.toByteArray());
 * BN_bin2bn parses it and OSSL_PARAM_BLD_push_BN normalises endianness for the
 * provider, so no manual byte juggling is required.
 */
JNIEXPORT jobjectArray JNICALL
Java_com_canonical_openssl_keypairgenerator_RSAKeyPairGenerator_generateRSAKeyPair0
  (JNIEnv *env, jclass clazz, jint keysize, jbyteArray publicExponent) {

    EVP_PKEY       *pkey     = NULL;
    EVP_PKEY_CTX   *pctx     = NULL;
    OSSL_PARAM_BLD *bld      = NULL;
    OSSL_PARAM     *params   = NULL;
    BIGNUM         *e        = NULL;
    unsigned char  *e_bytes  = NULL;
    unsigned char  *priv_der = NULL;
    unsigned char  *pub_der  = NULL;
    size_t priv_len          = 0;
    size_t pub_len           = 0;
    jsize  e_len             = 0;
    jobjectArray result      = NULL;
    jbyteArray privArr       = NULL;
    jbyteArray pubArr        = NULL;

    if (keysize <= 0) {
        throwIllegalArgument(env, "invalid RSA key size");
        return NULL;
    }
    if (publicExponent == NULL) {
        throwIllegalArgument(env, "public exponent must not be null");
        return NULL;
    }

    e_len = (*env)->GetArrayLength(env, publicExponent);
    if (e_len <= 0) {
        throwIllegalArgument(env, "invalid public exponent");
        return NULL;
    }
    e_bytes = OPENSSL_malloc((size_t)e_len);
    if (e_bytes == NULL) {
        throwOOM(env, "allocating public exponent buffer");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, publicExponent, 0, e_len, (jbyte *)e_bytes);
    e = BN_bin2bn(e_bytes, (int)e_len, NULL);
    if (e == NULL) {
        throwProviderException(env, "failed to parse RSA public exponent");
        goto cleanup;
    }

    pctx = EVP_PKEY_CTX_new_from_name(jssl_libctx(), "RSA", NULL);
    if (pctx == NULL) {
        throwProviderException(env, "EVP_PKEY_CTX_new_from_name failed");
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        throwProviderException(env, "EVP_PKEY_keygen_init failed");
        goto cleanup;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL
            || OSSL_PARAM_BLD_push_size_t(bld, OSSL_PKEY_PARAM_RSA_BITS,
                                          (size_t)keysize) <= 0
            || OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) <= 0) {
        throwProviderException(env, "failed to build RSA keygen parameters");
        goto cleanup;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        throwProviderException(env, "failed to finalize RSA keygen parameters");
        goto cleanup;
    }
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
    if (e_bytes != NULL) {
        OPENSSL_free(e_bytes);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (bld != NULL) {
        OSSL_PARAM_BLD_free(bld);
    }
    if (e != NULL) {
        BN_free(e);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    return result;
}
