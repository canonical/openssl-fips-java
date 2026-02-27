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
#include "jssl.h"
#include "evp_utils.h"
#include "jni_utils.h"

extern OSSL_LIB_CTX *global_libctx;

/*
 * Class:     com_canonical_openssl_key_KeyConverter
 * Method:    privateKeyToEVPKey0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_key_KeyConverter_privateKeyToEVPKey0
  (JNIEnv *env, jclass clazz, jbyteArray encodedKey) {

    if (encodedKey == NULL) {
        return 0;
    }

    jsize length = (*env)->GetArrayLength(env, encodedKey);
    if (length <= 0) {
        return 0;
    }

    byte* bytes = jbyteArray_to_byte_array(env, encodedKey);
    if (bytes == NULL) {
        return 0;
    }

    /* Use FIPS-safe decoder to convert DER to EVP_PKEY */
    EVP_PKEY *pkey = decode_private_key_fips(bytes, (size_t)length, global_libctx);

    free(bytes);

    return (jlong)pkey;
}

/*
 * Class:     com_canonical_openssl_key_KeyConverter
 * Method:    publicKeyToEVPKey0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_key_KeyConverter_publicKeyToEVPKey0
  (JNIEnv *env, jclass clazz, jbyteArray encodedKey) {

    if (encodedKey == NULL) {
        return 0;
    }

    jsize length = (*env)->GetArrayLength(env, encodedKey);
    if (length <= 0) {
        return 0;
    }

    byte* bytes = jbyteArray_to_byte_array(env, encodedKey);
    if (bytes == NULL) {
        return 0;
    }

    /* Use FIPS-safe decoder to convert DER to EVP_PKEY */
    EVP_PKEY *pkey = decode_public_key_fips(bytes, (size_t)length, global_libctx);

    free(bytes);

    return (jlong)pkey;
}

/*
 * Class:     com_canonical_openssl_key_KeyConverter
 * Method:    freeEVPKey0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_key_KeyConverter_freeEVPKey0
  (JNIEnv *env, jclass clazz, jlong evpKeyPtr) {

    EVP_PKEY *pkey = (EVP_PKEY *)evpKeyPtr;
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
}

