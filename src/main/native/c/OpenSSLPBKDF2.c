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
#include "jni_utils.h"
#include "kdf.h"
#include "OpenSSLPBKDF2.h"
#include <openssl/crypto.h>

#define MAX_KEY_SIZE 256
/*
 * Class:     com_canonical_openssl_kdf_OpenSSLPBKDF2
 * Method:    generateSecret0
 * Signature: ([C[BII)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_kdf_OpenSSLPBKDF2_generateSecret0
  (JNIEnv *env, jobject this, jcharArray password, jbyteArray salt, jint iteration_count, jint key_length) {
    if (key_length <= 0 || key_length > MAX_KEY_SIZE) {
        throwProviderException(env, "Invalid PBKDF2 key length");
        return NULL;
    }

    int password_length = (*env)->GetArrayLength(env, password);
    int salt_length = array_length(env, salt);
    byte output[MAX_KEY_SIZE] = {0};
    jbyteArray result = NULL;

    jchar *password_chars = (*env)->GetCharArrayElements(env, password, NULL);
    if (password_chars == NULL) {
        return NULL;
    }
    jbyte *salt_bytes = (*env)->GetByteArrayElements(env, salt, NULL);
    if (salt_bytes == NULL) {
        (*env)->ReleaseCharArrayElements(env, password, password_chars, JNI_ABORT);
        return NULL;
    }

    kdf_spec *spec = create_pbkdf_spec((byte *)password_chars, password_length * sizeof(jchar),
                        (byte *)salt_bytes, salt_length, iteration_count);

    (*env)->ReleaseCharArrayElements(env, password, password_chars, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, salt, salt_bytes, JNI_ABORT);

    if (spec == NULL) {
        throwOOM(env, "Failed to allocate PBKDF2 spec");
        return NULL;
    }

    kdf_params *params = create_pbkdf_params("SHA-512");
    if (params == NULL) {
        free_kdf_spec(&spec, PBKDF2);
        throwOOM(env, "Failed to allocate PBKDF2 params");
        return NULL;
    }

    if (kdf_derive(jssl_libctx(), spec, params, output, key_length, PBKDF2) == SUCCESS) {
        result = byte_array_to_jbyteArray(env, output, key_length);
    }

    OPENSSL_cleanse(output, sizeof(output));
    free_kdf_spec(&spec, PBKDF2);
    free_kdf_params(&params, PBKDF2);
    return result;
}

JNIEXPORT jint JNICALL Java_com_canonical_openssl_kdf_OpenSSLPBKDF2_getMaxKeyLengthBytes0
  (JNIEnv *env, jclass cls) {
    return MAX_KEY_SIZE;
}
