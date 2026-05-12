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
#include "jssl.h"
#include "keyencapsulation.h"
#include "RSAKEMEncapsulator.h"
#include "evp_utils.h"
#include "jni_utils.h"

/*
 * Class:     OpenSSLKEMRSA_RSAKEMEncapsulator
 * Method:    encapsulatorInit0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMEncapsulator_encapsulatorInit0
  (JNIEnv *env, jobject this, jbyteArray key) {
    byte* bytes = jbyteArray_to_byte_array(env, key);
    if (bytes == NULL) {
        return 0;
    }
    int length = array_length(env, key);
    EVP_PKEY *public_key = decode_public_key_fips(bytes, length, jssl_libctx());
    release_jbyteArray(env, key, bytes);
    kem_keyspec *spec = init_kem_keyspec_with_key(public_key, NULL, jssl_libctx());
    if (spec == NULL) {
        throwOOM(env, "Could not allocate KEM keyspec");
        return 0;
    }
    jssl_status rc = init_encapsulator(spec);
    if (rc != SUCCESS) {
        free_kem_keyspec(&spec);
        if (rc == FAIL_OOM)
            throwOOM(env, "Out of memory initializing encapsulator");
        else
            throwProviderException(env, "Failed to initialize encapsulator");
        return 0;
    }
    return (jlong)spec;
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMEncapsulator
 * Method:    engineEncapsulate0
 * Signature: ([B[B)V;
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMEncapsulator_engineEncapsulate0
  (JNIEnv *env, jobject this, jbyteArray secret_bytes, jbyteArray encapsulated_bytes) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    jssl_status rc = generate_and_wrap(spec);
    if (rc == FAIL_OOM) {
        throwOOM(env, "Out of memory during encapsulation");
        return;
    } else if (rc == FAIL_EVP) {
        throwProviderException(env, "Encapsulation failed");
        return;
    }
    copy_byte_array(env, secret_bytes, spec->secret, spec->secret_length);
    copy_byte_array(env, encapsulated_bytes, spec->wrapped_key, spec->wrapped_key_length);
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMEncapsulator
 * Method:    engineSecretSize0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMEncapsulator_engineSecretSize0
  (JNIEnv *env, jobject this) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    return get_secret_size(spec, JNI_TRUE);
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMEncapsulator
 * Method:    engineEncapsulationSize0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMEncapsulator_engineEncapsulationSize0
  (JNIEnv *env, jobject this) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    return get_encapsulation_size(spec, JNI_TRUE);
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMEncapsulator_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    kem_keyspec *spec = (kem_keyspec*)handle;
    free_kem_keyspec(&spec);
}
