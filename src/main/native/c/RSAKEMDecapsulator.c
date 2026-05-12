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
#include "RSAKEMDecapsulator.h"
#include "evp_utils.h"
#include "jni_utils.h"

/*
 * Class:     OpenSSLKEMRSA_RSAKEMDecapsulator
 * Method:    decapsulatorInit0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_decapsulatorInit0
  (JNIEnv *env, jobject this, jbyteArray key) {
    byte* bytes = jbyteArray_to_byte_array(env, key);
    if (bytes == NULL) {
        return 0;
    }
    int length = array_length(env, key);
    EVP_PKEY *private_key = decode_private_key_fips(bytes, length, jssl_libctx());
    release_jbyteArray(env, key, bytes);
    kem_keyspec *spec = init_kem_keyspec_with_key(NULL, private_key, jssl_libctx());
    if (spec == NULL) {
        throwOOM(env, "Could not allocate KEM keyspec");
        return 0;
    }
    return (jlong)spec;
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMDecapsulator
 * Method:    engineDecapsulate0
 * Signature: ([B[B)V;
 */
JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_engineDecapsulate0
  (JNIEnv *env, jobject this, jbyteArray encapsulated) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    byte* bytes = jbyteArray_to_byte_array(env, encapsulated);
    if (bytes == NULL) {
        return NULL;
    }
    int length = array_length(env, encapsulated);
    set_wrapped_key(spec, bytes, length);
    jssl_status rc = unwrap(spec);
    release_jbyteArray(env, encapsulated, bytes);
    spec->wrapped_key = NULL;
    spec->wrapped_key_length = 0;
    if (rc == FAIL_OOM) {
        throwOOM(env, "Out of memory during decapsulation");
        return NULL;
    } else if (rc == FAIL_EVP) {
        throwProviderException(env, "Decapsulation failed");
        return NULL;
    }
    return new_byteArray(env, spec->secret, spec->secret_length);
}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMDecapsulator
 * Method:    engineSecretSize0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_engineSecretSize0
  (JNIEnv *env, jobject this) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    return get_secret_size(spec, JNI_FALSE);

}

/*
 * Class:     OpenSSLKEMRSA_RSAKEMDecapsulator
 * Method:    engineEncapsulationSize0
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_engineEncapsulationSize0
  (JNIEnv *env, jobject this) {
    kem_keyspec *spec = (kem_keyspec*)get_long_field(env, this, "nativeHandle");
    return get_encapsulation_size(spec, JNI_FALSE);
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    kem_keyspec *spec = (kem_keyspec*)handle;
    free_kem_keyspec(&spec);
}
