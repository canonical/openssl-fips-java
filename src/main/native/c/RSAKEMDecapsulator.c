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

extern OSSL_LIB_CTX *global_libctx;
/*
 * Class:     OpenSSLKEMRSA_RSAKEMDecapsulator
 * Method:    decapsulatorInit0
 * Signature: ([B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_keyencapsulation_OpenSSLKEMRSA_00024RSAKEMDecapsulator_decapsulatorInit0
  (JNIEnv *env, jobject this, jbyteArray key) {
    byte* bytes = jbyteArray_to_byte_array(env, key);
    int length = array_length(env, key);
    EVP_PKEY *private_key = create_private_key(EVP_PKEY_RSA, bytes, length);
    kem_keyspec *spec = init_kem_keyspec_with_key(NULL, private_key, global_libctx);
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
    int length = array_length(env, encapsulated);
    set_wrapped_key(spec, bytes, length);
    unwrap(spec);
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
    free_kem_keyspec((kem_keyspec*)handle);
}
