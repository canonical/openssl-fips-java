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
#include "keyagreement.h"
#include "OpenSSLKeyAgreement.h"
#include "evp_utils.h"
#include "jni_utils.h"

extern OSSL_LIB_CTX *global_libctx;


/*
 * Class:     OpenSSLKeyAgreementSpi
 * Method:    engineInit0
 * Signature: (I[B)J
 */
JNIEXPORT long JNICALL Java_com_canonical_openssl_keyagreement_OpenSSLKeyAgreement_engineInit0
  (JNIEnv *env, jobject this, jint algo, jbyteArray keyBytes) {
    key_agreement_algorithm type = algo;
    key_agreement *agreement = init_key_agreement(type, global_libctx);
    if (agreement == NULL) return 0;
    jsize key_length = (*env)->GetArrayLength(env, keyBytes);
    jbyte *key_bytes = (*env)->GetByteArrayElements(env, keyBytes, NULL);
    EVP_PKEY *private_key = decode_private_key_fips((byte *)key_bytes, key_length, global_libctx);
    (*env)->ReleaseByteArrayElements(env, keyBytes, key_bytes, JNI_ABORT);
    set_private_key(agreement, private_key);
    return (long)agreement;
}

/*
 * Class:     OpenSSLKeyAgreementSpi
 * Method:    engineDoPhase0
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_keyagreement_OpenSSLKeyAgreement_engineDoPhase0
  (JNIEnv *env, jobject this, jbyteArray keyBytes) {
    key_agreement *agreement = (key_agreement *)get_long_field(env, this, "nativeHandle");
    jsize key_length = (*env)->GetArrayLength(env, keyBytes);
    jbyte *key_bytes = (*env)->GetByteArrayElements(env, keyBytes, NULL);
    EVP_PKEY *public_key = decode_public_key_fips((byte *)key_bytes, key_length, global_libctx);
    (*env)->ReleaseByteArrayElements(env, keyBytes, key_bytes, JNI_ABORT);
    set_peer_key(agreement, public_key);
}

/*
 * Class:     OpenSSLKeyAgreementSpi
 * Method:    engineGenerateSecret0
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_keyagreement_OpenSSLKeyAgreement_engineGenerateSecret0
  (JNIEnv * env, jobject this) {
    key_agreement *agreement = (key_agreement *)get_long_field(env, this, "nativeHandle");
    int evp_error = JNI_FALSE;
    shared_secret *secret = generate_shared_secret(agreement, &evp_error);
    if (secret == NULL) {
        if (evp_error == JNI_TRUE) {
            throwProviderException(env, "Provider failed to generate a secret");
	    return NULL;
   	} else {
            throwOOM(env, "Failed to allocate memory for secret");
	    return NULL;
        }
    }
    jbyteArray byteArray = byte_array_to_jbyteArray(env, secret->bytes, secret->length);
    return byteArray;
}

/*
 * Class:     com_canonical_openssl_keyagreement_OpenSSLKeyAgreement
 * Method:    cleanupNativeMemory0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_keyagreement_OpenSSLKeyAgreement_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    free_key_agreement((key_agreement**) &handle);
}
