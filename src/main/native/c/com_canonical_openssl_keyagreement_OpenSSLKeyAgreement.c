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
#include "com_canonical_openssl_keyagreement_OpenSSLKeyAgreement.h"
#include "evp_utils.h"
#include "jni_utils.h"

extern OSSL_LIB_CTX *global_libctx;


int get_key_type(key_agreement_algorithm algo) {
    switch(algo) {
        case DIFFIE_HELLMAN: return EVP_PKEY_DH;
        case ELLIPTIC_CURVE: return EVP_PKEY_EC;
        default: return -1;
    }
}

/*
 * Class:     OpenSSLKeyAgreementSpi
 * Method:    engineInit0
 * Signature: (I[B)J
 */
JNIEXPORT long JNICALL Java_com_canonical_openssl_keyagreement_OpenSSLKeyAgreement_engineInit0
  (JNIEnv *env, jobject this, jint algo, jbyteArray keyBytes) {
    key_agreement_algorithm type = algo;
    key_agreement *agreement = init_key_agreement(type, global_libctx);
    byte* key_bytes = jbyteArray_to_byte_array(env, keyBytes);
    size_t key_length = array_length(env, keyBytes);
    EVP_PKEY *private_key = create_private_key(get_key_type(type), key_bytes, key_length);
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
    byte* key_bytes = jbyteArray_to_byte_array(env, keyBytes);
    size_t key_length = array_length(env, keyBytes);
    EVP_PKEY *public_key = create_public_key(key_bytes, key_length);
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
    shared_secret *secret = generate_shared_secret(agreement);
    jbyteArray byteArray = byte_array_to_jbyteArray(env, secret->bytes, secret->length);
    free_shared_secret(secret);
    return byteArray;
}

/*
 * Class:     com_canonical_openssl_keyagreement_OpenSSLKeyAgreement
 * Method:    cleanupNativeMemory0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_keyagreement_OpenSSLKeyAgreement_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    free_key_agreement((key_agreement*) handle);
}
