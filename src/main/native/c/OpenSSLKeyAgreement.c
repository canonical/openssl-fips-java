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
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include "jssl.h"
#include "keyagreement.h"
#include "OpenSSLKeyAgreement.h"
#include "jni_utils.h"

static int evp_type_for(key_agreement_algorithm algo) {
    switch (algo) {
        case DIFFIE_HELLMAN: return EVP_PKEY_DH;
        case ELLIPTIC_CURVE: return EVP_PKEY_EC;
        default:             return -1;
    }
}

/*
 * Class:     OpenSSLKeyAgreementSpi
 * Method:    engineInit0
 * Signature: (I[B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_keyagreement_OpenSSLKeyAgreement_engineInit0
  (JNIEnv *env, jobject this, jint algo, jbyteArray keyBytes) {
    key_agreement_algorithm type = algo;
    key_agreement *agreement = init_key_agreement(type, jssl_libctx());
    if (agreement == NULL) return 0;
    jsize key_length = (*env)->GetArrayLength(env, keyBytes);
    jbyte *key_bytes = (*env)->GetByteArrayElements(env, keyBytes, NULL);
    if (key_bytes == NULL) {
        free_key_agreement(&agreement);
        return 0;
    }
    const byte *p = (const byte *)key_bytes;
    EVP_PKEY *private_key = d2i_PrivateKey_ex(evp_type_for(type), NULL,
                                              &p, key_length,
                                              jssl_libctx(), NULL);
    (*env)->ReleaseByteArrayElements(env, keyBytes, key_bytes, JNI_ABORT);
    if (private_key == NULL) {
        free_key_agreement(&agreement);
        throwProviderException(env, "Failed to decode private key for key agreement");
        return 0;
    }
    set_private_key(agreement, private_key);
    return (jlong)agreement;
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
    if (key_bytes == NULL) {
        return;
    }
    const byte *p = (const byte *)key_bytes;
    EVP_PKEY *public_key = d2i_PUBKEY_ex(NULL, &p, key_length,
                                         jssl_libctx(), NULL);
    (*env)->ReleaseByteArrayElements(env, keyBytes, key_bytes, JNI_ABORT);
    if (public_key == NULL) {
        throwProviderException(env, "Failed to decode public key for key agreement");
        return;
    }
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
    OPENSSL_cleanse(secret->bytes, secret->length);
    return byteArray;
}

/*
 * Class:     com_canonical_openssl_keyagreement_OpenSSLKeyAgreement
 * Method:    cleanupNativeMemory0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_keyagreement_OpenSSLKeyAgreement_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    key_agreement *agreement = (key_agreement*)handle;
    free_key_agreement(&agreement);
}
