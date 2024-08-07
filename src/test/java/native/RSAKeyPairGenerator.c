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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/encoder.h>
#include <stdlib.h>
#include <openssl/err.h>

# define TEST_ptr(a)          (a)
# define TEST_true(a)         ((a) != 0)

int rsa_keygen(OSSL_LIB_CTX *libctx, int bits, EVP_PKEY **pub, EVP_PKEY **priv)
{
    int ret = 0;
    unsigned char *pub_der = NULL;
    const unsigned char *pp = NULL;
    size_t len = 0;
    OSSL_ENCODER_CTX *ectx = NULL;

    if (!TEST_ptr(*priv = EVP_PKEY_Q_keygen(libctx, NULL, "RSA", bits))
        || !TEST_ptr(ectx =
                     OSSL_ENCODER_CTX_new_for_pkey(*priv,
                                                   EVP_PKEY_PUBLIC_KEY,
                                                   "DER", "type-specific",
                                                   NULL))
        || !TEST_true(OSSL_ENCODER_to_data(ectx, &pub_der, &len)))
        goto err;
    pp = pub_der;
    if (NULL == (d2i_PublicKey(EVP_PKEY_RSA, pub, &pp, len)))
        goto err;
    ret = 1;
err:
    OSSL_ENCODER_CTX_free(ectx);
    OPENSSL_free(pub_der);
    return ret;
}

/*
 * Class:     RSAKeyPairGenerator
 * Method:    generateKeyPair0
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_RSAKeyPairGenerator_generateKeyPair0
  (JNIEnv *env, jobject this) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    EVP_PKEY *public_key = NULL;
    EVP_PKEY *private_key = NULL;
    rsa_keygen(libctx, 4096, &public_key, &private_key);
    
    // set public key in Java object
    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID id1 = (*env)->GetFieldID(env, clazz, "nativePrivKey", "J");
    (*env)->SetLongField(env, this, id1, (jlong)private_key);

    // set private key in Java object
    jfieldID id2 = (*env)->GetFieldID(env, clazz, "nativePubKey", "J");
    (*env)->SetLongField(env, this, id2, (jlong)public_key);
}



