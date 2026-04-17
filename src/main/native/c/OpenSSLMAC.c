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
#include "jssl.h"
#include "mac.h"
#include "OpenSSLMAC.h"
#include "jni_utils.h"
#include <openssl/crypto.h>

#define MAX_OUTPUT_LEN 512

// TODO: error handling, exception class design

/*
 * Class:     OpenSSLMACSpi
 * Method:    doInit0
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[BI[B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_mac_OpenSSLMAC_doInit0
    (JNIEnv *env, jobject this, jstring name, jstring cipher, jstring digest, jbyteArray iv, jint output_length, jbyteArray key) {
    const char *name_str   = jstring_to_char_array(env, name);
    const char *cipher_str = jstring_to_char_array(env, cipher);
    const char *digest_str = jstring_to_char_array(env, digest);
    byte       *iv_bytes   = jbyteArray_to_byte_array(env, iv);
    int         iv_len     = array_length(env, iv);
    byte       *key_bytes  = jbyteArray_to_byte_array(env, key);
    int         key_len    = array_length(env, key);

    mac_params *params = init_mac_params((char *)cipher_str, (char *)digest_str,
                                         iv_bytes, iv_len, (size_t)output_length);
    int oom = 0;
    mac_context *ctx = mac_init((char *)name_str, key_bytes, key_len, params, &oom);
    free(params);

    if (key_bytes) {
        OPENSSL_cleanse(key_bytes, key_len);
        (*env)->ReleaseByteArrayElements(env, key, (jbyte *)key_bytes, JNI_ABORT);
    }
    if (iv_bytes) {
        OPENSSL_cleanse(iv_bytes,  iv_len);
        (*env)->ReleaseByteArrayElements(env, iv,  (jbyte *)iv_bytes,  JNI_ABORT);
    }
    if (name_str)
        (*env)->ReleaseStringUTFChars(env, name,   name_str);

    if (cipher_str)
        (*env)->ReleaseStringUTFChars(env, cipher, cipher_str);

    if (digest_str)
        (*env)->ReleaseStringUTFChars(env, digest, digest_str);

    if (ctx == NULL) {
        if (oom)
            throwOOM(env, "Out of memory initializing MAC");
        else
            throwProviderException(env, "Failed to initialize MAC");
        return 0;
    }
    return (jlong)ctx;
}

/*
 * Class:     OpenSSLMACSpi
 * Method:    getMacLength
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_canonical_openssl_mac_OpenSSLMAC_getMacLength
    (JNIEnv * env, jobject this) {
    mac_context *ctx = (mac_context*)get_long_field(env, this, "nativeHandle");
    return (jint)get_mac_length(ctx);
}

/*
 * Class:     OpenSSLMACSpi
 * Method:    doUpdate0
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_mac_OpenSSLMAC_doUpdate0
    (JNIEnv *env, jobject this, jbyteArray input) {
    mac_context *ctx = (mac_context*)get_long_field(env, this, "nativeHandle");
    byte *input_bytes = jbyteArray_to_byte_array(env, input);
    int input_len = array_length(env, input);
    jssl_status rc = mac_update(ctx, input_bytes, input_len);
    (*env)->ReleaseByteArrayElements(env, input, (jbyte *)input_bytes, JNI_ABORT);
    if (rc != SUCCESS) {
        throwProviderException(env, "MAC update failed");
    }
}

/*
 * Class:     OpenSSLMACSpi
 * Method:    doFinal0
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_mac_OpenSSLMAC_doFinal0
    (JNIEnv *env, jobject this) {
    byte output[MAX_OUTPUT_LEN];
    size_t output_length = 0; 

    mac_context *ctx = (mac_context*)get_long_field(env, this, "nativeHandle");
    if (mac_final(ctx, output, &output_length, MAX_OUTPUT_LEN) != SUCCESS) {
        OPENSSL_cleanse(output, MAX_OUTPUT_LEN);
        throwProviderException(env, "MAC final failed");
        return NULL;
    }

    jbyteArray result = byte_array_to_jbyteArray(env, output, output_length);
    OPENSSL_cleanse(output, output_length);
    return result;
}

/*
 * Class:     com_canonical_openssl_mac_OpenSSLMAC
 * Method:    cleanupNativeMemory0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_mac_OpenSSLMAC_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    mac_context *ctx = (mac_context*)handle;
    free_mac_context(&ctx);
}
