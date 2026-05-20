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
    const char *name_str    = NULL;
    const char *cipher_str  = NULL;
    const char *digest_str  = NULL;
    jbyte      *iv_pinned   = NULL;
    jbyte      *key_pinned  = NULL;
    byte       *iv_copy     = NULL;
    byte       *key_copy    = NULL;
    int         iv_len      = 0;
    int         key_len     = 0;
    mac_params *params      = NULL;
    mac_context *ctx        = NULL;
    int oom = 0;
    jlong ret = 0;

    name_str = jstring_to_char_array(env, name);
    if (name != NULL && name_str == NULL) goto cleanup;
    cipher_str = jstring_to_char_array(env, cipher);
    if (cipher != NULL && cipher_str == NULL) goto cleanup;
    digest_str = jstring_to_char_array(env, digest);
    if (digest != NULL && digest_str == NULL) goto cleanup;

    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_pinned = (*env)->GetByteArrayElements(env, iv, NULL);
        if (iv_pinned == NULL) goto cleanup;
        iv_copy = (byte *)malloc(iv_len);
        if (iv_copy == NULL) {
            throwOOM(env, "Could not allocate IV buffer");
            goto cleanup;
        }
        memcpy(iv_copy, iv_pinned, iv_len);
    }

    if (key != NULL) {
        key_len = (*env)->GetArrayLength(env, key);
        key_pinned = (*env)->GetByteArrayElements(env, key, NULL);
        if (key_pinned == NULL) goto cleanup;
        key_copy = (byte *)malloc(key_len);
        if (key_copy == NULL) {
            throwOOM(env, "Could not allocate key buffer");
            goto cleanup;
        }
        memcpy(key_copy, key_pinned, key_len);
    }

    params = init_mac_params((char *)cipher_str, (char *)digest_str,
                             iv_copy, iv_len, (size_t)output_length);
    ctx = mac_init(jssl_libctx(), (char *)name_str, key_copy, key_len, params, &oom);

    if (ctx == NULL) {
        if (oom)
            throwOOM(env, "Out of memory initializing MAC");
        else
            throwProviderException(env, "Failed to initialize MAC");
        goto cleanup;
    }
    ret = (jlong)ctx;

cleanup:
    free(params);
    if (key_pinned) {
        (*env)->ReleaseByteArrayElements(env, key, key_pinned, JNI_ABORT);
    }
    if (iv_pinned) {
        (*env)->ReleaseByteArrayElements(env, iv, iv_pinned, JNI_ABORT);
    }
    if (key_copy) {
        OPENSSL_cleanse(key_copy, key_len);
        free(key_copy);
    }
    if (iv_copy) {
        OPENSSL_cleanse(iv_copy, iv_len);
        free(iv_copy);
    }
    release_jstring(env, name,   name_str);
    release_jstring(env, cipher, cipher_str);
    release_jstring(env, digest, digest_str);
    return ret;
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
    if (input_bytes == NULL) {
        return;
    }
    int input_len = array_length(env, input);
    jssl_status rc = mac_update(ctx, input_bytes, input_len);
    release_jbyteArray(env, input, input_bytes);
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
