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
#include "cipher.h"
#include "jni_utils.h"
#include "OpenSSLCipher.h"

#define LARGE_SIZE 1024
extern OSSL_LIB_CTX *global_libctx;

JNIEXPORT jlong JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_createContext0
  (JNIEnv *env, jobject this, jstring name, jstring padding) {
     const char *namestr = (*env)->GetStringUTFChars(env, name, 0);
     const char *paddingstr = (*env)->GetStringUTFChars(env, padding, 0);
     jlong handle = (jlong) create_cipher_context(global_libctx, namestr, paddingstr);
     (*env)->ReleaseStringUTFChars(env, name, namestr);
     (*env)->ReleaseStringUTFChars(env, padding, paddingstr);
     return handle;
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_doInit0
  (JNIEnv *env, jobject this, jbyteArray input, jint offset, jint length, jbyteArray key, jbyteArray iv, jint opmode) {

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jbyte *input_bytes = NULL;
    unsigned char *key_bytes = NULL;
    unsigned char *iv_bytes = NULL;
    unsigned char *key_copy = NULL;
    unsigned char *iv_copy = NULL;
    int key_length = 0;
    int iv_length = 0;
    jssl_status rc = SUCCESS;

    if (input != NULL) {
        input_bytes = (jbyte *)malloc(length);
        if (input_bytes == NULL) {
            throwOOM(env, "Could not allocate memory for input bytes");
            goto cleanup;
        }
        (*env)->GetByteArrayRegion(env, input, offset, length, input_bytes);
    }

    key_length = (*env)->GetArrayLength(env, key);
    key_bytes = (unsigned char *) (*env)->GetByteArrayElements(env, key, NULL);
    key_copy = (unsigned char *) malloc(key_length);
    if (key_copy == NULL) {
        throwOOM(env, "Could not allocate memory for the key");
        goto cleanup;
    }
    memcpy(key_copy, key_bytes, key_length);

    iv_length = (*env)->GetArrayLength(env, iv);
    iv_bytes = (unsigned char *) (*env)->GetByteArrayElements(env, iv, NULL);
    iv_copy = (unsigned char *) malloc(iv_length);
    if (iv_copy == NULL) {
        throwOOM(env, "Could not allocate memory for the initialization vector");
        goto cleanup;
    }
    memcpy(iv_copy, iv_bytes, iv_length);

    rc = cipher_init((cipher_context*)ctx_handle, input_bytes, length, key_copy, key_length, iv_copy, iv_length, opmode);

    switch (rc) {
        case FAIL_OOM:
            throwOOM(env, "Out of memory: failed to initialize cipher");
            break;
        case FAIL_EVP:
            throwProviderException(env, "EVP_CipherInit_ex failed for the given key and IV");
            break;
        default:
            break;
    }

cleanup:
    if (key_bytes) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)key_bytes, JNI_ABORT);
    if (iv_bytes)  (*env)->ReleaseByteArrayElements(env, iv,  (jbyte *)iv_bytes,  JNI_ABORT);
    if (input_bytes) { memset(input_bytes, 0, length); free(input_bytes); }
    if (key_copy)  { OPENSSL_cleanse(key_copy, key_length); free(key_copy); }
    if (iv_copy)   { OPENSSL_cleanse(iv_copy,  iv_length);  free(iv_copy); }
}

JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_doUpdate0
  (JNIEnv *env, jobject this, jbyteArray input, jint offset, jint length) {
    byte *output_bytes = NULL;
    int output_length = 0;

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jbyte *input_bytes = (jbyte *)malloc(length);
    if (input_bytes == NULL) {
        throwOOM(env, "Could not allocate input buffer");
	return NULL;
    }
    (*env)->GetByteArrayRegion(env, input, offset, length, input_bytes);

    output_bytes = (byte *)malloc(length + MAX_BLOCK_LENGTH);
    if (output_bytes == NULL) {
        throwOOM(env, "Could not allocate output buffer");
	return NULL;
    }

    jssl_status rc = cipher_update((cipher_context*)ctx_handle, output_bytes, &output_length, input_bytes, length);
    if (rc == FAIL_EVP) {
        memset(input_bytes, 0, length);
        memset(output_bytes, 0, output_length);
        free(input_bytes);
        free(output_bytes);
	throwProviderException(env, "Cipher update failed");
	return NULL;
    }

    jbyteArray ret_array = (*env)->NewByteArray(env, output_length);
    (*env)->SetByteArrayRegion(env, ret_array, 0, output_length, output_bytes);
    memset(input_bytes, 0, length);
    memset(output_bytes, 0, output_length);
    free(input_bytes);
    free(output_bytes);
    return ret_array;
}

JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_doFinal0
  (JNIEnv *env, jobject this, jbyteArray output, jint length) {
    int templen = 0;

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jboolean copy = JNI_FALSE;
    jbyte *out_bytes  = (*env)->GetByteArrayElements(env, output, &copy);

    byte *final_output = (byte *)malloc(length + GCM_TAG_LEN);
    if (final_output == NULL) {
        throwOOM(env, "Could not allocate output buffer");
        if (copy) {
            (*env)->ReleaseByteArrayElements(env, output, out_bytes, JNI_ABORT);
        }
        return NULL;
    }
    memcpy(final_output, out_bytes, length);
    jssl_status rc = cipher_do_final((cipher_context*)ctx_handle, final_output + length, &templen);
    if (rc == FAIL_EVP) {
        memset(final_output, 0, length + GCM_TAG_LEN);
        free(final_output);
        if (copy) {
            (*env)->ReleaseByteArrayElements(env, output, out_bytes, JNI_ABORT);
        }
        throwProviderException(env, "Final update to cipher failed");
        return NULL;
    }

    jbyteArray ret_array = (*env)->NewByteArray(env, length + templen);
    (*env)->SetByteArrayRegion(env, ret_array, 0, length + templen, final_output);

    memset(final_output, 0, length + GCM_TAG_LEN);
    free(final_output);
    if (copy) {
        (*env)->ReleaseByteArrayElements(env, output, out_bytes, JNI_ABORT);
    }

    return ret_array;
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_setGCMTag0
  (JNIEnv *env, jobject this, jbyteArray tag, jint offset, jint len) {
    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);
    cipher_context *ctx = (cipher_context *)ctx_handle;

    (*env)->GetByteArrayRegion(env, tag, offset, len, (jbyte *)ctx->gcm_tag);
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_updateAAD0
    (JNIEnv *env, jobject this, jbyteArray aad, jint offset, jint length) {
    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jbyte *aad_bytes = (jbyte *)malloc(length);
    if (aad_bytes == NULL) {
        throwOOM(env, "Could not allocate buffer for AAD");
	return;
    }
    (*env)->GetByteArrayRegion(env, aad, offset, length, aad_bytes);

    int len;
    jssl_status rc = cipher_update_aad((cipher_context*)ctx_handle, &len, aad_bytes, length);
    memset(aad_bytes, 0, length);
    free(aad_bytes);

    if (rc == FAIL_OPERATION_UNSUPPORTED) {
        throwProviderException(env, "AAD not supported by cipher");
    }
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    free_cipher((cipher_context**) &handle);
}
