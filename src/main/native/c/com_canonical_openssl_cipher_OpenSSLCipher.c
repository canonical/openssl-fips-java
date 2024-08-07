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
#include "com_canonical_openssl_cipher_OpenSSLCipher.h"

#define LARGE_SIZE 1024
extern OSSL_LIB_CTX *global_libctx;

JNIEXPORT jlong JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_createContext0
  (JNIEnv *env, jobject this, jstring name, jstring padding) {
     const char *namestr = (*env)->GetStringUTFChars(env, name, 0);
     const char *paddingstr = (*env)->GetStringUTFChars(env, padding, 0);
     return (jlong) create_cipher_context(global_libctx, namestr, paddingstr); 
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_doInit0
  (JNIEnv *env, jobject this, jbyteArray input, jint offset, jint length, jbyteArray key, jbyteArray iv, jint opmode) {

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jbyte *input_bytes = NULL;
    if (input != NULL) {
        input_bytes = (jbyte *)malloc(length);
        (*env)->GetByteArrayRegion(env, input, offset, length, input_bytes);
    } 

    unsigned char *key_bytes = (unsigned char *) (*env)->GetByteArrayElements(env, key, NULL);
    unsigned char *iv_bytes  = (unsigned char *) (*env)->GetByteArrayElements(env, iv, NULL);
    int iv_length = (*env)->GetArrayLength(env, iv);

    if (input_bytes != NULL) { 
        cipher_init((cipher_context*)ctx_handle, input_bytes, length, key_bytes, iv_bytes, iv_length, opmode);
    } else {
        cipher_init((cipher_context*)ctx_handle, NULL, 0, key_bytes, iv_bytes, iv_length, opmode);
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_doUpdate0
  (JNIEnv *env, jobject this, jbyteArray input, jint offset, jint length) {
    byte output_bytes[1024];
    int output_length = 0;

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jbyte *input_bytes = (jbyte *)malloc(length);
    (*env)->GetByteArrayRegion(env, input, offset, length, input_bytes);

    cipher_update((cipher_context*)ctx_handle, output_bytes, &output_length, input_bytes, length);

    jbyteArray ret_array = (*env)->NewByteArray(env, output_length);
    (*env)->SetByteArrayRegion(env, ret_array, 0, output_length, output_bytes);
    return ret_array;
}

JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_doFinal0
  (JNIEnv *env, jobject this, jbyteArray output, jint length) {
    int templen = 0;

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, "cipherContext", "J");
    jlong ctx_handle = (*env)->GetLongField(env, this, ctx_id);

    jbyte *out_bytes  = (*env)->GetByteArrayElements(env, output, NULL);
    byte *final_output = (byte *)malloc(length * 2);
    memcpy(final_output, out_bytes, length);
    cipher_do_final((cipher_context*)ctx_handle, final_output + length, &templen);
    jbyteArray ret_array = (*env)->NewByteArray(env, length + templen);
    (*env)->SetBooleanArrayRegion(env, ret_array, 0, length + templen, final_output);
    return ret_array;
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_cipher_OpenSSLCipher_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    free_cipher((cipher_context*) handle);
}
