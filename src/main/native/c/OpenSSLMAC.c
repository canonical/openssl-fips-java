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

#define MAX_OUTPUT_LEN 512

// TODO: error handling, exception class design

/*
 * Class:     OpenSSLMACSpi
 * Method:    doInit0
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[BI[B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_mac_OpenSSLMAC_doInit0
    (JNIEnv *env, jobject this, jstring name, jstring cipher, jstring digest, jbyteArray iv, jint output_length, jbyteArray key) {
    char *cipher_str = jstring_to_char_array(env, cipher);
    char *digest_str = jstring_to_char_array(env, digest);
    mac_params *params = init_mac_params(cipher_str,
                                        digest_str,
                                        jbyteArray_to_byte_array(env, iv), array_length(env, iv),
                                        (size_t)output_length);
    release_jstring(env, cipher, cipher_str);
    release_jstring(env, digest, digest_str);
    char *name_str = jstring_to_char_array(env, name);
    mac_context *ctx = mac_init(name_str, jbyteArray_to_byte_array(env, key), array_length(env, key), params);
    release_jstring(env, name, name_str);
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
    mac_update(ctx, jbyteArray_to_byte_array(env, input), array_length(env, input));
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
    mac_final(ctx, output, &output_length, MAX_OUTPUT_LEN);

    return byte_array_to_jbyteArray(env, output, output_length);
}

/*
 * Class:     com_canonical_openssl_mac_OpenSSLMAC
 * Method:    cleanupNativeMemory0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_mac_OpenSSLMAC_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    free_mac_context((mac_context*) handle);
}
