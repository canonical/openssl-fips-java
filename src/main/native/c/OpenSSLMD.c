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
#include "OpenSSLMD.h"
#include "jssl.h"
#include "md.h"
#include "jni_utils.h"
#include <openssl/crypto.h>

/*
 * Class:     OpenSSLMD
 * Method:    doInit0
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_md_OpenSSLMD_doInit0
  (JNIEnv *env, jobject this, jstring algorithm) {
    const char *algorithm_str = jstring_to_char_array(env, algorithm);
    if (algorithm_str == NULL) {
        return 0;
    }
    int oom = 0;
    md_context *ctx = md_init(jssl_libctx(), algorithm_str, &oom);
    release_jstring(env, algorithm, algorithm_str);
    if (ctx == NULL) {
        if (oom)
            throwOOM(env, "Out of memory initializing digest");
        else
            throwProviderException(env, "Failed to initialize digest");
        return 0;
    }
    return (jlong)ctx;
}

/*
 * Class:     OpenSSLMD
 * Method:    doUpdate0
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_md_OpenSSLMD_doUpdate0
  (JNIEnv *env, jobject this, jbyteArray data) {
    md_context *ctx = (md_context*) get_long_field(env, this, "nativeHandle");
    byte *data_array = jbyteArray_to_byte_array(env, data);
    if (data_array == NULL) {
        return;
    }
    int length = array_length(env, data);
    if (md_update(ctx, data_array, length) != SUCCESS) {
        throwProviderException(env, "Digest update failed");
    }
    release_jbyteArray(env, data, data_array);
}

/*
 * Class:     OpenSSLMD
 * Method:    doFinal0
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_md_OpenSSLMD_doFinal0
  (JNIEnv *env, jobject this) {
    byte digest[1024];
    int digest_length = 0;
    md_context *ctx = (md_context*) get_long_field(env, this, "nativeHandle");
    if (md_digest(ctx, digest, &digest_length) != SUCCESS) {
        OPENSSL_cleanse(digest, sizeof(digest));
        throwProviderException(env, "Digest final failed");
        return NULL;
    }
    jbyteArray result = byte_array_to_jbyteArray(env, digest, digest_length);
    OPENSSL_cleanse(digest, digest_length);
    return result;
}

/*
 * Class:     com_canonical_openssl_md_OpenSSLMD
 * Method:    cleanupNativeMemory0
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_md_OpenSSLMD_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    md_context *ctx = (md_context*)handle;
    free_md_context(&ctx);
}
