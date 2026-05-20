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
#include "OpenSSLSignature.h"
#include "signature.h"
#include "evp_utils.h"
#include "jni_utils.h"
#include <openssl/crypto.h>

sv_params *create_params(JNIEnv *env, jobject this, jobject params, int *oom) {
   int salt_length = get_int_field(env, params, "saltLength");
   jstring digest = get_string_field(env, params, "digest");
   char *digest_name = jstring_to_char_array(env, digest);
   jstring mgf1_digest = get_string_field(env, params, "mgf1Digest");
   char *mgf1_digest_name = jstring_to_char_array(env, mgf1_digest);
   int padding = get_int_field(env, params, "padding");
   sv_params *svp = sv_create_params(jssl_libctx(), salt_length, padding == 0 ? NONE : PSS, digest_name, mgf1_digest_name, oom);
   release_jstring(env, digest, digest_name);
   release_jstring(env, mgf1_digest, mgf1_digest_name);
   return svp;
}

sv_type svtype_from_str(char *str) {
   if      (strcmp(str, "RSA"    ) == 0) return SV_RSA;
   else if (strcmp(str, "ED25519") == 0) return SV_ED25519;
   else if (strcmp(str, "ED448"  ) == 0) return SV_ED448;
   else                                  return INVALID;
}

jlong init_signature(JNIEnv *env, jobject this, jstring sig_name, jobject jkey, jobject params, sv_state state) {
    int oom = 0;
    sv_params *svparams = NULL;
    sv_key *key = NULL;
    sv_context *svc = NULL;
    char *sig_name_str = NULL;
    jlong ret = 0;

    svparams = create_params(env, this, params, &oom);
    if (svparams == NULL) {
        if (oom) throwOOM(env, "Out of memory creating signature params");
        else throwProviderException(env, "Failed to create signature params");
        goto cleanup;
    }

    EVP_PKEY* evpkey = CASTPTR(EVP_PKEY, invokeLongMethod(env, jkey, "getNativeKeyHandle", "()J"));
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }
    oom = 0;
    key = sv_init_key(jssl_libctx(), evpkey, &oom);
    if (key == NULL) {
        if (oom) throwOOM(env, "Out of memory initializing signature key");
        else throwProviderException(env, "Failed to initialize signature key");
        goto cleanup;
    }

    sig_name_str = jstring_to_char_array(env, sig_name);
    if (sig_name_str == NULL) {
        goto cleanup;
    }
    sv_type type = svtype_from_str(sig_name_str);

    oom = 0;
    svc = sv_init(jssl_libctx(), key, svparams, state, type, &oom);
    if (svc == NULL) {
        if (oom) throwOOM(env, "Out of memory initializing signature context");
        else throwProviderException(env, "Failed to initialize signature context");
        goto cleanup;
    }
    ret = (jlong)svc;
    key = NULL;

cleanup:
    release_jstring(env, sig_name, sig_name_str);
    if (svparams) free_sv_params(&svparams);
    if (key) free_sv_key(&key);
    return ret;
}

/*
 * Class:     OpenSSLSignatureSpi
 * Method:    engineSignInit
 * Signature: (Ljava/lang/String;LOpenSSLPublicKey;LOpenSSLSignatureSpi/Params;)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_signature_OpenSSLSignature_engineInitSign0
  (JNIEnv *env, jobject this, jstring sig_name, jobject private_key, jobject params) {
    return init_signature(env, this, sig_name, private_key, params, SIGN);
}


/*
 * Class:     OpenSSLSignatureSpi
 * Method:    engineVerifyInit
 * Signature: (Ljava/lang/String;LOpenSSLPrivateKey;LOpenSSLSignatureSpi/Params;)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_signature_OpenSSLSignature_engineInitVerify0
  (JNIEnv *env, jobject this, jstring sig_name, jobject public_key, jobject params) {
    return init_signature(env, this, sig_name, public_key, params, VERIFY);
}

/*
 * Class:     OpenSSLSignatureSpi
 * Method:    engineUpdate0
 * Signature: ([BII)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_signature_OpenSSLSignature_engineUpdate0
  (JNIEnv *env, jobject this, jbyteArray bytes, jint offset, jint length) {
    if (offset < 0 || length < 0) {
        throwIllegalArgument(env, "offset and length must be non-negative");
        return;
    }
    sv_context *ctx = (sv_context*)get_long_field(env, this, "nativeHandle");
    byte *to_update = (byte*)malloc(length);
    if (to_update == NULL) {
        throwOOM(env, "Out of memory in signature update");
        return;
    }
    copy_byte_array_range(env, bytes, offset, length, to_update);
    if (sv_update(ctx, to_update, length) <= 0) {
        throwProviderException(env, "Signature update failed");
    }
    OPENSSL_cleanse(to_update, length);
    free(to_update);
}

/*
 * Class:     OpenSSLSignatureSpi
 * Method:    engineSign0
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_signature_OpenSSLSignature_engineSign0
  (JNIEnv *env, jobject this) {
    sv_context *ctx = (sv_context*)get_long_field(env, this, "nativeHandle");
    size_t sig_length = 0;
    if (sv_sign(ctx, NULL, &sig_length) < 0) {
        throwProviderException(env, "Signing failed");
        return NULL;
    }

    byte *signature = (byte *)malloc(sig_length);
    if (signature == NULL) {
        throwOOM(env, "Out of memory allocating signature buffer");
        return NULL;
    }
    if (sv_sign(ctx, signature, &sig_length) < 0) {
        OPENSSL_cleanse(signature, sig_length);
        free(signature);
        throwProviderException(env, "Signing failed");
        return NULL;
    }
    jbyteArray result = byte_array_to_jbyteArray(env, signature, sig_length);
    OPENSSL_cleanse(signature, sig_length);
    free(signature);
    return result;
}


/*
 * Class:     OpenSSLSignatureSpi
 * Method:    engineVerify0
 * Signature: ([BII)Z
 */
JNIEXPORT jboolean JNICALL Java_com_canonical_openssl_signature_OpenSSLSignature_engineVerify0
  (JNIEnv *env, jobject this, jbyteArray sig_bytes, jint offset, jint length) {
    if (offset < 0 || length < 0) {
        throwIllegalArgument(env, "offset and length must be non-negative");
        return JNI_FALSE;
    }
    sv_context *ctx = (sv_context*)get_long_field(env, this, "nativeHandle");
    byte *signature = (byte*)malloc(length);
    if (signature == NULL) {
        throwOOM(env, "Out of memory allocating signature buffer");
        return JNI_FALSE;
    }
    copy_byte_array_range(env, sig_bytes, offset, length, signature);
    int rc = sv_verify(ctx, signature, length);
    free(signature);
    if (rc < 0) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/security/SignatureException"),
            "Signature verification error");
        return JNI_FALSE;
    }
    return rc == 1 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_signature_OpenSSLSignature_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong nativeHandle) {
    sv_context *ctx = (sv_context*)nativeHandle;
    free_sv_context(&ctx);
}
