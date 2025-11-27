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

extern OSSL_LIB_CTX *global_libctx;

sv_params *create_params(JNIEnv *env, jobject this, jobject params) {
   int salt_length = get_int_field(env, params, "saltLength");
   jstring digest = get_string_field(env, params, "digest");
   char *digest_name = jstring_to_char_array(env, digest);
   jstring mgf1_digest = get_string_field(env, params, "mgf1Digest");
   char *mgf1_digest_name = jstring_to_char_array(env, mgf1_digest);
   int padding = get_int_field(env, params, "padding"); 
   sv_params *result = sv_create_params(global_libctx, salt_length, padding == 0 ? NONE : PSS, digest_name, mgf1_digest_name);
   release_jstring(env, digest, digest_name);
   release_jstring(env, mgf1_digest, mgf1_digest_name);
   return result;
}

sv_type svtype_from_str(char *str) {
   if      (strcmp(str, "RSA"    ) == 0) return SV_RSA;
   else if (strcmp(str, "ED25519") == 0) return SV_ED25519;
   else if (strcmp(str, "ED448"  ) == 0) return SV_ED448;
   else                                  return INVALID;
}

jlong init_signature(JNIEnv *env, jobject this, jstring sig_name, jobject jkey, jobject params, sv_state state) {
    sv_params *svparams = create_params(env, this, params);
    EVP_PKEY* evpkey = CASTPTR(EVP_PKEY, invokeLongMethod(env, jkey, "getNativeKeyHandle", "()J"));
    sv_key *key = sv_init_key(global_libctx, evpkey);
    char *sig_name_str = jstring_to_char_array(env, sig_name);
    sv_type type = svtype_from_str(sig_name_str);
    release_jstring(env, sig_name, sig_name_str);
    sv_context *svc = sv_init(global_libctx, key, svparams, state, type);
    free_sv_params(svparams);
    free_sv_key(key);
    return (jlong)svc;
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
    sv_context *ctx = (sv_context*)get_long_field(env, this, "nativeHandle");
    byte *to_update = (byte*)malloc(length);
    copy_byte_array_range(env, bytes, offset, length, to_update);
    sv_update(ctx, to_update, length);
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
        free_sv_context(ctx);
        return NULL;
    }

    byte *signature = (byte *)malloc(sig_length);
    if (sv_sign(ctx, signature, &sig_length) < 0) {
        free_sv_context(ctx);
        return NULL;
    }
    return byte_array_to_jbyteArray(env, signature, sig_length);
}


/*
 * Class:     OpenSSLSignatureSpi
 * Method:    engineVerify0
 * Signature: ([BII)Z
 */
JNIEXPORT jboolean JNICALL Java_com_canonical_openssl_signature_OpenSSLSignature_engineVerify0
  (JNIEnv *env, jobject this, jbyteArray sig_bytes, jint offset, jint length) {
    sv_context *ctx = (sv_context*)get_long_field(env, this, "nativeHandle");
    byte *signature = (byte*)malloc(length);
    copy_byte_array_range(env, sig_bytes, offset, length, signature);
    int rc = sv_verify(ctx, signature, length);
    return rc <= 0 ? JNI_FALSE : JNI_TRUE;
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_signature_OpenSSLSignature_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong nativeHandle) {
    free_sv_context((sv_context*) nativeHandle);
}
