#include "jssl.h"
#include "mac.h"
#include "com_canonical_openssl_mac_OpenSSLMAC.h"
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
    mac_params *params = init_mac_params(jstring_to_char_array(env, cipher),
                                        jstring_to_char_array(env, digest),
                                        jbyteArray_to_byte_array(env, iv), array_length(env, iv),
                                        (size_t)output_length);
    mac_context *ctx = mac_init(jstring_to_char_array(env, name), jbyteArray_to_byte_array(env, key), array_length(env, key), params);
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
