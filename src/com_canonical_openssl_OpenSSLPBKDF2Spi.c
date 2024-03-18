#include "jni_utils.h" 
#include "kdf.h"
#include "com_canonical_openssl_OpenSSLPBKDF2Spi.h"

#define MAX_KEY_SIZE 64
extern OSSL_LIB_CTX *global_libctx;
/*
 * Class:     OpenSSLPBKDF2Spi
 * Method:    generateKey0
 * Signature: ([C[BI)LOpenSSLPBKDF2Spi/PBKDF2SecretKey;
 */
JNIEXPORT jbyteArray JNICALL Java_OpenSSLPBKDF2Spi_generateSecret0
  (JNIEnv *env, jobject this, jcharArray password, jbyteArray salt, jint iteration_count) {
    int password_length = array_length(env, password);
    int salt_length = array_length(env, salt);
    byte output[MAX_KEY_SIZE] = {0};

    char *password_chars = jcharArray_to_char_array(env, password);
    byte *salt_bytes = jbyteArray_to_byte_array(env, salt);

    kdf_spec *spec = create_pbkdf_spec((byte *)password_chars, password_length,
                        salt_bytes, salt_length, iteration_count);
    kdf_params *params = create_pbkdf_params("SHA-512");

    if (kdf_derive(global_libctx, spec, params, output, MAX_KEY_SIZE, PBKDF2) <= 0) {
        free_kdf_spec(spec);
        free_kdf_params(params);
        return NULL; 
    }

    return byte_array_to_jbyteArray(env, output, MAX_KEY_SIZE);
}
