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
#include "jni_utils.h" 
#include "kdf.h"
#include "OpenSSLPBKDF2.h"

#define MAX_KEY_SIZE 64
extern OSSL_LIB_CTX *global_libctx;
/*
 * Class:     OpenSSLPBKDF2Spi
 * Method:    generateKey0
 * Signature: ([C[BI)LOpenSSLPBKDF2Spi/PBKDF2SecretKey;
 */
JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_kdf_OpenSSLPBKDF2_generateSecret0
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
