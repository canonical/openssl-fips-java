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
#include <openssl/pem.h>
#include <openssl/encoder.h>
#include <stdlib.h>

/*
 * Class:     EdDSAPrivateKey
 * Method:    readPrivKeyFromPem0
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_EdDSAPrivateKey_readPrivKeyFromPem0
  (JNIEnv *env, jobject this, jstring filename) {
   OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
   char *c_filename = (char*)(*env)->GetStringUTFChars(env, filename, 0);
   FILE *pemfile = fopen(c_filename, "r");
   return (jlong)PEM_read_PrivateKey_ex(pemfile, NULL, NULL, NULL, libctx, NULL); 
}

