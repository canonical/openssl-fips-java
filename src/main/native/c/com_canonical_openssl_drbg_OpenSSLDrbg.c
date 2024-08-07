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
#include "com_canonical_openssl_drbg_OpenSSLDrbg.h"
#include "drbg.h"

/* TODOs
 * 1. throw exceptions for error situations
 * 2. make sure all unused memory is free'd
 * 3. cache the field id in a static variable
 * 4. check return values of drbg functions 
 */

void populate_params(DRBGParams *params, int strength, int prediction_resistance, int reseed,
                    byte *personalization_str, int personalization_str_length,
                    byte *additional_input, int additional_input_length) {
    params->strength = strength;
    params->prediction_resistance = prediction_resistance;
    params->reseed = reseed; 
    params->personalization_str = personalization_str; 
    params->personalization_str_len = personalization_str_length; 
    params->additional_data = additional_input;
    params->additional_data_length = additional_input_length;
    return;
}

/*
 * Class:     com_canonical_openssl_OpenSSLDrbg
 * Method:    init
 * Signature: (Ljava/lang/String;IZZ[B)J
 */
JNIEXPORT jlong JNICALL Java_com_canonical_openssl_drbg_OpenSSLDrbg_init
  (JNIEnv *env, jobject this, jstring name, jint strength, jboolean prediction_resistance, jboolean reseeding, jbyteArray personalization_string) {
    const char *name_string = (*env)->GetStringUTFChars(env, name, 0);
    byte *pstr_bytes = NULL;
    jsize pstr_length = 0;

    if (personalization_string != NULL) { 
        pstr_length = (*env)->GetArrayLength(env, personalization_string);
        pstr_bytes = (*env)->GetByteArrayElements(env, personalization_string, NULL);
    }

    DRBGParams *params = (DRBGParams *)malloc(sizeof(DRBGParams));
    populate_params(params, strength, prediction_resistance, reseeding, pstr_bytes, pstr_length, NULL, 0);

    DRBG* drbg = create_DRBG_with_params(name_string, NULL, params);
    (*env)->ReleaseStringUTFChars(env, name, name_string);

    if (personalization_string != NULL) {
        (*env)->ReleaseByteArrayElements(env, personalization_string, pstr_bytes, JNI_ABORT);
    }
    return (jlong)drbg; 
}

/*
 * Class:     com_canonical_openssl_OpenSSLDrbg
 * Method:    nextBytes0
 * Signature: ([BIZ[B)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_drbg_OpenSSLDrbg_nextBytes0
  (JNIEnv *env, jobject this, jbyteArray out_bytes, jint strength, jboolean prediction_resistance , jbyteArray additional_input) {

    int additional_input_length = 0;
    jbyte *additional_input_bytes = NULL;

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID drbg_id = (*env)->GetFieldID(env, clazz, "drbgContext", "J");
    jlong drbg_handle = (*env)->GetLongField(env, this, drbg_id);

    int output_bytes_length = (*env)->GetArrayLength(env, out_bytes);
    byte *output_bytes = (byte *)malloc(sizeof(output_bytes_length));

    if (additional_input != NULL) {
        additional_input_length = (*env)->GetArrayLength(env, additional_input);
        additional_input_bytes = (*env)->GetByteArrayElements(env, additional_input, NULL);
    }
    
    DRBGParams *params = (DRBGParams *)malloc(sizeof(DRBGParams));
    populate_params(params, strength, prediction_resistance, 0, NULL, 0, (byte *)additional_input_bytes, additional_input_length);

    next_rand_with_params((DRBG *)drbg_handle, output_bytes, output_bytes_length, params);

    (*env)->SetByteArrayRegion(env, out_bytes, 0, output_bytes_length, output_bytes);
    if (additional_input != NULL) {
        (*env)->ReleaseByteArrayElements(env, additional_input, additional_input_bytes, JNI_ABORT);
    }
}

/*
 * Class:     com_canonical_openssl_OpenSSLDrbg
 * Method:    reseed0
 * Signature: ([BZ[B)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_drbg_OpenSSLDrbg_reseed0
  (JNIEnv *env, jobject this, jbyteArray in_bytes, jboolean reseeding, jbyteArray additional_input) {
    byte *ai_bytes = NULL;
    jsize ai_length = 0;
    jsize input_length = 0;
    byte *input_bytes = NULL;

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID drbg_id = (*env)->GetFieldID(env, clazz, "drbgContext", "J");
    jlong drbg_handle = (*env)->GetLongField(env, this, drbg_id);


    if (in_bytes != NULL) {
        input_length = (*env)->GetArrayLength(env, in_bytes);
        input_bytes = (*env)->GetByteArrayElements(env, in_bytes, NULL);         
    }

    if (additional_input != NULL) {
        ai_length = (*env)->GetArrayLength(env, additional_input);
        jbyte *bytes = (*env)->GetByteArrayElements(env, additional_input, NULL);
        ai_bytes = (byte *)malloc(ai_length);
        memcpy(ai_bytes, bytes, ai_length);
    }


    DRBGParams *params = (DRBGParams *)malloc(sizeof(DRBGParams));
    populate_params(params, -1, 0, reseeding, NULL, 0, (byte *)ai_bytes, ai_length);

    if (input_bytes == NULL) {
        reseed_with_params((DRBG*)drbg_handle, params); 
    } else {
        reseed_with_seed_and_params((DRBG*)drbg_handle, input_bytes, input_length, params);
    }
}

/*
 * Class:     com_canonical_openssl_OpenSSLDrbg
 * Method:    generateSeed0
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_canonical_openssl_drbg_OpenSSLDrbg_generateSeed0
  (JNIEnv *env, jobject this, jint num_bytes) {

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID drbg_id = (*env)->GetFieldID(env, clazz, "drbgContext", "J");
    jlong drbg_handle = (*env)->GetLongField(env, this, drbg_id);

    byte *output = (byte *)malloc(num_bytes);

    if (output == NULL) {
        return NULL;
    }

    generate_seed((DRBG*)drbg_handle, output, num_bytes);

    jbyteArray ret_array = (*env)->NewByteArray(env, num_bytes);
    (*env)->SetBooleanArrayRegion(env, ret_array, 0, num_bytes, output);

    free(output);
    return ret_array;
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_drbg_OpenSSLDrbg_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    free_DRBG((DRBG*)handle);  
}
