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
#include "OpenSSLDrbg.h"
#include "drbg.h"
#include "jssl.h"
#include "jni_utils.h"

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
    const char *name_string = NULL;
    byte *ps_bytes_native = NULL;
    DRBGParams *params = NULL;
    DRBG *drbg = NULL;
    jsize pstr_length = 0;

    name_string = (*env)->GetStringUTFChars(env, name, 0);
    if (name_string == NULL) {
        goto error;
    }

    if (personalization_string != NULL) {
        pstr_length = (*env)->GetArrayLength(env, personalization_string);
        jbyte *pstr_bytes = (*env)->GetByteArrayElements(env, personalization_string, NULL);
        if (pstr_bytes == NULL) {
            goto error;
        }
        ps_bytes_native = (byte *)malloc(pstr_length);
	if (ps_bytes_native == NULL) {
            (*env)->ReleaseByteArrayElements(env, personalization_string, pstr_bytes, JNI_ABORT);
	    throwOOM(env, "Could not allocate memory for password");
	    goto error;
	}
        memcpy(ps_bytes_native, pstr_bytes, pstr_length);
        (*env)->ReleaseByteArrayElements(env, personalization_string, pstr_bytes, JNI_ABORT);
    }

    params = (DRBGParams *)malloc(sizeof(DRBGParams));
    if (params == NULL) {
        throwOOM(env, "Failed to allocate memory for DRBG parameters");
	goto error;
    }
    populate_params(params, strength, prediction_resistance, reseeding, ps_bytes_native, pstr_length, NULL, 0);
    ps_bytes_native = NULL; // ownership transferred to params; free_DRBGParams will release it

    int evp_error = JNI_FALSE;
    drbg = create_DRBG_with_params(jssl_libctx(), name_string, NULL, params, &evp_error);

    if (drbg == NULL) {
        if (evp_error) {
            throwProviderException(env, "DRBG instantiation failed");
        } else {
            throwOOM(env, "Failed to allocate memory for a DRBG");
        }
	goto error;
    }

    release_jstring(env, name, name_string);
    return (jlong)drbg;

error:
    release_jstring(env, name, name_string);
    if (ps_bytes_native) {
        memset(ps_bytes_native, 0, pstr_length);
        free(ps_bytes_native);
    }

    if (params) {
        free_DRBGParams(&params);
    }

    if (drbg) {
        free_DRBG(&drbg);
    }
    return (jlong)0;
}

/*
 * Class:     com_canonical_openssl_OpenSSLDrbg
 * Method:    nextBytes0
 * Signature: ([BIZ[B)V
 */
JNIEXPORT void JNICALL Java_com_canonical_openssl_drbg_OpenSSLDrbg_nextBytes0
  (JNIEnv *env, jobject this, jbyteArray out_bytes, jint strength, jboolean prediction_resistance , jbyteArray additional_input) {
    byte *ai_bytes_native = NULL;
    byte *output_bytes = NULL;
    DRBGParams *params = NULL;
    jsize additional_input_length = 0;
    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID drbg_id = (*env)->GetFieldID(env, clazz, "drbgContext", "J");
    jlong drbg_handle = (*env)->GetLongField(env, this, drbg_id);

    int output_bytes_length = (*env)->GetArrayLength(env, out_bytes);
    output_bytes = (byte *)malloc(output_bytes_length);
    if (output_bytes == NULL) {
        throwOOM(env, "Could not allocate output bytes");
	goto cleanup;
    }

    if (additional_input != NULL) {
        additional_input_length = (*env)->GetArrayLength(env, additional_input);
        jbyte *additional_input_bytes = (*env)->GetByteArrayElements(env, additional_input, NULL);
        if (additional_input_bytes == NULL) {
            goto cleanup;
        }
        ai_bytes_native = (byte*)malloc(additional_input_length);
	if (ai_bytes_native == NULL) {
            (*env)->ReleaseByteArrayElements(env, additional_input, additional_input_bytes, JNI_ABORT);
            throwOOM(env, "Could not allocate memory for additional input");
            goto cleanup;
	}
        memcpy(ai_bytes_native, additional_input_bytes, additional_input_length);
        (*env)->ReleaseByteArrayElements(env, additional_input, additional_input_bytes, JNI_ABORT);
    }
    
    params = (DRBGParams *)malloc(sizeof(DRBGParams));
    if (params == NULL) {
        throwOOM(env, "Could not allocate DRBG params");
	goto cleanup;
    }
    populate_params(params, strength, prediction_resistance, 0, NULL, 0, ai_bytes_native, additional_input_length);
    ai_bytes_native = NULL; // ownership transferred to params; free_DRBGParams will release it

    if (!next_rand_with_params((DRBG *)drbg_handle, output_bytes, output_bytes_length, params)) {
        throwProviderException(env, "DRBG generate failed");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, out_bytes, 0, output_bytes_length, (const jbyte *)output_bytes);

cleanup:
    if (output_bytes) {
        OPENSSL_cleanse(output_bytes, output_bytes_length);
        free(output_bytes);
    }

    if (ai_bytes_native) {
        memset(ai_bytes_native, 0, additional_input_length);
	free(ai_bytes_native);
    }

    if (params)
        free_DRBGParams(&params);

    return;
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
    byte *input_copy = NULL;
    jbyte *input_pinned = NULL;
    jbyte *ai_pinned = NULL;
    DRBGParams *params = NULL;

    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID drbg_id = (*env)->GetFieldID(env, clazz, "drbgContext", "J");
    jlong drbg_handle = (*env)->GetLongField(env, this, drbg_id);

    if (in_bytes != NULL) {
        input_length = (*env)->GetArrayLength(env, in_bytes);
        input_pinned = (*env)->GetByteArrayElements(env, in_bytes, NULL);
        if (input_pinned == NULL) {
            goto cleanup;
        }
        input_copy = (byte *)malloc(input_length);
        if (input_copy == NULL) {
            throwOOM(env, "Could not allocate memory for seed");
            goto cleanup;
        }
        memcpy(input_copy, input_pinned, input_length);
    }

    if (additional_input != NULL) {
        ai_length = (*env)->GetArrayLength(env, additional_input);
        ai_pinned = (*env)->GetByteArrayElements(env, additional_input, NULL);
        if (ai_pinned == NULL) {
            goto cleanup;
        }
        ai_bytes = (byte *)malloc(ai_length);
        if (ai_bytes == NULL) {
            throwOOM(env, "Could not allocate memory for additional data");
            goto cleanup;
        }
        memcpy(ai_bytes, ai_pinned, ai_length);
    }

    params = (DRBGParams *)malloc(sizeof(DRBGParams));
    if (params == NULL) {
        throwOOM(env, "Could not allocate memory for DRBG params");
        goto cleanup;
    }

    populate_params(params, -1, 0, reseeding, NULL, 0, (byte *)ai_bytes, ai_length);
    ai_bytes = NULL; // ownership transferred to params; free_DRBGParams will release it

    /* Reseed entropy comes from OpenSSL's FIPS entropy chain, not getrandom(). */
    jssl_status status;
    if (input_copy == NULL) {
        status = reseed_with_params((DRBG*)drbg_handle, params);
    } else {
        status = reseed_with_seed_and_params((DRBG*)drbg_handle, input_copy, input_length, params);
    }
    if (FAIL_EVP == status) {
        throwProviderException(env, "DRBG reseed failed");
    }

cleanup:
    if (ai_bytes) {
        OPENSSL_cleanse(ai_bytes, ai_length);
        free(ai_bytes);
    }
    if (ai_pinned) {
        (*env)->ReleaseByteArrayElements(env, additional_input, ai_pinned, JNI_ABORT);
    }
    if (input_copy) {
        OPENSSL_cleanse(input_copy, input_length);
        free(input_copy);
    }
    if (input_pinned) {
        (*env)->ReleaseByteArrayElements(env, in_bytes, input_pinned, JNI_ABORT);
    }
    free_DRBGParams(&params);
}

#define MAX_SEED_BYTES 256
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

    if (num_bytes < 0) {
        (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/IllegalArgumentException"),
                         "num_bytes must not be negative");
        return NULL;
    }

    if (num_bytes > 256) {
        num_bytes = 256;
    }

    byte output[MAX_SEED_BYTES];

    if (!generate_seed((DRBG*)drbg_handle, output, num_bytes)) {
        OPENSSL_cleanse(output, sizeof(output));
        throwProviderException(env, "Seed generation failed");
        return NULL;
    }

    jbyteArray ret_array = (*env)->NewByteArray(env, num_bytes);
    if (ret_array != NULL) {
        (*env)->SetByteArrayRegion(env, ret_array, 0, num_bytes, (const jbyte *)output);
    }
    OPENSSL_cleanse(output, sizeof(output));

    return ret_array;
}

JNIEXPORT void JNICALL Java_com_canonical_openssl_drbg_OpenSSLDrbg_cleanupNativeMemory0
  (JNIEnv *env, jclass clazz, jlong handle) {
    DRBG *drbg = (DRBG*)handle;
    free_DRBG(&drbg);
}
