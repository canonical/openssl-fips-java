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
#include <drbg.h>
#include <stdio.h>
#include <sys/random.h>
#include <unistd.h>

DRBGParams NO_PARAMS = { DEFAULT_STRENGTH, 0, 0, NULL, 0, NULL, 0 };

/* Created the necessary params for the given algorithm 
 * Return the number of parameters added to `params`
 */
static int create_params(const char *name, OSSL_PARAM params[]) {
    int param_count = 0;
    if (str_equal(name, "HASH-DRBG")) {
        params[param_count++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, SN_sha512, 0);
        params[param_count++] = OSSL_PARAM_construct_end();
    } else if (str_equal(name, "HMAC-DRBG")) {
        params[param_count++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, SN_hmac, 0);
        params[param_count++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, SN_sha256, 0);
        params[param_count++] = OSSL_PARAM_construct_end();
    } else if (str_equal(name, "CTR-DRBG")) {
        params[param_count++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, SN_aes_256_ctr, 0);
        params[param_count++] = OSSL_PARAM_construct_end();
    } else if (str_equal(name, "SEED-SRC")) {
	// TODO: We don't come here in the FIPS mode
        params[param_count++] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, SN_aes_256_ctr, 0);
        params[param_count++] = OSSL_PARAM_construct_end();
    } else if (str_equal(name, "TEST-RAND")) {
	// TODO: We don't come here in the FIPS mode
    } else {
        // We should never come here!
    }
    return param_count;
}
DRBG* create_DRBG(const char* name, DRBG* parent) {
    return create_DRBG_with_params(name, parent, NULL);
}

#define MIN_NUMBER_OF_PARAMS 2
#define MAX_NUMBER_OF_PARAMS 4

DRBG* create_DRBG_with_params(const char* name, DRBG* parent, DRBGParams *drbg_params) {
    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *context = NULL;

    rand = EVP_RAND_fetch(NULL, name, NULL);
    if (NULL == rand) {
        fprintf(stderr, "Couldn't allocate EVP_RAND: %s\n", name);
        goto error;
    }
    
    context = EVP_RAND_CTX_new(rand, parent == NULL ? NULL : parent->context);
    if (NULL == context) {
        fprintf(stderr, "Couldn't allocate EVP_RAND_CTX\n");
        goto error;
    }

    OSSL_PARAM params[MAX_NUMBER_OF_PARAMS];
    int n_params = create_params(name, params);
    if (n_params < MIN_NUMBER_OF_PARAMS) {
        fprintf(stderr, "Couldn't create params");
        goto error;
    }

    if (NULL == drbg_params) {
        EVP_RAND_instantiate(context, 128, 0, NULL, 0, params);
    } else {
        EVP_RAND_instantiate(context, drbg_params->strength,
                             drbg_params->prediction_resistance,
                             drbg_params->personalization_str, drbg_params->personalization_str_len, params);
    }

    const OSSL_PROVIDER *prov = EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(context));
    DRBG *newDRBG = (DRBG*) malloc(sizeof(DRBG));
    newDRBG->context = context;
    newDRBG->seed = NULL;
    newDRBG->params = drbg_params; 
    newDRBG->parent = parent;
    return newDRBG;

error:
    if ( rand != NULL ) {
        EVP_RAND_free(rand);
    }
    if ( context != NULL ) {
        EVP_RAND_CTX_free(context);
    }
    return NULL;
}

void free_DRBGParams(DRBGParams **pparams) {
    if (pparams == NULL || *pparams == NULL) {
        return;
    }
    free((*pparams)->additional_data);
    free((*pparams)->personalization_str);
    free(*pparams);
    *pparams = NULL;
    return;
}

void free_DRBG(DRBG **pgenerator) {
    if (pgenerator == NULL || *pgenerator == NULL) {
        return;
    }
    free_DRBGParams(&((*pgenerator)->params));
    free_DRBG(&((*pgenerator)->parent));
    free((*pgenerator)->seed);
    EVP_RAND_CTX_free((*pgenerator)->context);
    free(*pgenerator);
    *pgenerator = NULL;
    return;
}

int next_rand(DRBG *drbg, byte output[], int n_bytes) {
    return EVP_RAND_generate(drbg->context, output, n_bytes, DEFAULT_STRENGTH, 0, NULL, 0);
}

int next_rand_with_params(DRBG *drbg, byte output[], int n_bytes, DRBGParams *params) {
    return EVP_RAND_generate(drbg->context, output, n_bytes,
                             params->strength, params->prediction_resistance,
                             params->additional_data, params->additional_data_length);
}

int next_rand_int(DRBG *drbg, int num_bits) {
    if (num_bits <= 0 || num_bits > 32) {
        return 0; // can this indicate failure?
    }
    int num_bytes = num_bits/8 + (num_bits % 8 == 0 ? 0 : 1);
    int mask = ~(~1 << ((num_bits-1) % 8));
    byte output[4] = {0};
    next_rand(drbg, output, num_bytes);
    output[num_bytes-1] &= mask;

    int32_t target;
    memcpy(&target, output, 4);
    return target;
}

int generate_seed(DRBG* generator, byte output[], int n_bytes) {
    DRBG *parent = generator->parent;
    if (parent != NULL) {
        return next_rand(parent, output, n_bytes);
    } else {
        return getrandom(output, n_bytes, 0);
    }
}

void reseed(DRBG* generator) {
    reseed_with_params(generator, &NO_PARAMS);
}

void reseed_with_params(DRBG *generator, DRBGParams *params) {
    byte seed[128]; // TODO: what should the default seed size be?
    size_t length = 128;
    getrandom(seed, length, 0);
    EVP_RAND_reseed(generator->context, params->prediction_resistance, seed, length, params->additional_data, params->additional_data_length);
}

void reseed_with_seed(DRBG* generator, byte seed[], int seed_length) {
    EVP_RAND_reseed(generator->context, 0, seed, seed_length, NULL, 0);
}

void reseed_with_seed_and_params(DRBG* generator, byte seed[], int seed_length, DRBGParams *params) {
    EVP_RAND_reseed(generator->context, params->prediction_resistance, seed, seed_length, params->additional_data, params->additional_data_length);
}
