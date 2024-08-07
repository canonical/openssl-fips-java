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
#include <unistd.h>

DRBGParams NO_PARAMS = { DEFAULT_STRENGTH, 0, 0, NULL, 0, NULL, 0 };

/* Created the necessary params for the given algorithm 
 * Return the number of parameters added to `params`
 */
static int create_params(const char *name, OSSL_PARAM params[]) {
    if (STR_EQUAL(name, "HASH-DRBG")) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, SN_sha512, 0);
        params[1] = OSSL_PARAM_construct_end();
        return 2;
    } else if (STR_EQUAL(name, "HMAC-DRBG")) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, SN_hmac, 0);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, SN_sha256, 0);
        params[2] = OSSL_PARAM_construct_end();
        return 3;
    } else if (STR_EQUAL(name, "CTR-DRBG")) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, SN_aes_256_ctr, 0);
        params[1] = OSSL_PARAM_construct_end();
        return 2;
    } else if (STR_EQUAL(name, "SEED-SRC")) {
	// TODO: We don't come here in the FIPS mode
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, SN_aes_256_ctr, 0);
        params[1] = OSSL_PARAM_construct_end();
        return 2;
    } else if (STR_EQUAL(name, "TEST-RAND")) {
	// TODO: We don't come here in the FIPS mode
        return 0;
    } else {
        // We should never come here!
        return 0;
    }
}
DRBG* create_DRBG(const char* name, DRBG* parent) {
    return create_DRBG_with_params(name, parent, NULL);
}

DRBG* create_DRBG_with_params(const char* name, DRBG* parent, DRBGParams *drbg_params) {
    EVP_RAND *rand = EVP_RAND_fetch(NULL, name, NULL);
    if (NULL == rand) {
        fprintf(stderr, "Couldn't allocate EVP_RAND\n");
        return NULL;
    }
    
    EVP_RAND_CTX * context = EVP_RAND_CTX_new(rand, parent == NULL ? NULL : parent->context);
    if (NULL == context) {
        EVP_RAND_free(rand);
        fprintf(stderr, "Couldn't allocate EVP_RAND_CTX\n");
        return NULL;
    }

    OSSL_PARAM params[4];
    int n_params = create_params(name, params);
    if (n_params < 2) {
         fprintf(stderr, "Couldn't create params");
         return NULL;
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
}

int free_DRBGParams(DRBGParams *params) {
    FREE_IF_NON_NULL(params->additional_data);
    FREE_IF_NON_NULL(params->personalization_str);
    FREE_IF_NON_NULL(params);
    return 1;
}

int free_DRBG(DRBG *generator) {
    if (generator == NULL) {
        return 0;
    }

    FREE_IF_NON_NULL(generator->seed);
    if (generator->context != NULL) {
        EVP_RAND_CTX_free(generator->context);
        generator->context = NULL;
    }

    if (generator->params != NULL) {
        free_DRBGParams(generator->params);
        generator->params = NULL;
    }

    if (generator->parent != NULL) {
        free_DRBG(generator->parent);
        generator->parent = NULL;
    }

    free(generator);
    return 1;
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

    int o3 = ((0x00ff) & output[3]) << 24;
    int o2 = ((0x00ff) & output[2]) << 16;
    int o1 = ((0x00ff) & output[1]) << 8;
    int o0 = ((0x00ff) & output[0]);

    return o3 | o2 | o1 | o0;
}

int generate_seed(DRBG* generator, byte output[], int n_bytes) {
    DRBG *parent = generator->parent;
    if (parent != NULL) {
        return next_rand(parent, output, n_bytes);
    } else {
        return getentropy(output, n_bytes);
    }
}

void reseed(DRBG* generator) {
    reseed_with_params(generator, &NO_PARAMS);
}

void reseed_with_params(DRBG *generator, DRBGParams *params) {
    byte seed[128]; // TODO: what should the default seed size be?
    size_t length = 128;
    getentropy(seed, length);
    EVP_RAND_reseed(generator->context, params->prediction_resistance, seed, length, params->additional_data, params->additional_data_length);
}

void reseed_with_seed(DRBG* generator, byte seed[], int seed_length) {
    EVP_RAND_reseed(generator->context, 0, seed, seed_length, NULL, 0);
}

void reseed_with_seed_and_params(DRBG* generator, byte seed[], int seed_length, DRBGParams *params) {
    EVP_RAND_reseed(generator->context, params->prediction_resistance, seed, seed_length, params->additional_data, params->additional_data_length);
}
