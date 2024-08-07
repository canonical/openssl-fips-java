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
#include "kdf.h"
#include <stdio.h>

static unsigned char password[] = {
    'P', 'a', 's', 's', 'w', 'o', 'r', 'd', '\0'
};

static unsigned char pbkdf2_salt[] = {
    'N', 'a', 'C', 'l', 'O', 'R', 'c', 'o', 'm', 'm', 'o', 'n', 's', 'a', 'l', 't', '\0'
};

static unsigned int pbkdf2_iterations = 80000;

static unsigned char hkdf_salt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f
};

static unsigned char hkdf_key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static unsigned char hkdf_info[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
};

int test_pbkdf2(OSSL_LIB_CTX *libctx) {
    printf("Testing PBKDF2: ");
    kdf_spec *spec = create_pbkdf_spec(password, strlen(password), pbkdf2_salt, strlen(pbkdf2_salt), pbkdf2_iterations);
    kdf_params *params = create_pbkdf_params("SHA-512");
    byte output[64] = {0};
    if (kdf_derive(libctx, spec, params, output, 64, PBKDF2) <= 0) {
        printf("FAILED (derive)\n");
        free_kdf_spec(spec);
        free_kdf_params(params);
        return 1;
    }
    free_kdf_spec(spec);
    free_kdf_params(params);
    printf("PASSED\n");
    return 0; 
}

int test_hkdf(OSSL_LIB_CTX *libctx) {
    printf("Testing HKDF: ");
    kdf_spec *spec = create_hkdf_spec(hkdf_salt, sizeof(hkdf_salt), hkdf_info, sizeof(hkdf_info), hkdf_key, sizeof(hkdf_key));
    kdf_params *params = create_pbkdf_params("SHA-256");
    byte output[42] = {0};
    if (kdf_derive(libctx, spec, params, output, 42, HKDF) <= 0) {
        free_kdf_spec(spec);
        free_kdf_params(params);
        printf("FAILED (derive)\n");
        return 1;
    }
    free_kdf_spec(spec);
    free_kdf_params(params);
    printf("PASSED\n");
    return 0;
}

int main(int argc, char ** argv) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    int rc;
    rc = test_pbkdf2(libctx);
    rc = test_hkdf(libctx);
    return rc;
}
