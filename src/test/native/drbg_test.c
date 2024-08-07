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
#include <drbg.h>

int result = 0;
void test_xxx_drbg(const char *test, const char *algo) {
    DRBG *drbg = create_DRBG(algo, NULL);
    byte output1[10] = {0}, output2[10] = {0}, output3[10] = {0};
    next_rand(drbg, output1, 10);
    next_rand(drbg, output2, 10);
    next_rand(drbg, output3, 10);
    for (int i = 0; i < 10; i++) {
        printf("output3[%d] = %d\n", i, output3[i]);
    }
    for (int i = 0; i < 10; i++) {
        if(output1[i] != output2[i]) {
            printf("drbg_test/%s: PASS\n", test);
            return;
        }
    }
    printf("drbg_test/%s: FAIL\n", test);
    result = 1;
    free_DRBG(drbg);
}

void test_basic_hmac_drbg() {
    test_xxx_drbg("test_basic_hmac_drbg", "HMAC-DRBG");
}

void test_basic_hash_drbg() {
    test_xxx_drbg("test_basic_hash_drbg", "HASH-DRBG");
}

void test_basic_ctr_drbg() {
    test_xxx_drbg("test_basic_hash_drbg", "CTR-DRBG");
}

void test_xxx_drbg_fails(const char *test, const char *algo) {
    DRBG *drbg = NULL;
    if (NULL == (drbg = create_DRBG(algo, NULL))) {
        printf("drbg_test/%s: PASS\n", test);
    } else {
        printf("drbg_test/%s: FAIL\n", test);
        free_DRBG(drbg);
    }
}

void test_seed_src_drbg_fails() {
    test_xxx_drbg_fails("test_seed_src_drbg_fails", "SEED-SRC");
}

void test_test_rand_drbg_fails() {
   test_xxx_drbg_fails("test_test_rand_drbg_fails", "TEST-RAND");
}

void test_rand_int_num_bits(const char *algo, int num_bits) {
    DRBG *drbg;
    if (NULL == (drbg = create_DRBG(algo, NULL))) {
        printf("drbg_test/test_rand_int_num_bits: FAIL\n");
    } else {
        printf("next_rand_int(%d) = %x (PASS)\n", num_bits, next_rand_int(drbg, num_bits));
        free_DRBG(drbg);
    }
}

int main(int argc, char ** argv) {
    load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    test_basic_hmac_drbg();
    test_basic_hash_drbg();
    test_basic_ctr_drbg();
    test_seed_src_drbg_fails();
    test_test_rand_drbg_fails();
    test_rand_int_num_bits("CTR-DRBG", 1);
    test_rand_int_num_bits("HMAC-DRBG", 16);
    test_rand_int_num_bits("HASH-DRBG", 30);
    test_rand_int_num_bits("HASH-DRBG", 32);
    return result;
}
