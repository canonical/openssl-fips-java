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
#include "mac.h"

int rc;

static unsigned char key[] = {
    0x6c, 0xde, 0x14, 0xf5, 0xd5, 0x2a, 0x4a, 0xdf,
    0x12, 0x39, 0x1e, 0xbf, 0x36, 0xf9, 0x6a, 0x46,
    0x48, 0xd0, 0xb6, 0x51, 0x89, 0xfc, 0x24, 0x85,
    0xa8, 0x8d, 0xdf, 0x7e, 0x80, 0x14, 0xc8, 0xce,
    0x38, 0xb5, 0xb1, 0xe0, 0x82, 0x2c, 0x70, 0xa4,
    0xc0, 0x8e, 0x5e, 0xf9, 0x93, 0x9f, 0xcf, 0xf7,
    0x32, 0x4d, 0x0c, 0xbd, 0x31, 0x12, 0x0f, 0x9a,
    0x15, 0xee, 0x82, 0xdb, 0x8d, 0x29, 0x54, 0x14
};

static unsigned char iv[] = {
    0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7, 0xba,
    0x01, 0x36, 0xa7, 0x97, 0xf3
};

static unsigned char data[] =
    "To be, or not to be, that is the question,\n"
    "Whether tis nobler in the minde to suffer\n"
    "The ſlings and arrowes of outragious fortune,\n"
    "Or to take Armes again in a sea of troubles,\n"
    "And by opposing, end them, to die to sleep;\n"
    "No more, and by a sleep, to say we end\n"
    "The heart-ache, and the thousand natural shocks\n"
    "That flesh is heir to? tis a consumation\n"
    "Devoutly to be wished. To die to sleep,\n"
    "To sleepe, perchance to dreame, Aye, there's the rub,\n"
    "For in that sleep of death what dreams may come\n"
    "When we haue shuffled off this mortal coil\n"
    "Must give us pause. There's the respect\n"
    "That makes calamity of so long life:\n"
    "For who would bear the Ships and Scorns of time,\n"
    "The oppressor's wrong, the proud man's Contumely,\n"
    "The pangs of dispised love, the Law's delay,\n"
;

void run_test(mac_context *ctx) {
    if (NULL == ctx) {
        printf("FAILED (Couldn't init MAC)\n");
    }

    if(0 == (mac_update(ctx, data, sizeof(data)))) {
        printf("FAILED (Update failed)\n");
    }

    byte output[256];
    size_t written;
    if(0 == (mac_final(ctx, output, &written, 256))) {
        printf("FAILED(final)\n");
        rc = 1;
    }

    printf("PASSED (MAC: ");
    for(int i = 0; i < (32 >= written ? written : 32); i++) {
        printf("%x", output[i]);
    }
    if (written > 32) printf("...<length = %ld, truncated>", written);
    printf(")\n");
}

void test_cmac(OSSL_LIB_CTX *libctx) {
    printf("Testing CMAC: ");
    mac_params *params = init_mac_params("AES-256-CBC", NULL, NULL, 0, 0);
    mac_context *ctx = mac_init("CMAC", key, 32, params);
    run_test(ctx);
    free_mac_context(ctx);
    free(params);
}

void test_hmac_sha1(OSSL_LIB_CTX *libctx) {
    printf("Testing HMAC with SHA-1: ");
    mac_params *params = init_mac_params(NULL, "SHA1", NULL, 0, 0); 
    mac_context *ctx = mac_init("HMAC", key, 64, params);
    run_test(ctx);
    free_mac_context(ctx);
    free(params);
}

void test_hmac_sha3(OSSL_LIB_CTX *libctx) {
    printf("Testing HMAC with SHA3-512: ");
    mac_params *params = init_mac_params(NULL, "SHA3-512", NULL, 0, 0);
    mac_context *ctx = mac_init("HMAC", key, 64, params);
    run_test(ctx);
    free_mac_context(ctx);
    free(params);
}

void test_gmac(OSSL_LIB_CTX *libctx) {
    printf("Testing GMAC: ");
    mac_params *params = init_mac_params("AES-128-GCM", NULL, iv, sizeof(iv), 0);
    mac_context *ctx = mac_init("GMAC", key, 16, params);
    run_test(ctx); 
    free_mac_context(ctx);
    free(params);
}

void test_kmac128(OSSL_LIB_CTX *libctx) {
    printf("Testing KMAC-128: ");
    mac_context *ctx = mac_init("KMAC-128", key, 16, NULL);
    run_test(ctx);
    free_mac_context(ctx);
}

void test_kmac256(OSSL_LIB_CTX *libctx) {
    printf("Testing KMAC-256: ");
    mac_context *ctx = mac_init("KMAC-256", key, 32, NULL);
    run_test(ctx);
    free_mac_context(ctx);
}


void test_mac_context_creation(OSSL_LIB_CTX *libctx) {
    test_cmac(libctx);
    test_gmac(libctx);
    test_hmac_sha1(libctx);
    test_hmac_sha3(libctx);
    test_kmac128(libctx);
    test_kmac256(libctx);
}    

int main(int argc, char ** argv) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    test_mac_context_creation(libctx);
    return rc;
}

