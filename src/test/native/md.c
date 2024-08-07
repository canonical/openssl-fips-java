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
#include "md.h"
#include <openssl/evp.h>

char *message1 = "Namaste, World!";
char *message2 = "How are you all?";
char *message3 = "How are you all!";
int rc;

int equal(byte *out1, int len1, byte *out2, int len2) {
    if (len1 != len2) return 0;
    for (int i = 0; i < len1; i++) {
        if (out1[i] != out2[i]) return 0;
    }
    return 1;
}

void test_digest(const char *algo, OSSL_LIB_CTX *libctx) {
    byte output1[EVP_MAX_MD_SIZE] = {0};
    byte output2[EVP_MAX_MD_SIZE] = {0};
    int len1 = 0, len2 = 0;

    printf("Test MessageDigest of type %s: ", algo); 
    md_context *ctx = md_init(libctx, algo);

    if (ctx == NULL) {
        free_md_context(ctx);
        printf("FAILED (init)\n");
        rc = 1;
    }

    if (!(md_update(ctx, message1, strlen(message1)) &&
        md_update(ctx, message2, strlen(message2)))) {
        free_md_context(ctx);
        printf("FAILED (update)\n");
        rc = 1;
        return;
    }

    if (!md_digest(ctx, output1, &len1)) {
        free_md_context(ctx);
        printf("FAILED (digest)\n");
        rc = 1;
        return;
    }
    free_md_context(ctx);

    md_context *ctx1 = md_init(libctx, algo);
    if (!(md_update(ctx1, message1, strlen(message1)) &&
        md_update(ctx1, message3, strlen(message3)))) {
        free_md_context(ctx1);
        printf("FAILED (update)\n");
        rc = 1;
        return;   
    }

    if (!md_digest(ctx1, output2, &len2)) {
        free_md_context(ctx1);
        printf("FAILED (digest)\n");
        rc = 1;
        return;
    }

    if(equal(output1, len1, output2, len2)) {
       printf("FAILED (digests match)\n");
       rc = 1;
       return;
    }

    free_md_context(ctx1);
    printf("PASSED\n"); 
}

int main(int argc, char ** argv) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    test_digest("SHA1", libctx);
    test_digest("SHA224", libctx);
    test_digest("SHA256", libctx);
    test_digest("SHA384", libctx);
    test_digest("SHA512", libctx);
    test_digest("SHA2-224", libctx);
    test_digest("SHA2-256", libctx);
    test_digest("SHA2-384", libctx);
    test_digest("SHA2-512", libctx);
    test_digest("SHA3-224", libctx);
    test_digest("SHA3-256", libctx);
    test_digest("SHA3-384", libctx);
    test_digest("SHA3-512", libctx);
    test_digest("KECCAK-KMAC-128", libctx);
    test_digest("KECCAK-KMAC-256", libctx);
    return rc;
}
