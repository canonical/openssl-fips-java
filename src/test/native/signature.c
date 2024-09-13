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
#include "signature.h"
#include "md.h"
#include "keyencapsulation.h"
#include <openssl/pem.h>
#include <openssl/encoder.h>
#include <stdlib.h>

char* message = "Into the valley of death, rode the six hundred!";
int rc;
 
void test_sign_and_verify(OSSL_LIB_CTX *libctx, EVP_PKEY *public_key, EVP_PKEY *private_key, char *digest, sv_type type) {
    // TODO: this crashes in openssl/fips.so
    // sv_params *p = sv_create_params(libctx, -1, PSS, "SHA-256", "SHA-256");

    // This fails because the default mask generation hash - mgf1 - is SHA-1 and FIPS hates it :/
    // sv_params *p = sv_create_params(libctx, -1, PSS, "SHA-256", NULL);

    // So test without padding for now 
    sv_params *p = sv_create_params(libctx, -1, NONE, digest, NULL);
    sv_key *key = sv_init_key(libctx, private_key);

    sv_context *svc = sv_init(libctx, key, p, SIGN, type);
    if (NULL == svc) {
        free_sv_params(p);
        free_sv_key(key);
        printf("FAILED (sign init)\n");
        rc = 1;
        return;
    }
    sv_update(svc, message, strlen(message));

    size_t sig_length = 0;
    if (sv_sign(svc, NULL, &sig_length) < 0) {
        free_sv_params(p);
        free_sv_key(key);
        free_sv_context(svc);
        printf("FAILED (signing)\n");
        rc = 1;
        return;
    }

    byte *signature = (byte *)malloc(sig_length);
    if (sv_sign(svc, signature, &sig_length) < 0) {
        free_sv_params(p);
        free_sv_key(key);
        free_sv_context(svc);
        printf("FAILED (signing)\n");
        rc = 1;
        return;
    }

    sv_key *pubkey = sv_init_key(libctx, public_key);
    sv_context *svc1 = sv_init(libctx, pubkey, p, VERIFY, type);
    if (NULL == svc1) {
        free_sv_params(p);
        free_sv_key(pubkey);
        printf("FAILED (verify init)\n");
        rc = 1;
        return;
    }

    if (sv_update(svc1, message, strlen(message)) <= 0) {
        free_sv_params(p);
        free_sv_key(pubkey);
        free_sv_context(svc1);
        printf("FAILED (verify update) \n");
        rc = 1;
        return;  
    }

    if (sv_verify(svc1, signature, sig_length) <= 0) {
        free_sv_params(p);
        free_sv_key(pubkey);
        free_sv_context(svc1);
        printf("FAILED (verify)\n");
        rc = 1;
        return;
    }

    printf("PASSED\n");
}

void test_rsa_sign_and_verify(OSSL_LIB_CTX *libctx) {
    printf("Testing RSA sign and verify: ");

    EVP_PKEY *public_key = NULL, *private_key = NULL;
    rsa_keygen(libctx, 4096, &public_key, &private_key);
    test_sign_and_verify(libctx, public_key, private_key, "SHA-256", SV_RSA);
}

void test_ed25519_sign_and_verify(OSSL_LIB_CTX *libctx) {
    printf("Testing ED25519 sign and verify: ");

    EVP_PKEY *public_key = NULL, *private_key = NULL;
    FILE *priv_key_pem = fopen("src/test/keys/ed25519-priv.pem", "r");
    FILE *pub_key_pem = fopen("src/test/keys/ed25519-pub.pem", "r");

    if (priv_key_pem == NULL || pub_key_pem == NULL) {
        printf("FAILED (can't read PEM files)\n");
        rc = 1;
    }

    private_key = PEM_read_PrivateKey_ex(priv_key_pem, NULL, NULL, NULL, libctx, NULL);
    public_key = PEM_read_PUBKEY_ex(pub_key_pem, NULL, NULL, NULL, libctx, NULL);

    if (private_key == NULL || public_key == NULL) {
        printf("FAILED (can't decode PEM files)");
        rc = 1;
    }
    test_sign_and_verify(libctx, public_key, private_key, NULL, SV_ED25519);
}

void test_ed448_sign_and_verify(OSSL_LIB_CTX *libctx) {
    printf("Testing ED448 sign and verify: ");

    EVP_PKEY *public_key = NULL, *private_key = NULL;
    FILE *priv_key_pem = fopen("src/test/keys/ed448-priv.pem", "r");
    FILE *pub_key_pem = fopen("src/test/keys/ed448-pub.pem", "r");
    
    if (priv_key_pem == NULL || pub_key_pem == NULL) {
        printf("FAILED (can't read PEM files)\n");
        rc = 1;
    }
    
    private_key = PEM_read_PrivateKey_ex(priv_key_pem, NULL, NULL, NULL, libctx, NULL);
    public_key = PEM_read_PUBKEY_ex(pub_key_pem, NULL, NULL, NULL, libctx, NULL);
    
    if (private_key == NULL || public_key == NULL) {
        printf("FAILED (can't decode PEM files)");
        rc = 1;
    }
    test_sign_and_verify(libctx, public_key, private_key, NULL, SV_ED448);
}


int main(int argc, char ** argv) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf"); 
    test_rsa_sign_and_verify(libctx);
    //test_ed25519_sign_and_verify(libctx);
    //test_ed448_sign_and_verify(libctx);
    return rc;
}
