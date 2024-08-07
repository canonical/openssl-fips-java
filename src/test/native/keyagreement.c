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
#include "keyagreement.h"

int compare(shared_secret *s1, shared_secret *s2) {
    if (s1 == NULL || s2 == NULL) return 0;

    if (s1->length != s2->length) return 0;

    for(int i = 0; i < s1->length; i++) {
        if (s1->bytes[i] != s2->bytes[i]) return 0;
    }

    return 1;
}

int test(key_agreement_algorithm algo, OSSL_LIB_CTX *libctx) {
    int rc = 0;
    switch(algo) {
        case DIFFIE_HELLMAN: printf("Testing DIFFIE_HELLMAN key-agreement: "); break;
        case ELLIPTIC_CURVE: printf("Testing ELLIPTIC_CURVE key-agreement: "); break;
    }

    shared_secret *alice_secret, *bob_secret;

    EVP_PKEY *alice_key = generate_key(algo);
    EVP_PKEY *bob_key = generate_key(algo);

    key_agreement *alice = init_key_agreement(algo, libctx);
    set_private_key(alice, alice_key);
    set_peer_key(alice, bob_key);
    alice_secret = generate_shared_secret(alice);
    
    key_agreement *bob = init_key_agreement(algo, libctx);
    set_private_key(bob, bob_key);
    set_peer_key(bob, alice_key);
    bob_secret = generate_shared_secret(bob);

    if (compare(alice_secret, bob_secret)) {
        printf(" PASSED\n");
    } else {
        printf(" FAILED\n");
        rc = 1;
    }

    free_shared_secret(alice_secret);
    free_shared_secret(bob_secret);
    free_key_agreement(alice);
    //free_key_agreement(bob); // keys are shared, don't free twice
    free(bob);
    return rc;
}

int main(int argc, char *argv[]) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    int rc = 0;
    rc = test(DIFFIE_HELLMAN, libctx);
    rc = test(ELLIPTIC_CURVE, libctx);
    return rc;
}

