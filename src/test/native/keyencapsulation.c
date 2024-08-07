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
#include "keyencapsulation.h"

int check(byte* alice_secret, size_t as_len, byte* bob_secret, size_t bs_len) {
    if (as_len != bs_len ) {
        return 0;
    }
    for (int i = 0; i < as_len; i++) {
        if (alice_secret[i] != bob_secret[i]) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char ** argv) {
    int rc = 0;
    printf("Testing EVP_KEM-RSA key encapsulation: ");
    byte *public_key_bytes = NULL;
    size_t public_key_len = 0;
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");

    // Alice creates a KEM key specification
    kem_keyspec *spec_alice = init_kem_keyspec(libctx); 

    // Alice sends the public key to Bob
    // Bob generates and encapsulates a secret key using the public key
    kem_keyspec *spec_bob = init_kem_keyspec_with_key(spec_alice->public_key, NULL, libctx);
    if (generate_and_wrap(spec_bob)) {
        return 1;
    }
    // Bob sends the wrapped key to Alice
    // Alice uses her private key to decapsulate the secret key
    //spec_alice->wrapped_key = spec_bob->wrapped_key;
    //spec_alice->wrapped_key_length = spec_bob->wrapped_key_length;
    set_wrapped_key(spec_alice, spec_bob->wrapped_key, spec_bob->wrapped_key_length);
    if (unwrap(spec_alice)) {
        return 1;
    }

    // Test: the secrets should match
    if (check(spec_alice->secret, spec_alice->secret_length, spec_bob->secret, spec_bob->secret_length)) {
        printf("PASSED\n");
    } else {
        printf("FAILED\n");
        rc = 1;
    }
    free_kem_keyspec(spec_alice);
    //free_kem_keyspec(spec_bob); //alice and bob share keys, don't delete twice
    free(spec_bob);
    return rc; 
} 
