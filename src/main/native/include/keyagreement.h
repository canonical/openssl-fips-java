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
#include <openssl/evp.h>

typedef enum key_agreement_algorithm {
    DIFFIE_HELLMAN, // Diffie-Hellman
    ELLIPTIC_CURVE  // Elliptic-Curve
} key_agreement_algorithm;

typedef struct shared_secret {
    byte *bytes;
    int length;
} shared_secret;

typedef struct key_agreement {
    OSSL_LIB_CTX *libctx;
    key_agreement_algorithm algorithm;
    EVP_PKEY *private_key;
    EVP_PKEY *peer_public_key;
    shared_secret *secret;
} key_agreement;

EVP_PKEY *generate_key(key_agreement_algorithm algo);

key_agreement* init_key_agreement(key_agreement_algorithm algo, OSSL_LIB_CTX *libctx);

void set_private_key(key_agreement *agreement, EVP_PKEY *private_key);

void set_peer_key(key_agreement *agreement, EVP_PKEY *peer_public_key);

shared_secret *generate_shared_secret(key_agreement *agreement);

int get_shared_secret_bytes(key_agreement *agreement, byte secret[]);

EVP_PKEY *generate_key(key_agreement_algorithm algo);

void free_key_agreement(key_agreement *this);

void free_shared_secret(shared_secret *this);
