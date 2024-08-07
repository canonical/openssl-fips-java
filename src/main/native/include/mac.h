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
#include <openssl/evp.h>
#include <openssl/params.h>

typedef struct mac_params {
    char *cipher_name;
    char *digest_name;
    byte *iv;
    size_t iv_length;
    size_t output_length;
} mac_params;

typedef struct mac_context {
    char *algorithm;
    EVP_MAC_CTX *ctx;
} mac_context;

mac_params *init_mac_params(char *cipher, char *digest, byte *iv, size_t iv_length, size_t output_length);
mac_context *mac_init(char *algorithm, byte *key, size_t key_length, mac_params *params);
int mac_update(mac_context *ctx, byte *input, size_t input_size);
int mac_final_with_input(mac_context *ctx, byte *input, size_t input_size, byte *output, size_t *bytes_written, size_t output_size);
int mac_final(mac_context *ctx, byte *output, size_t *bytes_written, size_t output_size);
size_t get_mac_length(mac_context *mac);
void free_mac_context(mac_context *mac);
