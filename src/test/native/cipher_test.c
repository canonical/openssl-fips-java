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
#include "cipher.h"

//TODO: Non-multiples of 16 fail with padding=NONE
#define INPUT_SIZE 32 
static byte input[] = { 0x1, 0x10, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                        0x2, 0x20, 0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a,
                        0x3, 0x30, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                        0x4, 0x40, 0x4f, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a,
                        0x1, 0x10, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                        0x2, 0x20, 0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a,
                        0x3, 0x30, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                        0x4, 0x40, 0x4f, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a };

void print_byte_array(byte *array, int length) {
    printf("[ ");
    for (int i = 0; i < length; i++) {
        printf("%d", array[i]);
        if (i < length-1) {
            printf(", ");
        }
    }
    printf(" ]\n");
}


static int array_equals(byte a1[], int l1, byte a2[], int l2) {
    if (l1 != l2) return 0;

    for (int i = 0; i < l1; i++) {
        if (a1[i] != a2[i]) return 0;
    }

    return 1;
}

int test_round_trip(OSSL_LIB_CTX *libctx, const char *cipher_type, const char *padding_name) {
    unsigned char key[] = {0x5a, 0x33, 0x98, 0x0e, 0x71, 0xe7, 0xd6, 0x7f, 0xd6, 0xcf, 0x17, 0x14, 0x54, 0xdc, 0x96, 0xe5};
    unsigned char iv[] =  {0x33, 0xae, 0x68, 0xeb, 0xb8, 0x01, 0x0c, 0x6b, 0x3d, 0xa6, 0xb9, 0xcb, 0x29, 0x3a, 0x4d, 0x34};
    unsigned char aad[] = {0x12, 0x31, 0x99, 0x71, 0x82, 0x88, 0x27, 0x2a, 0x9b, 0xad, 0xc4, 0x95, 0x7f, 0x6d, 0x11, 0x30};

    byte encrypted_output[1024], decrypted_output[1024];
    int enc_out_len = 0, dec_out_len = 0, tmplen = 0; 
 
    cipher_context *context = create_cipher_context(libctx, cipher_type, padding_name);
    if (IS_NULL(context)) {
        printf("Null context: ");
        return 0;
    }

    int total_enc_out_len = 0;
    cipher_init(context, input, INPUT_SIZE, key, iv, 16, ENCRYPT);
    cipher_update_aad(context, &enc_out_len, aad, 16);
    cipher_update(context, encrypted_output, &enc_out_len, input, INPUT_SIZE);
    total_enc_out_len += enc_out_len;
    cipher_update(context, encrypted_output + total_enc_out_len, &enc_out_len, input, INPUT_SIZE);
    total_enc_out_len += enc_out_len;
    cipher_do_final(context, encrypted_output + total_enc_out_len, &tmplen);
    total_enc_out_len += tmplen;
    //printf("total len = %d\n", total_enc_out_len);
    //print_byte_array(encrypted_output, total_enc_out_len);
    tmplen = 0;
    cipher_init(context, encrypted_output, enc_out_len, key, iv, 16, DECRYPT);
    cipher_update_aad(context, &dec_out_len, aad, 16);
    cipher_update(context, decrypted_output, &dec_out_len, encrypted_output, total_enc_out_len);
    cipher_do_final(context, decrypted_output + dec_out_len, &tmplen);
    dec_out_len += tmplen;
    free_cipher(context);
    if (array_equals(decrypted_output, dec_out_len, input, INPUT_SIZE*2)) {
        return 1;
    } else {
        return 0;
    }
}

// CCM tests currently fail, skip them
// see https://github.com/openssl/openssl/issues/22773
int main(int argc, char ** argv) {
    OSSL_LIB_CTX *libctx = load_openssl_fips_provider("/usr/local/ssl/openssl.cnf");
    char *cipher_type[] = {
        "AES-128-ECB",
	"AES-256-ECB",
        "AES-192-ECB",
        "AES-128-CBC",
        "AES-256-CBC",
        "AES-128-CFB1",
        "AES-256-CFB1",
        "AES-192-CFB1",
        "AES-128-CFB8",
        "AES-192-CFB8",
        "AES-256-CFB8",
        "AES-128-CTR",
        "AES-192-CTR",
        "AES-256-CTR",
        //"AES-128-CCM",
        //"AES-256-CCM",
        //"AES-192-CCM",
        "AES-128-GCM",
        "AES-192-GCM",
        "AES-256-GCM",
        "END"
    };

    char *padding_type[] = {
        "NONE",
        "PKCS7" ,
        "PKCS5",
        "ISO10126-2",
        "X9.23",
        "ISO7816-4"
    }; 

    int n_padding_types = 6;
    int rc = 0;
    int idx = 0;
    const char *cipher_name = cipher_type[idx++];
    while (!STR_EQUAL(cipher_name, "END")) {
        for(int j = 0; j < n_padding_types; j++) {
            if(!test_round_trip(libctx, cipher_name, padding_type[j])) {
                printf("FAILED: test_round_trip(%s, %s)\n", cipher_name, padding_type[j]);
                rc = 1;
            } else {
                printf("PASSED: test_round_trip(%s, %s)\n", cipher_name, padding_type[j]);
            }
        }
        cipher_name = cipher_type[idx++];
    }

    return rc;
}
