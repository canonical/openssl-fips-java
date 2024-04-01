#include <openssl/evp.h>
#include <openssl/types.h>
#include <jssl.h>

#define DECRYPT 0
#define ENCRYPT 1 

typedef struct cipher_context {
    const char *name;
    EVP_CIPHER_CTX *context;
    EVP_CIPHER* cipher;
    int mode;
    int padding;
} cipher_context;

cipher_context* create_cipher_context(OSSL_LIB_CTX *libctx, const char *name, const char *padding_name);

void cipher_init(cipher_context * ctx, byte in[], int in_len, unsigned char *key, unsigned char *iv, int iv_len, int mode);

void cipher_update(cipher_context *ctx, byte out[], int *out_len_ptr, byte in[], int in_len);

void cipher_do_final(cipher_context *ctx, byte *out, int *out_len_ptr);

void free_cipher(cipher_context *ctx);
