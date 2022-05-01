#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <syslog.h>

static RSA *create_RSA_filename(const char *filename, int is_public)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL)
        return NULL;

    RSA *rsa = RSA_new();
 
    if (is_public)
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    else
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);

    fclose(fp);
 
    return rsa;
}

static RSA *create_RSA(const unsigned char *key, int is_public)
{
    RSA *rsa = NULL;
    BIO *keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
        return NULL;

    if (is_public)
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    else
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
 
    return rsa;
}
 
int public_encrypt_RSA(const unsigned char *data, int data_len, unsigned char *encrypted_data, const unsigned char *key)
{
    RSA *rsa = create_RSA(key, 1);
    if (rsa == NULL)
        return -1;

    return RSA_public_encrypt(data_len, data, encrypted_data, rsa, RSA_PKCS1_PADDING);
}

int private_encrypt_RSA(const unsigned char *data, int data_len, unsigned char *encrypted_data, const unsigned char *key)
{
    RSA *rsa = create_RSA(key, 0);
    if (rsa == NULL)
        return -1;

    return RSA_private_encrypt(data_len, data, encrypted_data, rsa, RSA_PKCS1_PADDING);
}

int public_decrypt_RSA(const unsigned char *encrypted_data, int data_len, unsigned char *decrypted_data, const unsigned char *key)
{
    RSA *rsa = create_RSA(key, 1);
    if (rsa == NULL)
        return -1;

    return RSA_public_decrypt(data_len, encrypted_data, decrypted_data, rsa, RSA_PKCS1_PADDING);
}

int private_decrypt_RSA(const unsigned char *encrypted_data, int data_len, unsigned char *decrypted_data, const unsigned char *key)
{
    RSA *rsa = create_RSA(key, 0);
    if (rsa == NULL)
        return -1;

    return RSA_private_decrypt(data_len, encrypted_data, decrypted_data, rsa, RSA_PKCS1_PADDING);
}

int public_encrypt_RSA_filename(const unsigned char *data, int data_len, unsigned char *encrypted_data, const char *key_filename)
{
    RSA *rsa = create_RSA_filename(key_filename, 1);
    if (rsa == NULL)
        return -1;

    return RSA_public_encrypt(data_len, data, encrypted_data, rsa, RSA_PKCS1_PADDING);
}

int private_encrypt_RSA_filename(const unsigned char *data, int data_len, unsigned char *encrypted_data, const char *key_filename)
{
    RSA *rsa = create_RSA_filename(key_filename, 0);
    if (rsa == NULL)
        return -1;

    return RSA_private_encrypt(data_len, data, encrypted_data, rsa, RSA_PKCS1_PADDING);
}

int public_decrypt_RSA_filename(const unsigned char *encrypted_data, int data_len, unsigned char *decrypted_data, const char *key_filename)
{
    RSA *rsa = create_RSA_filename(key_filename, 1);
    if (rsa == NULL)
        return -1;

    return RSA_public_decrypt(data_len, encrypted_data, decrypted_data, rsa, RSA_PKCS1_PADDING);
}

int private_decrypt_RSA_filename(const unsigned char *encrypted_data, int data_len, unsigned char *decrypted_data, const char *key_filename)
{
    RSA *rsa = create_RSA_filename(key_filename, 0);
    if (rsa == NULL)
        return -1;

    return RSA_private_decrypt(data_len, encrypted_data, decrypted_data, rsa, RSA_PKCS1_PADDING);
}

int encrypt_AES(const unsigned char *data, int data_len, unsigned char *encrypted_data, const unsigned char *key)
{
    int len = 0;
    int encrypted_data_len = 0;
    const unsigned char iv[] = "abdkdzZKnuih78n&";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return -1;

    if (EVP_EncryptUpdate(ctx, encrypted_data, &len, data, data_len) != 1)
        return -1;

    encrypted_data_len = len;

    if (EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len) != 1)
        return -1;
    
    encrypted_data_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return encrypted_data_len;
}

int decrypt_AES(const unsigned char *encrypted_data, int encrypted_data_len, unsigned char *data, const unsigned char *key)
{
    int len = 0;
    int data_len = 0;
    const unsigned char iv[] = "abdkdzZKnuih78n&";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        return -1;

    if (EVP_DecryptUpdate(ctx, data, &len, encrypted_data, encrypted_data_len) != 1)
        return -1;

    data_len = len;

    if (EVP_DecryptFinal_ex(ctx, data + len, &len) != 1)
        return -1;

    data_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return data_len;
}

