#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

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
