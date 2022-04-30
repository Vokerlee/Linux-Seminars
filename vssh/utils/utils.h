#ifndef NET_UTILS_H_
#define NET_UTILS_H_

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sysexits.h>
#include <err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

off_t get_file_size(int file_fd);

int public_encrypt_RSA           (const unsigned char *data,           int data_len, unsigned char *encrypted_data, const unsigned char *key);
int private_encrypt_RSA          (const unsigned char *data,           int data_len, unsigned char *encrypted_data, const unsigned char *key);
int public_decrypt_RSA           (const unsigned char *encrypted_data, int data_len, unsigned char *decrypted_data, const unsigned char *key);
int private_decrypt_RSA          (const unsigned char *encrypted_data, int data_len, unsigned char *decrypted_data, const unsigned char *key);
int public_encrypt_RSA_filename  (const unsigned char *data,           int data_len, unsigned char *encrypted_data, const char *key_filename);
int private_encrypt_RSA_filename (const unsigned char *data,           int data_len, unsigned char *encrypted_data, const char *key_filename);
int public_decrypt_RSA_filename  (const unsigned char *encrypted_data, int data_len, unsigned char *decrypted_data, const char *key_filename);
int private_decrypt_RSA_filename (const unsigned char *encrypted_data, int data_len, unsigned char *decrypted_data, const char *key_filename);

#endif // !NET_UTILS_H_
