#include "utils.h"
#include "ipv4_net.h"
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/aes.h>

int ipv4_socket(int type, int optname)
{
    if (type == SOCK_STREAM_UDT)
        type = SOCK_DGRAM;

    int socket_fd = socket(AF_INET, type, 0);

    if (optname != 0 && socket_fd != -1)
    {
        int optval = 1;
        int setsockopt_error = setsockopt(socket_fd, SOL_SOCKET, optname, &optval, sizeof(optval));
        if (setsockopt_error == -1)
            return -1;
    }

    return socket_fd;
}

int ipv4_connect(int socket_fd, in_addr_t dest_ip, in_port_t dest_port, int connection_type)
{
    struct sockaddr_in dest_addr = {0};
    socklen_t length = sizeof(struct sockaddr_in);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = dest_port;
    dest_addr.sin_addr.s_addr = dest_ip;

    int connect_state = 0;

    // Connection
    if (connection_type == SOCK_STREAM || connection_type == SOCK_DGRAM)
        connect_state = connect(socket_fd, (struct sockaddr *) &dest_addr, length);
    else if (connection_type == SOCK_STREAM_UDT)
        connect_state = udt_connect(socket_fd, (struct sockaddr *) &dest_addr, length);
    else
        return -1;

    return connect_state;
}

int ipv4_bind(int socket_fd, in_addr_t ip, in_port_t port, int connection_type, void *(*udt_server_handler)(void *))
{
    struct sockaddr_in addr = {0};
    socklen_t length = sizeof(struct sockaddr_in);

    addr.sin_family = AF_INET;
    addr.sin_port = port;
    addr.sin_addr.s_addr = ip;

    int bind_state = 0;

    if (connection_type == SOCK_STREAM || connection_type == SOCK_DGRAM)
        bind_state = bind(socket_fd, (struct sockaddr *) &addr, length);
    else if (connection_type == SOCK_STREAM_UDT)
    {
        if (udt_server_handler != NULL)
            udt_set_server_handler(udt_server_handler);

        bind_state = udt_bind(socket_fd, (struct sockaddr *) &addr, length);
    }	
    else
        return -1;

    return bind_state;
}

int ipv4_listen(int socket_fd)
{
    return listen(socket_fd, TCP_N_MAX_PENDING_CONNECTIONS);
}

int ipv4_accept(int socket_fd, struct sockaddr *addr, socklen_t *length)
{
    return accept(socket_fd, addr, length);
}

int ipv4_close(int socket_fd, int connection_type)
{
    if (connection_type == SOCK_STREAM_UDT)
        return udt_close(socket_fd);
    else
    {
        int ctl_msg_state = ipv4_send_ctl_message(socket_fd, IPV4_SHUTDOWN_TYPE, 0, NULL, 0, NULL, 0, NULL, 0, SOCK_STREAM);
        if (ctl_msg_state == -1)
        {
            close(socket_fd);
            return -1;
        }

        return close(socket_fd);
    }
}

// Standart API

int ipv4_send_ctl_message(int socket_fd, uint64_t msg_type, uint64_t msg_length, 
                          uint32_t *spare_fields, size_t spare_fields_size, char *spare_buffer1, size_t spare_buffer_size1,
                          char *spare_buffer2, size_t spare_buffer_size2, int connection_type)
{
    if (spare_fields != NULL && spare_fields_size > IPV4_SPARE_FIELDS)
        return -1;

    if (spare_buffer1 != NULL && spare_buffer_size1 > IPV4_SPARE_BUFFER_LENGTH)
        return -1;

    if (spare_buffer2 != NULL && spare_buffer_size2 > IPV4_SPARE_BUFFER_LENGTH)
        return -1;

    ipv4_ctl_message message = {.message_type = msg_type, .message_length = msg_length};

    if (spare_fields  != NULL)
        memcpy(message.spare_fields, spare_fields, spare_fields_size * sizeof(spare_fields[0]));
    if (spare_buffer1 != NULL)
        memcpy(message.spare_buffer1, spare_buffer1, spare_buffer_size1 * sizeof(spare_buffer1[0]));
    if (spare_buffer2 != NULL)
        memcpy(message.spare_buffer2, spare_buffer2, spare_buffer_size2 * sizeof(spare_buffer2[0]));

    if (connection_type == SOCK_STREAM || connection_type == SOCK_DGRAM)
        return send(socket_fd, &message, sizeof(ipv4_ctl_message), 0);
    else if (connection_type == SOCK_STREAM_UDT)
        return udt_send(socket_fd, (char *) &message, sizeof(ipv4_ctl_message));
    else
        return -1;
}

ssize_t ipv4_send_message(int socket_fd, const void *buffer, size_t n_bytes, int connection_type)
{
    if (buffer == NULL)
        return -1;

    int ctl_msg_state = ipv4_send_ctl_message(socket_fd, IPV4_MSG_HEADER_TYPE, n_bytes, NULL, 0, NULL, 0, NULL, 0, connection_type);
    if (ctl_msg_state == -1)
        return -1;

    if (connection_type == SOCK_STREAM || connection_type == SOCK_DGRAM)
        return send(socket_fd, buffer, n_bytes, 0);
    else if (connection_type == SOCK_STREAM_UDT)
        return udt_send(socket_fd, buffer, n_bytes);
    else
        return -1;
}

ssize_t ipv4_receive_message(int socket_fd, void *buffer, size_t n_bytes, int connection_type)
{
    if (buffer == NULL)
        return -1;

    if (connection_type == SOCK_STREAM || connection_type == SOCK_DGRAM)
        return read(socket_fd, buffer, n_bytes);
    else if (connection_type == SOCK_STREAM_UDT)
        return udt_recv(socket_fd, buffer, n_bytes);
    else
        return -1;
}

ssize_t ipv4_send_buffer(int socket_fd, const void *buffer, size_t n_bytes, int msg_type,
                         uint32_t *spare_fields, size_t spare_fields_size, char *spare_buffer1, size_t spare_buffer_size1,
                         char *spare_buffer2, size_t spare_buffer_size2, int connection_type)
{
    if (buffer == NULL)
        return -1;

    if (connection_type != SOCK_STREAM && connection_type != SOCK_DGRAM && connection_type != SOCK_STREAM_UDT)
        return -1;

    if (msg_type == -1)
        msg_type = IPV4_BUF_HEADER_TYPE;

    int ctl_msg_state = ipv4_send_ctl_message(socket_fd, msg_type, n_bytes, spare_fields, spare_fields_size, 
                                              spare_buffer1, spare_buffer_size1, spare_buffer2, spare_buffer_size2, connection_type);
    if (ctl_msg_state == -1)
        return -1;

    ssize_t n_sent_bytes = 0;
    size_t n_iters = n_bytes / PACKET_DATA_SIZE;
    size_t n_remaining_bytes = n_bytes % PACKET_DATA_SIZE;
    
    const char *cur_pos = buffer;

    for (size_t i = 0; i < n_iters; ++i)
    {
        ssize_t n_bytes = 0;
        if (connection_type == SOCK_STREAM_UDT)
            n_bytes = udt_send(socket_fd, cur_pos, PACKET_DATA_SIZE);
        else
            n_bytes = send(socket_fd, cur_pos, PACKET_DATA_SIZE, 0);

        if (n_bytes <= 0)
            return -1;

        n_sent_bytes += n_bytes;
        cur_pos      += n_bytes;
    }

    if (n_remaining_bytes > 0)
    {
        ssize_t n_bytes = 0;
        if (connection_type == SOCK_STREAM_UDT)
            n_bytes = udt_send(socket_fd, cur_pos, n_remaining_bytes);
        else
            n_bytes = send(socket_fd, cur_pos, n_remaining_bytes, 0);

        if (n_bytes <= 0)
            return -1;

        n_sent_bytes += n_bytes;
    }

    return n_sent_bytes;
}

ssize_t ipv4_receive_buffer(int socket_fd, void *buffer, size_t n_bytes, int connection_type)
{
    if (buffer == NULL)
        return -1;

    if (connection_type != SOCK_STREAM && connection_type != SOCK_DGRAM && connection_type != SOCK_STREAM_UDT)
        return -1;

    ssize_t n_recv_bytes = 0;
    size_t n_iters = n_bytes / PACKET_DATA_SIZE;
    size_t n_remaining_bytes = n_bytes % PACKET_DATA_SIZE;

    char *cur_pos = buffer;

    for (size_t i = 0; i < n_iters; ++i)
    {
        ssize_t n_bytes = 0;
        if (connection_type == SOCK_STREAM_UDT)
            n_bytes = udt_recv(socket_fd, cur_pos, PACKET_DATA_SIZE);
        else
            n_bytes = read(socket_fd, cur_pos, PACKET_DATA_SIZE);

        if (n_bytes <= 0)
            return -1;

        n_recv_bytes += n_bytes;
        cur_pos      += n_bytes;
    }

    if (n_remaining_bytes > 0)
    {
        ssize_t n_bytes = 0;
        if (connection_type == SOCK_STREAM_UDT)
            n_bytes = udt_recv(socket_fd, cur_pos, n_remaining_bytes);
        else
            n_bytes = read(socket_fd, cur_pos, n_remaining_bytes);

        if (n_bytes <= 0)
            return -1;

        n_recv_bytes += n_bytes;
    }

    return n_recv_bytes;
}

ssize_t ipv4_send_file(int socket_fd, int file_fd, uint32_t *spare_fields, size_t spare_fields_size, 
                       char *spare_buffer1, size_t spare_buffer_size1, char *spare_buffer2, size_t spare_buffer_size2, int connection_type)
{
    off_t file_size = get_file_size(file_fd);

    char *buffer = malloc(file_size + 1);
    if (buffer == NULL)
        return -1;

    buffer[file_size + 1] = 0;

    ssize_t read_error = read(file_fd, buffer, file_size);
    if (read_error == -1)
        return -1;

    ssize_t sent_bytes = ipv4_send_buffer(socket_fd, buffer, file_size, IPV4_FILE_HEADER_TYPE, spare_fields, spare_fields_size,
                                          spare_buffer1, spare_buffer_size1, spare_buffer2, spare_buffer_size2, connection_type);
    if (sent_bytes == -1)
        return -1;

    free(buffer);

    return sent_bytes;
}

ssize_t ipv4_receive_file(int socket_fd, int file_fd, size_t n_bytes, int connection_type)
{
    char *buffer = malloc(n_bytes + 1);
    if (buffer == NULL)
        return -1;

    buffer[n_bytes + 1] = 0;

    ssize_t sent_bytes = ipv4_receive_buffer(socket_fd, buffer, n_bytes, connection_type);
    if (sent_bytes == -1)
        return -1;

    ssize_t read_error = write(file_fd, buffer, n_bytes);
    if (read_error == -1)
        return -1;

    free(buffer);

    return sent_bytes;
}

// Secured API

int ipv4_send_ctl_message_secure(int socket_fd, uint64_t msg_type, uint64_t msg_length, 
                                 uint32_t *spare_fields, size_t spare_fields_size, char *spare_buffer1, size_t spare_buffer_size1,
                                 char *spare_buffer2, size_t spare_buffer_size2, int connection_type, unsigned char *key)
{
    if (spare_fields != NULL && spare_fields_size > IPV4_SPARE_FIELDS)
        return -1;

    if (spare_buffer1 != NULL && spare_buffer_size1 > IPV4_SPARE_BUFFER_LENGTH)
        return -1;

    if (spare_buffer2 != NULL && spare_buffer_size2 > IPV4_SPARE_BUFFER_LENGTH)
        return -1;

    ipv4_ctl_message message = {.message_type = msg_type, .message_length = msg_length};

    if (spare_fields  != NULL)
        memcpy(message.spare_fields, spare_fields, spare_fields_size * sizeof(spare_fields[0]));
    if (spare_buffer1 != NULL)
        memcpy(message.spare_buffer1, spare_buffer1, spare_buffer_size1 * sizeof(spare_buffer1[0]));
    if (spare_buffer2 != NULL)
        memcpy(message.spare_buffer2, spare_buffer2, spare_buffer_size2 * sizeof(spare_buffer2[0]));

    unsigned char encrypted_message[sizeof(ipv4_ctl_message) + AES_BLOCK_SIZE];
    int ciphertext_len = encrypt_AES((unsigned char *) &message, sizeof(ipv4_ctl_message), encrypted_message, key);

    if (connection_type == SOCK_STREAM || connection_type == SOCK_DGRAM)
        return send(socket_fd, encrypted_message, ciphertext_len, 0);
    else if (connection_type == SOCK_STREAM_UDT)
        return udt_send(socket_fd, (char *) encrypted_message, ciphertext_len);
    else
        return -1;
}

ssize_t ipv4_send_message_secure(int socket_fd, const void *buffer, size_t n_bytes, int connection_type, unsigned char *key)
{
    if (buffer == NULL)
        return -1;

    int ctl_msg_state = ipv4_send_ctl_message_secure(socket_fd, IPV4_MSG_HEADER_TYPE, n_bytes, NULL, 0, NULL, 0, NULL, 0, connection_type, key);
    if (ctl_msg_state == -1)
        return -1;

    unsigned char *encrypted_buffer = malloc(n_bytes + AES_BLOCK_SIZE);
    if (encrypted_buffer == NULL)
        return -1;

    int ciphertext_len = encrypt_AES(buffer, n_bytes, encrypted_buffer, key);

    ssize_t send_state = -1;
    if (connection_type == SOCK_STREAM || connection_type == SOCK_DGRAM)
        send_state = send(socket_fd, encrypted_buffer, ciphertext_len, 0);
    else if (connection_type == SOCK_STREAM_UDT)
        send_state = udt_send(socket_fd, (char *) encrypted_buffer, ciphertext_len);
    else
    {
        free(encrypted_buffer);
        return -1;
    }

    free(encrypted_buffer);

    return send_state;
}

ssize_t ipv4_receive_message_secure(int socket_fd, void *buffer, size_t n_bytes, int connection_type, unsigned char *key)
{
    if (buffer == NULL)
        return -1;

    ssize_t n_encrypted_bytes_rem = n_bytes % AES_BLOCK_SIZE;
    ssize_t n_encrypted_bytes = n_bytes - n_encrypted_bytes_rem + AES_BLOCK_SIZE;

    unsigned char *encrypted_buffer = malloc(n_encrypted_bytes);
    if (encrypted_buffer == NULL)
        return -1;

    unsigned char *decrypted_buffer = malloc(n_encrypted_bytes);
    if (decrypted_buffer == NULL)
        return -1;

    ssize_t read_state = -1;
    if (connection_type == SOCK_STREAM || connection_type == SOCK_DGRAM)
        read_state = read(socket_fd, encrypted_buffer, n_encrypted_bytes);
    else if (connection_type == SOCK_STREAM_UDT)
        read_state = udt_recv(socket_fd, (char *) encrypted_buffer, n_encrypted_bytes);
    else
    {
        free(encrypted_buffer);
        free(decrypted_buffer);
        return -1;
    }
        
    if (read_state == -1)
        return -1;

    int decryptedtext_len = decrypt_AES(encrypted_buffer, n_encrypted_bytes, decrypted_buffer, key);
    memcpy(buffer, decrypted_buffer, n_bytes);
    
    free(encrypted_buffer);
    free(decrypted_buffer);

    return decryptedtext_len;
}

int ipv4_close_secure(int socket_fd, int connection_type, unsigned char *key)
{
    if (connection_type == SOCK_STREAM_UDT)
        return udt_close(socket_fd);
    else
    {
        int ctl_msg_state = ipv4_send_ctl_message_secure(socket_fd, IPV4_SHUTDOWN_TYPE, 0, NULL, 0, NULL, 0, NULL, 0, SOCK_STREAM, key);
        if (ctl_msg_state == -1)
        {
            close(socket_fd);
            return -1;
        }

        return close(socket_fd);
    }
}

ssize_t ipv4_send_buffer_secure(int socket_fd, const void *buffer, size_t n_bytes, int msg_type,
                                uint32_t *spare_fields, size_t spare_fields_size, char *spare_buffer1, size_t spare_buffer_size1,
                                char *spare_buffer2, size_t spare_buffer_size2, int connection_type, unsigned char *key)
{
    if (buffer == NULL)
        return -1;

    if (connection_type != SOCK_STREAM && connection_type != SOCK_DGRAM && connection_type != SOCK_STREAM_UDT)
        return -1;

    if (msg_type == -1)
        msg_type = IPV4_BUF_HEADER_TYPE;

    int ctl_msg_state = ipv4_send_ctl_message_secure(socket_fd, msg_type, n_bytes, spare_fields, spare_fields_size, 
                                                     spare_buffer1, spare_buffer_size1, spare_buffer2, spare_buffer_size2, connection_type, key);
    if (ctl_msg_state == -1)
        return -1;

    ssize_t n_sent_bytes = 0;
    size_t n_iters = n_bytes / (PACKET_DATA_SIZE - AES_BLOCK_SIZE);
    size_t n_remaining_bytes = n_bytes % (PACKET_DATA_SIZE - AES_BLOCK_SIZE);
    
    const unsigned char *cur_pos = buffer;
    unsigned char encrypted_buffer[PACKET_DATA_SIZE];

    for (size_t i = 0; i < n_iters; ++i)
    {
        int ciphertext_len = encrypt_AES(cur_pos, PACKET_DATA_SIZE - AES_BLOCK_SIZE, encrypted_buffer, key);

        ssize_t n_bytes = 0;
        if (connection_type == SOCK_STREAM_UDT)
            n_bytes = udt_send(socket_fd, (char *) encrypted_buffer, ciphertext_len);
        else
            n_bytes = send(socket_fd, encrypted_buffer, ciphertext_len, 0);

        if (n_bytes <= 0)
            return -1;

        n_sent_bytes += PACKET_DATA_SIZE - AES_BLOCK_SIZE;
        cur_pos      += PACKET_DATA_SIZE - AES_BLOCK_SIZE;
    }

    if (n_remaining_bytes > 0)
    {
        int ciphertext_len = encrypt_AES(cur_pos, n_remaining_bytes, encrypted_buffer, key);

        ssize_t n_bytes = 0;
        if (connection_type == SOCK_STREAM_UDT)
            n_bytes = udt_send(socket_fd, (char *) encrypted_buffer, ciphertext_len);
        else
            n_bytes = send(socket_fd, encrypted_buffer, ciphertext_len, 0);

        if (n_bytes <= 0)
            return -1;

        n_sent_bytes += n_remaining_bytes;
    }

    return n_sent_bytes;
}

ssize_t ipv4_receive_buffer_secure(int socket_fd, void *buffer, size_t n_bytes, int connection_type, unsigned char *key)
{
    if (buffer == NULL)
        return -1;

    if (connection_type != SOCK_STREAM && connection_type != SOCK_DGRAM && connection_type != SOCK_STREAM_UDT)
        return -1;

    ssize_t n_recv_bytes = 0;
    size_t n_iters = n_bytes / (PACKET_DATA_SIZE - AES_BLOCK_SIZE);
    size_t n_remaining_bytes = n_bytes % (PACKET_DATA_SIZE - AES_BLOCK_SIZE);

    char unsigned *cur_pos = buffer;
    unsigned char encrypted_buffer[PACKET_DATA_SIZE];
    unsigned char decrypted_buffer[PACKET_DATA_SIZE];

    ssize_t n_encrypted_bytes_rem = (PACKET_DATA_SIZE - AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
    ssize_t n_encrypted_bytes = PACKET_DATA_SIZE - n_encrypted_bytes_rem;

    ssize_t n_last_encrypted_bytes_rem = n_remaining_bytes % AES_BLOCK_SIZE;
    ssize_t n_last_encrypted_bytes =  n_remaining_bytes - n_last_encrypted_bytes_rem + AES_BLOCK_SIZE;

    for (size_t i = 0; i < n_iters; ++i)
    {
        ssize_t n_bytes = 0;
        if (connection_type == SOCK_STREAM_UDT)
            n_bytes = udt_recv(socket_fd, (char *) encrypted_buffer, n_encrypted_bytes);
        else
            n_bytes = read(socket_fd, encrypted_buffer, n_encrypted_bytes);

        if (n_bytes <= 0)
            return -1;

        int encryptedtext_len = decrypt_AES(encrypted_buffer, n_encrypted_bytes, decrypted_buffer, key);
        if (encryptedtext_len == -1)
        {
            syslog(LOG_ERR, "decrypt error");
            return -1;
        }

        memcpy(cur_pos, decrypted_buffer, PACKET_DATA_SIZE - AES_BLOCK_SIZE);

        n_recv_bytes += PACKET_DATA_SIZE - AES_BLOCK_SIZE;
        cur_pos      += PACKET_DATA_SIZE - AES_BLOCK_SIZE;
    }

    if (n_remaining_bytes > 0)
    {
        ssize_t n_bytes = 0;
        if (connection_type == SOCK_STREAM_UDT)
            n_bytes = udt_recv(socket_fd, (char *) encrypted_buffer, n_last_encrypted_bytes);
        else
            n_bytes = read(socket_fd, encrypted_buffer, n_last_encrypted_bytes);

        if (n_bytes <= 0)
            return -1;

        int encryptedtext_len = decrypt_AES(encrypted_buffer, n_last_encrypted_bytes, decrypted_buffer, key);
        if (encryptedtext_len == -1)
        {
            syslog(LOG_ERR, "decrypt error");
            return -1;
        }

        memcpy(cur_pos, decrypted_buffer, n_remaining_bytes);

        n_recv_bytes += n_remaining_bytes;
    }

    return n_recv_bytes;
}


ssize_t ipv4_execute_DH_protocol(int socket_fd, unsigned char *secret, int is_initiator, const char *rsa_key_path, int connection_type)
{
    if (secret == NULL)
        return -1;
    
    DH *dh_struct = DH_new();
    if (dh_struct == NULL)
        return -1;

    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *q = NULL;
    unsigned char p_buffer[IPV4_SPARE_BUFFER_LENGTH] = {0};
    unsigned char g_buffer[IPV4_SPARE_BUFFER_LENGTH] = {0};
    unsigned char p_buffer_encrypted[IPV4_SPARE_BUFFER_LENGTH] = {0};
    unsigned char g_buffer_encrypted[IPV4_SPARE_BUFFER_LENGTH] = {0};

    ipv4_ctl_message ctl_message;

    if (is_initiator == 0)
    {
        ssize_t recv_bytes = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ctl_message), connection_type);
        if (recv_bytes == -1 || recv_bytes == 0)
            return -1;

        private_decrypt_RSA_filename((unsigned char *) ctl_message.spare_buffer1, ctl_message.spare_fields[2], p_buffer, rsa_key_path);
        private_decrypt_RSA_filename((unsigned char *) ctl_message.spare_buffer2, ctl_message.spare_fields[3], g_buffer, rsa_key_path);

        p = BN_bin2bn(p_buffer, ctl_message.spare_fields[0], NULL);
        g = BN_bin2bn(g_buffer, ctl_message.spare_fields[1], NULL);

        if (p == NULL || g == NULL)
            return -1;

        DH_set0_pqg(dh_struct, p, NULL, g);
    }
    else
    {
        if (DH_generate_parameters_ex(dh_struct, 1024, DH_GENERATOR_2, NULL) != 1)
            return -1;

        int codes = -1;
        if (DH_check(dh_struct, &codes) != 1)
            return -1;

        if (codes != 0)
            return -1;

        DH_get0_pqg(dh_struct, (const BIGNUM **) &p, (const BIGNUM **) &q, (const BIGNUM **) &g);

        BN_bn2bin(p, p_buffer);
        BN_bn2bin(g, g_buffer);

        uint32_t pg_sizes[4] = {BN_num_bytes(p), BN_num_bytes(g)};

        pg_sizes[2] = public_encrypt_RSA_filename(p_buffer, pg_sizes[0], p_buffer_encrypted, rsa_key_path);
        pg_sizes[3] = public_encrypt_RSA_filename(g_buffer, pg_sizes[1], g_buffer_encrypted, rsa_key_path);

        int ctl_msg_state = ipv4_send_ctl_message(socket_fd, IPV4_ENCRYPTION_PG_NUM_TYPE, 0, pg_sizes, 4,
                                                  (char *) p_buffer_encrypted, pg_sizes[2],
                                                  (char *) g_buffer_encrypted, pg_sizes[3], connection_type);
        if (ctl_msg_state == -1)
            return -1;
    }

    // Now both sides know p and g values

    if (DH_generate_key(dh_struct) != 1) // generate private & public keys
        return -1;

    const BIGNUM *public_key = DH_get0_pub_key(dh_struct);
    if (public_key == NULL)
        return -1;

    unsigned char public_key_buffer[IPV4_SPARE_BUFFER_LENGTH] = {0};
    unsigned char public_key_buffer_encrypted[IPV4_SPARE_BUFFER_LENGTH] = {0};


    BN_bn2bin(public_key, public_key_buffer);

    // Exchange public keys

    int decrypted_size = -1;

    if (is_initiator == 0)
    {
        uint32_t public_key_size = private_encrypt_RSA_filename(public_key_buffer, BN_num_bytes(public_key), public_key_buffer_encrypted, rsa_key_path);

        int ctl_msg_state = ipv4_send_ctl_message(socket_fd, IPV4_ENCRYPTION_PUBKEY_TYPE, 0, &public_key_size, 1,
                                                  (char *) public_key_buffer_encrypted, public_key_size, NULL, 0, connection_type);
        if (ctl_msg_state == -1)
            return -1;

        ssize_t recv_bytes = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ctl_message), connection_type);
        if (recv_bytes == -1 || recv_bytes == 0)
            return -1;

        decrypted_size = private_decrypt_RSA_filename((unsigned char *) ctl_message.spare_buffer1, ctl_message.spare_fields[0], public_key_buffer, rsa_key_path);
    }
    else
    {
        uint32_t public_key_size = public_encrypt_RSA_filename(public_key_buffer, BN_num_bytes(public_key), public_key_buffer_encrypted, rsa_key_path);

        ssize_t recv_bytes = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ctl_message), connection_type);
        if (recv_bytes == -1 || recv_bytes == 0)
            return -1;

        int ctl_msg_state = ipv4_send_ctl_message(socket_fd, IPV4_ENCRYPTION_PUBKEY_TYPE, 0, &public_key_size, 1,
                                                  (char *) public_key_buffer_encrypted, public_key_size, NULL, 0, connection_type);
        if (ctl_msg_state == -1)
            return -1;

        decrypted_size = public_decrypt_RSA_filename((unsigned char *) ctl_message.spare_buffer1, ctl_message.spare_fields[0], public_key_buffer, rsa_key_path);
    }

    BIGNUM *alien_public_key = BN_bin2bn(public_key_buffer, decrypted_size, NULL);
    if (alien_public_key == NULL)
        return -1;

    int secret_size = DH_compute_key(secret, alien_public_key, dh_struct);

    DH_free(dh_struct);
    BN_free(alien_public_key);

    return secret_size;
}
