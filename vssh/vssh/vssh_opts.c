#include "vssh.h"

#include <stdlib.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/aes.h>

extern struct termios DEFAULT_TERM;

static int SOCKET_FD = -1;
static int CONNECTION_TYPE = -1;
static pthread_t SENDER_THREAD;
static unsigned char *KEY = NULL;

extern const char *VSSH_RSA_PRIVATE_KEY_PATH;

static void *vssh_shell_receiver(void *arg);

int vssh_send_message(in_addr_t dest_ip, const char *message, size_t len, int connection_type)
{
    int socket_type = connection_type;
    if (socket_type == SOCK_STREAM_UDT)
        socket_type = SOCK_DGRAM;

    int socket_fd = ipv4_socket(socket_type, SO_REUSEADDR);
    if (socket_fd == -1)
    {
        fprintf(stderr, "ipv4_socket() couldn't create socket\n");
        return -1;
    }

    int connnection_state = ipv4_connect(socket_fd, dest_ip, htons(SSH_SERVER_PORT), connection_type);
    if (connnection_state == -1)
    {
        fprintf(stderr, "ipv4_connect() couldn't connect\n");
        close(socket_fd);
        return -1;
    }
    
    unsigned char secret[IPV4_SPARE_BUFFER_LENGTH] = {0};
    int secret_size = ipv4_execute_DH_protocol(socket_fd, secret, 0, VSSH_RSA_PRIVATE_KEY_PATH, connection_type);
    if (secret_size <= 0)
    {
        close(socket_fd);
        return -1;
    }

    size_t bytes_to_send = len > PACKET_DATA_SIZE ? PACKET_DATA_SIZE: len;

    ssize_t sent_bytes = ipv4_send_message_secure(socket_fd, message, bytes_to_send, connection_type, secret);
    if (sent_bytes == -1 || sent_bytes == 0)
    {
        ipv4_close_secure(socket_fd, connection_type, secret);
        return -1;
    }

    return ipv4_close_secure(socket_fd, connection_type, secret);
}

int vssh_shell_request(in_addr_t dest_ip, int connection_type, char *username)
{
    int socket_type = connection_type;
    if (socket_type == SOCK_STREAM_UDT)
        socket_type = SOCK_DGRAM;

    ssize_t username_length = strlen(username);
    if (username_length > IPV4_SPARE_BUFFER_LENGTH)
    {
        fprintf(stderr, "too many symbols in username: is can be no more than 256 symbols\n");
        return -1;
    }

    struct termios term;
    if (tcgetattr(STDIN_FILENO, &term) == -1)
    {
        perror("tcgetattr()");
        return -1;
    }

    cfmakeraw(&term);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &term) == -1)
    {
        perror("tcsetattr()");
        return -1;
    }

    int socket_fd = ipv4_socket(socket_type, SO_REUSEADDR);
    if (socket_fd == -1)
    {
        fprintf(stderr, "ipv4_socket() couldn't create socket\n");
        return -1;
    }

    int connnection_state = ipv4_connect(socket_fd, dest_ip, htons(SSH_SERVER_PORT), connection_type);
    if (connnection_state == -1)
    {
        fprintf(stderr, "ipv4_connect() couldn't connect\n");
        close(socket_fd);
        return -1;
    }

    unsigned char secret[IPV4_SPARE_BUFFER_LENGTH] = {0};
    int secret_size = ipv4_execute_DH_protocol(socket_fd, secret, 0, VSSH_RSA_PRIVATE_KEY_PATH, connection_type);
    if (secret_size <= 0)
    {
        close(socket_fd);
        return -1;
    }

    int ctl_msg_state = ipv4_send_ctl_message_secure(socket_fd, IPV4_SHELL_REQUEST_TYPE, 0, NULL, 0, username, username_length, NULL, 0, connection_type, secret);
    if (ctl_msg_state == -1)
    {
        fprintf(stderr, "ipv4_send_ctl_message_secure() couldn't send message\n");
        ipv4_close(socket_fd, connection_type);
        return -1;
    }

    CONNECTION_TYPE = connection_type;
    SOCKET_FD       = socket_fd;
    SENDER_THREAD   = pthread_self();
    KEY             = secret;
    
    int old_type = 0;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);
    pthread_detach(SENDER_THREAD);

    char buffer[BUFSIZ + 1] = {0};

    pthread_t recv_thread;
    int recv_pthread_error = pthread_create(&recv_thread, NULL, vssh_shell_receiver, NULL);
    if (recv_pthread_error == -1)
    {
        fprintf(stderr, "pthread_create() couldn't control message : %s\n", strerror(errno));
        return -1;
    }

    pthread_detach(recv_thread);

    while (1)
    {
        ssize_t read_cmd_bytes = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (read_cmd_bytes == -1)
        {
            perror("read() error");
            ipv4_close(socket_fd, connection_type);
            return -1;
        }

        size_t bytes_to_send = read_cmd_bytes > (PACKET_DATA_SIZE - AES_BLOCK_SIZE) ? (PACKET_DATA_SIZE - AES_BLOCK_SIZE) : read_cmd_bytes;

        ssize_t sent_bytes = ipv4_send_message_secure(socket_fd, buffer, bytes_to_send, connection_type, secret);
        if (sent_bytes == -1 || sent_bytes == 0)
        {
            fprintf(stderr, "ipv4_send_message() couldn't sent message\n");
            ipv4_close(socket_fd, connection_type);
            return -1;
        }

        memset(buffer, 0, read_cmd_bytes + 1);
    }

    pthread_cancel(recv_thread);

    return ipv4_close_secure(socket_fd, connection_type, secret);
}

static void *vssh_shell_receiver(void *arg)
{
    int old_type = 0;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);

    char buffer[PACKET_DATA_SIZE + 1] = {0};
    ipv4_ctl_message ctl_message = {0};
    char cancel_sign = 0x18;

    fprintf(stderr, "\033[0;37m"); // gray

    while (1)
    {
        ssize_t recv_bytes_ctl = ipv4_receive_message_secure(SOCKET_FD, &ctl_message, sizeof(ipv4_ctl_message), CONNECTION_TYPE, KEY);
        if (recv_bytes_ctl == -1)
        {
            fprintf(stderr, "ipv4_receive_message_secure() couldn't receive message\n");
            pthread_exit(NULL);
        }

        if (ctl_message.message_type == IPV4_SHUTDOWN_TYPE)
        {
            char buffer[3] = {0x17, 0};
            ipv4_send_message_secure(SOCKET_FD, buffer, 2, CONNECTION_TYPE, KEY);
            ipv4_send_ctl_message_secure(SOCKET_FD, IPV4_SHUTDOWN_TYPE, 0, NULL, 0, NULL, 0, NULL, 0, CONNECTION_TYPE, KEY);
            tcsetattr(STDIN_FILENO, TCSANOW, &DEFAULT_TERM);

            exit(EXIT_SUCCESS);
        }

        ssize_t recv_bytes = ipv4_receive_message_secure(SOCKET_FD, buffer, ctl_message.message_length, CONNECTION_TYPE, KEY);
        if (recv_bytes == -1)
        {
            fprintf(stderr, "ipv4_receive_message_secure() couldn't receive message\n");
            pthread_exit(NULL);
        }
        buffer[ctl_message.message_length] = 0;

        if (buffer[0] == cancel_sign)
        {
            pthread_cancel(SENDER_THREAD);
            fprintf(stderr, "Password is invalid or server error occured!\n");
            tcsetattr(STDIN_FILENO, TCSANOW, &DEFAULT_TERM);
            ipv4_close_secure(SOCKET_FD, CONNECTION_TYPE, KEY);

            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "%s", buffer);
        memset(buffer, 0, ctl_message.message_length + 1);
    }
    
    return NULL;
}

int vssh_send_broadcast_request()
{
    // Creating own socket
    int socket_fd = ipv4_socket(SOCK_STREAM_UDT, SO_REUSEADDR);
    if (socket_fd == -1)
    {
        fprintf(stderr, "ipv4_socket() couldn't create socket");
        return -1;
    }

    int optval = 1;
    int error = setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
    if (error == -1)
    {
        perror("setsockopt()");
        close(socket_fd);
        return -1;
    }

    // Binding to own socket
    int bind_state = ipv4_bind(socket_fd, INADDR_ANY, htons(SSH_BROADCAST_PORT), SOCK_DGRAM, NULL);
    if (bind_state == -1)
    {
        perror("ipv4_bind()");
        close(socket_fd);
        return -1;
    }

    struct sockaddr_in broadcast_addr = {0};
    socklen_t length = sizeof(struct sockaddr_in);

    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(SSH_SERVER_PORT);
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

    ipv4_ctl_message message = {.message_type = IPV4_BROADCAST_TYPE, .message_length = 0};
    
    int ctl_send_state = sendto(socket_fd, &message, sizeof(message), 0, (struct sockaddr *) &broadcast_addr, length);
    if (ctl_send_state == -1)
    {
        fprintf(stderr, "sendto() error");
        close(socket_fd);
        return -1;
    }

    struct timeval tv = {.tv_sec = SSH_SECONDS_TIMEOUT_BROADCAST, .tv_usec = SSH_USECONDS_TIMEOUT_BROADCAST};
    int sockopt_state = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));
    if (sockopt_state == -1)
    {
        perror("setsockopt()");
        close(socket_fd);
        return -1;
    }

    char received_msg[PACKET_DATA_SIZE + 1] = {0};
    struct sockaddr_in accept_addr = {0};

    fprintf(stderr, "\033[0;34m"); // green
    fprintf(stderr, "Found servers:\n");

    size_t n_servers = 1;

    while (1)
    {
        memset(received_msg, 0, sizeof(received_msg));

        ssize_t n_received_bytes = recvfrom(socket_fd, received_msg, sizeof(received_msg), 0, (struct sockaddr *) &accept_addr, &length);
        if (n_received_bytes == -1 && errno != EWOULDBLOCK && errno != EAGAIN)
        {
            perror("recvfrom()");
            close(socket_fd);
            return -1;
        }
        else if (n_received_bytes == -1)
            break;

        fprintf(stderr, "%zu) IP = %s, port = %d!\n", n_servers++, inet_ntoa(accept_addr.sin_addr), (int) ntohs(accept_addr.sin_port));
    }

    close(socket_fd);

    return 0;
}

int vssh_users_list_request(in_addr_t dest_ip, int connection_type)
{
    int socket_type = connection_type;
    if (socket_type == SOCK_STREAM_UDT)
        socket_type = SOCK_DGRAM;

    int socket_fd = ipv4_socket(socket_type, SO_REUSEADDR);
    if (socket_fd == -1)
    {
        fprintf(stderr, "ipv4_socket() couldn't create socket\n");
        return -1;
    }

    int connnection_state = ipv4_connect(socket_fd, dest_ip, htons(SSH_SERVER_PORT), connection_type);
    if (connnection_state == -1)
    {
        fprintf(stderr, "ipv4_connect() couldn't connect\n");
        close(socket_fd);
        return -1;
    }

    unsigned char secret[IPV4_SPARE_BUFFER_LENGTH] = {0};
    int secret_size = ipv4_execute_DH_protocol(socket_fd, secret, 0, VSSH_RSA_PRIVATE_KEY_PATH, connection_type);
    if (secret_size <= 0)
    {
        ipv4_close(socket_fd, connection_type);
        return -1;
    }

    int ctl_msg_state = ipv4_send_ctl_message_secure(socket_fd, IPV4_USERS_LIST_REQUEST_TYPE, 0, NULL, 0, NULL, 0, NULL, 0, connection_type, secret);
    if (ctl_msg_state == -1)
    {
        fprintf(stderr, "ipv4_send_ctl_message() couldn't control message\n");
        ipv4_close_secure(socket_fd, connection_type, secret);
        return -1;
    }

    ipv4_ctl_message ctl_message = {0};
    char buffer[PACKET_DATA_SIZE + 1];

    ssize_t recv_bytes_ctl = ipv4_receive_message_secure(socket_fd, &ctl_message, sizeof(ipv4_ctl_message), connection_type, secret);
    if (recv_bytes_ctl == -1)
    {
        fprintf(stderr, "ipv4_receive_message_secure() couldn't receive message\n");
        ipv4_close_secure(socket_fd, connection_type, secret);
        return -1;
    }
    
    ssize_t recv_bytes = ipv4_receive_message_secure(socket_fd, buffer, ctl_message.message_length, connection_type, secret);
    if (recv_bytes == -1)
    {
        fprintf(stderr, "ipv4_receive_message_secure() couldn't receive message\n");
        ipv4_close_secure(socket_fd, connection_type, secret);
        return -1;
    }

    fprintf(stderr, "\033[0;34m"); // green
    printf("All server users:\n"
           "%s\n", buffer);

    return ipv4_close_secure(socket_fd, connection_type, secret);
}

int vssh_send_file(in_addr_t dest_ip, int connection_type, char *username, char *src_file, char *dest_path)
{
    // Preparation
    int socket_type = connection_type;
    if (socket_type == SOCK_STREAM_UDT)
        socket_type = SOCK_DGRAM;

    ssize_t username_length = strlen(username);
    if (username_length > IPV4_SPARE_BUFFER_LENGTH)
    {
        fprintf(stderr, "too many symbols in username: ts can be no more than 256 symbols\n");
        return -1;
    }

    ssize_t dest_path_length = strlen(dest_path);
    if (dest_path_length > IPV4_SPARE_BUFFER_LENGTH)
    {
        fprintf(stderr, "too many symbols in destination path: ts can be no more than 256 symbols\n");
        return -1;
    }

    int src_file_fd = open(src_file, O_RDONLY, 0666);
    if (src_file_fd == -1)
    {
        perror("open()");
        return -1;
    }

    int socket_fd = ipv4_socket(socket_type, SO_REUSEADDR);
    if (socket_fd == -1)
    {
        fprintf(stderr, "ipv4_socket() couldn't create socket\n");
        close(src_file_fd);
        return -1;
    }

    int connnection_state = ipv4_connect(socket_fd, dest_ip, htons(SSH_SERVER_PORT), connection_type);
    if (connnection_state == -1)
    {
        fprintf(stderr, "ipv4_connect() couldn't connect\n");
        close(socket_fd);
        close(src_file_fd);
        return -1;
    }

    unsigned char secret[IPV4_SPARE_BUFFER_LENGTH] = {0};
    int secret_size = ipv4_execute_DH_protocol(socket_fd, secret, 0, VSSH_RSA_PRIVATE_KEY_PATH, connection_type);
    if (secret_size <= 0)
    {
        close(socket_fd);
        return -1;
    }

    // Get ready to send file
    off_t file_size = get_file_size(src_file_fd);

    char *file_buffer = malloc(file_size + 1);
    if (file_buffer == NULL)
    {
        fprintf(stderr, "malloc() error\n");
        ipv4_close_secure(socket_fd, connection_type, secret);
        close(src_file_fd);
        return -1;
    }

    file_buffer[file_size + 1] = 0;

    fprintf(stderr, "\033[0;37m"); // gray
    fprintf(stderr, "Password: ");

    ssize_t read_error = read(src_file_fd, file_buffer, file_size);
    if (read_error == -1)
    {
        perror("read");
        free(file_buffer);
        close(src_file_fd);
        ipv4_close_secure(socket_fd, connection_type, secret);
        return -1;
    }

    ipv4_send_ctl_message_secure(socket_fd, IPV4_FILE_HEADER_TYPE, file_size, NULL, 0,
                                 username, username_length, dest_path, dest_path_length, connection_type, secret);

    char password_buffer[BUFSIZ + 1] = {0};
    ipv4_ctl_message ctl_message = {0};

    // Read password, send it and get respond
    ssize_t read_cmd_bytes = read(STDIN_FILENO, password_buffer, sizeof(password_buffer)); // read password
    if (read_cmd_bytes == -1)
    {
        perror("read() error");
        free(file_buffer);
        ipv4_close_secure(socket_fd, connection_type, secret);
        return -1;
    }

    ssize_t sent_bytes = ipv4_send_message_secure(socket_fd, password_buffer, read_cmd_bytes, connection_type, secret);
    if (sent_bytes == -1 || sent_bytes == 0)
    {
        fprintf(stderr, "ipv4_send_message() couldn't sent message\n");
        free(file_buffer);
        close(src_file_fd);
        ipv4_close_secure(socket_fd, connection_type, secret);
        return -1;
    }

    memset(password_buffer, 0, read_cmd_bytes + 1);

    ssize_t recv_bytes_ctl = ipv4_receive_message_secure(socket_fd, &ctl_message, sizeof(ipv4_ctl_message), connection_type, secret);
    if (recv_bytes_ctl == -1)
    {
        fprintf(stderr, "ipv4_receive_message() couldn't receive message\n");
        free(file_buffer);
        close(src_file_fd);
        ipv4_close_secure(socket_fd, connection_type, secret);
    }

    size_t bytes_to_read = ctl_message.message_length > BUFSIZ ? BUFSIZ: ctl_message.message_length;

    ssize_t recv_bytes = ipv4_receive_message_secure(socket_fd, password_buffer, bytes_to_read, connection_type, secret);
    if (recv_bytes == -1)
    {
        fprintf(stderr, "ipv4_receive_message() couldn't receive message\n");
        free(file_buffer);
        close(src_file_fd);
        ipv4_close_secure(socket_fd, connection_type, secret);
    }

    // Check for respond
    const char error_msg = 0x17;
    const char cancel_msg = 0x18;
    const char file_send_request_msg = 0x19;

    sent_bytes = -1;

    if (password_buffer[0] == cancel_msg)
    {
        fprintf(stderr, "Invalid password!\n");
        free(file_buffer);
        close(src_file_fd);
        ipv4_close_secure(socket_fd, connection_type, secret);
        
        return -1;
    }
    else if (password_buffer[0] == error_msg)
    {
        fprintf(stderr, "Error occured! See vsshd journal logs.\n");
        free(file_buffer);
        close(src_file_fd);
        ipv4_close_secure(socket_fd, connection_type, secret);

        return -1;
    }
    else if (password_buffer[0] == file_send_request_msg)
    {
        ipv4_send_buffer_secure(socket_fd, file_buffer, file_size, IPV4_FILE_HEADER_TYPE, NULL, 0,
                                username, username_length, dest_path, dest_path_length, connection_type, secret);

        free(file_buffer);
        fprintf(stdout, "Successfully sent!\n");

        close(src_file_fd);
    }

    ipv4_close_secure(socket_fd, connection_type, secret);

    return 0;
}
