#include <sys/socket.h>
#include <unistd.h>

#include "ipv4_net.h"
#include "udt_api.h"
#include "udt_core.h"
#include "udt_utils.h"
#include "udt_buffer.h"

extern udt_conn_t connection;

int udt_bind(int socket_fd, const struct sockaddr *addr, socklen_t len)
{
    if (connection.socket_fd != 0) // impossible to use this function twice
        return -1;

    if (connection.server_handler == NULL) // server handler wasn't set
        return -1;

    udt_startup();

    int bind_error = bind(socket_fd, (const struct sockaddr *) addr, len);
    if (bind_error == -1)
        return -1;

    connection.socket_fd      = socket_fd;
    connection.addrlen        = len;
    connection.is_connected   = 0;
    connection.is_client      = 0;
    connection.is_main_server = 1;
    
    int pthread_error = pthread_atfork(udt_prepare_to_fork, NULL, udt_child_after_fork);
    if (pthread_error == -1)
        return -1;

    pthread_t recv_thread;
    int recv_pthread_error = pthread_create(&recv_thread, NULL, udt_receiver_start, (void *) &connection);
    if (recv_pthread_error == -1)
        return -1;

    connection.recv_thread = recv_thread;

    int old_type = 0;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);

    pthread_exit(NULL);

    return 0;
}

int udt_connect(int socket_fd, const struct sockaddr *addr, socklen_t len)
{
    if (addr == NULL)
        return -1;
        
    memset(&connection, 0, sizeof(connection));

    udt_startup();

    connection.socket_fd    = socket_fd;
    connection.addr         = *((struct sockaddr_in *) addr);
    connection.addrlen      = len;
    connection.is_connected = 0;
    connection.is_client    = 1;

    pthread_t recv_thread;
    pthread_t send_thread;

    int recv_pthread_error = pthread_create(&recv_thread, NULL, udt_receiver_start, (void *) &connection);
    if (recv_pthread_error == -1)
        return -1;

    int send_pthread_error = pthread_create(&send_thread, NULL, udt_sender_start, (void *) &connection);
    if (send_pthread_error == -1)
        return -1;

    struct timeval tv = {.tv_sec = UDT_SECONDS_TIMEOUT_CONN, .tv_usec = UDT_USECONDS_TIMEOUT_CONN};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));

    udt_handshake_init();

    if (connection.is_connected == 1)
    {
        struct timeval new_tv = {.tv_sec = UDT_SECONDS_TIMEOUT_CLIENT, .tv_usec = UDT_USECONDS_TIMEOUT_CLIENT};
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &new_tv, sizeof(struct timeval));

        connection.recv_thread = recv_thread;
        connection.send_thread = send_thread;

        return 0;
    }
    else
    {
        memset(&connection, 0, sizeof(connection));

        struct timeval new_tv = {.tv_sec = 0, .tv_usec = 0};
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &new_tv, sizeof(struct timeval));

        pthread_cancel(recv_thread);
        pthread_cancel(send_thread);

        return -1;
    }
}

ssize_t udt_recv(int socket_fd, char *buffer, size_t len)
{
    if (buffer == NULL)
        return -1;

    if (connection.is_connected == 0 && connection.is_client == 1)
        return -1;

    ssize_t received_bytes = udt_recv_buffer_read(buffer, len);
    if (connection.is_connected == 0 && connection.is_client == 1)
    {
        pthread_cancel(connection.recv_thread);
        pthread_cancel(connection.send_thread);

        memset(&connection, 0, sizeof(connection));

        return -1;
    }

    return received_bytes;
}

ssize_t udt_send(int socket_fd, const char *buffer, size_t len)
{
    if (buffer == NULL)
        return -1;

    if (connection.is_connected == 0)
        return -1;

    struct timeval old_tv;
    socklen_t optlen;
    getsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &old_tv, &optlen);

    struct timeval new_tv = {.tv_sec = UDT_SECONDS_TIMEOUT_SEND, .tv_usec = UDT_USECONDS_TIMEOUT_SEND};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &new_tv, sizeof(struct timeval));

    ssize_t sent_bytes = udt_send_buffer_write(buffer, len);
    if (connection.is_connected == 0 && connection.is_client == 1)
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &old_tv, sizeof(struct timeval));
        
    return sent_bytes;
}

int udt_close(int socket_fd)
{
    if (connection.is_connected == 1)
    {   
        udt_connection_close();
        connection.is_connected = 0;
    }

    if (connection.recv_thread != 0)
        pthread_cancel(connection.recv_thread);

    if (connection.send_thread != 0)
        pthread_cancel(connection.send_thread);

    memset(&connection, 0, sizeof(connection));

    return close(socket_fd);
}

ssize_t udt_recvfile(int socket_fd, int fd, off_t *offset, ssize_t filesize)
{
    if (offset == NULL)
        return -1;

    if (connection.is_connected == 0 && connection.is_client == 1)
        return -1;

    ssize_t received_bytes = udt_recv_file_buffer_read(fd, offset, filesize);
    if (connection.is_connected == 0 && connection.is_client == 1)
    {
        pthread_cancel(connection.recv_thread);
        pthread_cancel(connection.send_thread);

        memset(&connection, 0, sizeof(connection));

        return -1;
    }

    return received_bytes;
}

ssize_t udt_sendfile(int socket_fd, int fd, off_t offset, ssize_t filesize)
{
    if (connection.is_connected == 0)
        return -1;

    struct timeval old_tv;
    socklen_t optlen;
    getsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &old_tv, &optlen);

    struct timeval new_tv = {.tv_sec = UDT_SECONDS_TIMEOUT_SEND, .tv_usec = UDT_USECONDS_TIMEOUT_SEND};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &new_tv, sizeof(struct timeval));

    ssize_t sent_bytes = udt_send_file_buffer_write(fd, offset, filesize);
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &old_tv, sizeof(struct timeval));
        
    return sent_bytes;
}

void udt_set_server_handler(void *(*server_handler)(void *))
{
    memset(&connection, 0, sizeof(connection));
    connection.server_handler = server_handler;
}
