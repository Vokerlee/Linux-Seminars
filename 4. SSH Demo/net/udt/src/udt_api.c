#include <sys/socket.h>
#include <unistd.h>

#include "net.h"
#include "udt_api.h"
#include "udt_core.h"
#include "udt_utils.h"
#include "udt_buffer.h"

extern udt_conn_t connection;

int udt_startup()
{
    return udt_send_buffer_init() || udt_recv_buffer_init();
}

int udt_bind(int socket_fd, const struct sockaddr *addr, socklen_t len)
{
    int bind_error = bind(socket_fd, (const struct sockaddr *) addr, len);
    if (bind_error == -1)
        return -1;

    memset(&connection, 0, sizeof(connection));

    connection.socket_fd    = socket_fd;
    connection.addrlen      = len;
    connection.is_connected = 0;
    connection.is_client    = 0;

    pthread_t recv_thread = {0};
    pthread_t send_thread = {0};

    int recv_pthread_error = pthread_create(&recv_thread, NULL, udt_receiver_start, (void *) &connection);
    if (recv_pthread_error == -1)
        return -1;

    int send_pthread_error = pthread_create(&send_thread, NULL, udt_sender_start, (void *) &connection);
    if (send_pthread_error == -1)
        return -1;

    connection.recv_thread = recv_thread;
    connection.send_thread = send_thread;

    return 0;
}

int udt_connect(int socket_fd, const struct sockaddr *addr, socklen_t len)
{
    int connect_error = connect(socket_fd, (struct sockaddr *) addr, len);
    if (connect_error == -1)
        return -1;

    memset(&connection, 0, sizeof(connection));

    connection.socket_fd    = socket_fd;
    connection.addr         = *((struct sockaddr_in *) addr);
    connection.addrlen      = len;
    connection.is_connected = 0;
    connection.is_client    = 1;

    pthread_t recv_thread = {0};
    pthread_t send_thread = {0};

    int recv_pthread_error = pthread_create(&recv_thread, NULL, udt_receiver_start, (void *) &connection);
    if (recv_pthread_error == -1)
        return -1;

    int send_pthread_error = pthread_create(&send_thread, NULL, udt_sender_start, (void *) &connection);
    if (send_pthread_error == -1)
        return -1;

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));

    udt_handshake_init();

    if (connection.is_connected == 1)
    {
        struct timeval new_tv = {.tv_sec = 2, .tv_usec = 0};
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

ssize_t udt_recv(int socket_fd, char *buffer, int len)
{
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

ssize_t udt_send(int socket_fd, char *buffer, int len)
{
    if (connection.is_connected == 0)
        return -1;

    ssize_t sent_bytes = udt_send_buffer_write(buffer, len);
    if (connection.is_connected == 0 && connection.is_client == 1)
    {
        pthread_cancel(connection.recv_thread);
        pthread_cancel(connection.send_thread);

        memset(&connection, 0, sizeof(connection));

        return -1;
    }
        
    return sent_bytes;
}

int udt_close(int socket_fd)
{
    if (connection.is_connected == 1)
    {   
        udt_connection_close();
        while (connection.is_connected == 1);
    }

    if (connection.socket_fd != 0) // is not cleaned yet
    {
        pthread_cancel(connection.recv_thread);
        pthread_cancel(connection.send_thread);
    }

    memset(&connection, 0, sizeof(connection));

    return close(socket_fd);
}

ssize_t udt_recvfile(int socket_fd, int fd, off_t *offset, ssize_t filesize)
{
    if (connection.is_connected == 0)
        return -1;

    return udt_recv_file_buffer_read(fd, offset, filesize);
}

ssize_t udt_sendfile(int socket_fd, int fd, off_t offset, ssize_t filesize)
{
    if (connection.is_connected == 0)
        return -1;
    
    return udt_send_file_buffer_write(fd, offset, filesize);
}
