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

    connection.socket_fd    = socket_fd;
    connection.is_open      = 1;
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

    return 0;
}

int udt_connect(int socket_fd, const struct sockaddr *addr, socklen_t len)
{
    int connect_error = connect(socket_fd, (struct sockaddr *) addr, len);
    if (connect_error == -1)
        return -1;

    connection.socket_fd    = socket_fd;
    connection.addr         = *addr;
    connection.addrlen      = len;
    connection.is_open      = 1;
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

    udt_handshake_init();

    while (!connection.is_connected);
    
    return 0;
}

int udt_accept(int socket_fd, struct sockaddr *addr, socklen_t *len)
{
    return accept(socket_fd, addr, len);
}

ssize_t udt_recv(int socket_fd, char *buffer, int len)
{
    ssize_t num_read = 0;

    do
    {
        if (connection.is_open == 0 && connection.is_connected == 0)
            return 0;

        num_read = udt_recv_buffer_read(buffer, len);
    } while (num_read == 0);

    return num_read;
}

ssize_t udt_send(int socket_fd, char *buffer, int len)
{
    if (!connection.is_connected)
        return -1;
    
    return udt_send_buffer_write(buffer, len);
}

int udt_close(int socket_fd)
{
    udt_connection_close();
    while (connection.is_open);

    return close(socket_fd);
}

ssize_t udt_recvfile(int socket_fd, int fd, off_t *offset, ssize_t filesize)
{
    ssize_t num_read = 0;

    do
    {
        if (connection.is_open == 0 && connection.is_connected == 0)
            return 0;

        num_read = udt_recv_file_buffer_read(fd, offset, filesize);
    } while (num_read == 0);

    return num_read;
}

ssize_t udt_sendfile(int socket_fd, int fd, off_t offset, ssize_t filesize)
{
    if (!connection.is_connected)
        return -1;
    
    return udt_send_file_buffer_write(fd, offset, filesize);
}
