#include "vssh.h"

int vssh_send_message(in_addr_t dest_ip, const char *message, size_t len, int connection_type)
{
    int socket_type = connection_type;
    if (socket_type == SOCK_STREAM_UDT)
        socket_type = SOCK_DGRAM;

    int socket_fd = ipv4_socket(socket_type, SO_REUSEADDR);
    if (socket_fd == -1)
    {
        fprintf(stderr, "ipv4_socket() couldn't create socket");
        return -1;
    }

    int connnection_state = ipv4_connect(socket_fd, dest_ip, htons(SSH_SERVER_PORT), connection_type);
    if (connnection_state == -1)
    {
        fprintf(stderr, "ipv4_connect() couldn't connect");
        close(socket_fd);
        return -1;
    }

    ssize_t sent_bytes = ipv4_send_message(socket_fd, message, len, connection_type);
    if (sent_bytes == -1 || sent_bytes == 0)
    {
        ipv4_close(socket_fd, connection_type);
        return -1;
    }

    return ipv4_close(socket_fd, connection_type);
}
