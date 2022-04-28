#include "utils.h"
#include "ipv4_net.h"

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

    if (spare_fields != NULL)
        memcpy(message.spare_fields, spare_fields, spare_fields_size * sizeof(spare_fields[0]));
    else 
    {
        if (spare_buffer1 != NULL)
            memcpy(message.spare_buffer1, spare_buffer1, spare_buffer_size1 * sizeof(spare_buffer1[0]));
        if (spare_buffer2 != NULL)
            memcpy(message.spare_buffer2, spare_buffer2, spare_buffer_size2 * sizeof(spare_buffer2[0]));
    }

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
