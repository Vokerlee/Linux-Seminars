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
        int ctl_msg_state = ipv4_send_ctl_message(socket_fd, IPV4_SHUTDOWN_TYPE, 0, NULL, 0, NULL, 0, SOCK_STREAM);
        if (ctl_msg_state == -1)
        {
            close(socket_fd);
            return -1;
        }

        return close(socket_fd);
    }
}

int ipv4_send_ctl_message(int socket_fd, uint64_t msg_type, uint64_t msg_length, 
                          uint32_t *spare_fields, size_t spare_fields_size, char *spare_buffer, size_t spare_buffer_size,
                          int connection_type)
{
    if (spare_fields != NULL && spare_fields_size > IPV4_SPARE_FIELDS)
        return -1;

    if (spare_buffer != NULL && spare_buffer_size > IPV4_SPARE_BUFFER_LENGTH)
        return -1;

    ipv4_ctl_message message = {.message_type = msg_type, .message_length = msg_length};

    if (spare_fields != NULL)
        memcpy(message.spare_fields, spare_fields, spare_fields_size * sizeof(spare_fields[0]));
    else if (spare_buffer != NULL)
        memcpy(message.spare_buffer, spare_buffer, spare_buffer_size * sizeof(spare_buffer[0]));

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

    int ctl_msg_state = ipv4_send_ctl_message(socket_fd, IPV4_MSG_HEADER_TYPE, n_bytes, NULL, 0, NULL, 0, connection_type);
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

// ssize_t ipv4_send_file(int type, int socket_fd, int file_fd, const char* file_name)
// {
//     if (type == SOCK_STREAM)
//         return ipv4_send_file_tcp(socket_fd, file_fd, file_name);
//     else if (type == SOCK_DGRAM)
//         return ipv4_send_file_udp(socket_fd, file_fd, file_name);
//     else
//         return -1;
// }

// ssize_t ipv4_receive_file(int type, int socket_fd, pthread_mutex_t *sync_mutex)
// {
//     if (type == SOCK_STREAM)
//         return ipv4_receive_file_tcp(socket_fd, sync_mutex);
//     else if (type == SOCK_DGRAM)
//         return ipv4_receive_file_udp(socket_fd, sync_mutex);
//     else
//         return -1;
// }

// ssize_t ipv4_send_file_tcp(int socket_fd, int file_fd, const char* file_name)
// {   
//     int saved_errno = errno;

//     off_t file_size = get_file_size(file_fd);
//     if (file_size == -1)
//         return -1;

//     size_t n_iters = file_size / PACKET_DATA_SIZE; // iterations to send the whole file
//     if (file_size % PACKET_DATA_SIZE != 0)
//         n_iters++;

//     char message[PACKET_DATA_SIZE] = {0};

//     *((size_t *) message)     = file_size;
//     *((size_t *) message + 1) = n_iters;
//     *((size_t *) message + 2) = strlen(file_name);
//     strncpy((char *)((size_t *) message + 3), file_name, N_MAX_FILENAME_LEN);

//     ssize_t sent_hdr_bytes = write(socket_fd, message, HDR_MSG_LEN);
//     if (sent_hdr_bytes == -1 || sent_hdr_bytes != HDR_MSG_LEN)
//     {
//         perror("write()");
//         return -1;
//     }

//     // Sending the file

//     for (size_t i = 0; i < n_iters - 1; i++)
//     {
//         int read_error = read(file_fd, message, PACKET_DATA_SIZE);
//         if (read_error == -1)
//         {
//             perror("read()");
//             return -1;
//         }

//         ssize_t sent_bytes = write(socket_fd, message, PACKET_DATA_SIZE);
//         if (sent_bytes == -1 || sent_bytes != PACKET_DATA_SIZE)
//         {
//             perror("write()");
//             return -1;
//         }
//     }

//     memset(message, 0, sizeof(message));

//     int read_error = read(file_fd, message, file_size % PACKET_DATA_SIZE);
//     if (read_error == -1)
//     {
//         perror("read()");
//         return -1;
//     }

//     ssize_t sent_bytes = write(socket_fd, message, file_size % PACKET_DATA_SIZE);
//     if (sent_bytes == -1 || sent_bytes != file_size % PACKET_DATA_SIZE)
//     {
//         perror("write()");
//         close(socket_fd);
//         errx(EX_OSERR, "write() error");
//     }

//     errno = saved_errno;

//     return sent_hdr_bytes + n_iters * PACKET_DATA_SIZE;
// }

// ssize_t ipv4_send_file_udp(int socket_fd, int file_fd, const char* file_name)
// {
//     return 0;
// }

// ssize_t ipv4_receive_file_tcp(int socket_fd, pthread_mutex_t *sync_mutex)
// {
//     char message[PACKET_DATA_SIZE] = {0};
//     char file_name[N_MAX_FILENAME_LEN] = {0};

//     if (read(socket_fd, message, HDR_MSG_LEN) == -1)
//     {
//         perror("read()");
//         return -1;
//     }

//     size_t file_size     = *((size_t *) message);
//     size_t n_iters       = *((size_t *) message + 1);
//     size_t filename_size = *((size_t *) message + 2);
//     strncpy(file_name, (char *)((size_t *) message + 3), N_MAX_FILENAME_LEN);

//     if (sync_mutex)
//     {
//         int mutex_error = pthread_mutex_lock(sync_mutex);
//         if (mutex_error != -1)
//         {
//             printf("File information:\n");
//             printf("\tsize       = %zu\n", file_size);
//             printf("\titerations = %zu\n", n_iters);
//             printf("\tname size  = %zu\n", filename_size);
//             printf("\tname       = %s\n",  file_name);
//             printf("==================================================\n");

//             pthread_mutex_unlock(sync_mutex);
//         }
//         else
//             perror("pthread_mutex_unlock()");
//     }

//     int file_fd = open(file_name, O_WRONLY | O_CREAT, 0666);
//     if (file_fd == -1)
//     {
//         perror("open()");
//         exit(EXIT_FAILURE);
//     }

//     for (size_t i = 0; i < n_iters - 1; i++)
//     {
//         int read_error = read(socket_fd, message, PACKET_DATA_SIZE);
//         if (read_error == -1)
//         {
//             perror("read()");
//             close(file_fd);
//             return -1;
//         }

//         ssize_t written_bytes = write(file_fd, message, PACKET_DATA_SIZE);
//         if (written_bytes == -1 || written_bytes != PACKET_DATA_SIZE)
//         {
//             perror("write()");
//             close(file_fd);
//             return -1;
//         }
//     }

//     memset(message, 0, sizeof(message));

//     int read_error = read(socket_fd, message, file_size % PACKET_DATA_SIZE);
//     if (read_error == -1)
//     {
//         perror("read()");
//         close(file_fd);
//         return -1;
//     }

//     ssize_t sent_bytes = write(file_fd, message, file_size % PACKET_DATA_SIZE);
//     if (sent_bytes == -1 || sent_bytes != file_size % PACKET_DATA_SIZE)
//     {
//         perror("write()");
//         close(file_fd);
//         return -1;
//     }

//     close(file_fd);

//     return HDR_MSG_LEN + n_iters * PACKET_DATA_SIZE;
// }

// ssize_t ipv4_receive_file_udp(int socket_fd, pthread_mutex_t *sync_mutex)
// {
//     return 0;
// }
