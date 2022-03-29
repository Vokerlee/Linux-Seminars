#include "vssh.h"

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

    ssize_t sent_bytes = ipv4_send_message(socket_fd, message, len, connection_type);
    if (sent_bytes == -1 || sent_bytes == 0)
    {
        ipv4_close(socket_fd, connection_type);
        return -1;
    }

    return ipv4_close(socket_fd, connection_type);
}

int vssh_shell_request(in_addr_t dest_ip, int connection_type)
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

    int ctl_msg_state = ipv4_send_ctl_message(socket_fd, IPV4_SHELL_REQUEST_TYPE, 0, NULL, 0, NULL, 0, connection_type);
    if (ctl_msg_state == -1)
    {
        fprintf(stderr, "ipv4_send_ctl_message() couldn't control message\n");
        ipv4_close(socket_fd, connection_type);
        return -1;
    }

    fprintf(stderr, "\033[0;37m"); // gray

    char buffer[BUFSIZ + 1] = {0};
    ipv4_ctl_message ctl_message = {0};

    while(1)
    {
        fprintf(stderr, "\033[0;36m"); // yellow
        ssize_t read_cmd_bytes = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (read_cmd_bytes == -1)
        {
            perror("read() error");
            ipv4_close(socket_fd, connection_type);
            return -1;
        }

        ssize_t sent_bytes = ipv4_send_message(socket_fd, buffer, read_cmd_bytes, connection_type);
        if (sent_bytes == -1 || sent_bytes == 0)
        {
            fprintf(stderr, "ipv4_send_message() couldn't sent message\n");
            ipv4_close(socket_fd, connection_type);
            return -1;
        }

        if (strcmp(buffer, "exit\n") == 0)
            break;

        memset(buffer, 0, read_cmd_bytes + 1);
        fprintf(stderr, "\033[0;37m"); // gray

        ssize_t recv_bytes_ctl = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ipv4_ctl_message), connection_type);
        if (recv_bytes_ctl == -1)
        {
            fprintf(stderr, "ipv4_receive_message() couldn't receive message\n");
            ipv4_close(socket_fd, connection_type);
            return -1;
        }

        size_t bytes_to_read = ctl_message.message_length > BUFSIZ ? BUFSIZ: ctl_message.message_length;

        ssize_t recv_bytes = ipv4_receive_message(socket_fd, buffer, bytes_to_read, connection_type);
        if (recv_bytes == -1)
        {
            fprintf(stderr, "ipv4_receive_message() couldn't receive message\n");
            ipv4_close(socket_fd, connection_type);
            return -1;
        }

        printf("%s", buffer);

        memset(buffer, 0, bytes_to_read + 1);
    }

    return ipv4_close(socket_fd, connection_type);
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
