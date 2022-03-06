#include "client_server.h"

int main(int argc, char *argv[])
{
	if (argc != 4)
		errx(EX_USAGE, "error: invalid amount of arguments");

	int connection_type = SOCK_STREAM;
	if (strcmp(argv[1], "--udp") == 0)
		connection_type = SOCK_DGRAM;
	else if (strcmp(argv[1], "--tcp") != 0)
		errx(EX_USAGE, "error: invalid argument \"%s\"", argv[1]);

	int victim_fd = open(argv[2], O_RDONLY, 0666);
	if (victim_fd == -1)
	{
		perror("open()");
		errx(EX_OSERR, "open() error");
	}

	if (connection_type == SOCK_STREAM)
		launch_tcp_client(inet_addr(argv[3]), victim_fd, argv[2]);
	else if (connection_type == SOCK_DGRAM)
		launch_udp_client(inet_addr(argv[3]), victim_fd, argv[2]);

	close(victim_fd);

	return 0;
}

int launch_tcp_client(in_addr_t dest_ip, int file_fd, const char *file_name)
{
	int socket_fd = ipv4_sock_connect(SOCK_STREAM, dest_ip, htons(USING_PORT));
	if (socket_fd == -1)
		errx(EX_OSERR, "ipv4_sock_connect() error");

	ssize_t sent_bytes = ipv4_send_file(SOCK_STREAM, socket_fd, file_fd, file_name);
	if (sent_bytes == -1)
	{
		close(socket_fd);
		return -1;
	}

	close(socket_fd);

	return 0;
}

int launch_udp_client(in_addr_t dest_ip, int file_fd, const char *file_name)
{
	udt_startup();

	int socket_fd = ipv4_socket(SOCK_DGRAM, SO_REUSEADDR);
	if (socket_fd == -1)
		return -1;

	struct sockaddr_in server_addr = {0};
	socklen_t length = sizeof(struct sockaddr_in);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(USING_PORT);
	server_addr.sin_addr.s_addr = dest_ip;

	if (udt_connect(socket_fd, (struct sockaddr *) &server_addr, length) == -1)
	{
        fprintf(stderr, "Could not connect to server\n");
        exit(errno);
    }
	else
        fprintf(stderr, "Connected\n");

	char buffer[PACKET_DATA_SIZE] = {0};
	strcpy(buffer, "LLLLLLLLLJJJDJJ jhdjvfffffffffffffffffffffffffbshdbvhjsbdvhjbdscjebdvhjksjdbvhjce,whsdbvbhj,mehwbshj vm"
				   "efwsdfsdfdsfsdfdfgnj.k/.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffk,jm55555555555555555555555555555555555555555555555555");

    udt_send(socket_fd, buffer, 244);

	// char new_buffer[1000] = {0};
	// ssize_t recv_bytes = udt_recv(socket_fd, new_buffer, 180);
    // if (recv_bytes != -1 && recv_bytes != 0)
	// {
    //     printf("\tMessage: %s\n\n", new_buffer);
    //     memset(new_buffer, 0, sizeof(new_buffer));
    // }

	// if (udt_sendfile(socket_fd, file_fd, 0, 305) < 0)
	// 	return -1;

	udt_close(socket_fd);

	return 0;
}
