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
	int socket_fd = ipv4_sock_connect(SOCK_DGRAM, dest_ip, htons(USING_PORT));
	if (socket_fd == -1)
		errx(EX_OSERR, "ipv4_sock_connect() error");

	// const char msg[N_MAX_MSG_LEN] = "Test message!!!!!!99999UDP";

	// ssize_t sent_bytes = send(socket_fd, msg, sizeof(msg), 0);
	// if (sent_bytes == -1 || sent_bytes != sizeof(msg))
	// {
	// 	perror("send()");
	// 	close(socket_fd);
	// 	errx(EX_OSERR, "send() error");
	// }

	// close(socket_fd);
}
