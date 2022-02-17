#include "net.h"

int main(int argc, char *argv[])
{
	// Setting connection type
	enum connection_type connection = TCP_CONNECT;
	if (argc == 2)
	{
		if (strcmp(argv[1], "--udp") == 0)
			connection = UDP_CONNECT;
		else if (strcmp(argv[1], "--tcp") != 0)
			errx(EX_USAGE, "error: invalid argument \"%s\"", argv[1]);
	}
	else if (argc != 1)
		errx(EX_USAGE, "error: too many arguments");

	// Launch server
	if (connection == TCP_CONNECT)
		launch_tcp_client();
	else if (connection == UDP_CONNECT)
		launch_udp_client();

	return 0;
}

void launch_tcp_client()
{
	// Creating socket
	int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd == -1)
	{
		perror("socket()");
		errx(EX_OSERR, "socket() error");
	}

	struct sockaddr_in server_addr = {0};
	socklen_t length = sizeof(struct sockaddr_in);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(USING_PORT);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	// Connection
	int connect_error = connect(socket_fd, (struct sockaddr *) &server_addr, length);
	if (connect_error == -1)
	{
		perror("connect()");
		errx(EX_OSERR, "connect() error");
	}

	const char msg[N_MAX_MSG_LEN] = "Test message!!!!!!99999";

	ssize_t sent_bytes = write(socket_fd, msg, sizeof(msg));
	if (sent_bytes == -1 || sent_bytes != sizeof(msg))
	{
		perror("write()");
		errx(EX_OSERR, "write() error");
	}

	close(socket_fd);
}

void launch_udp_client()
{
	// Creating socket
	int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd == -1)
	{
		perror("socket()");
		errx(EX_OSERR, "socket() error");
	}

	struct sockaddr_in server_addr = {0};
	socklen_t length = sizeof(struct sockaddr_in);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(USING_PORT);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	// Connection
	int connect_error = connect(socket_fd, (struct sockaddr *) &server_addr, length);
	if (connect_error == -1)
	{
		perror("connect()");
		errx(EX_OSERR, "connect() error");
	}

	const char msg[N_MAX_MSG_LEN] = "Test message!!!!!!99999UDP";

	ssize_t sent_bytes = send(socket_fd, msg, sizeof(msg), 0);
	if (sent_bytes == -1 || sent_bytes != sizeof(msg))
	{
		perror("send()");
		errx(EX_OSERR, "send() error");
	}
}
