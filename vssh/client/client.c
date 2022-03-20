#include "client.h"

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
