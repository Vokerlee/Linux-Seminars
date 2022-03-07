#include "client_server.h"

int main(int argc, char *argv[])
{
	if (argc != 3)
		errx(EX_USAGE, "error: invalid amount of arguments");

	int connection_type = SOCK_STREAM;
	if (strcmp(argv[1], "--udp") == 0)
		connection_type = SOCK_DGRAM;
	else if (strcmp(argv[1], "--tcp") != 0)
		errx(EX_USAGE, "error: invalid argument \"%s\"", argv[1]);

	// Launch server
	if (connection_type == SOCK_STREAM)
		return launch_tcp_server(inet_addr(argv[2]));
	else if (connection_type == SOCK_DGRAM)
		return launch_udp_server(inet_addr(argv[2]));
}
