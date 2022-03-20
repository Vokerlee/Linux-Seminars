#include "client_server.h"

int launch_tcp_client(in_addr_t dest_ip, int file_fd, const char *file_name)
{
	int socket_fd = ipv4_socket(SOCK_STREAM, SO_REUSEADDR);
	if (socket_fd == -1)
		return -1;

	int connnection_state = ipv4_connect(socket_fd, dest_ip, htons(SERVER_PORT), SOCK_STREAM);
	if (connnection_state == -1)
	{
		ipv4_close(socket_fd, SOCK_STREAM);
		return -1;
	}

    char buffer[PACKET_DATA_SIZE] = {0};
	strcpy(buffer, "LLLLLLLLLJJJDJJ jhdjvfffffffffffffffffffffffffbshdbvhjsbdvhjbdscjebdvhjksjdbvhjce,whsdbvbhj,mehwbshj vm"
				   "efwsdfsdfdsfsdfdfgnj.k/.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffk,jm55555555555555555555555555555555555555555555555555");

    ssize_t sent_bytes = ipv4_send_message(socket_fd, buffer, 244, SOCK_STREAM);
	if (sent_bytes == -1 || sent_bytes == 0)
		errx(EX_OSERR, "ipv4_send_message() error");

	// ssize_t sent_bytes = ipv4_send_file(SOCK_STREAM, socket_fd, file_fd, file_name);
	// if (sent_bytes == -1)
	// {
	// 	ipv4_close(socket_fd, SOCK_STREAM);
	// 	return -1;
	// }

	ipv4_close(socket_fd, SOCK_STREAM);

	return 0;
}
