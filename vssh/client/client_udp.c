#include "client_server.h"

int launch_udp_client(in_addr_t dest_ip, int file_fd, const char *file_name)
{
	int socket_fd = ipv4_socket(SOCK_DGRAM, SO_REUSEADDR);
	if (socket_fd == -1)
		return -1;

	int connnection_state = ipv4_connect(socket_fd, dest_ip, htons(SERVER_PORT), SOCK_STREAM_UDT);
	if (connnection_state == -1)
	{
		ipv4_close(socket_fd, SOCK_STREAM_UDT);
		return -1;
	}

	fprintf(stderr, "Connected\n");

	char buffer[PACKET_DATA_SIZE] = {0};
	strcpy(buffer, "LLLLLLLLLJJJDJJ jhdjvfffffffffffffffffffffffffbshdbvhjsbdvhjbdscjebdvhjksjdbvhjce,whsdbvbhj,mehwbshj vm"
				   "efwsdfsdfdsfsdfdfgnj.k/.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffk,jm55555555555555555555555555555555555555555555555555");

    ssize_t sent_bytes = ipv4_send_message(socket_fd, buffer, 244, SOCK_STREAM_UDT);
	if (sent_bytes == -1 || sent_bytes == 0)
		errx(EX_OSERR, "ipv4_send_message() error");

	// char new_buffer[1000] = {0};
	// ssize_t recv_bytes = udt_recv(socket_fd, new_buffer, 180);
    // if (recv_bytes != -1 && recv_bytes != 0)
	// {
    //     printf("\tMessage: %s\n\n", new_buffer);
    //     memset(new_buffer, 0, sizeof(new_buffer));
    // }

	// if (udt_sendfile(socket_fd, file_fd, 0, 305) < 0)
	// 	return -1;

	ipv4_close(socket_fd, SOCK_STREAM_UDT);

	return 0;
}
