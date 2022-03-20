#include "client_server.h"

void *udt_server_handler(void *connection_socket)
{
	int socket_fd = (int) connection_socket;
	
	ipv4_ctl_message ctl_message = {0};
	char message[PACKET_DATA_SIZE + 1] = {0};

	while(1)
	{
		ssize_t recv_bytes = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ipv4_ctl_message), SOCK_STREAM_UDT);
		if (recv_bytes != -1 && recv_bytes != 0)
		{
			printf("type = %d\n",  ctl_message.message_type);
			printf("len  = %ld\n", ctl_message.message_length);
			printf("msg  = %s\n",  ctl_message.spare_buffer);

			switch (ctl_message.message_type)
			{
				case IPV4_MSG_HEADER_TYPE:
				{
					printf("GET MSG HEADER... %ld\n", ctl_message.message_length);
					recv_bytes = ipv4_receive_message(socket_fd, message, ctl_message.message_length, SOCK_STREAM_UDT);
					printf("\tMessage: %s\n\n", message);
					break;
				}
					
				default:
					break;
			}

			memset(message, 0, sizeof(message));
		}
	}

	void *retval = 0;
	pthread_exit(retval);
}

int launch_udp_server(in_addr_t ip)
{
	int socket_fd = ipv4_socket(SOCK_DGRAM, SO_REUSEADDR);
	if (socket_fd == -1)
		return -1;

	int bind_state = ipv4_bind(socket_fd, ip, htons(SERVER_PORT), SOCK_STREAM_UDT, udt_server_handler);
	if (bind_state == -1)
	{
		ipv4_close(socket_fd, SOCK_STREAM_UDT);
		return -1;
	}

	// char new_buffer[1000] = {0};
	// strcpy(new_buffer, "888LLLLLLLLLJJJDJJ jhdjvbshdbvhjsbdvhjbdscjebdvhjksjdbvhjce,whsdbvbhj,mehwbshj vm"
	// 			   "efwsdfsdfdsfsdfdfgnj.k/.k,jm5555555555555999999999999999999995555555555555555555555555555555555555");

	// udt_send(socket_fd, new_buffer, 180);

	// int file_fd = open("test_recv_file", O_WRONLY | O_TRUNC | O_CREAT, 0666);
	// if (file_fd == -1)
	// 	return -1;

	// off_t offset = 0;

	// if (udt_recvfile(socket_fd, file_fd, &offset, 305) < 0)
	// 	return -1;

    // close(file_fd);

	return 0;
}
