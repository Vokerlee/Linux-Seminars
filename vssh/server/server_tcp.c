#include "client_server.h"

static pthread_mutex_t SERVER_SOCKETS_HANDLER_MUTEX = PTHREAD_MUTEX_INITIALIZER;

void *tcp_server_handler(void *connection_socket)
{
	int socket_fd = (int) connection_socket;

	ipv4_ctl_message ctl_message = {0};
	char message[PACKET_DATA_SIZE + 1] = {0};

	while(1)
	{
		ssize_t recv_bytes = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ipv4_ctl_message), SOCK_STREAM);
		if (recv_bytes != -1 && recv_bytes != 0)
		{
			printf("type = %d\n",  ctl_message.message_type);
			printf("len  = %ld\n", ctl_message.message_length);
			printf("msg  = %s\n",  ctl_message.spare_buffer);

			switch (ctl_message.message_type)
			{
				case IPV4_SHUTDOWN_TYPE: // only in TCP
				{
					printf("GET SHUTDOWN...\n");

					void *retval = 0;
					pthread_exit(retval);
				}
					
				case IPV4_MSG_HEADER_TYPE:
				{
					printf("GET MSG HEADER... %ld\n", ctl_message.message_length);
					recv_bytes = ipv4_receive_message(socket_fd, message, ctl_message.message_length, SOCK_STREAM);
					printf("\tMessage: %s\n\n", message);
					break;
				}
					
				default:
					break;
			}

			memset(message, 0, sizeof(message));
		}
	}
	
	// ssize_t received_bytes = ipv4_receive_file(SOCK_STREAM, socket_fd, &SERVER_SOCKETS_HANDLER_MUTEX);
	// if (received_bytes == -1)
	// {
	// 	close(socket_fd);
	// 	exit(EXIT_FAILURE);
	// }

	void *retval = 0;
	pthread_exit(retval);
}

int launch_tcp_server(in_addr_t ip)
{
	int socket_fd = ipv4_socket(SOCK_STREAM, SO_REUSEADDR);
	if (socket_fd == -1)
		return -1;

	int bind_state = ipv4_bind(socket_fd, ip, htons(SERVER_PORT), SOCK_STREAM, NULL);
	if (bind_state == -1)
		return -1;

	// Listening on
	int listen_state = ipv4_listen(socket_fd);
	if (listen_state == -1)
	{
		perror("listen()");
		ipv4_close(socket_fd, SOCK_STREAM);
		errx(EX_OSERR, "listen() error");
	}

	// Accept connections
	while(1)
	{
		struct sockaddr_in accept_addr = {0};
		socklen_t length = sizeof(struct sockaddr_in);

		int accepted_socket_fd = ipv4_accept(socket_fd, (struct sockaddr *) &accept_addr, &length);
		if (accepted_socket_fd == -1)
		{
			perror("accept()");
			continue;
		}

		printf("New connection!\n");
	 	printf("From IP = %s, port = %d!\n", inet_ntoa(accept_addr.sin_addr), (int) ntohs(accept_addr.sin_port));

		pthread_t new_thread = {0};
		int pthread_error = pthread_create(&new_thread, NULL, tcp_server_handler, (void *) accepted_socket_fd);
		if (pthread_error == -1)
		{
			perror("pthread_create()");
			continue;
		}

		pthread_error = pthread_detach(new_thread);
		if (pthread_error == -1)
			perror("pthread_detach()");
	}	

	return 0;
}