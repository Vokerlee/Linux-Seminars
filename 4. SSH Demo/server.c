#include "client_server.h"

int SERVER_SOCKET_FD;
static pthread_mutex_t SERVER_SOCKETS_HANDLER_MUTEX = PTHREAD_MUTEX_INITIALIZER;

static void close_main_socket();

int main(int argc, char *argv[])
{
	if (argc != 3)
		errx(EX_USAGE, "error: invalid amount of arguments");

	int connection_type = SOCK_STREAM;
	if (strcmp(argv[1], "--udp") == 0)
		connection_type = SOCK_DGRAM;
	else if (strcmp(argv[1], "--tcp") != 0)
		errx(EX_USAGE, "error: invalid argument \"%s\"", argv[1]);

	atexit(close_main_socket);

	// Launch server
	if (connection_type == SOCK_STREAM)
		launch_tcp_server(inet_addr(argv[2]));
	else if (connection_type == SOCK_DGRAM)
		launch_udp_server(inet_addr(argv[2]));

	return 0;
}

static void close_main_socket()
{
	close(SERVER_SOCKET_FD);
}

void launch_tcp_server(in_addr_t ip)
{
	int socket_fd = ipv4_sock_bind(SOCK_STREAM, ip, htons(USING_PORT));
	if (socket_fd == -1)
		errx(EX_OSERR, "ipv4_sock_connect() error");

	SERVER_SOCKET_FD = socket_fd;

	// Listening on
	int error_listen = listen(socket_fd, N_MAX_PENDING_CONNECTIONS);
	if (error_listen == -1)
	{
		perror("listen()");
		close(socket_fd);
		errx(EX_OSERR, "listen() error");
	}

	// Accept connections
	while(1)
	{
		struct sockaddr_in accept_addr = {0};
		socklen_t length = sizeof(struct sockaddr_in);

		int accepted_socket_fd = accept(socket_fd, (struct sockaddr *) &accept_addr, &length);
		if (accepted_socket_fd == -1)
		{
			perror("accept()");
			errno = 0;
			continue;
		}

		printf("New connection!\n");
	 	printf("From IP = %s, port = %d!\n", inet_ntoa(accept_addr.sin_addr), (int) ntohs(accept_addr.sin_port));

		pthread_t new_thread = {0};
		int pthread_error = pthread_create(&new_thread, NULL, client_handler, (void *) accepted_socket_fd);
		if (pthread_error == -1)
		{
			perror("pthread_create()");
			errno = 0;
			continue;
		}

		pthread_error = pthread_detach(new_thread);
		if (pthread_error == -1)
		{
			perror("pthread_detach()");
			errno = 0;
			continue;
		}
	}	
}

void *client_handler(void *connection_socket)
{
	int socket_fd = (int) connection_socket;
	
	ssize_t received_bytes = ipv4_receive_file(SOCK_STREAM, socket_fd, &SERVER_SOCKETS_HANDLER_MUTEX);
	if (received_bytes == -1)
	{
		close(socket_fd);
		exit(EXIT_FAILURE);
	}

	if (close(socket_fd) == -1)
	{
		perror("close()");
		exit(EXIT_FAILURE);
	}

	void *retval = 0;
	pthread_exit(retval);
}

int launch_udp_server(in_addr_t ip)
{
	udt_startup();

	int socket_fd = ipv4_socket(SOCK_DGRAM, SO_REUSEADDR);
	if (socket_fd == -1)
		return -1;

	struct sockaddr_in server_addr = {0};
	socklen_t length = sizeof(struct sockaddr_in);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(USING_PORT);
	server_addr.sin_addr.s_addr = ip;	

	if (udt_bind(socket_fd, (struct sockaddr *) &server_addr, length) == -1)
	{
        fprintf(stderr, "Could not connect to socket\n");
        exit(errno);
    }

	char buffer[1000] = {0};
	ssize_t recv_bytes = udt_recv(socket_fd, buffer, 244);
    if (recv_bytes != -1 && recv_bytes != 0)
	{
        printf("\tMessage: %s\n\n", buffer);
        memset(buffer, 0, sizeof(buffer));
    }

	//sleep(5);

	char new_buffer[1000] = {0};
	strcpy(new_buffer, "888LLLLLLLLLJJJDJJ jhdjvbshdbvhjsbdvhjbdscjebdvhjksjdbvhjce,whsdbvbhj,mehwbshj vm"
				   "efwsdfsdfdsfsdfdfgnj.k/.k,jm5555555555555999999999999999999995555555555555555555555555555555555555");

	udt_send(socket_fd, new_buffer, 180);

	printf("In while()\n");

	while(1);

	return 0;
}
