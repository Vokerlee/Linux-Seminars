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

void launch_udp_server(in_addr_t ip)
{
	// // Creating socket
	// int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // UDP
	// if (socket_fd == -1)
	// {
	// 	perror("socket()");
	// 	errx(EX_OSERR, "socket() error");
	// }

	// int optval = 1;
	// int error = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	// if (error == -1)
	// {
	// 	perror("setsockopt()");
	// 	close(socket_fd);
	// 	errx(EX_OSERR, "setsockopt() error");
	// }

	// MAIN_SOCKET_FD = socket_fd;

	// // Binding
	// struct sockaddr_in server_addr = {0};

	// server_addr.sin_family = AF_INET;
	// server_addr.sin_port = htons(USING_PORT);
	// server_addr.sin_addr.s_addr = inet_addr(server_ip);

	// int error_bind_server = bind(socket_fd, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
	// if (error_bind_server == -1)
	// {
	// 	perror("bind()");
	// 	errx(EX_OSERR, "bind() error");
	// }

	// char msg[N_MAX_MSG_LEN] = {0};

	// while(1)
	// {
	// 	memset(msg, 0, N_MAX_MSG_LEN);

	// 	struct sockaddr_in accept_addr = {0};
	// 	socklen_t length = sizeof(struct sockaddr_in);

	// 	ssize_t n_received_bytes = recvfrom(socket_fd, msg, sizeof(msg), 0, (struct sockaddr *) &accept_addr, &length);
	// 	if (n_received_bytes == -1)
	// 	{
	// 		perror("recvfrom()");
	// 		errno = 0;
	// 		continue;
	// 	}

	// 	int mutex_error = pthread_mutex_lock(&SERVER_SOCKETS_HANDLER_MUTEX);
	// 	if (mutex_error == -1)
	// 	{
	// 		perror("pthread_mutex_lock()");
	// 		exit(EXIT_FAILURE);
	// 	}

	// 	printf("New message!\n");
	//  	printf("From IP = %s, port = %d!\n\n", inet_ntoa(accept_addr.sin_addr), (int) ntohs(accept_addr.sin_port));

	// 	printf("Message:\n%s\n", msg);
	// 	printf("==================================================\n");

	// 	mutex_error = pthread_mutex_unlock(&SERVER_SOCKETS_HANDLER_MUTEX);
	// 	if (mutex_error == -1)
	// 	{
	// 		perror("pthread_mutex_unlock()");
	// 		exit(EXIT_FAILURE);
	// 	}
	// }
}
