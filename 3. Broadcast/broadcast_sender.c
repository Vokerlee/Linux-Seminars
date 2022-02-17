// General
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sysexits.h>
#include <err.h>

// Sockets
#include <sys/socket.h>
#include <sys/un.h>

// IP
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

// Others
#include <pthread.h>
#include <arpa/inet.h>

#define BROADCAST_PORT 27311
#define MY_PERSONAL_PORT 14888
#define N_MAX_MSG_LEN  1024

int main()
{
    // Creating own socket
	int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // UDP
	if (socket_fd == -1)
	{
		perror("socket()");
		errx(EX_OSERR, "socket() error");
	}

    int optval = 1;
	int error = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (error == -1)
	{
		perror("setsockopt()");
		close(socket_fd);
		errx(EX_OSERR, "setsockopt() error");
	}

	// Binding to own socket
	struct sockaddr_in client_addr = {0};

	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(MY_PERSONAL_PORT);
	client_addr.sin_addr.s_addr = INADDR_ANY;

	int error_bind_server = bind(socket_fd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in));
	if (error_bind_server == -1)
	{
		perror("bind()");
		errx(EX_OSERR, "bind() error");
	}

    // To send broadcast
    struct sockaddr_in broadcast_addr = {0};
    socklen_t length = sizeof(struct sockaddr_in);

	broadcast_addr.sin_family = AF_INET;
	broadcast_addr.sin_port = htons(BROADCAST_PORT);
	broadcast_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Sending broadcast
    const char msg[N_MAX_MSG_LEN] = "I am a client!!";

    ssize_t sent_bytes = sendto(socket_fd, msg, sizeof(msg), 0, (struct sockaddr *) &broadcast_addr, length);
	if (sent_bytes == -1 || sent_bytes != sizeof(msg))
	{
		perror("sendto()");
		errx(EX_OSERR, "send() error");
	}

    // Now we are to receiver a otklik from server

    char new_msg[N_MAX_MSG_LEN] = {0};

    struct sockaddr_in accept_addr = {0};

	ssize_t n_received_bytes = recvfrom(socket_fd, new_msg, sizeof(new_msg), 0, (struct sockaddr *) &accept_addr, &length);
	if (n_received_bytes == -1)
	{
		perror("recvfrom()");
		exit(EXIT_FAILURE);
	}

	printf("New message!\n");
	printf("From IP = %s, port = %d!\n\n", inet_ntoa(accept_addr.sin_addr), (int) ntohs(accept_addr.sin_port));

	printf("Message:\n%s\n", new_msg);
	printf("==================================================\n");

    close(socket_fd);

    return 0;
}