#ifndef NET_H_
#define NET_H_

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

enum connection_type
{
    UDP_CONNECT = 33,
	TCP_CONNECT = 34,
	UNKNOWN     = 1
};

#define USING_PORT 16161
#define N_MAX_MSG_LEN 1024
#define N_MAX_PENDING_CONNECTIONS 1024
#define N_MAX_CLIENTS 1024

// Client functions
void launch_tcp_client();
void launch_udp_client();

// Server functions
void launch_tcp_server();
void launch_udp_server();
void *client_handler(void *connection_socket);
void close_main_socket();
 
#endif // !NET_H_
