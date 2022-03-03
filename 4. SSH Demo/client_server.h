#ifndef CLIENT_SERVER_H_
#define CLIENT_SERVER_H_

#include "net.h"
#include "udt_api.h"

#define USING_PORT 16161
#define N_MAX_PENDING_CONNECTIONS 1024

// Client functions
int launch_tcp_client(in_addr_t dest_ip, int file_fd, const char *file_name);
int launch_udp_client(in_addr_t dest_ip, int file_fd, const char *file_name);

// Server functions
int launch_tcp_server(in_addr_t ip);
int launch_udp_server(in_addr_t ip);
void *client_handler(void *connection_socket);

#endif // !CLIENT_SERVER_H_
