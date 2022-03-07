#ifndef CLIENT_SERVER_H_
#define CLIENT_SERVER_H_

#include "ipv4_net.h"
#include "ipv4_net_config.h"
#include "udt_api.h"

#define SERVER_PORT 16161

// Client functions
int launch_tcp_client(in_addr_t dest_ip, int file_fd, const char *file_name);
int launch_udp_client(in_addr_t dest_ip, int file_fd, const char *file_name);

// Server functions
int launch_tcp_server(in_addr_t ip);
void *tcp_server_handler(void *connection_socket);

int launch_udp_server(in_addr_t ip);
void *udt_server_handler(void *connection_socket);

#endif // !CLIENT_SERVER_H_
