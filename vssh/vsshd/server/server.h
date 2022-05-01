#ifndef SERVER_H_
#define SERVER_H_

#include "ipv4_net.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sysexits.h>
#include <err.h>
#include <errno.h>
#include <syslog.h>

#ifdef _IPV4_TCP_LOG_
    #define ipv4_tcp_syslog(priority, fmt, ...) \
        syslog(priority, "[IPv4 TCP]: " fmt, ##__VA_ARGS__)
#else
    #define ipv4_tcp_syslog(priority, fmt, ...)
#endif // !_IPV4_TCP_LOG_

#ifdef _IPV4_UDT_LOG_
    #define ipv4_udt_syslog(priority, fmt, ...) \
        syslog(priority, "[IPv4 UDT]: " fmt, ##__VA_ARGS__)
#else
    #define ipv4_udt_syslog(priority, fmt, ...)
#endif // !_IPV4_UDT_LOG_

#ifdef _IPV4_LOG_
    #define ipv4_syslog(priority, fmt, ...) \
        syslog(priority, fmt, ##__VA_ARGS__)
#else
    #define ipv4_syslog(priority, fmt, ...)
#endif // !_IPV4_LOG_

#define SSH_SERVER_PORT 16161

int launch_vssh_tcp_server(in_addr_t ip);
void *tcp_server_handler(void *connection_socket);

int launch_vssh_udp_server(in_addr_t ip);
void *udt_server_handler(void *connection_socket);

int handle_terminal_request(int socket_fd, int connection_type, char *username, unsigned char *key);
int handle_users_list_request(int socket_fd, int connection_type, unsigned char *key);
int handle_file(int socket_fd, int connection_type, size_t file_size, char *username, char *dest_file_path, unsigned char *key);

#endif // !SERVER_H_
