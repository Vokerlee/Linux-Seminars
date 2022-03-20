#ifndef SERVER_H_
#define SERVER_H_

#include "ipv4_net.h"
#include "ipv4_net_config.h"
#include "udt_api.h"

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
        syslog(priority, fmt, ##__VA_ARGS__)
#else
    #define ipv4_tcp_syslog(priority, fmt, ...)
#endif // !_IPV4_TCP_LOG_

#ifdef _IPV4_UDT_LOG_
    #define ipv4_udt_syslog(priority, fmt, ...) \
        syslog(priority, fmt, ##__VA_ARGS__)
#else
    #define ipv4_udt_syslog(priority, fmt, ...)
#endif // !_IPV4_UDT_LOG_

#define SSH_SERVER_PORT 16161

int launch_vssh_tcp_server(in_addr_t ip);
void *tcp_server_handler(void *connection_socket);

int launch_vssh_udp_server(in_addr_t ip);
void *udt_server_handler(void *connection_socket);

#endif // !SERVER_H_
