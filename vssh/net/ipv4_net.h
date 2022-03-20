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
#include <fcntl.h>

#include "ipv4_net_config.h"
#include "udt_api.h"

#define IPV4_SPARE_FIELDS 64
#define IPV4_SPARE_BUFFER_LENGTH 256

enum ipv4_msg_type
{
    IPV4_MSG_HEADER_TYPE  = 1,
    IPV4_FILE_HEADER_TYPE = 2,
    IPV4_SHUTDOWN_TYPE    = 3,
};

typedef struct
{
    uint64_t message_length;
    uint64_t message_type;

    union
    {
        uint32_t spare_fields[IPV4_SPARE_FIELDS];
        char     spare_buffer[IPV4_SPARE_BUFFER_LENGTH];
    };
} ipv4_ctl_message;

int ipv4_socket(int type, int optname);

int ipv4_connect(int socket_fd, in_addr_t dest_ip, in_port_t dest_port, int connection_type);
int ipv4_bind   (int socket_fd, in_addr_t ip,      in_port_t port,      int connection_type, void *(*udt_server_handler)(void *));
int ipv4_listen (int socket_fd);
int ipv4_accept (int socket_fd, struct sockaddr *addr, socklen_t *length);
int ipv4_close  (int socket_fd, int connection_type);

ssize_t ipv4_receive_message(int socket_fd,       void *buffer, size_t n_bytes, int connection_type);
ssize_t ipv4_send_message   (int socket_fd, const void *buffer, size_t n_bytes, int connection_type);

ssize_t ipv4_send_file(int type, int socket_fd, int file_fd, const char* file_name);
ssize_t ipv4_send_file_tcp(int socket_fd, int file_fd, const char* file_name);
ssize_t ipv4_send_file_udp(int socket_fd, int file_fd, const char* file_name);

ssize_t ipv4_receive_file(int type, int socket_fd, pthread_mutex_t *sync_mutex);
ssize_t ipv4_receive_file_tcp(int socket_fd, pthread_mutex_t *sync_mutex);
ssize_t ipv4_receive_file_udp(int socket_fd, pthread_mutex_t *sync_mutex);

static int ipv4_send_ctl_message(int socket_fd, enum ipv4_msg_type msg_type, uint64_t msg_length, 
								 uint32_t *spare_fields, size_t spare_fields_size, char *spare_buffer, size_t spare_buffer_size,
								 int connection_type);
 
#endif // !NET_H_
