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

#define HDR_MSG_LEN 1512
#define PACKET_DATA_SIZE 4096

#define N_MAX_FILENAME_LEN 1024

int ipv4_socket(int type, int optname);




int ipv4_connect(int socket_fd, in_addr_t dest_ip, in_port_t dest_port);
int ipv4_sock_connect(int type, in_addr_t dest_ip, in_port_t dest_port);

int ipv4_bind(int socket_fd, in_addr_t ip, in_port_t port);
int ipv4_sock_bind(int type, in_addr_t ip, in_port_t port);

ssize_t ipv4_send_file(int type, int socket_fd, int file_fd, const char* file_name);
ssize_t ipv4_send_file_tcp(int socket_fd, int file_fd, const char* file_name);
ssize_t ipv4_send_file_udp(int socket_fd, int file_fd, const char* file_name);

ssize_t ipv4_receive_file(int type, int socket_fd, pthread_mutex_t *sync_mutex);
ssize_t ipv4_receive_file_tcp(int socket_fd, pthread_mutex_t *sync_mutex);
ssize_t ipv4_receive_file_udp(int socket_fd, pthread_mutex_t *sync_mutex);
 
#endif // !NET_H_
