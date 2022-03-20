#ifndef NET_CONFIG_H_
#define NET_CONFIG_H_

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
#define _UNIX03_THREADS
#include <pthread.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define _UDT_LOG_
#define _IPV4_UDT_LOG_
#define _IPV4_TCP_LOG_

// UDT
#define UDT_VERSION_MAJOR 0
#define UDT_VERSION_MINOR 2
#define UDT_VERSION       5

#define UDT_N_MAX_ATTEMPTS_CONN   6 // attempts to connnect to server
#define UDT_SECONDS_TIMEOUT_CONN  2
#define UDT_USECONDS_TIMEOUT_CONN 0

#define UDT_SECONDS_TIMEOUT_SERVER  6
#define UDT_USECONDS_TIMEOUT_SERVER 0

#define UDT_SECONDS_TIMEOUT_CLIENT  6
#define UDT_USECONDS_TIMEOUT_CLIENT 0

#define UDT_SECONDS_TIMEOUT_SEND  2
#define UDT_USECONDS_TIMEOUT_SEND 0
#define UDT_N_MAX_ATTEMPTS_SEND 3

#define UDT_SECONDS_TIMEOUT_READ  UDT_SECONDS_TIMEOUT_SEND * UDT_N_MAX_ATTEMPTS_SEND
#define UDT_USECONDS_TIMEOUT_READ 0

// TCP
#define HDR_MSG_LEN 80
#define TCP_N_MAX_PENDING_CONNECTIONS 1024

// General
#define PACKET_DATA_SIZE 1000
#define N_MAX_FILENAME_LEN 1024

#endif // !NET_CONFIG_H_
