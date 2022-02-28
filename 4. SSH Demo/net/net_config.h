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
#include <pthread.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define UDT_VERSION_MAJOR 0
#define UDT_VERSION_MINOR 1
#define UDT_VERSION 4

#define N_MAX_FILENAME_LEN 1024

#endif // !NET_CONFIG_H_
