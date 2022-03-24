#ifndef UDT_CORE_H_
#define UDT_CORE_H_

#include "ipv4_net_config.h"
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>

typedef struct
{
    int socket_fd;
    int type;

    struct
    {
        struct sockaddr_in last_addr;
        struct sockaddr_in addr;
        socklen_t addrlen;
    };

    int is_connected;
    int is_client;
    int is_in_wait;

    int no_ack;
    size_t last_packet_number;

    int is_main_server;

    struct
    {   
        pthread_t recv_thread;
        pthread_t send_thread;
    };

    struct timeval saved_tv;

    void* (*server_handler)(void *);
} udt_conn_t;

extern udt_conn_t connection;

int udt_startup();

void udt_handshake_init     ();
void udt_handshake_terminate();
void udt_connection_close   ();

void *udt_sender_start  (void *arg);
void *udt_receiver_start(void *arg);

void udt_child_after_fork();
void udt_prepare_to_fork ();

#endif // !UDT_CORE_H_
