#ifndef UDT_CORE_H_
#define UDT_CORE_H_

#include "net_config.h"

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

    struct
    {   
        pthread_t recv_thread;
        pthread_t send_thread;
    };

    struct timeval saved_tv;
} udt_conn_t;

extern udt_conn_t connection;

void udt_handshake_init     ();
void udt_handshake_terminate();
void udt_connection_close   ();

void *udt_sender_start  (void *arg);
void *udt_receiver_start(void *arg);

#endif // !UDT_CORE_H_
