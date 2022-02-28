#ifndef UDT_CORE_H_
#define UDT_CORE_H_

#include "net_config.h"

typedef struct
{
    int socket_fd;

    struct
    {
        struct sockaddr addr;
        socklen_t addrlen;
    };

    int is_open;
    int is_connected;
    int is_client;
    int type;
} udt_conn_t;

extern udt_conn_t connection;

void udt_handshake_init      ();
void udt_handshake_terminate ();

void udt_connection_close    ();

void *udt_sender_start  (void *arg);
void *udt_receiver_start(void *arg);

#endif // !UDT_CORE_H_
