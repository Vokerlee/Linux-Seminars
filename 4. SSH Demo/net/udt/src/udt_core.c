#include "udt_core.h"
#include "udt_packet.h"
#include "udt_buffer.h"

udt_conn_t connection;

void udt_handshake_init()
{
    udt_packet_t packet;

    udt_packet_new_handshake(&packet);
    udt_send_packet_buffer_write(&packet);
}

void udt_handshake_terminate()
{
    connection.is_connected = 1;
}

void udt_connection_close()
{
    udt_packet_t packet;

    packet_clear_header(packet);
    packet_set_ctrl    (packet);
    packet_set_type    (packet, PACKET_TYPE_SHUTDOWN);

    udt_packet_new(&packet, NULL, 0);
    udt_send_packet_buffer_write(&packet);
}

void *udt_sender_start(void *arg)
{
    udt_conn_t *conn = (udt_conn_t *) arg;
    udt_packet_t packet;

    while (1)
    {
        if (conn->is_open == 1 && udt_send_packet_buffer_read(&packet))
        {
            if (sendto(conn->socket_fd, &packet, sizeof(udt_packet_t), 0,
                       &(conn->addr), sizeof(struct sockaddr)) == -1)
                exit(errno);

            // Shutdown message
            if (packet.header._head0 == 1408)
                conn->is_open = 0;

            memset(&packet, 0, sizeof(udt_packet_t));
        }
    }

    void *retval = 0;
	pthread_exit(retval);
}

void *udt_receiver_start(void *arg)
{
    udt_conn_t *conn = (udt_conn_t *) arg;
    udt_packet_t packet;

    memset(&packet, 0, sizeof(udt_packet_t));

    while (recvfrom(conn->socket_fd, &packet, sizeof(udt_packet_t), 0,
           &(conn->addr), &(conn->addrlen)))
    {
        conn->is_open = 1;
        udt_packet_parse(packet);
        memset(&packet, 0, sizeof(udt_packet_t));
    }

    void *retval = 0;
	pthread_exit(retval);
}
