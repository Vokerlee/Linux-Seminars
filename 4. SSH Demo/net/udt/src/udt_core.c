#include "udt_core.h"
#include "udt_packet.h"
#include "udt_buffer.h"

udt_conn_t connection = {0};

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

    while (udt_send_packet_buffer_read(&packet))
    {
        if (sendto(conn->socket_fd, &packet, sizeof(udt_packet_t), 0,
                    (struct sockaddr *) &(conn->addr), sizeof(struct sockaddr)) == -1)
            exit(errno);

        memset(&packet, 0, sizeof(udt_packet_t));
    }

    void *retval = 0;
	pthread_exit(retval);
}

void *udt_receiver_start(void *arg)
{
    udt_conn_t *conn = (udt_conn_t *) arg;
    udt_packet_t packet;

    memset(&packet, 0, sizeof(udt_packet_t));
    struct sockaddr_in sender_addr = {0};

    while (recvfrom(conn->socket_fd, &packet, sizeof(udt_packet_t), 0,
           (struct sockaddr *) &sender_addr, &(conn->addrlen)))
    {
        printf("MSG from ip = %s, port = %d\n", inet_ntoa(sender_addr.sin_addr), (int) ntohs(sender_addr.sin_port));

        if (conn->is_connected == 0)
            conn->addr = sender_addr;
        else if (sender_addr.sin_addr.s_addr != conn->addr.sin_addr.s_addr || sender_addr.sin_port != conn->addr.sin_port)
        {
            printf("ALIEN!!!\n"); // now we just skeep aliens, but in future they will be handled by other subservers
            memset(&packet, 0, sizeof(udt_packet_t));
            continue;
        }
            

        udt_packet_parse(packet);
        memset(&packet, 0, sizeof(udt_packet_t));
    }

    void *retval = 0;
	pthread_exit(retval);
}
