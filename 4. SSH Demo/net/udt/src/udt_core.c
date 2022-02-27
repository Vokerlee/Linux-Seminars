#include "udt_core.h"
#include "udt_packet.h"
#include "udt_buffer.h"

udt_conn_t connection;

void udt_handshake_init()
{
    udt_packet_t packet;

    packet_new_handshake(&packet);
    send_packet_buffer_write(&packet);
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

    packet_new(&packet, NULL, 0);
    send_packet_buffer_write(&packet);
}
