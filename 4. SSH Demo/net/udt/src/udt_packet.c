#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "net_config.h"
#include "udt_packet.h"
#include "udt_buffer.h"
#include "udt_core.h"
#include "udt_utils.h"

extern udt_conn_t connection;

extern pthread_mutex_t handshake_mutex;
extern pthread_cond_t  handshake_cond;

void udt_packet_deserialize(udt_packet_t *packet)
{
    if (packet == NULL)
        return;

    uint32_t *block = &(packet->header._head0);
    for (int i = 0; i < PACKET_HEADER_SIZE; ++i)
    {
        *block = ntohl(*block);
        block++;
    }
}

void udt_packet_serialize(udt_packet_t *packet)
{
    if (packet == NULL)
        return;

    uint32_t *block = &(packet->header._head0);
    for (int i = 0; i < PACKET_HEADER_SIZE; ++i)
    {
        *block = htonl(*block);
        block++;
    }
}

int udt_packet_new(udt_packet_t *packet, char *buffer, int len)
{
    if (packet == NULL)
        return -1;

    if (len > sizeof(packet->data) || len < 0)
        return -1;

    memset(packet->data, 0, sizeof(packet->data));
    memcpy(packet->data, buffer, len);
    udt_packet_serialize(packet);

    return len;
}

int udt_packet_new_handshake(udt_packet_t *packet)
{
    if (packet == NULL)
        return -1;

    char buffer[8 * sizeof(uint32_t)];
    uint32_t *p = NULL;
    uint32_t flight_flag_size = 10;
    uint32_t id = 10;
    uint32_t req_type = 0;
    uint32_t cookie = 10;

    packet_clear_header (*packet);
    packet_set_ctrl     (*packet);
    packet_set_type     (*packet, PACKET_TYPE_HANDSHAKE);
    packet_set_timestamp(*packet, 0);
    packet_set_id       (*packet, 0);

    p = (uint32_t *) buffer;
    *p++ = UDT_VERSION;
    *p++ = connection.type;
    *p++ = 0x123123;
    *p++ = PACKET_DATA_SIZE;
    *p++ = flight_flag_size;
    *p++ = req_type;
    *p++ = id;
    *p++ = cookie;

    p = (uint32_t *) (packet->data);
    for (int i = 0; i < 8; ++i)
    {
        *p = htonl(*p);
        p++;
    }

    return udt_packet_new(packet, buffer, sizeof(buffer));
}

void udt_packet_parse(udt_packet_t packet)
{
    udt_packet_deserialize(&packet);

    if (packet_is_control(packet)) // control packet
    {
        switch (packet_get_type(packet))
        {
            case PACKET_TYPE_HANDSHAKE:             // handshake
                console_log("packet: handshake");

                if (connection.is_client == 1)
                {
                    pthread_cond_signal(&handshake_cond);
                    udt_handshake_terminate();
                }
                else if (connection.is_connected == 0)
                {
                    udt_packet_new_handshake(&packet);
                    udt_send_packet_buffer_write(&packet);
                    udt_handshake_terminate();

                    struct timeval tv = {.tv_sec = UDT_SECONDS_TIMEOUT_SERVER, .tv_usec = UDT_USECONDS_TIMEOUT_SERVER};
                    setsockopt(connection.socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));
                }

                break;

            case PACKET_TYPE_KEEPALIVE:             // keep-alive
                console_log("packet: keep alive");
                break;

            case PACKET_TYPE_ACK:                   // ack
                console_log("packet: ack");
                connection.is_in_wait = 0;

                break;

            case PACKET_TYPE_NAK:                   // nak
                console_log("packet: nak");
                break;

            case PACKET_TYPE_CONGDELAY:             // congestion-delay warn
                console_log("packet: congestion delay");
                break;

            case PACKET_TYPE_SHUTDOWN:              // shutdown
                console_log("packet: shutdown");

                if (connection.is_connected == 0)
                {
                    printf("Packet from alien!\n");
                    break;
                }

                connection.is_connected = 0;
                if (connection.is_client == 0) // server
                {
                    struct timeval tv = {.tv_sec = 0, .tv_usec = 0};
                    setsockopt(connection.socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));
                    udt_connection_close();
                }
                    
                break;

            case PACKET_TYPE_ACK2:                  // ack of ack
                console_log("packet: ack of ack");
                break;

            case PACKET_TYPE_DROPREQ:               // message drop request
                console_log("packet: drop request");
                break;

            case PACKET_TYPE_ERRSIG:                // error signal
                console_log("packet: error signal");
                break;

            default:                                // unsupported packet type
                console_log("packet: unknown");
        }
    }
    else // data packet
    {
        console_log("packet: data");

        if (connection.is_connected == 1)
        {
            if (packet.header._head1 & 0x80000000 &&
                packet.header._head1 & 0x40000000)      // solo packet
                udt_recv_buffer_write(packet.data, PACKET_DATA_SIZE);

            else if (packet.header._head1 & 0x40000000) // last packet
                udt_recv_buffer_write(packet.data, PACKET_DATA_SIZE);

            else if (packet.header._head1 & 0x80000000) // first packet
                udt_recv_buffer_write(packet.data, -1);

            else                                        // middle packet
                udt_recv_buffer_write(packet.data, -1);

            udt_packet_t packet_ack;

            packet_clear_header (packet_ack);
            packet_set_ctrl     (packet_ack);
            packet_set_type     (packet_ack, PACKET_TYPE_ACK);
            packet_set_timestamp(packet_ack, 0x0000051c);
            packet_set_id       (packet_ack, 0x08c42c74);

            udt_packet_new(&packet_ack, NULL, 0);
            udt_send_packet_buffer_write(&packet_ack);
        }
        else
        {
            printf("Packet from alien!\n");
        }
    }

    return;
}
