#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"
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

ssize_t udt_packet_new(udt_packet_t *packet, const void *buffer, size_t len)
{
    if (packet == NULL)
        return -1;

    if (len > sizeof(packet->data))
        return -1;

    memset(packet->data, 0, sizeof(packet->data));
    memcpy(packet->data, buffer, len);
    udt_packet_serialize(packet);

    return len;
}

ssize_t udt_packet_new_handshake(udt_packet_t *packet)
{
    if (packet == NULL)
        return -1;

    packet_clear_header (*packet);
    packet_set_ctrl     (*packet);
    packet_set_type     (*packet, PACKET_TYPE_HANDSHAKE);
    packet_set_timestamp(*packet, 0);
    packet_set_id       (*packet, 0);

    uint32_t buffer[8] = {0};

    uint32_t flight_flag_size = 10;
    uint32_t id = 10;
    uint32_t request_type = 0;
    uint32_t cookie = 10;

    buffer[0] = UDT_VERSION;
    buffer[1] = connection.type;
    buffer[2] = 0x123123; // random number
    buffer[3] = PACKET_DATA_SIZE;
    buffer[4] = flight_flag_size;
    buffer[5] = request_type;
    buffer[6] = id;
    buffer[7] = cookie;

    for (int i = 0; i < 8; ++i)
        buffer[i] = htonl(buffer[i]);

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
                udt_console_log("packet: handshake");

                if (connection.is_client == 1) // client
                {
                    pthread_cond_signal(&handshake_cond);
                    udt_handshake_terminate();
                }
                else if (connection.is_connected == 0) // server
                {
                    int fork_value = fork();
                    if (fork_value == -1)
                        return;
                    else if (fork_value == 0) // child
                    {
                        int new_socket_fd = ipv4_socket(SOCK_DGRAM, SO_REUSEADDR);
                        if (new_socket_fd == -1)
                            return;

                        struct timeval tv = {.tv_sec = UDT_SECONDS_TIMEOUT_SERVER, .tv_usec = UDT_USECONDS_TIMEOUT_SERVER};
                        setsockopt(new_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));

                        connection.socket_fd = new_socket_fd;

                        udt_packet_new_handshake(&packet);
                        udt_send_packet_buffer_write(&packet);
                        udt_handshake_terminate();
                    }
                }

                break;

            case PACKET_TYPE_KEEPALIVE:             // keep-alive
                udt_console_log("packet: keep alive");
                break;

            case PACKET_TYPE_ACK:                   // ack
                udt_console_log("packet: ack");
                if (packet_get_msgnum(packet) == connection.last_packet_number)
                    connection.is_in_wait = 0;

                break;

            case PACKET_TYPE_NAK:                   // nak
                udt_console_log("packet: nak");
                break;

            case PACKET_TYPE_CONGDELAY:             // congestion-delay warn
                udt_console_log("packet: congestion delay");
                break;

            case PACKET_TYPE_SHUTDOWN:              // shutdown
                udt_console_log("packet: shutdown");

                if (connection.is_connected == 0)
                {
                    printf("Packet from alien!\n");
                    break;
                }

                connection.is_connected = 0;
                if (connection.is_client == 0) // server
                {
                    udt_connection_close();
                    exit(EXIT_SUCCESS);
                }
                    
                break;

            case PACKET_TYPE_ACK2:                  // ack of ack
                udt_console_log("packet: ack of ack");
                break;

            case PACKET_TYPE_DROPREQ:               // message drop request
                udt_console_log("packet: drop request");
                break;

            case PACKET_TYPE_ERRSIG:                // error signal
                udt_console_log("packet: error signal");
                break;

            default:                                // unsupported packet type
                udt_console_log("packet: unknown");
        }
    }
    else // data packet
    {
        udt_console_log("packet: data");

        if (connection.is_connected == 1)
        {
            if (packet.header._head1 & 0x80000000 &&
                packet.header._head1 & 0x40000000)      // solo packet
                udt_recv_buffer_write(packet.data, PACKET_DATA_SIZE);

            else if (packet.header._head1 & 0x40000000) // last packet
            {
                setsockopt(connection.socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &(connection.saved_tv), sizeof(struct timeval));

                if (packet_get_msgnum(packet) == (connection.last_packet_number + 1))
                {
                    udt_recv_buffer_write(packet.data, PACKET_DATA_SIZE);
                    connection.last_packet_number = 0;
                }
                else
                    return;
            }
                
            else if (packet.header._head1 & 0x80000000) // first packet
            {
                socklen_t optlen;
                getsockopt(connection.socket_fd, SOL_SOCKET, SO_RCVTIMEO, &(connection.saved_tv), &optlen);

                struct timeval new_tv = {.tv_sec = UDT_SECONDS_TIMEOUT_READ, .tv_usec = UDT_USECONDS_TIMEOUT_READ};
                setsockopt(connection.socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &new_tv, sizeof(struct timeval));

                udt_recv_buffer_write(packet.data, -1);
                connection.last_packet_number = 1;
            }
                
            else // middle packet
            {
                if (packet_get_msgnum(packet) == (connection.last_packet_number + 1))
                {
                    udt_recv_buffer_write(packet.data, -1);
                    connection.last_packet_number++;
                }
                else
                    return;
            } 

            udt_packet_t packet_ack;
            size_t message_number = packet_get_msgnum(packet);

            packet_clear_header (packet_ack);
            packet_set_ctrl     (packet_ack);
            packet_set_type     (packet_ack, PACKET_TYPE_ACK);
            packet_set_timestamp(packet_ack, 0x0000051c);
            packet_set_id       (packet_ack, 0x08c42c74);
            packet_set_msgnum   (packet_ack, message_number);

            udt_packet_new(&packet_ack, NULL, 0);
            udt_send_packet_buffer_write(&packet_ack);
        }
        else
            udt_console_log("packet from alien!");
    }

    return;
}
