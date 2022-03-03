#ifndef UDT_PACKET_H_
#define UDT_PACKET_H_

#include "net_config.h"

#define PACKET_HEADER_SIZE 4
// #define PACKET_DATA_SIZE   4096

#define PACKET_MASK_CTRL 0x80000000
#define PACKET_MASK_SEQ  0x7FFFFFFF
#define PACKET_MASK_TYPE 0x7FFF0000

#define PACKET_TYPE_HANDSHAKE 0x00000000
#define PACKET_TYPE_KEEPALIVE 0x00010000
#define PACKET_TYPE_ACK       0x00020000
#define PACKET_TYPE_NAK       0x00030000
#define PACKET_TYPE_CONGDELAY 0x00040000
#define PACKET_TYPE_SHUTDOWN  0x00050000
#define PACKET_TYPE_ACK2      0x00060000
#define PACKET_TYPE_DROPREQ   0x00070000
#define PACKET_TYPE_ERRSIG    0x00080000

#define PACKET_BOUNDARY_NONE  0
#define PACKET_BOUNDARY_END   1
#define PACKET_BOUNDARY_START 2
#define PACKET_BOUNDARY_SOLO  3

#define packet_is_control(packet)                 \
    ((packet).header._head0 & PACKET_MASK_CTRL)

#define packet_get_type(packet)                   \
    ((packet).header._head0 & PACKET_MASK_TYPE)

#define packet_clear_header(packet)               \
    ((packet).header._head0 &= 0x00000000);       \
    ((packet).header._head1 &= 0x00000000);       \
    ((packet).header._head2 &= 0x00000000);       \
    ((packet).header._head3 &= 0x00000000)

#define packet_set_data(packet)                   \
    ((packet).header._head0 &= 0x7FFFFFFF)

#define packet_set_ctrl(packet)                   \
    ((packet).header._head0 |= PACKET_MASK_CTRL)

#define packet_set_seqnum(packet, seqnum)         \
    ((packet).header._head0 &= 0x80000000);       \
    ((packet).header._head0 |= (seqnum))

#define packet_set_boundary(packet, boundary)     \
    ((packet).header._head1 &= 0xC0000000);       \
    ((packet).header._head1 |= (boundary << 30))

#define packet_set_order(packet, order)           \
    ((packet).header._head1 |= (order) ? 0x20000000 : 0x00000000)

#define packet_set_msgnum(packet, msgnum)         \
    ((packet).header._head1 &= 0xF0000000);       \
    ((packet).header._head1 |= (msgnum))

#define packet_set_timestamp(packet, timestamp_)  \
    ((packet).header._head2 |= timestamp_)

#define packet_set_id(packet, packet_id)          \
    ((packet).header._head3 |= packet_id)

#define packet_set_type(packet, packet_type)      \
    ((packet).header._head0 &= 0x8000FFFF);       \
    ((packet).header._head0 |= (packet_type))

/**
 * The udt packet header structure
 *
 * There are two kinds of packets: data and control which are distinguished
 * based on the value of control.
 * 0 - data packet
 * 1 - control packet
 *
 * Data packet header contains:
 *   sequence_number
 *   boundary order message_number
 *   time_stamp
 *
 * Control packet header contains:
 *   type ext_type
 *   ack_sequence_number
 *   time_stamp
 */
typedef struct
{
    union
    {
        uint32_t sequence_number;
        struct
        {
            uint16_t type;
            uint16_t ext_type;
        };
        uint32_t _head0;
    };

    union
    {
        uint32_t message_number;
        uint32_t ack_sequence_number;
        uint32_t _head1;
    };

    union
    {
        uint32_t timestamp;
        uint32_t _head2;
    };

    union
    {
        uint32_t id;
        uint32_t _head3;
    };

} udt_packet_header_t;

typedef struct
{
    udt_packet_header_t header;
    char                data[PACKET_DATA_SIZE];
} udt_packet_t;

void udt_packet_deserialize   (udt_packet_t *packet);
void udt_packet_serialize     (udt_packet_t *packet);

int  udt_packet_new           (udt_packet_t *packet, char *buffer, int len);
int  udt_packet_new_handshake (udt_packet_t *packet);
void udt_packet_parse         (udt_packet_t  packet);

#endif // !UDT_PACKET_H_
