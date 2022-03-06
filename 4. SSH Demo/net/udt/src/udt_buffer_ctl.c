#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>

#include "net_config.h"
#include "udt_packet.h"
#include "udt_core.h"
#include "udt_buffer.h"

udt_buffer_t RECV_BUFFER = {0};
udt_buffer_t SEND_BUFFER = {0};

extern udt_conn_t connection;

int udt_recv_buffer_init()
{
    return udt_buffer_init(&RECV_BUFFER);
}

int udt_send_buffer_init()
{
    return udt_buffer_init(&SEND_BUFFER);
}

ssize_t udt_recv_buffer_write(char *data, ssize_t len)
{
    return udt_buffer_write(&RECV_BUFFER, data, len);
}

ssize_t udt_recv_buffer_read(char *data, ssize_t len)
{
    return udt_buffer_read(&RECV_BUFFER, data, len);
}

ssize_t udt_send_buffer_write(char *data, ssize_t len)
{
    if (data == NULL)
        return -1;

    udt_packet_t packet;

    size_t msgnum  = 1;
    int    seqnum  = 1; 
    size_t n_attempts = 0; 

    ssize_t n_sent_bytes = 0;
    int boundary = PACKET_BOUNDARY_START; 

    long n_bytes_to_send = len;
    char *buffer = data;

    while (n_bytes_to_send > 0)
    {
        ssize_t n_packet_bytes = (n_bytes_to_send > PACKET_DATA_SIZE) ? PACKET_DATA_SIZE : n_bytes_to_send;
        n_bytes_to_send -= PACKET_DATA_SIZE;
        boundary |= (n_bytes_to_send > 0) ? PACKET_BOUNDARY_NONE : PACKET_BOUNDARY_END;

        connection.last_packet_number = msgnum;

        packet_clear_header (packet);
        packet_set_data     (packet);
        packet_set_seqnum   (packet, seqnum++);
        packet_set_msgnum   (packet, msgnum++);
        packet_set_boundary (packet, boundary);
        packet_set_order    (packet, 1);
        packet_set_timestamp(packet, 0x0000051c);
        packet_set_id       (packet, 0x08c42c74);

        while (n_attempts < UDT_N_MAX_ATTEMPTS_SEND)
        {
            connection.is_in_wait = 1;
            
            udt_packet_new(&packet, buffer, n_packet_bytes);
            udt_send_packet_buffer_write(&packet);

            while (connection.is_in_wait == 1); // wait for ACK signal

            if (connection.no_ack == 1)
            {
                connection.no_ack = 0;
                n_attempts++;
            }
            else
                break;
        }

        if (n_attempts == UDT_N_MAX_ATTEMPTS_SEND)
            return n_sent_bytes;

        n_sent_bytes += n_packet_bytes;

        boundary = PACKET_BOUNDARY_NONE;
        buffer += n_packet_bytes;

        n_attempts = 0;
    }

    packet_clear_header (packet);
    packet_set_ctrl     (packet);
    packet_set_type     (packet, PACKET_TYPE_ACK2);
    packet_set_timestamp(packet, 0x0000051c);
    packet_set_id       (packet, 0x08c42c74);

    udt_packet_new(&packet, NULL, 0);
    udt_send_packet_buffer_write(&packet);

    return n_sent_bytes;
}

int udt_send_packet_buffer_write(udt_packet_t *packet)
{
    return udt_buffer_write_packet(&SEND_BUFFER, packet);
}

int udt_send_packet_buffer_read(udt_packet_t *packet)
{
    return udt_buffer_read_packet(&SEND_BUFFER, packet);
}

ssize_t udt_recv_file_buffer_read(int fd, off_t *offset, ssize_t size)
{
    char data[PACKET_DATA_SIZE + 1];
    ssize_t retval = 0;
    long buf_size = size;

    if (fd < 0 || offset == NULL)
        return -1;

    while (buf_size > 0)
    {
        int n_read_bytes = udt_buffer_read(&RECV_BUFFER, data, PACKET_DATA_SIZE);
        if (n_read_bytes != PACKET_DATA_SIZE)
            break; // the situation when connection has lost and there is nothing to read

        ssize_t bytes_to_write = (buf_size > PACKET_DATA_SIZE) ? PACKET_DATA_SIZE : buf_size;
        ssize_t n_written_bytes = pwrite(fd, &data, bytes_to_write, *offset);
        if (n_written_bytes < 1)
        {
            buf_size -= n_written_bytes;
            continue;
        }
            
        *offset  += n_written_bytes;
        retval   += n_written_bytes;
        buf_size -= n_written_bytes;
    }

    return retval;
}

ssize_t udt_send_file_buffer_write(int fd, off_t offset, ssize_t size)
{
    if (fd < 0)
        return -1;

    udt_packet_t packet;
    char buffer[PACKET_DATA_SIZE + 1] = {0};

    size_t msgnum = 1;
    int    seqnum = 1;
    size_t n_attempts = 0;

    ssize_t n_sent_bytes = 0;
    int boundary = PACKET_BOUNDARY_START;

    long n_bytes_to_send = size;
    while (n_bytes_to_send > 0)
    {
        ssize_t n_bytes_to_read = (n_bytes_to_send > PACKET_DATA_SIZE) ? PACKET_DATA_SIZE : n_bytes_to_send;
        ssize_t n_packet_bytes = pread(fd, buffer, n_bytes_to_read, offset);
        if (n_packet_bytes < 0)
            break;

        n_bytes_to_send -= n_packet_bytes;

        // If bytes read is less than the desired, then its EOF
        if (n_packet_bytes < n_bytes_to_read)
            n_bytes_to_send = 0;

        connection.last_packet_number = msgnum;

        boundary |= (n_bytes_to_send > 0) ? PACKET_BOUNDARY_NONE : PACKET_BOUNDARY_END;

        packet_clear_header (packet);
        packet_set_data     (packet);
        packet_set_seqnum   (packet, seqnum++);
        packet_set_msgnum   (packet, msgnum++);
        packet_set_boundary (packet, boundary);
        packet_set_order    (packet, 1);
        packet_set_timestamp(packet, 0x0000051c);
        packet_set_id       (packet, 0x08c42c74);

        while (n_attempts < UDT_N_MAX_ATTEMPTS_SEND)
        {
            connection.is_in_wait = 1;

            udt_packet_new(&packet, buffer, n_packet_bytes);
            udt_send_packet_buffer_write(&packet);

            while (connection.is_in_wait == 1); // wait for ACK signal

            if (connection.no_ack == 1)
            {
                connection.no_ack = 0;
                n_attempts++;
            }
            else
                break;
        }

        if (n_attempts == UDT_N_MAX_ATTEMPTS_SEND)
            return n_sent_bytes;

        n_sent_bytes += n_packet_bytes;

        boundary = PACKET_BOUNDARY_NONE;
        offset += n_packet_bytes;

        n_attempts = 0;
    }

    packet_clear_header (packet);
    packet_set_ctrl     (packet);
    packet_set_type     (packet, PACKET_TYPE_ACK2);
    packet_set_timestamp(packet, 0x0000051c);
    packet_set_id       (packet, 0x08c42c74);

    udt_packet_new(&packet, NULL, 0);
    udt_send_packet_buffer_write(&packet);

    return n_sent_bytes;
}
