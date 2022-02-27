#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "udt_buffer.h"
#include "udt_utils.h"

int udt_buffer_init(udt_buffer_t *buffer)
{
    if (buffer)
        return pthread_mutex_init(&(buffer->mutex), NULL);
    else
        return -1;
}

ssize_t udt_buffer_write(udt_buffer_t *buffer, char *data, ssize_t len)
{
    if (buffer == NULL || data == NULL)
        return -1;

    char *new_data = strdup(data);
    if (new_data == NULL)
        return -1;

    udt_block_t *new_block = (udt_block_t *) calloc(1, sizeof(udt_block_t));
    if (new_block == NULL)
        return -1;

    new_block->data = new_data;
    new_block->len  = len;

    if (len == -1) // default
    {
        new_block->last = 0;
        new_block->len  = PACKET_DATA_SIZE;
    } 
    else
        new_block->last = 1;

    linked_list_add((*buffer), new_block);

    return new_block->len;
}

ssize_t udt_buffer_read(udt_buffer_t *buffer, char *data, ssize_t len)
{
    if (buffer == NULL || data == NULL)
        return -1;

    udt_block_t *block = NULL;
    ssize_t n_read_bytes = 0;
    ssize_t cur_pos      = 0;
    int last = 0;

    while (last == 0)
    {
        linked_list_get((*buffer), block);
        if (block == NULL)
            continue;

        last = block->last;
        if (cur_pos >= len)
            break;

        ssize_t n = ((len - cur_pos) < block->len) ? len - cur_pos : block->len;
        strncpy(data + cur_pos, block->data, n);
        n_read_bytes += n;
        cur_pos      += n;

        free(block->data);
        free(block);
    }

    return n_read_bytes;
}

int udt_buffer_write_packet(udt_buffer_t *buffer, udt_packet_t *packet)
{
    if (buffer == NULL || packet == NULL)
        return -1;

    udt_packet_block_t *new_block = (udt_packet_block_t *) calloc(1, sizeof(udt_packet_block_t));
    if (new_block == NULL)
        return -1;

    memcpy(&(new_block->packet), packet, sizeof(udt_packet_t));

    linked_list_add((*buffer), new_block);

    return 1;
}

int udt_buffer_read_packet(udt_buffer_t *buffer, udt_packet_t *packet)
{
    if (buffer == NULL || packet == NULL)
        return 0;

    udt_packet_block_t *block = NULL;

    linked_list_get((*buffer), block);
    if (block == NULL)
        return 0;

    *packet = block->packet;
    free(block);

    return 1;
}
